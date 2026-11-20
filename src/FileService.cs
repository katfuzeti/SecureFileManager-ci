using System.Security.Cryptography;
using System.Text;

namespace SecureFileManager;

public sealed record DirEntry(string Name, string Kind, long Size, DateTime ModifiedUtc);

public sealed class FileService(Database db, UserSandbox sandbox, Session session)
{
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    public List<DirEntry> List(string path)
    {
        var location = sandbox.Resolve(path, allowRoot: true);
        var result = new List<DirEntry>();
        foreach (var item in new DirectoryInfo(location.Full).EnumerateFileSystemInfos().OrderBy(i => i.Name, StringComparer.Ordinal))
        {
            var kind = item.LinkTarget is not null ? "link" : item is DirectoryInfo ? "dir" : "file";
            result.Add(new DirEntry(item.Name, kind, item is FileInfo f && kind == "file" ? f.Length : 0, item.LastWriteTimeUtc));
        }
        return result;
    }

    public void MakeDirectory(string path)
    {
        using var writeLock = sandbox.AcquireWriteLock();
        var location = sandbox.Resolve(path);
        if (File.Exists(location.Full) || Directory.Exists(location.Full)) throw new AppException("Такое имя уже существует.");
        sandbox.EnsureParent(location);
        Directory.CreateDirectory(location.Full, UserSandbox.DirMode);
    }

    public byte[] ReadBytes(string path, long maxBytes)
    {
        var location = sandbox.Resolve(path);
        if (Directory.Exists(location.Full)) throw new AppException("Это каталог.");
        using var stream = sandbox.OpenRead(location);
        if (stream.Length > maxBytes) throw new AppException($"Файл больше допустимых {maxBytes / 1024 / 1024} МБ.");
        var buffer = new byte[stream.Length];
        stream.ReadExactly(buffer);
        return buffer;
    }

    public string ReadText(string path, long maxBytes = Limits.MaxReadBytes)
    {
        try
        {
            return StrictUtf8.GetString(ReadBytes(path, maxBytes));
        }
        catch (DecoderFallbackException)
        {
            throw new AppException("Файл не является текстом UTF-8.");
        }
    }

    /// <summary>Атомарная запись: сначала временный файл, затем rename в одной транзакции с записью в БД.</summary>
    public string Write(string path, byte[] data, bool overwrite)
    {
        if (data.Length > Limits.MaxFileBytes) throw new AppException("Данные превышают лимит размера файла.");
        using var writeLock = sandbox.AcquireWriteLock();
        var location = sandbox.Resolve(path);
        string tmp;
        using (var stream = sandbox.CreateTemp(out tmp))
        {
            stream.Write(data);
            stream.Flush(true);
        }
        return Commit(tmp, location, overwrite);
    }

    public string Append(string path, byte[] data)
    {
        using var writeLock = sandbox.AcquireWriteLock();
        var location = sandbox.Resolve(path);
        if (!File.Exists(location.Full)) throw new FileNotFoundException();

        string tmp;
        using (var target = sandbox.CreateTemp(out tmp))
        {
            using (var source = sandbox.OpenRead(location))
            {
                if (source.Length + data.Length > Limits.MaxFileBytes)
                {
                    target.Dispose();
                    File.Delete(tmp);
                    throw new AppException("Данные превышают лимит размера файла.");
                }
                source.CopyTo(target);
            }
            target.Write(data);
            target.Flush(true);
        }
        return Commit(tmp, location, overwrite: true);
    }

    /// <summary>Вызывать только под блокировкой записи. Удаляет временный файл в любом случае.</summary>
    public string Commit(string tmp, SafeLocation location, bool overwrite)
    {
        try
        {
            sandbox.EnsureParent(location);
            var size = new FileInfo(tmp).Length;
            var sha = HashFile(tmp);
            return db.Tx(() =>
            {
                if (Directory.Exists(location.Full)) throw new AppException("По этому пути находится каталог.");
                var onDisk = File.Exists(location.Full);
                if (onDisk && !overwrite) throw new AppException("Файл уже существует. Используйте overwrite.");

                var existing = db.FindActiveFile(session.UserId, location.Relative);
                EnsureQuota(size - (existing?.Size ?? 0));

                long id;
                if (existing is null) id = db.InsertFile(session.UserId, Path.GetFileName(location.Full), size, location.Relative, sha);
                else { id = existing.Id; db.UpdateFile(id, size, sha); }

                var operation = onDisk ? "modify" : "create";
                db.AddOperation(operation, id, session.UserId);
                // rename заменяет сам путь и не следует по ссылке; при ошибке откатится и БД.
                File.Move(tmp, location.Full, overwrite);
                return operation;
            });
        }
        finally
        {
            if (File.Exists(tmp)) File.Delete(tmp);
        }
    }

    public void DeleteFile(string path)
    {
        using var writeLock = sandbox.AcquireWriteLock();
        var location = sandbox.Resolve(path);
        if (Directory.Exists(location.Full)) throw new AppException("Это каталог. Используйте rmdir.");
        if (!File.Exists(location.Full)) throw new FileNotFoundException();
        var size = new FileInfo(location.Full).Length;

        db.TxRun(() =>
        {
            var existing = db.FindActiveFile(session.UserId, location.Relative);
            var id = existing?.Id ?? db.InsertFile(session.UserId, Path.GetFileName(location.Full), size, location.Relative, null);
            db.MarkDeleted(id);
            db.AddOperation("delete", id, session.UserId);
            File.Delete(location.Full);
        });
    }

    public void DeleteDirectory(string path, bool recursive)
    {
        using var writeLock = sandbox.AcquireWriteLock();
        var location = sandbox.Resolve(path);
        if (!Directory.Exists(location.Full)) throw new DirectoryNotFoundException();
        if (!recursive)
        {
            if (Directory.EnumerateFileSystemEntries(location.Full).Any()) throw new AppException("Каталог не пуст. Используйте rmdir -r.");
            Directory.Delete(location.Full);
            return;
        }

        db.TxRun(() =>
        {
            foreach (var record in db.ListActiveFiles(session.UserId, location.Relative + "/"))
            {
                db.MarkDeleted(record.Id);
                db.AddOperation("delete", record.Id, session.UserId);
            }
            Directory.Delete(location.Full, true); // символические ссылки удаляются, а не обходятся
        });
    }

    public void EnsureQuota(long additionalBytes)
    {
        if (db.TotalSize(session.UserId) + additionalBytes > Limits.UserQuotaBytes)
            throw new AppException("Превышена квота пользователя.");
    }

    public static string HashFile(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(stream));
    }
}
