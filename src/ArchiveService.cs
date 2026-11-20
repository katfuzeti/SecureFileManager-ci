using System.IO.Compression;

namespace SecureFileManager;

public sealed class ArchiveService(Database db, UserSandbox sandbox, FileService files, Session session)
{
    private static void EnsureZipName(SafeLocation location)
    {
        if (!location.Full.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
            throw new AppException("Имя архива должно оканчиваться на .zip.");
    }

    public int Create(string sourcePath, string archivePath)
    {
        using var writeLock = sandbox.AcquireWriteLock();
        var source = sandbox.Resolve(sourcePath, allowRoot: true);
        var archive = sandbox.Resolve(archivePath);
        EnsureZipName(archive);
        if (File.Exists(archive.Full)) throw new AppException("Архив уже существует.");

        var inputs = new List<(string Full, string Name)>();
        if (File.Exists(source.Full))
        {
            inputs.Add((source.Full, Path.GetFileName(source.Full)));
        }
        else if (Directory.Exists(source.Full))
        {
            var options = new EnumerationOptions { RecurseSubdirectories = true, AttributesToSkip = 0, ReturnSpecialDirectories = false };
            foreach (var path in Directory.EnumerateFileSystemEntries(source.Full, "*", options))
            {
                if (new FileInfo(path).LinkTarget is not null) throw new SecurityViolationException("Символические ссылки в архив не добавляются.");
                if (!Directory.Exists(path)) inputs.Add((path, Path.GetRelativePath(source.Full, path)));
            }
        }
        else throw new FileNotFoundException();

        if (inputs.Count > Limits.MaxZipEntries) throw new AppException("Слишком много файлов для архивации.");
        long total = 0;
        foreach (var input in inputs) total += new FileInfo(input.Full).Length;
        if (total > Limits.MaxUnzippedTotalBytes) throw new AppException("Слишком большой объём для архивации.");

        string tmp;
        using (var output = sandbox.CreateTemp(out tmp))
        using (var zip = new ZipArchive(output, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var input in inputs)
            {
                var entry = zip.CreateEntry(input.Name, CompressionLevel.Optimal);
                using var entryStream = entry.Open();
                using var fileStream = sandbox.OpenRead(new SafeLocation(input.Name, input.Full));
                fileStream.CopyTo(entryStream);
            }
        }
        files.Commit(tmp, archive, overwrite: false);
        return inputs.Count;
    }

    public int Extract(string archivePath, string destinationPath)
    {
        using var writeLock = sandbox.AcquireWriteLock();
        var archive = sandbox.Resolve(archivePath);
        var destination = sandbox.Resolve(destinationPath);
        EnsureZipName(archive);
        if (File.Exists(destination.Full) || Directory.Exists(destination.Full))
            throw new AppException("Каталог назначения уже существует.");

        // Сначала распаковка во временный каталог: при атаке в рабочую область не попадёт ничего.
        var staging = Path.Combine(sandbox.TmpDir, "unzip-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(staging, UserSandbox.DirMode);
        try
        {
            var extracted = ExtractToStaging(archive, staging);
            var total = extracted.Sum(e => e.Size);
            sandbox.EnsureParent(destination);

            db.TxRun(() =>
            {
                files.EnsureQuota(total);
                foreach (var (relative, size, sha) in extracted)
                {
                    var location = destination.Relative + "/" + relative;
                    var id = db.InsertFile(session.UserId, Path.GetFileName(relative), size, location, sha);
                    db.AddOperation("create", id, session.UserId);
                }
                Directory.Move(staging, destination.Full);
            });
            return extracted.Count;
        }
        finally
        {
            if (Directory.Exists(staging)) Directory.Delete(staging, true);
        }
    }

    private List<(string Relative, long Size, string Sha)> ExtractToStaging(SafeLocation archive, string staging)
    {
        using var input = sandbox.OpenRead(archive);
        if (input.Length > Limits.MaxZipFileBytes) throw new SecurityViolationException("Архив слишком большой.");
        using var zip = new ZipArchive(input, ZipArchiveMode.Read);
        if (zip.Entries.Count > Limits.MaxZipEntries) throw new SecurityViolationException("Слишком много файлов в архиве.");

        var result = new List<(string, long, string)>();
        long total = 0;
        var buffer = new byte[81920];

        foreach (var entry in zip.Entries)
        {
            // Unix-тип файла хранится в старших битах внешних атрибутов; 0xA000 — ссылка.
            if (((entry.ExternalAttributes >> 16) & 0xF000) == 0xA000)
                throw new SecurityViolationException("Символические ссылки в архиве запрещены.");

            var isDirectory = entry.FullName.EndsWith('/');
            var parts = UserSandbox.ValidateRelative(isDirectory ? entry.FullName.TrimEnd('/') : entry.FullName);
            var relative = string.Join('/', parts);
            var target = Path.Combine(staging, relative);

            if (isDirectory)
            {
                Directory.CreateDirectory(target, UserSandbox.DirMode);
                continue;
            }

            Directory.CreateDirectory(Path.GetDirectoryName(target)!, UserSandbox.DirMode);
            long written = 0;
            using (var source = entry.Open())
            using (var destination = UserSandbox.CreateNewPrivate(target))
            {
                // Размер из заголовка можно подделать, поэтому считаются реально распакованные байты.
                int read;
                while ((read = source.Read(buffer, 0, buffer.Length)) > 0)
                {
                    written += read;
                    total += read;
                    if (written > Limits.MaxUnzippedEntryBytes || total > Limits.MaxUnzippedTotalBytes)
                        throw new SecurityViolationException("Превышен лимит распаковки (возможна zip-бомба).");
                    if (written > Limits.RatioCheckAfterBytes && written / Math.Max(entry.CompressedLength, 1) > Limits.MaxCompressionRatio)
                        throw new SecurityViolationException("Подозрительная степень сжатия (возможна zip-бомба).");
                    destination.Write(buffer, 0, read);
                }
            }
            result.Add((relative, written, FileService.HashFile(target)));
        }
        return result;
    }
}
