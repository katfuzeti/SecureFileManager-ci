using System.Globalization;
using System.Text;

namespace SecureFileManager;

public sealed record SafeLocation(string Relative, string Full);

/// <summary>Каталог пользователя: любой путь проверяется здесь, выйти за его пределы нельзя.</summary>
public sealed class UserSandbox
{
    public const UnixFileMode DirMode = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
    public const UnixFileMode FileMode600 = UnixFileMode.UserRead | UnixFileMode.UserWrite;

    public string Root { get; }
    public string TmpDir { get; }
    private readonly string _lockPath;
    private readonly string _realRoot;

    public UserSandbox(string storageBase, long userId)
    {
        var userDir = Path.Combine(storageBase, userId.ToString(CultureInfo.InvariantCulture));
        Root = Path.Combine(userDir, "files");
        TmpDir = Path.Combine(userDir, "tmp");
        _lockPath = Path.Combine(userDir, "write.lock");

        Directory.CreateDirectory(Root, DirMode);
        Directory.CreateDirectory(TmpDir, DirMode);
        if (new DirectoryInfo(userDir).LinkTarget is not null
            || new DirectoryInfo(Root).LinkTarget is not null
            || new DirectoryInfo(TmpDir).LinkTarget is not null)
            throw new SecurityViolationException("Каталог хранения не может быть символической ссылкой.");

        // Настоящий путь до корня: базовый каталог сам может лежать за ссылкой (например, /tmp).
        string probePath;
        string realProbe;
        using (var probe = CreateTemp(out probePath)) realProbe = RealPathOf(probe);
        File.Delete(probePath);
        var realUserDir = Path.GetDirectoryName(Path.GetDirectoryName(realProbe))
            ?? throw new SecurityViolationException("Не удалось определить каталог хранения.");
        _realRoot = Path.Combine(realUserDir, "files");
    }

    /// <summary>Разбирает относительный путь. Также применяется к именам внутри ZIP. Запрещает, а не "исправляет".</summary>
    public static string[] ValidateRelative(string path, bool allowRoot = false)
    {
        if (string.IsNullOrWhiteSpace(path)) throw new SecurityViolationException("Пустой путь.");
        if (path.Length > Limits.MaxPathChars) throw new SecurityViolationException("Слишком длинный путь.");
        if (path[0] == '/') throw new SecurityViolationException("Абсолютные пути запрещены.");
        if (path.Contains('\\')) throw new SecurityViolationException("Обратная косая черта в пути запрещена.");
        if (path.Any(char.IsControl)) throw new SecurityViolationException("Управляющие символы в пути запрещены.");

        var parts = new List<string>();
        foreach (var part in path.Split('/', StringSplitOptions.RemoveEmptyEntries))
        {
            if (part == ".") continue;
            if (part == "..") throw new SecurityViolationException("Переход '..' в пути запрещён.");
            if (Encoding.UTF8.GetByteCount(part) > 255) throw new SecurityViolationException("Слишком длинное имя.");
            parts.Add(part);
        }
        if (parts.Count > Limits.MaxPathDepth) throw new SecurityViolationException("Слишком большая вложенность.");
        if (parts.Count == 0 && !allowRoot) throw new SecurityViolationException("Нужно указать имя внутри каталога.");
        return parts.ToArray();
    }

    public SafeLocation Resolve(string path, bool allowRoot = false)
    {
        var parts = ValidateRelative(path, allowRoot);
        var current = Root;
        foreach (var part in parts)
        {
            current = Path.Combine(current, part);
            // Проверяется каждый компонент: ссылка могла бы увести наружу с любого уровня.
            if (new FileInfo(current).LinkTarget is not null)
                throw new SecurityViolationException("Символические ссылки запрещены.");
        }

        var full = Path.GetFullPath(current);
        if (full != Root && !full.StartsWith(Root + Path.DirectorySeparatorChar, StringComparison.Ordinal))
            throw new SecurityViolationException("Путь вне рабочего каталога.");
        return new SafeLocation(string.Join('/', parts), full);
    }

    public void EnsureParent(SafeLocation location)
    {
        var parent = Path.GetDirectoryName(location.Full);
        if (parent is not null && parent != Root) Directory.CreateDirectory(parent, DirMode);
        Resolve(location.Relative); // повторная проверка после создания
    }

    /// <summary>Открывает файл и по /proc проверяет, что открылось: это закрывает гонку между проверкой и открытием.</summary>
    public FileStream OpenRead(SafeLocation location)
    {
        var stream = new FileStream(location.Full, FileMode.Open, FileAccess.Read, FileShare.Read);
        try
        {
            if (!RealPathOf(stream).StartsWith(_realRoot + Path.DirectorySeparatorChar, StringComparison.Ordinal))
                throw new SecurityViolationException("Файл находится вне рабочего каталога.");
            return stream;
        }
        catch
        {
            stream.Dispose();
            throw;
        }
    }

    public FileStream CreateTemp(out string path)
    {
        path = Path.Combine(TmpDir, Guid.NewGuid().ToString("N"));
        return CreateNewPrivate(path);
    }

    public static FileStream CreateNewPrivate(string path) => new(path, new FileStreamOptions
    {
        Mode = FileMode.CreateNew, // O_EXCL: файл не перезаписывается и ссылка не разыменовывается
        Access = FileAccess.ReadWrite,
        Share = FileShare.None,
        UnixCreateMode = FileMode600,
    });

    /// <summary>Межпроцессная блокировка изменений в каталоге пользователя.</summary>
    public IDisposable AcquireWriteLock()
    {
        var deadline = DateTime.UtcNow.AddSeconds(Limits.LockWaitSeconds);
        while (true)
        {
            try
            {
                return new FileStream(_lockPath, new FileStreamOptions
                {
                    Mode = FileMode.OpenOrCreate,
                    Access = FileAccess.ReadWrite,
                    Share = FileShare.None,
                    UnixCreateMode = FileMode600,
                });
            }
            catch (IOException) when (DateTime.UtcNow < deadline)
            {
                Thread.Sleep(100);
            }
        }
    }

    private static string RealPathOf(FileStream stream)
    {
        var fd = stream.SafeFileHandle.DangerousGetHandle().ToInt64();
        return new FileInfo(string.Create(CultureInfo.InvariantCulture, $"/proc/self/fd/{fd}")).LinkTarget
            ?? throw new SecurityViolationException("Не удалось проверить открытый файл.");
    }
}
