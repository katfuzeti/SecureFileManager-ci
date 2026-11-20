using System.Text;
using SecureFileManager;

Console.OutputEncoding = Encoding.UTF8;
Console.InputEncoding = Encoding.UTF8;

try
{
    var baseDir = Environment.GetEnvironmentVariable("SECUREFM_HOME");
    if (string.IsNullOrWhiteSpace(baseDir))
    {
        var dataDir = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData, Environment.SpecialFolderOption.Create);
        if (string.IsNullOrEmpty(dataDir)) throw new AppException("Не удалось определить каталог данных.");
        baseDir = Path.Combine(dataDir, "securefm");
    }
    baseDir = Path.GetFullPath(baseDir);

    Directory.CreateDirectory(baseDir, UserSandbox.DirMode);
    File.SetUnixFileMode(baseDir, UserSandbox.DirMode);
    var storage = Path.Combine(baseDir, "storage");
    Directory.CreateDirectory(storage, UserSandbox.DirMode);

    using var database = new Database(Path.Combine(baseDir, "securefm.db"));
    new ConsoleApp(database, storage).Run();
    return 0;
}
catch (Exception e)
{
    // Технические подробности (пути, стек) пользователю не показываются.
    Console.Error.WriteLine(e is AppException ? e.Message : $"Не удалось запустить приложение: {e.GetType().Name}");
    return 1;
}
