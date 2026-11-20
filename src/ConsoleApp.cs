using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Xml;
using Microsoft.Data.Sqlite;

namespace SecureFileManager;

public sealed class ConsoleApp(Database db, string storageBase)
{
    private const string HelpText = """
        Без входа:   help | register | login | exit
        Сессия:      whoami | logout
        Система:     drives
        Файлы:       ls [путь] | info <путь> | mkdir <путь> | read <путь>
                     write <путь> | overwrite <путь> | append <путь> | rm <путь> | rmdir [-r] <путь>
        JSON/XML:    json-write <путь> | json-read <путь> | xml-write <путь> | xml-read <путь>
        Отчёт:       report-json <путь> | report-xml <путь> | report-show <путь>
        ZIP:         zip <источник> <архив.zip> | unzip <архив.zip> <новый_каталог>
        База данных: files | log [N]
        Пути указываются относительно личного каталога. Текст вводится до строки из одной точки.
        """;

    private readonly AuthService _auth = new(db);
    private Session? _session;
    private FileService? _files;
    private ArchiveService? _archives;

    public void Run()
    {
        Console.WriteLine("Безопасный файловый менеджер. Команда help выводит справку.");
        while (true)
        {
            Console.Write(_session is null ? "securefm> " : $"{_session.Username}> ");
            var line = Console.ReadLine();
            if (line is null) return;

            List<string> args;
            try
            {
                args = Tokenize(line);
            }
            catch (AppException e)
            {
                Console.WriteLine($"[ОШИБКА] {e.Message}");
                continue;
            }
            if (args.Count == 0) continue;

            var command = args[0];
            args.RemoveAt(0);
            if (command == "exit") return;
            Execute(command, args);
        }
    }

    private void Execute(string command, List<string> args)
    {
        // Значение из команды login/register в журнал не идёт: туда мог попасть пароль.
        var audited = command is not ("help" or "register" or "login");
        var known = true;
        try
        {
            known = Dispatch(command, args);
            if (known && audited && _session is not null)
                db.Audit(_session.UserId, _session.Username, command, string.Join(' ', args), true);
        }
        catch (Exception e)
        {
            var (label, message) = Classify(e);
            Console.WriteLine($"[{label}] {message}");
            if (audited && _session is not null) TryAuditFailure(command, args, e);
        }
        if (!known) Console.WriteLine("[ОШИБКА] Неизвестная команда. Введите help.");
    }

    private void TryAuditFailure(string command, List<string> args, Exception error)
    {
        try
        {
            db.Audit(_session!.UserId, _session.Username, command, string.Join(' ', args), false, error.GetType().Name);
        }
        catch (SqliteException)
        {
            Console.WriteLine("[ОШИБКА] Не удалось записать событие в журнал.");
        }
    }

    private static (string Label, string Message) Classify(Exception e) => e switch
    {
        SecurityViolationException => ("ОТКАЗ", e.Message),
        AppException => ("ОШИБКА", e.Message),
        FileNotFoundException or DirectoryNotFoundException => ("ОШИБКА", "Файл или каталог не найден."),
        UnauthorizedAccessException => ("ОТКАЗ", "Нет доступа."),
        InvalidDataException => ("ОШИБКА", "Архив повреждён или не поддерживается."),
        XmlException => ("ОТКАЗ", "XML некорректен или запрещён политикой (например, содержит DTD)."),
        JsonException => ("ОШИБКА", "JSON некорректен или не соответствует схеме."),
        IOException => ("ОШИБКА", "Ошибка ввода-вывода."),
        SqliteException => ("ОШИБКА", "Ошибка базы данных."),
        _ => ("ОШИБКА", "Внутренняя ошибка."),
    };

    private bool Dispatch(string command, List<string> a)
    {
        switch (command)
        {
            case "help": Console.WriteLine(HelpText); return true;
            case "register": Register(); return true;
            case "login": Login(); return true;
        }

        var isKnown = command is "whoami" or "logout" or "drives" or "ls" or "info" or "mkdir" or "read" or "write"
            or "overwrite" or "append" or "rm" or "rmdir" or "json-write" or "json-read" or "xml-write" or "xml-read"
            or "report-json" or "report-xml" or "report-show" or "zip" or "unzip" or "files" or "log";
        if (!isKnown) return false;
        if (_session is null || _files is null || _archives is null) throw new AppException("Сначала выполните вход: login.");

        switch (command)
        {
            case "whoami": Console.WriteLine(_session.Username); break;
            case "logout":
                db.Audit(_session.UserId, _session.Username, "logout", "", true);
                _session = null; _files = null; _archives = null;
                Console.WriteLine("Сессия завершена.");
                break;
            case "drives": ShowDrives(); break;
            case "ls": ShowList(a.Count > 0 ? Arg(a, 0, 1) : "."); break;
            case "info": ShowInfo(Arg(a, 0, 1)); break;
            case "mkdir": _files.MakeDirectory(Arg(a, 0, 1)); Ok(); break;
            case "read": Console.WriteLine(Text.Clean(_files.ReadText(Arg(a, 0, 1)), keepNewlines: true)); break;
            case "write": ReportOp(_files.Write(Arg(a, 0, 1), Encoding.UTF8.GetBytes(ReadBlock()), false)); break;
            case "overwrite": ReportOp(_files.Write(Arg(a, 0, 1), Encoding.UTF8.GetBytes(ReadBlock()), true)); break;
            case "append": ReportOp(_files.Append(Arg(a, 0, 1), Encoding.UTF8.GetBytes(ReadBlock()))); break;
            case "rm": _files.DeleteFile(Arg(a, 0, 1)); Ok(); break;
            case "rmdir":
                if (a.Count == 2 && a[0] == "-r") _files.DeleteDirectory(a[1], true);
                else _files.DeleteDirectory(Arg(a, 0, 1), false);
                Ok();
                break;
            case "json-write": WriteStructured(Arg(a, 0, 1), StructuredData.NormalizeJson); break;
            case "xml-write": WriteStructured(Arg(a, 0, 1), StructuredData.NormalizeXml); break;
            case "json-read": Print(StructuredData.NormalizeJson(_files.ReadText(Arg(a, 0, 1), Limits.MaxStructuredBytes))); break;
            case "xml-read": Print(StructuredData.NormalizeXml(_files.ReadText(Arg(a, 0, 1), Limits.MaxStructuredBytes))); break;
            case "report-json": ReportOp(_files.Write(Arg(a, 0, 1), Encoding.UTF8.GetBytes(StructuredData.ReportToJson(BuildReport())), false)); break;
            case "report-xml": ReportOp(_files.Write(Arg(a, 0, 1), Encoding.UTF8.GetBytes(StructuredData.ReportToXml(BuildReport())), false)); break;
            case "report-show": ShowReport(Arg(a, 0, 1)); break;
            case "zip": Console.WriteLine($"Файлов в архиве: {_archives.Create(Arg(a, 0, 2), a[1])}"); break;
            case "unzip": Console.WriteLine($"Извлечено файлов: {_archives.Extract(Arg(a, 0, 2), a[1])}"); break;
            case "files": ShowFiles(); break;
            case "log": ShowLog(a); break;
        }
        return true;
    }

    private static string Arg(List<string> args, int index, int expected)
    {
        if (args.Count != expected) throw new AppException("Неверное число аргументов. Введите help.");
        return args[index];
    }

    private static void Ok() => Console.WriteLine("Готово.");
    private static void ReportOp(string operation) => Console.WriteLine($"Готово ({operation}).");
    private static void Print(string text) => Console.WriteLine(Text.Clean(text, keepNewlines: true));

    private void Register()
    {
        var username = Prompt("Логин: ");
        var password = ReadPassword("Пароль: ");
        var repeat = ReadPassword("Повторите пароль: ");
        if (password != repeat) throw new AppException("Пароли не совпадают.");
        _auth.Register(username, password);
        Console.WriteLine("Пользователь создан.");
    }

    private void Login()
    {
        if (_session is not null) throw new AppException("Сначала завершите текущую сессию: logout.");
        var username = Prompt("Логин: ");
        var password = ReadPassword("Пароль: ");
        var session = _auth.Login(username, password)
            ?? throw new AppException("Неверный логин или пароль, либо учётная запись временно заблокирована.");
        var sandbox = new UserSandbox(storageBase, session.UserId);
        _files = new FileService(db, sandbox, session);
        _archives = new ArchiveService(db, sandbox, _files, session);
        _session = session;
        Console.WriteLine("Вход выполнен.");
    }

    private static void ShowDrives()
    {
        foreach (var drive in DriveInfo.GetDrives())
        {
            try
            {
                // /proc, /sys, tmpfs и прочие псевдо-ФС не являются накопителями.
                if (!drive.IsReady || drive.DriveType == DriveType.Ram || drive.TotalSize == 0) continue;
                Console.WriteLine($"{Text.Clean(drive.Name)}  тип: {drive.DriveType}  ФС: {Text.Clean(drive.DriveFormat)}  " +
                    $"всего: {FormatSize(drive.TotalSize)}  доступно: {FormatSize(drive.AvailableFreeSpace)}  " +
                    $"метка: {Text.Clean(drive.VolumeLabel)}");
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                // Закрытую точку монтирования пропускаем.
            }
        }
    }

    private void ShowList(string path)
    {
        var entries = _files!.List(path);
        if (entries.Count == 0) Console.WriteLine("(пусто)");
        foreach (var entry in entries)
            Console.WriteLine($"{entry.Kind,-5} {FormatSize(entry.Size),10}  {entry.ModifiedUtc:yyyy-MM-dd HH:mm}  {Text.Clean(entry.Name)}");
    }

    private void ShowInfo(string path)
    {
        var record = db.ListActiveFiles(_session!.UserId).FirstOrDefault(f => f.Location == string.Join('/', UserSandbox.ValidateRelative(path)));
        if (record is null) throw new AppException("Запись о файле в базе данных не найдена.");
        Console.WriteLine($"Имя: {Text.Clean(record.Filename)}\nПуть: {Text.Clean(record.Location)}\nРазмер: {FormatSize(record.Size)}\nСоздан: {record.CreatedAt}\nSHA-256: {record.Sha256}");
    }

    private void WriteStructured(string path, Func<string, string> normalize) =>
        ReportOp(_files!.Write(path, Encoding.UTF8.GetBytes(normalize(ReadBlock())), false));

    private FileReport BuildReport() => new()
    {
        Owner = _session!.Username,
        GeneratedAtUtc = DateTime.UtcNow,
        Files = db.ListActiveFiles(_session.UserId)
            .Select(f => new FileReportItem { Location = f.Location, Size = f.Size, Sha256 = f.Sha256 })
            .ToList(),
    };

    private void ShowReport(string path)
    {
        var text = _files!.ReadText(path, Limits.MaxStructuredBytes);
        var report = path.EndsWith(".xml", StringComparison.OrdinalIgnoreCase)
            ? StructuredData.ReportFromXml(text)
            : path.EndsWith(".json", StringComparison.OrdinalIgnoreCase)
                ? StructuredData.ReportFromJson(text)
                : throw new AppException("Отчёт должен иметь расширение .json или .xml.");
        Console.WriteLine($"Владелец: {Text.Clean(report.Owner)}, создан: {report.GeneratedAtUtc:O}, файлов: {report.Files.Count}");
        foreach (var file in report.Files) Console.WriteLine($"  {Text.Clean(file.Location)}  {FormatSize(file.Size)}");
    }

    private void ShowFiles()
    {
        foreach (var file in db.ListActiveFiles(_session!.UserId))
            Console.WriteLine($"{file.Id,5}  {FormatSize(file.Size),10}  {file.CreatedAt}  {Text.Clean(file.Location)}");
    }

    private void ShowLog(List<string> args)
    {
        var limit = 20;
        if (args.Count > 0 && (!int.TryParse(args[0], NumberStyles.None, CultureInfo.InvariantCulture, out limit) || limit is < 1 or > 1000))
            throw new AppException("N должно быть числом от 1 до 1000.");
        foreach (var row in db.ReadAudit(_session!.UserId, limit))
            Console.WriteLine($"{row.Timestamp}  {(row.Success ? "OK  " : "FAIL")}  {row.Action}  {row.Target}  {row.Details}");
    }

    private static string FormatSize(long bytes) => bytes switch
    {
        >= 1L << 30 => string.Create(CultureInfo.InvariantCulture, $"{bytes / (double)(1L << 30):F1} ГБ"),
        >= 1L << 20 => string.Create(CultureInfo.InvariantCulture, $"{bytes / (double)(1L << 20):F1} МБ"),
        >= 1L << 10 => string.Create(CultureInfo.InvariantCulture, $"{bytes / (double)(1L << 10):F1} КБ"),
        _ => $"{bytes} Б",
    };

    private static string Prompt(string label)
    {
        Console.Write(label);
        return (Console.ReadLine() ?? throw new AppException("Ввод прерван.")).Trim();
    }

    private static string ReadPassword(string label)
    {
        Console.Write(label);
        if (Console.IsInputRedirected) return Console.ReadLine() ?? throw new AppException("Ввод прерван.");

        var password = new StringBuilder();
        while (true)
        {
            var key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter) break;
            if (key.Key == ConsoleKey.Backspace) { if (password.Length > 0) password.Length--; continue; }
            if (!char.IsControl(key.KeyChar) && password.Length <= 128) password.Append(key.KeyChar);
        }
        Console.WriteLine();
        return password.ToString();
    }

    private static string ReadBlock()
    {
        Console.WriteLine("Введите текст, в конце строка из одной точки:");
        var text = new StringBuilder();
        while (true)
        {
            var line = Console.ReadLine() ?? throw new AppException("Ввод прерван, файл не изменён.");
            if (line == ".") return text.ToString();
            if (text.Length + line.Length > Limits.MaxStructuredBytes) throw new AppException("Слишком большой ввод.");
            text.Append(line).Append('\n');
        }
    }

    private static List<string> Tokenize(string line)
    {
        var tokens = new List<string>();
        var current = new StringBuilder();
        var inQuotes = false;
        var hasToken = false;
        foreach (var c in line)
        {
            if (c == '"') { inQuotes = !inQuotes; hasToken = true; }
            else if (char.IsWhiteSpace(c) && !inQuotes)
            {
                if (hasToken) { tokens.Add(current.ToString()); current.Clear(); hasToken = false; }
            }
            else { current.Append(c); hasToken = true; }
        }
        if (inQuotes) throw new AppException("Незакрытая кавычка.");
        if (hasToken) tokens.Add(current.ToString());
        return tokens;
    }
}
