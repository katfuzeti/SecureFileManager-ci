using System.Text;

namespace SecureFileManager;

/// <summary>Ошибка, текст которой безопасно показать пользователю.</summary>
public class AppException(string message) : Exception(message);

/// <summary>Попытка нарушить политику безопасности (обход пути, zip-бомба и т. п.).</summary>
public sealed class SecurityViolationException(string message) : AppException(message);

public static class Limits
{
    public const long MaxFileBytes = 50L * 1024 * 1024;
    public const long MaxReadBytes = 10L * 1024 * 1024;
    public const long MaxStructuredBytes = 10L * 1024 * 1024;
    public const long UserQuotaBytes = 500L * 1024 * 1024;

    public const long MaxZipFileBytes = 200L * 1024 * 1024;
    public const long MaxUnzippedTotalBytes = 200L * 1024 * 1024;
    public const long MaxUnzippedEntryBytes = 50L * 1024 * 1024;
    public const int MaxZipEntries = 1000;
    public const long MaxCompressionRatio = 100;
    public const long RatioCheckAfterBytes = 1024 * 1024;

    public const int MaxPathChars = 1024;
    public const int MaxPathDepth = 32;
    public const int MaxDataDepth = 32;
    public const int MaxLockoutAttempts = 5;
    public const int LockoutMinutes = 5;
    public const int LockWaitSeconds = 30;
}

public static class Text
{
    /// <summary>
    /// Убирает управляющие и форматирующие символы: ESC-последовательности терминала,
    /// переводы строк (подделка записей журнала), U+202E (подмена расширения).
    /// </summary>
    public static string Clean(string? value, bool keepNewlines = false)
    {
        if (string.IsNullOrEmpty(value)) return string.Empty;
        var sb = new StringBuilder(value.Length);
        foreach (var c in value)
        {
            if (keepNewlines && (c == '\n' || c == '\t')) { sb.Append(c); continue; }
            if (char.IsControl(c) || char.GetUnicodeCategory(c) == System.Globalization.UnicodeCategory.Format) continue;
            sb.Append(c);
        }
        return sb.ToString();
    }
}

public sealed record Session(long UserId, string Username);
