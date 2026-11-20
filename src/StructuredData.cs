using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Unicode;
using System.Xml;
using System.Xml.Linq;

namespace SecureFileManager;

public sealed class FileReport
{
    public string Owner { get; set; } = "";
    public DateTime GeneratedAtUtc { get; set; }
    public List<FileReportItem> Files { get; set; } = [];
}

public sealed class FileReportItem
{
    public string Location { get; set; } = "";
    public long Size { get; set; }
    public string? Sha256 { get; set; }
}

/// <summary>JSON и XML считаются недоверенными: типы фиксированы, глубина и объём ограничены, DTD запрещён.</summary>
public static class StructuredData
{
    private static readonly JavaScriptEncoder Encoder = JavaScriptEncoder.Create(UnicodeRanges.All);

    private static readonly JsonSerializerOptions WriteOptions = new() { WriteIndented = true, Encoder = Encoder };

    private static readonly JsonSerializerOptions StrictReadOptions = new()
    {
        MaxDepth = Limits.MaxDataDepth,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    private static readonly JsonDocumentOptions DocumentOptions = new()
    {
        MaxDepth = Limits.MaxDataDepth,
        AllowTrailingCommas = false,
        CommentHandling = JsonCommentHandling.Disallow,
    };

    public static string NormalizeJson(string text)
    {
        EnsureSize(text);
        using var document = JsonDocument.Parse(text, DocumentOptions);
        return JsonSerializer.Serialize(document.RootElement, WriteOptions);
    }

    public static string NormalizeXml(string text)
    {
        var document = ParseXml(text);
        document.Declaration = new XDeclaration("1.0", "utf-8", null);
        return document.Declaration + Environment.NewLine + document;
    }

    public static string ReportToJson(FileReport report) => JsonSerializer.Serialize(report, WriteOptions);

    public static string ReportToXml(FileReport report)
    {
        var document = new XDocument(
            new XDeclaration("1.0", "utf-8", null),
            new XElement("report",
                new XAttribute("owner", report.Owner),
                new XAttribute("generatedAtUtc", report.GeneratedAtUtc.ToString("O", System.Globalization.CultureInfo.InvariantCulture)),
                report.Files.Select(f => new XElement("file",
                    new XAttribute("location", f.Location),
                    new XAttribute("size", f.Size),
                    new XAttribute("sha256", f.Sha256 ?? "")))));
        return document.Declaration + Environment.NewLine + document;
    }

    public static FileReport ReportFromJson(string text)
    {
        EnsureSize(text);
        return JsonSerializer.Deserialize<FileReport>(text, StrictReadOptions)
            ?? throw new AppException("Пустой отчёт.");
    }

    public static FileReport ReportFromXml(string text)
    {
        var root = ParseXml(text).Root;
        if (root is null || root.Name != "report") throw new AppException("Это не файл отчёта.");
        try
        {
            return new FileReport
            {
                Owner = (string?)root.Attribute("owner") ?? "",
                GeneratedAtUtc = (DateTime?)root.Attribute("generatedAtUtc") ?? default,
                Files = root.Elements("file").Select(f => new FileReportItem
                {
                    Location = (string?)f.Attribute("location") ?? "",
                    Size = (long?)f.Attribute("size") ?? 0,
                    Sha256 = (string?)f.Attribute("sha256"),
                }).ToList(),
            };
        }
        catch (FormatException)
        {
            throw new AppException("Некорректные значения в файле отчёта.");
        }
    }

    private static XDocument ParseXml(string text)
    {
        EnsureSize(text);
        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit, // защита от XXE и "billion laughs"
            XmlResolver = null,
            MaxCharactersInDocument = Limits.MaxStructuredBytes,
            MaxCharactersFromEntities = 1024,
        };

        using (var stringReader = new StringReader(text))
        using (var depthReader = XmlReader.Create(stringReader, settings))
        {
            while (depthReader.Read())
                if (depthReader.Depth > Limits.MaxDataDepth) throw new AppException("Слишком большая вложенность XML.");
        }

        using var contentReader = new StringReader(text);
        using var xmlReader = XmlReader.Create(contentReader, settings);
        return XDocument.Load(xmlReader);
    }

    private static void EnsureSize(string text)
    {
        if (Encoding.UTF8.GetByteCount(text) > Limits.MaxStructuredBytes)
            throw new AppException("Документ слишком большой.");
    }
}
