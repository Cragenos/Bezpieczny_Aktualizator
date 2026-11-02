using System.Globalization;
using System.Net.NetworkInformation;
using System.Text;
using BezpiecznyAktualizator.Core.Localization;

namespace BezpiecznyAktualizator.Core.Logging;

/// <summary>Poziomy ważności wg RFC 5424, sekcja 6.2.1.</summary>
public enum SyslogSeverity
{
    Emergency = 0, Alert = 1, Critical = 2, Error = 3, Warning = 4, Notice = 5, Informational = 6, Debug = 7,
}

/// <summary>Identyfikatory typów zdarzeń (pole MSGID).</summary>
public static class LogEvent
{
    public const string App = "APP";
    public const string Settings = "SETTINGS";
    public const string Scan = "SW_SCAN";
    public const string UpdateCheck = "SW_UPDATE_CHECK";
    public const string Assess = "SW_ASSESS";
    public const string Upgrade = "SW_UPGRADE";
    public const string Verify = "SW_VERIFY";
    public const string Search = "SW_SEARCH";
    public const string DriverScan = "DRV_SCAN";
    public const string DriverCheck = "DRV_UPDATE_CHECK";
    public const string DriverInstall = "DRV_INSTALL";
    public const string Report = "REPORT";
    public const string Scheduled = "SCHEDULED";
    public const string Vulnerability = "SW_VULN";
    public const string Rollback = "SW_ROLLBACK";
    public const string Policy = "POLICY";
    public const string Integrity = "INTEGRITY";
    public const string AppUpdate = "APP_UPDATE";
    public const string WindowsUpdate = "WINDOWS_UPDATE";
    public const string StoreUpdate = "STORE_UPDATE";
    public const string Error = "ERROR";
}

/// <summary>
/// Dziennik zdarzeń aplikacji w pliku tekstowym w formacie syslog (RFC 5424), np.:
/// <c>&lt;14&gt;1 2026-10-30T16:18:00.278000+01:00 PC BezpiecznyAktualizator 1234 SW_SCAN [origin software="BezpiecznyAktualizator" swVersion="2.0.0"][meta sequenceId="1" language="pl"] BOM tekst</c>.
/// Jeden komunikat w wierszu (znaki sterujące kodowane jako #ooo, jak w rsyslog), UTF-8,
/// rotacja po przekroczeniu <see cref="MaxFileSize"/>. Błędy zapisu nigdy nie przerywają działania aplikacji.
/// </summary>
public static class Syslog
{
    public const string AppName = "BezpiecznyAktualizator";
    /// <summary>Facility 1 = user-level messages.</summary>
    public const int Facility = 1;
    public const string FileName = "BezpiecznyAktualizator.log";
    private const int MaxMessageLength = 16 * 1024;

    private static readonly object Gate = new();
    private static readonly UTF8Encoding Utf8 = new(false);
    private static readonly string Host = Header(HostName(), 255);
    private static readonly string ProcId = Environment.ProcessId.ToString(CultureInfo.InvariantCulture);
    private static readonly string SoftwareVersion = typeof(Syslog).Assembly.GetName().Version?.ToString(3) ?? "0.0.0";
    private static int _sequence;
    private static Mutex? _mutex;

    public static string Directory { get; private set; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), AppName, "Logs");

    public static string FilePath => Path.Combine(Directory, FileName);
    public static bool Enabled { get; set; } = true;
    public static long MaxFileSize { get; set; } = 5 * 1024 * 1024;
    /// <summary>Liczba archiwalnych plików (.log.1 … .log.N) zachowywanych przy rotacji.</summary>
    public static int MaxArchives { get; set; } = 5;
    /// <summary>Ostatni błąd zapisu (null, jeśli zapis się powiódł).</summary>
    public static Exception? LastError { get; private set; }

    /// <summary>Zmienia katalog dziennika (np. w testach).</summary>
    public static void Configure(string directory) => Directory = Path.GetFullPath(directory);

    public static void Debug(string msgId, string message) => Write(SyslogSeverity.Debug, msgId, message);
    public static void Info(string msgId, string message) => Write(SyslogSeverity.Informational, msgId, message);
    public static void Notice(string msgId, string message) => Write(SyslogSeverity.Notice, msgId, message);
    public static void Warning(string msgId, string message) => Write(SyslogSeverity.Warning, msgId, message);

    public static void Error(string msgId, string message, Exception? ex = null) =>
        Write(SyslogSeverity.Error, msgId, ex is null ? message : $"{message}\n{ex}");

    public static IReadOnlyList<string> ReadRecentIssues(int limit = 500)
    {
        if (limit is < 1 or > 10000) throw new ArgumentOutOfRangeException(nameof(limit));
        if (!System.IO.Directory.Exists(Directory)) return [];

        var files = System.IO.Directory.EnumerateFiles(Directory, FileName + "*")
            .Select(path => (Path: path, Archive: ArchiveNumber(path)))
            .Where(item => item.Archive >= 0)
            .OrderBy(item => item.Archive);
        var issues = new List<string>(Math.Min(limit, 500));
        foreach (var file in files)
        {
            using var stream = new FileStream(file.Path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var reader = new StreamReader(stream, Utf8, detectEncodingFromByteOrderMarks: true);
            var lines = new List<string>();
            while (reader.ReadLine() is { } line) lines.Add(line);
            for (var i = lines.Count - 1; i >= 0; i--)
            {
                if (!IsIssue(lines[i])) continue;
                issues.Add(lines[i]);
                if (issues.Count == limit) return issues;
            }
        }
        return issues;
    }

    private static int ArchiveNumber(string path)
    {
        var name = Path.GetFileName(path);
        if (name.Equals(FileName, StringComparison.OrdinalIgnoreCase)) return 0;
        var suffix = name.StartsWith(FileName + ".", StringComparison.OrdinalIgnoreCase) ? name[(FileName.Length + 1)..] : "";
        return int.TryParse(suffix, CultureInfo.InvariantCulture, out var archive) ? archive : -1;
    }

    private static bool IsIssue(string line)
    {
        var end = line.IndexOf('>');
        if (!line.StartsWith('<') || end <= 1 ||
            !int.TryParse(line.AsSpan(1, end - 1), NumberStyles.None, CultureInfo.InvariantCulture, out var priority))
            return false;
        return priority is >= 0 and <= 191 && (priority & 7) <= (int)SyslogSeverity.Warning;
    }

    public static void Write(SyslogSeverity severity, string msgId, string message)
    {
        if (!Enabled) return;
        try
        {
            var sequence = Interlocked.Increment(ref _sequence) & int.MaxValue;
            var line = Format(severity, msgId, message, DateTimeOffset.Now, Math.Max(sequence, 1), LanguageTag(L.Language));
            var bytes = Utf8.GetBytes(line + "\n");
            lock (Gate)
            {
                var mutex = _mutex ??= new Mutex(false, @"Local\BezpiecznyAktualizator.Syslog");
                bool owned;
                try { owned = mutex.WaitOne(TimeSpan.FromSeconds(2)); }
                catch (AbandonedMutexException) { owned = true; }
                try
                {
                    System.IO.Directory.CreateDirectory(Directory);
                    Rotate(bytes.Length);
                    using var fs = new FileStream(FilePath, FileMode.Append, FileAccess.Write,
                                                  FileShare.ReadWrite | FileShare.Delete);
                    fs.Write(bytes);
                }
                finally
                {
                    if (owned) mutex.ReleaseMutex();
                }
            }
            LastError = null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            LastError = ex;
        }
    }

    /// <summary>Buduje komunikat RFC 5424 (bez znaku końca wiersza).</summary>
    public static string Format(SyslogSeverity severity, string msgId, string message, DateTimeOffset timestamp,
                                int sequenceId, string language)
    {
        var sb = new StringBuilder(message.Length + 200);
        sb.Append('<').Append(Facility * 8 + (int)severity).Append(">1 ")
          .Append(timestamp.ToString("yyyy-MM-dd'T'HH:mm:ss.ffffffzzz", CultureInfo.InvariantCulture)).Append(' ')
          .Append(Host).Append(' ')
          .Append(AppName).Append(' ')
          .Append(ProcId).Append(' ')
          .Append(Header(msgId, 32)).Append(' ')
          .Append("[origin software=\"").Append(SdValue(AppName))
          .Append("\" swVersion=\"").Append(SdValue(SoftwareVersion)).Append("\"]")
          .Append("[meta sequenceId=\"").Append(sequenceId.ToString(CultureInfo.InvariantCulture))
          .Append("\" language=\"").Append(SdValue(language)).Append("\"]");
        if (message.Length > 0)
        {
            if (message.Length > MaxMessageLength) message = message[..MaxMessageLength] + "…";
            sb.Append(' ').Append('\uFEFF').Append(EscapeMessage(message)); // MSG-UTF8 zaczyna się od BOM (RFC 5424, 6.4)
        }
        return sb.ToString();
    }

    /// <summary>Pole nagłówka: tylko drukowalne ASCII (33–126), maks. <paramref name="max"/> znaków, "-" gdy puste.</summary>
    internal static string Header(string? value, int max)
    {
        if (string.IsNullOrEmpty(value)) return "-";
        return new string(value.Select(c => c is >= '!' and <= '~' ? c : '_').Take(max).ToArray());
    }

    /// <summary>Wartość PARAM-VALUE: znaki '"', '\' i ']' poprzedzone ukośnikiem (RFC 5424, 6.3.3).</summary>
    internal static string SdValue(string value) =>
        value.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("]", "\\]");

    /// <summary>Znaki sterujące jako #ooo (ósemkowo, jak w rsyslog), aby każdy komunikat zajmował jeden wiersz.</summary>
    internal static string EscapeMessage(string message)
    {
        var sb = new StringBuilder(message.Length);
        foreach (var c in message.Replace("\r\n", "\n"))
        {
            if (c < ' ' || c == '\x7f') sb.Append('#').Append(Convert.ToString(c, 8).PadLeft(3, '0'));
            else sb.Append(c);
        }
        return sb.ToString();
    }

    /// <summary>Znacznik języka RFC 4646 dla parametru meta/language.</summary>
    internal static string LanguageTag(string code) => code switch { "pt" => "pt-BR", "zh" => "zh-Hans", _ => code };

    private static string HostName()
    {
        try
        {
            var p = IPGlobalProperties.GetIPGlobalProperties();
            return string.IsNullOrEmpty(p.DomainName) ? p.HostName : $"{p.HostName}.{p.DomainName}";
        }
        catch (NetworkInformationException)
        {
            return Environment.MachineName;
        }
    }

    private static void Rotate(int incoming)
    {
        var file = new FileInfo(FilePath);
        if (!file.Exists || file.Length + incoming <= MaxFileSize) return;
        try
        {
            if (MaxArchives <= 0)
            {
                file.Delete();
                return;
            }
            for (var i = MaxArchives; i >= 1; i--)
            {
                var source = i == 1 ? FilePath : $"{FilePath}.{i - 1}";
                if (File.Exists(source)) File.Move(source, $"{FilePath}.{i}", overwrite: true);
            }
        }
        catch (IOException) { } // plik zablokowany (np. przez skaner AV) - dopisujemy do bieżącego
    }
}
