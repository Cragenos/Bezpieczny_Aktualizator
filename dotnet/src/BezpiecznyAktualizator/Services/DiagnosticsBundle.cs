using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using BezpiecznyAktualizator.Core.Logging;

namespace BezpiecznyAktualizator.Services;

internal static partial class DiagnosticsBundle
{
    private const int MaximumIssueCount = 500;
    private const int MaximumIssueLength = 8192;
    private const int MaximumLogCharacters = 1024 * 1024;
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    internal static string Create(string path, IReadOnlyList<string> recentIssues)
    {
        var destination = Path.GetFullPath(path);
        if (!string.Equals(Path.GetExtension(destination), ".zip", StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("A diagnostic bundle must use the .zip extension.", nameof(path));
        if (string.Equals(destination, Syslog.FilePath, StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("The diagnostic bundle cannot overwrite the application log.", nameof(path));

        var directory = Path.GetDirectoryName(destination)
            ?? throw new InvalidOperationException("The diagnostic bundle directory could not be determined.");
        Directory.CreateDirectory(directory);
        var temporary = destination + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using (var file = new FileStream(temporary, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None))
            using (var archive = new ZipArchive(file, ZipArchiveMode.Create))
            {
                var metadata = new DiagnosticMetadata
                {
                    ApplicationVersion = typeof(App).Assembly.GetName().Version?.ToString(3) ?? "0.0.0",
                    WindowsVersion = Environment.OSVersion.VersionString,
                    Runtime = RuntimeInformation.FrameworkDescription,
                    OperatingSystemArchitecture = RuntimeInformation.OSArchitecture.ToString(),
                    ProcessArchitecture = RuntimeInformation.ProcessArchitecture.ToString(),
                    GeneratedAtUtc = DateTimeOffset.UtcNow,
                };
                var metadataEntry = archive.CreateEntry("diagnostics.json", CompressionLevel.Optimal);
                using (var stream = metadataEntry.Open())
                    JsonSerializer.Serialize(stream, metadata, JsonOptions);

                var log = BuildRecentIssues(recentIssues);
                var logEntry = archive.CreateEntry("recent-issues.log", CompressionLevel.Optimal);
                using var writer = new StreamWriter(logEntry.Open(), new UTF8Encoding(false));
                writer.Write(log);
            }
            File.Move(temporary, destination, overwrite: true);
            return destination;
        }
        finally
        {
            if (File.Exists(temporary)) File.Delete(temporary);
        }
    }

    internal static string Redact(string value)
    {
        var redacted = UserProfilePath().Replace(value, "%USERPROFILE%");
        redacted = Url().Replace(redacted, "$1/[REDACTED]");
        redacted = Credential().Replace(redacted, "$1=[REDACTED]");
        redacted = Authorization().Replace(redacted, "$1=[REDACTED]");
        return redacted.Length <= MaximumIssueLength ? redacted : redacted[..MaximumIssueLength];
    }

    private static string BuildRecentIssues(IReadOnlyList<string> issues)
    {
        var result = new StringBuilder(Math.Min(MaximumLogCharacters, issues.Count * 256));
        foreach (var issue in issues.Take(MaximumIssueCount))
        {
            var line = Redact(issue);
            var remaining = MaximumLogCharacters - result.Length;
            if (remaining <= 1) break;
            if (line.Length + 1 > remaining) line = line[..(remaining - 1)];
            result.AppendLine(line);
            if (line.Length + 1 < remaining) continue;
            break;
        }
        return result.ToString();
    }

    [System.Reflection.Obfuscation(Exclude = true)]
    private sealed class DiagnosticMetadata
    {
        public string ApplicationVersion { get; init; } = "";
        public string WindowsVersion { get; init; } = "";
        public string Runtime { get; init; } = "";
        public string OperatingSystemArchitecture { get; init; } = "";
        public string ProcessArchitecture { get; init; } = "";
        public DateTimeOffset GeneratedAtUtc { get; init; }
    }

    [GeneratedRegex(@"(?i)\b(https?://[^/\s?#]+)(?:/[^\s?#]*)?(?:[?#][^\s]*)?")]
    private static partial Regex Url();

    [GeneratedRegex(@"(?i)\b(api[-_ ]?key|access[-_ ]?token|token|password|secret)\b\s*[:=]\s*([^\s,;]+)")]
    private static partial Regex Credential();

    [GeneratedRegex(@"(?i)\b(authorization)\b\s*[:=]\s*(?:Bearer\s+)?[^\s,;]+")]
    private static partial Regex Authorization();

    [GeneratedRegex(@"(?i)\b[A-Z]:\\Users\\[^\\/\s]+")]
    private static partial Regex UserProfilePath();
}
