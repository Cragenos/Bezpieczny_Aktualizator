using System.IO.Compression;
using System.Text;
using System.Text.Json;
using BezpiecznyAktualizator.Services;

namespace BezpiecznyAktualizator.Tests;

public class DiagnosticsBundleTests
{
    [Fact]
    public void RedactsCredentialValuesUserPathsAndUrlPaths()
    {
        const string input = @"Access token=top-secret C:\Users\alice\AppData\Local\log https://example.org/hooks/private?key=secret Authorization: Bearer bearer-secret";
        var output = DiagnosticsBundle.Redact(input);
        Assert.DoesNotContain("top-secret", output);
        Assert.DoesNotContain("C:\\Users\\alice", output);
        Assert.DoesNotContain("/hooks/private", output);
        Assert.DoesNotContain("******", output);
        Assert.Contains("%USERPROFILE%", output);
        Assert.Contains("https://example.org/[REDACTED]", output);
    }

    [Fact]
    public void BundleContainsOnlyMetadataAndRedactedIssues()
    {
        var directory = Path.Combine(Path.GetTempPath(), "ba-diagnostics-" + Guid.NewGuid().ToString("N"));
        var path = Path.Combine(directory, "diagnostics.zip");
        try
        {
            DiagnosticsBundle.Create(path,
            [
                @"<11>1 warning C:\Users\alice\AppData\log token=hidden",
            ]);
            using var archive = ZipFile.OpenRead(path);
            Assert.Equal(["diagnostics.json", "recent-issues.log"], archive.Entries.Select(entry => entry.FullName));
            using (var metadata = JsonDocument.Parse(archive.GetEntry("diagnostics.json")!.Open()))
            {
                var root = metadata.RootElement;
                Assert.Equal(6, root.EnumerateObject().Count());
                Assert.Equal(typeof(DiagnosticsBundle).Assembly.GetName().Version?.ToString(3),
                    root.GetProperty("ApplicationVersion").GetString());
                Assert.False(string.IsNullOrWhiteSpace(root.GetProperty("WindowsVersion").GetString()));
                Assert.False(string.IsNullOrWhiteSpace(root.GetProperty("Runtime").GetString()));
                Assert.False(string.IsNullOrWhiteSpace(root.GetProperty("OperatingSystemArchitecture").GetString()));
                Assert.False(string.IsNullOrWhiteSpace(root.GetProperty("ProcessArchitecture").GetString()));
                Assert.True(root.GetProperty("GeneratedAtUtc").TryGetDateTimeOffset(out _));
            }
            using var reader = new StreamReader(archive.GetEntry("recent-issues.log")!.Open(), Encoding.UTF8);
            var log = reader.ReadToEnd();
            Assert.Contains("%USERPROFILE%", log);
            Assert.DoesNotContain("hidden", log);
            Assert.DoesNotContain("settings.json", archive.Entries.Select(entry => entry.FullName));
            Assert.DoesNotContain("update-history.json", archive.Entries.Select(entry => entry.FullName));
        }
        finally
        {
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
        }
    }
}
