using System.IO.Compression;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using BezpiecznyAktualizator.Core.History;

namespace BezpiecznyAktualizator.Tests;

public class UpdateStateBackupTests
{
    [Fact]
    public void BackupContainsUpdaterStateButOmitsNvdApiKeyAndVerifiesManifest()
    {
        var root = Directory.CreateTempSubdirectory("ba_backup_test_");
        try
        {
            var data = Directory.CreateDirectory(Path.Combine(root.FullName, "data"));
            var settingsPath = Path.Combine(root.FullName, "settings.json");
            File.WriteAllText(settingsPath, """{"language":"pl","nvdApiKey":"do-not-copy"}""");
            File.WriteAllText(Path.Combine(data.FullName, "update-history.json"), """[{"name":"App"}]""");
            File.WriteAllText(Path.Combine(data.FullName, "schedule-state.json"), """{"updates":2}""");

            var backup = UpdateStateBackup.Create(Path.Combine(root.FullName, "backups"), settingsPath, data.FullName,
                DateTimeOffset.Parse("2026-05-01T12:00:00Z"));
            Assert.True(UpdateStateBackup.Verify(backup.Path));
            Assert.Equal(3, backup.Files);
            Assert.Equal(64, backup.Sha256.Length);

            using var archive = ZipFile.OpenRead(backup.Path);
            using (var manifest = JsonDocument.Parse(archive.GetEntry("manifest.json")!.Open()))
            {
                var entries = manifest.RootElement.EnumerateArray().ToArray();
                Assert.Equal(3, entries.Length);
                Assert.Contains(entries, entry => entry.GetProperty("Name").GetString() == "settings.json");
                Assert.All(entries, entry =>
                {
                    Assert.True(entry.GetProperty("Size").GetInt64() > 0);
                    Assert.Equal(64, entry.GetProperty("Sha256").GetString()!.Length);
                });
            }
            var settingsEntry = archive.GetEntry("settings.json")!;
            using var reader = new StreamReader(settingsEntry.Open());
            var settings = JsonNode.Parse(reader.ReadToEnd())!.AsObject();
            Assert.Equal("pl", settings["language"]!.GetValue<string>());
            Assert.Null(settings["nvdApiKey"]);
        }
        finally
        {
            root.Delete(true);
        }
    }

    [Fact]
    public void BackupVerificationRejectsTamperedContent()
    {
        var root = Directory.CreateTempSubdirectory("ba_backup_tamper_test_");
        try
        {
            var data = Directory.CreateDirectory(Path.Combine(root.FullName, "data"));
            var historyPath = Path.Combine(data.FullName, "update-history.json");
            File.WriteAllText(historyPath, """[{"name":"Original"}]""", Encoding.UTF8);
            var backup = UpdateStateBackup.Create(Path.Combine(root.FullName, "backups"), Path.Combine(root.FullName, "missing.json"),
                data.FullName, DateTimeOffset.UtcNow);
            Assert.True(UpdateStateBackup.Verify(backup.Path));

            using (var archive = ZipFile.Open(backup.Path, ZipArchiveMode.Update))
            {
                archive.GetEntry("update-history.json")!.Delete();
                var replacement = archive.CreateEntry("update-history.json");
                using var writer = new StreamWriter(replacement.Open());
                writer.Write("""[{"name":"Tampered"}]""");
            }
            Assert.False(UpdateStateBackup.Verify(backup.Path));
        }
        finally
        {
            root.Delete(true);
        }
    }
}
