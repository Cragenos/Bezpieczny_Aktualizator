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

    [Fact]
    public void RestoreReplacesBackedUpStateAndPreservesCurrentNvdApiKey()
    {
        var root = Directory.CreateTempSubdirectory("ba_backup_restore_test_");
        try
        {
            var data = Directory.CreateDirectory(Path.Combine(root.FullName, "data"));
            var settingsPath = Path.Combine(root.FullName, "settings.json");
            var historyPath = Path.Combine(data.FullName, "update-history.json");
            File.WriteAllText(settingsPath, """{"language":"pl","nvdApiKey":"original-secret"}""");
            File.WriteAllText(historyPath, """[{"name":"Original"}]""");
            File.WriteAllText(Path.Combine(data.FullName, "schedule-state.json"), """{"updates":2}""");

            var backup = UpdateStateBackup.Create(Path.Combine(root.FullName, "backups"), settingsPath, data.FullName,
                DateTimeOffset.Parse("2026-05-01T12:00:00Z"));
            File.WriteAllText(settingsPath, """{"language":"en","nvdApiKey":"current-secret"}""");
            File.WriteAllText(historyPath, """[{"name":"Changed"}]""");

            Assert.Equal(["settings.json", "update-history.json", "schedule-state.json"],
                UpdateStateBackup.GetFileNames(backup.Path));
            Assert.Equal(3, UpdateStateBackup.Restore(backup.Path, settingsPath, data.FullName).Count);

            using var settings = JsonDocument.Parse(File.ReadAllText(settingsPath));
            Assert.Equal("pl", settings.RootElement.GetProperty("language").GetString());
            Assert.Equal("current-secret", settings.RootElement.GetProperty("nvdApiKey").GetString());
            Assert.Contains("Original", File.ReadAllText(historyPath));
        }
        finally
        {
            root.Delete(true);
        }
    }

    [Fact]
    public void PartialRestoreFailureRollsBackAlreadyReplacedFiles()
    {
        var root = Directory.CreateTempSubdirectory("ba_backup_partial_restore_test_");
        try
        {
            var data = Directory.CreateDirectory(Path.Combine(root.FullName, "data"));
            var settingsPath = Path.Combine(root.FullName, "settings.json");
            var historyPath = Path.Combine(data.FullName, "update-history.json");
            var schedulePath = Path.Combine(data.FullName, "schedule-state.json");
            File.WriteAllText(settingsPath, """{"language":"pl","nvdApiKey":"backup-key"}""");
            File.WriteAllText(historyPath, """[{"name":"Backed up"}]""");
            File.WriteAllText(schedulePath, """{"updates":1}""");
            var backup = UpdateStateBackup.Create(Path.Combine(root.FullName, "backups"), settingsPath, data.FullName,
                DateTimeOffset.UtcNow);

            const string currentSettings = """{"language":"en","nvdApiKey":"current-key"}""";
            const string currentHistory = """[{"name":"Current"}]""";
            const string currentSchedule = """{"updates":2}""";
            File.WriteAllText(settingsPath, currentSettings);
            File.WriteAllText(historyPath, currentHistory);
            File.WriteAllText(schedulePath, currentSchedule);

            using (new FileStream(schedulePath, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                var error = Record.Exception(() => UpdateStateBackup.Restore(backup.Path, settingsPath, data.FullName));
                Assert.NotNull(error);
                Assert.True(error is IOException or UnauthorizedAccessException, error.ToString());
            }

            Assert.Equal(currentSettings, File.ReadAllText(settingsPath));
            Assert.Equal(currentHistory, File.ReadAllText(historyPath));
            Assert.Equal(currentSchedule, File.ReadAllText(schedulePath));
            Assert.Empty(Directory.GetFiles(root.FullName, "*.tmp", SearchOption.AllDirectories));
            Assert.Empty(Directory.GetFiles(root.FullName, "*.rollback", SearchOption.AllDirectories));
        }
        finally
        {
            root.Delete(true);
        }
    }

    [Fact]
    public void CreatingSafetyCopyDoesNotPruneBackupBeingRestored()
    {
        var root = Directory.CreateTempSubdirectory("ba_backup_retention_test_");
        try
        {
            var data = Directory.CreateDirectory(Path.Combine(root.FullName, "data"));
            var settingsPath = Path.Combine(root.FullName, "settings.json");
            File.WriteAllText(settingsPath, """{"language":"pl"}""");
            var backupDirectory = Path.Combine(root.FullName, "backups");
            var start = DateTimeOffset.Parse("2026-05-01T12:00:00Z");
            var oldest = UpdateStateBackup.Create(backupDirectory, settingsPath, data.FullName, start);
            for (var i = 1; i < 10; i++)
                UpdateStateBackup.Create(backupDirectory, settingsPath, data.FullName, start.AddMinutes(i));

            UpdateStateBackup.Create(backupDirectory, settingsPath, data.FullName, start.AddMinutes(10), oldest.Path);

            Assert.True(File.Exists(oldest.Path));
            Assert.Equal(10, Directory.GetFiles(backupDirectory, "state-*.zip").Length);
        }
        finally
        {
            root.Delete(true);
        }
    }
}
