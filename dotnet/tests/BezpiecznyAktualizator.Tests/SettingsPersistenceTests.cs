using System.Text.Json;
using BezpiecznyAktualizator.Core.Logging;
using BezpiecznyAktualizator.Services;

namespace BezpiecznyAktualizator.Tests;

[CollectionDefinition(nameof(SettingsPersistenceTests), DisableParallelization = true)]
public sealed class SettingsPersistenceTestsCollectionDefinition
{
}

[Collection(nameof(SettingsPersistenceTests))]
public class SettingsPersistenceTests
{
    [Fact]
    public void SettingsAreAtomicallyWrittenAndCanBeReadBack()
    {
        RunWithTemporaryPaths((path, directory) =>
        {
            Settings.CheckSoftwareOnStart = false;
            Settings.CheckSoftwareOnStart = true;

            using var json = JsonDocument.Parse(File.ReadAllText(path));
            Assert.True(json.RootElement.GetProperty("checkSoftwareOnStart").GetBoolean());
            Assert.True(Settings.CheckSoftwareOnStart);
            Assert.Empty(Directory.GetFiles(directory, "settings.json.*.tmp"));
            Assert.Null(Settings.PersistenceError);
        });
    }

    [Fact]
    public void UnreadableSettingsAreReportedAndNeverOverwritten()
    {
        RunWithTemporaryPaths((path, _) =>
        {
            const string invalidSettings = "{ invalid JSON";
            File.WriteAllText(path, invalidSettings);

            Assert.True(Settings.CheckSoftwareOnStart);
            Settings.CheckSoftwareOnStart = false;

            Assert.Equal(invalidSettings, File.ReadAllText(path));
            Assert.NotNull(Settings.PersistenceError);
            var log = File.ReadAllText(Syslog.FilePath);
            Assert.Contains("Could not read settings file", log);
            Assert.Contains("Settings were not saved", log);
        });
    }

    private static void RunWithTemporaryPaths(Action<string, string> action)
    {
        var root = Path.Combine(Path.GetTempPath(), "BA-settings-" + Guid.NewGuid().ToString("N"));
        var settingsDirectory = Path.Combine(root, "settings");
        var settingsPath = Path.Combine(settingsDirectory, "settings.json");
        var logDirectory = Path.Combine(root, "logs");
        var originalSettingsPath = Settings.FilePath;
        var originalLogDirectory = Syslog.Directory;
        var originalLoggingEnabled = Syslog.Enabled;
        try
        {
            Directory.CreateDirectory(settingsDirectory);
            Settings.FilePath = settingsPath;
            Syslog.Configure(logDirectory);
            Syslog.Enabled = true;
            action(settingsPath, settingsDirectory);
        }
        finally
        {
            Settings.FilePath = originalSettingsPath;
            Syslog.Configure(originalLogDirectory);
            Syslog.Enabled = originalLoggingEnabled;
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }
}
