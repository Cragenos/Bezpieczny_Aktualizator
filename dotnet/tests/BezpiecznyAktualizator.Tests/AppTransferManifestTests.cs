using BezpiecznyAktualizator.Core.Inventory;

namespace BezpiecznyAktualizator.Tests;

public sealed class AppTransferManifestTests : IDisposable
{
    private readonly DirectoryInfo _root = Directory.CreateTempSubdirectory("ba_apps_test_");

    public void Dispose() => _root.Delete(recursive: true);

    private string PathOf(string name) => Path.Combine(_root.FullName, name);

    [Fact]
    public void ManifestRoundTripsWingetPackages()
    {
        var manifest = AppTransferManifestFile.Create(
            [new AppTransferEntry("Microsoft.PowerToys", "PowerToys", "winget", "0.91.0")], "SOURCE-PC");
        var path = PathOf("apps" + AppTransferManifestFile.Extension);

        AppTransferManifestFile.Write(path, manifest);
        var loaded = AppTransferManifestFile.Read(path);

        Assert.Equal(AppTransferManifestFile.CurrentSchemaVersion, loaded.SchemaVersion);
        Assert.Equal("SOURCE-PC", loaded.Machine);
        Assert.Equal(manifest.Apps, loaded.Apps);
    }

    [Fact]
    public void ManifestRejectsInvalidIdsAndNonWingetSources()
    {
        Assert.Throws<InvalidDataException>(() => AppTransferManifestFile.Create(
            [new AppTransferEntry("Microsoft.PowerToys;--force", "PowerToys", "winget", "1.0")], "PC"));
        Assert.Throws<InvalidDataException>(() => AppTransferManifestFile.Create(
            [new AppTransferEntry("Microsoft.PowerToys", "PowerToys", "custom", "1.0")], "PC"));
    }

    [Fact]
    public void ManifestRejectsDuplicatePackageIds()
    {
        Assert.Throws<InvalidDataException>(() => AppTransferManifestFile.Create(
        [
            new AppTransferEntry("Microsoft.PowerToys", "PowerToys", "winget", "1.0"),
            new AppTransferEntry("microsoft.powertoys", "PowerToys duplicate", "winget", "1.0"),
        ], "PC"));
    }

    [Fact]
    public void ReadRejectsUnsupportedSchemaVersion()
    {
        var path = PathOf("future" + AppTransferManifestFile.Extension);
        File.WriteAllText(path, """{"schemaVersion":2,"createdAt":"2026-10-25T10:00:00+00:00","machine":"PC","apps":[]}""");

        Assert.Throws<InvalidDataException>(() => AppTransferManifestFile.Read(path));
    }
}
