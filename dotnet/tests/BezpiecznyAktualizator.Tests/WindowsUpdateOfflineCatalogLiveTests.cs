using BezpiecznyAktualizator.Core.Updates;

namespace BezpiecznyAktualizator.Tests;

[Trait("Category", "Live")]
public sealed class WindowsUpdateOfflineCatalogLiveTests
{
    [Fact]
    public void SignedMicrosoftCatalogCanBeScannedWithoutInstallingUpdates()
    {
        var catalogPath = Environment.GetEnvironmentVariable("BA_WSUSSCN2_PATH");
        Assert.False(string.IsNullOrWhiteSpace(catalogPath),
            "Set BA_WSUSSCN2_PATH to the downloaded Microsoft Wsusscn2.cab catalog.");
        Assert.True(File.Exists(catalogPath), $"Offline scan catalog does not exist: {catalogPath}");

        var result = WindowsUpdateAgent.SearchOffline(catalogPath);

        Assert.All(result.Updates, update => Assert.True(update.IsOfflineScan));
        Assert.All(result.Warnings, warning => Assert.False(string.IsNullOrWhiteSpace(warning)));
    }
}
