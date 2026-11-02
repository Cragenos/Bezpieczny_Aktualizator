using BezpiecznyAktualizator.Core.Drivers;
using BezpiecznyAktualizator.Core.Inventory;
using BezpiecznyAktualizator.Core.Updates;
using BezpiecznyAktualizator.Core.Winget;
using System.Text.RegularExpressions;

namespace BezpiecznyAktualizator.Tests;

/// <summary>Testy na rzeczywistym systemie (rejestr, WMI). Pominięcie: dotnet test --filter Category!=Live</summary>
[Trait("Category", "Live")]
public class LiveSystemTests
{
    [Fact]
    public void RegistryInventoryFindsPrograms()
    {
        var items = SoftwareInventory.ScanInstalled();
        Assert.NotEmpty(items);
        Assert.All(items, s => Assert.False(string.IsNullOrWhiteSpace(s.Name)));
    }

    [Trait("Category", "VmIntegration")]
    public class WingetAppInstallerIntegrationTests
    {
        [Fact]
        public async Task RunsOnlyMicrosoftSignedStoreAppInstallerWinget()
        {
            Assert.True(WingetClient.IsAvailable(), "The dedicated Windows VM must have the official Microsoft App Installer package.");
            var (code, output) = await WingetClient.RunAsync(["--version"], timeoutSeconds: 30);
            Assert.Equal(0, code);
            Assert.Matches(new Regex(@"(?m)^\s*v?\d+\.\d+\.\d+", RegexOptions.CultureInvariant), output);
        }
    }

    [Fact]
    public void WmiInventoryFindsDrivers()
    {
        var drivers = DriverInventory.Scan();
        Assert.NotEmpty(drivers);
        Assert.Contains(drivers, d => d.HardwareIds.Count > 0);
        Assert.Contains(drivers, d => d.Date.Length == 10);
    }

    [Fact]
    public async Task WingetCheckUpdatesMergesWithRegistry()
    {
        if (!BezpiecznyAktualizator.Core.Winget.WingetClient.IsAvailable()) return;
        var (items, count) = await BezpiecznyAktualizator.Core.Winget.WingetClient.CheckUpdatesAsync(SoftwareInventory.ScanInstalled());
        Assert.True(count > 0);
        Assert.Contains(items, s => s.WingetDetected);
    }

    [Fact]
    public void WindowsUpdateDriverSearchRuns()
    {
        var updates = WindowsUpdateDrivers.Search();
        Assert.All(updates, u => Assert.True(WindowsUpdateDrivers.IsValidUpdateId(u.UpdateId)));
    }

    [Fact]
    public void WindowsUpdateSoftwareSearchRuns()
    {
        var result = WindowsUpdateAgent.Search();
        Assert.All(result.Updates, update => Assert.NotEqual(Guid.Empty, update.Identity.UpdateId));
    }

    [Fact]
    public void WindowsUpdateCachedMetadataCanBeMapped()
    {
        var type = Type.GetTypeFromProgID("Microsoft.Update.Session")!;
        dynamic session = Activator.CreateInstance(type)!;
        var searcher = session.CreateUpdateSearcher();
        searcher.Online = false;
        var updates = searcher.Search("IsInstalled=1 and Type='Software'").Updates;
        for (var i = 0; i < Math.Min(5, (int)updates.Count); i++)
        {
            var item = WindowsUpdateAgent.ToItem((object)updates.Item[i]);
            Assert.NotEqual(Guid.Empty, item.Identity.UpdateId);
            Assert.False(string.IsNullOrWhiteSpace(item.Title));
        }
    }
}
