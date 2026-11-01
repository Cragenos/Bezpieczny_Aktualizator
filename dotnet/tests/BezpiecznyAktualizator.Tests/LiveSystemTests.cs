using BezpiecznyAktualizator.Core.Drivers;
using BezpiecznyAktualizator.Core.Inventory;

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
}
