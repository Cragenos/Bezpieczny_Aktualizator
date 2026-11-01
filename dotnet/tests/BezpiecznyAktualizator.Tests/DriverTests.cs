using BezpiecznyAktualizator.Core.Drivers;
using BezpiecznyAktualizator.Core.Security;

namespace BezpiecznyAktualizator.Tests;

public class DriverTests
{
    private static readonly Dictionary<string, object?>[] InventoryRows =
    [
        new()
        {
            ["DeviceName"] = "Intel(R) UHD Graphics", ["DeviceID"] = @"PCI\VEN_8086&DEV_9A49\3&11583659&0&10",
            ["DriverVersion"] = "30.0.101.1191", ["DriverDate"] = "2021-11-10", ["DriverProviderName"] = "Intel Corporation",
            ["Manufacturer"] = "Intel Corporation", ["InfName"] = "oem12.inf", ["DeviceClass"] = "DISPLAY", ["IsSigned"] = true,
            ["Signer"] = "Microsoft Windows Hardware Compatibility Publisher",
            ["HardwareID"] = new[] { @"PCI\VEN_8086&DEV_9A49&SUBSYS_0A6D1028", @"PCI\VEN_8086&DEV_9A49" },
            ["CompatibleID"] = new[] { @"PCI\CC_030000" }, ["ErrorCode"] = 0,
        },
        new()
        {
            ["DeviceName"] = "Stary skaner", ["DeviceID"] = @"USB\VID_04A9&PID_1909\5", ["DriverVersion"] = "1.0.0.0",
            ["DriverDate"] = "2009-01-01", ["DriverProviderName"] = "Acme", ["DeviceClass"] = "IMAGE", ["IsSigned"] = false,
            ["HardwareID"] = @"USB\VID_04A9&PID_1909", ["ErrorCode"] = 0,
        },
        new()
        {
            ["DeviceName"] = "Nieznane urządzenie", ["DeviceID"] = @"ACPI\FOO0001\0", ["DeviceClass"] = "",
            ["HardwareID"] = new[] { @"ACPI\FOO0001" }, ["CompatibleID"] = null, ["ErrorCode"] = 28u,
        },
    ];

    private static List<DriverUpdate> Updates() =>
    [
        new()
        {
            UpdateId = "6b1e5a2c-1111-4c3e-9a0b-0123456789ab", Title = "Intel Corporation - Display - 31.0.101.5186",
            Model = "Intel(R) UHD Graphics", Manufacturer = "Intel Corporation", Provider = "Intel Corporation",
            DriverClass = "Display", HardwareId = @"pci\ven_8086&dev_9a49&subsys_0a6d1028", Date = "2024-01-15",
            Size = 524288000, EulaAccepted = true,
        },
        new()
        {
            UpdateId = "aaaaaaaa-2222-4c3e-9a0b-0123456789ab", Title = "Contoso - System - 2.0.0.0", Model = "Contoso ACPI",
            Provider = "Contoso", HardwareId = @"ACPI\FOO0001", Date = "2023-05-01", EulaAccepted = false,
        },
        new()
        {
            UpdateId = "bbbbbbbb-3333-4c3e-9a0b-0123456789ab", Title = "Fabrikam - Net - 5.1", Model = "Fabrikam NIC",
            HardwareId = @"PCI\VEN_FFFF&DEV_0001",
        },
    ];

    private static List<Driver> Drivers() => DriverInventory.FromRecords(InventoryRows);

    private static Driver ByName(IEnumerable<Driver> items, string name) => items.Single(d => d.DeviceName == name);

    [Fact]
    public void ParseInventory()
    {
        var drivers = Drivers();
        Assert.Equal(3, drivers.Count);
        var gpu = ByName(drivers, "Intel(R) UHD Graphics");
        Assert.Equal("Microsoft (WHQL)", gpu.SignatureText);
        Assert.Equal(2, gpu.HardwareIds.Count);
        var scanner = ByName(drivers, "Stary skaner");
        Assert.Equal([@"USB\VID_04A9&PID_1909"], scanner.HardwareIds);
        Assert.Equal("NIEPODPISANY", scanner.SignatureText);
        var unknown = ByName(drivers, "Nieznane urządzenie");
        Assert.True(unknown.MissingDriver);
        Assert.Equal("Brak sterownika", unknown.Status);
        Assert.Contains("ACPI%5CFOO0001", unknown.CatalogUrl());
        Assert.StartsWith("https://www.catalog.update.microsoft.com/", unknown.CatalogUrl());
    }

    [Fact]
    public void UpdateVersionFromTitle()
    {
        var updates = Updates();
        Assert.Equal("31.0.101.5186", updates[0].Version);
        Assert.Equal("5.1", updates[2].Version);
        Assert.Equal("", new DriverUpdate { UpdateId = "x", Title = "Bez wersji" }.Version);
    }

    [Fact]
    public void IsNewer()
    {
        var d = new Driver { DeviceName = "x", Version = "30.0.101.1191", Date = "2021-11-10" };
        Assert.True(DriverMatcher.IsNewer(new DriverUpdate { Title = "A - B - 31.0.101.5186" }, d));
        Assert.False(DriverMatcher.IsNewer(new DriverUpdate { Title = "A - B - 30.0.9.1" }, d));
        Assert.True(DriverMatcher.IsNewer(new DriverUpdate { Title = "Bez wersji", Date = "2022-01-01" },
                                          new Driver { DeviceName = "x", Date = "2021-11-10" }));
        Assert.True(DriverMatcher.CompareVersions("10.0.2", "9.1") > 0);
    }

    [Fact]
    public void MatchUpdates()
    {
        var drivers = Drivers();
        var merged = DriverMatcher.MatchUpdates(drivers, Updates());
        Assert.Equal(4, merged.Count); // niedopasowana karta sieciowa jako nowy wiersz
        var gpu = ByName(merged, "Intel(R) UHD Graphics");
        Assert.Equal("6b1e5a2c-1111-4c3e-9a0b-0123456789ab", gpu.Update?.UpdateId);
        Assert.Equal("Aktualizacja dostępna", gpu.Status);
        Assert.Equal("Sterownik dostępny", ByName(merged, "Nieznane urządzenie").Status);
        Assert.Null(ByName(merged, "Stary skaner").Update);
        Assert.Equal("Fabrikam - Net - 5.1", ByName(merged, "Fabrikam NIC").Update?.Title);
        var again = DriverMatcher.MatchUpdates(drivers, []);
        Assert.Null(ByName(again, "Intel(R) UHD Graphics").Update);
    }

    [Fact]
    public void Assessments()
    {
        var merged = DriverMatcher.MatchUpdates(Drivers(), Updates());
        Assert.Equal(Levels.High, DriverAssessor.Assess(ByName(merged, "Intel(R) UHD Graphics")).Level);
        var unsigned = DriverAssessor.Assess(ByName(merged, "Stary skaner"));
        Assert.Equal(Levels.Low, unsigned.Level);
        Assert.Contains("Katalogu Microsoft Update", unsigned.Report());
        Assert.Equal(Levels.Medium, DriverAssessor.Assess(ByName(merged, "Nieznane urządzenie")).Level);
        var older = new Driver
        {
            DeviceName = "x", Version = "99.0", Provider = "Intel", HardwareIds = ["HW"],
            Update = new DriverUpdate { UpdateId = "u", Title = "Intel - D - 1.0", Provider = "AMD", HardwareId = "HW" },
        };
        Assert.Equal(Levels.Medium, DriverAssessor.Assess(older).Level);
    }

    [Fact]
    public void ApplySetsLevelOnlyForUpdatesOrLowTrust()
    {
        var merged = DriverMatcher.MatchUpdates(Drivers(), Updates());
        foreach (var d in merged) DriverAssessor.Apply(d);
        Assert.Equal(Levels.High, ByName(merged, "Intel(R) UHD Graphics").SecurityLevel);
        Assert.Equal(Levels.Low, ByName(merged, "Stary skaner").SecurityLevel);
        Assert.NotEmpty(ByName(merged, "Stary skaner").SecurityReport);
    }

    [Fact]
    public async Task InstallRejectsInvalidIds()
    {
        await Assert.ThrowsAsync<DriverException>(() =>
            WindowsUpdateDrivers.InstallElevatedAsync("x.exe", [@"abc; Remove-Item C:\"], false, _ => { }));
        Assert.Empty(await WindowsUpdateDrivers.InstallElevatedAsync("x.exe", [], false, _ => { }));
        Assert.True(WindowsUpdateDrivers.IsValidUpdateId("6b1e5a2c-1111-4c3e-9a0b-0123456789ab"));
        Assert.False(WindowsUpdateDrivers.IsValidUpdateId("------------------------------------"));
    }

    [Fact]
    public void InstallJobWithoutIdsFileFails()
    {
        var dir = Directory.CreateTempSubdirectory("ba_test_").FullName;
        try
        {
            Assert.Equal(2, WindowsUpdateDrivers.RunInstallJob(dir));
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }
}
