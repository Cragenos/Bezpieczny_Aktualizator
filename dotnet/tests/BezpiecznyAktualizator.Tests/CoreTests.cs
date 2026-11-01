using System.Text.Json.Nodes;
using BezpiecznyAktualizator.Core.Catalogs;
using BezpiecznyAktualizator.Core.Models;
using BezpiecznyAktualizator.Core.Security;
using BezpiecznyAktualizator.Core.Winget;

namespace BezpiecznyAktualizator.Tests;

public class WingetParsingTests
{
    internal const string UpgradeOutput =
        "   - \r   \\ \r" +
        "Name                                               Id                                Version            Available          Source\r\n" +
        "---------------------------------------------------------------------------------------------------------------------------------\r\n" +
        "Battle.net                                         Blizzard.BattleNet                Unknown            2.0.0.4232         winget\r\n" +
        "foobar2000 v2.26.1 (x64)                           PeterPawlowski.foobar2000         2.26.1             2.26.2             winget\r\n" +
        "Mozilla Thunderbird (x64 pl)                       Mozilla.Thunderbird.pl            155.0.1            159.0              winget\r\n" +
        "3 upgrades available.\r\n";

    internal const string ListOutput =
        "Name                     Id                                                       Version     Available Source\r\n" +
        "--------------------------------------------------------------------------------------------------------------\r\n" +
        "7-Zip 26.05 (x64)        7zip.7zip                                                26.05                 winget\r\n" +
        "Adobe Acrobat (64-bit)   ARP\\Machine\\X64\\{AC76BA86-1033-1033-7760-BC15014EA700}   26.002.22031\r\n" +
        "Zegar Windows            MSIX\\Microsoft.WindowsAlarms_1.1.158.0_x64__8wekyb3d8bbwe 1.1.158.0\r\n";

    internal const string ShowOutput = """
        Found OBS Studio [OBSProject.OBSStudio]
        Version: 33.0.0
        Publisher: OBS Project
        Publisher Url: https://obsproject.com/
        Homepage: https://obsproject.com/
        License: GPL-2.0
        Release Notes:
          Bug Fixes
          - Note: this is not a key
        Installer:
          Installer Type: nullsoft
          Installer Url: https://cdn-fastly.obsproject.com/downloads/OBS-Studio-33.0-Windows-x64-Installer.exe
          Installer SHA256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
          Offline Distribution Supported: true

        """;

    [Fact]
    public void ParseUpgradeTable()
    {
        var rows = WingetClient.ParseTable(UpgradeOutput);
        Assert.Equal(3, rows.Count);
        Assert.Equal(["foobar2000 v2.26.1 (x64)", "PeterPawlowski.foobar2000", "2.26.1", "2.26.2", "winget"], rows[1]);
        Assert.Equal("Unknown", rows[0][2]);
    }

    [Fact]
    public void ParseListWithLocalIds()
    {
        var packages = WingetClient.RowsToPackages(WingetClient.ParseTable(ListOutput));
        Assert.Equal("7zip.7zip", packages[0].Id);
        Assert.True(packages[1].IsLocalOnly);
        Assert.Equal("26.002.22031", packages[1].Version);
        Assert.Equal("", packages[2].Source);
    }

    [Fact]
    public void ParseShow()
    {
        var info = WingetClient.ParseShow(ShowOutput);
        Assert.Equal("OBSProject.OBSStudio", info["id"]);
        Assert.Equal("OBS Studio", info["name"]);
        Assert.Equal("OBS Project", info["Publisher"]);
        Assert.StartsWith("https://cdn-fastly.obsproject.com/", WingetClient.InstallerUrl(info));
        Assert.Equal(64, WingetClient.InstallerSha256(info).Length);
        Assert.Equal("nullsoft", WingetClient.InstallerType(info));
        Assert.DoesNotContain("Installer.Note", info.Keys);
    }

    [Fact]
    public void MergeMatchesByNameAndRegistryKey()
    {
        List<Software> software =
        [
            new() { Name = "7-Zip 26.05 (x64)", Version = "26.05", Origin = "HKLM" },
            new() { Name = "Adobe Acrobat (64-bit)", Version = "26.002.22031", Origin = "HKLM",
                    RegKey = "{AC76BA86-1033-1033-7760-BC15014EA700}" },
            new() { Name = "foobar2000 v2.26.1 (x64)", Version = "2.26.1", Origin = "HKLM" },
        ];
        var packages = WingetClient.RowsToPackages(WingetClient.ParseTable(ListOutput));
        packages.AddRange(WingetClient.RowsToPackages(WingetClient.ParseTable(UpgradeOutput)).Where(p => p.Id.Contains("foobar")));
        var merged = WingetClient.Merge(software, packages).ToDictionary(s => s.Name);
        Assert.Equal("7zip.7zip", merged["7-Zip 26.05 (x64)"].WingetId);
        Assert.False(merged["7-Zip 26.05 (x64)"].HasUpdate);
        Assert.Null(merged["Adobe Acrobat (64-bit)"].WingetId);
        Assert.True(merged["Adobe Acrobat (64-bit)"].WingetDetected);
        Assert.True(merged["foobar2000 v2.26.1 (x64)"].CanUpgrade);
        Assert.Contains("Zegar Windows", merged.Keys);
    }

    [Fact]
    public void LocalDuplicateDoesNotOverrideRepositoryMatch()
    {
        List<Software> software = [new() { Name = "Microsoft Edge", Version = "156.0.4314.50", Origin = "HKLM", RegKey = "Microsoft Edge" }];
        WingetPackage[] packages =
        [
            new("Microsoft Edge", "Microsoft.Edge", "156.0.4314.50", "156.0.4314.56", "winget"),
            new("Microsoft Edge", @"MSIX\Microsoft.MicrosoftEdge.Stable_154.0_neutral__8wekyb3d8bbwe", "154.0"),
        ];
        var merged = WingetClient.Merge(software, packages);
        var edge = merged.Single(s => s.Origin == "HKLM");
        Assert.Equal("Microsoft.Edge", edge.WingetId);
        Assert.True(edge.CanUpgrade);
        Assert.Equal(2, merged.Count);
    }
}

public class SecurityTests
{
    [Fact]
    public void RegistrableDomain()
    {
        Assert.Equal("obsproject.com", SecurityRules.RegistrableDomain("https://cdn-fastly.obsproject.com/x.exe"));
        Assert.Equal("example.co.uk", SecurityRules.RegistrableDomain("https://www.example.co.uk/"));
    }

    [Fact]
    public void PublishersMatch()
    {
        Assert.True(SecurityRules.PublishersMatch("Mozilla", "Mozilla Foundation"));
        Assert.True(SecurityRules.PublishersMatch("OBS Project", "OBS Project"));
        Assert.False(SecurityRules.PublishersMatch("Evil Corp", "OBS Project"));
    }

    [Fact]
    public async Task AssessWingetHigh()
    {
        var info = WingetClient.ParseShow(WingetParsingTests.ShowOutput);
        var a = await SoftwareAssessor.AssessWingetAsync(info, "winget", "OBS Project", verifyTls: false);
        Assert.True(a.Level == Levels.High, a.Report());
    }

    [Fact]
    public async Task AssessWingetHttpIsLow()
    {
        var info = WingetClient.ParseShow(WingetParsingTests.ShowOutput.Replace("https://cdn-fastly", "http://cdn-fastly"));
        var a = await SoftwareAssessor.AssessWingetAsync(info, "winget", "OBS Project", verifyTls: false);
        Assert.Equal(Levels.Low, a.Level);
    }

    [Fact]
    public async Task AssessWingetMissingHashIsLow()
    {
        var info = WingetClient.ParseShow(WingetParsingTests.ShowOutput.Replace("Installer SHA256", "Something"));
        var a = await SoftwareAssessor.AssessWingetAsync(info, "winget", verifyTls: false);
        Assert.Equal(Levels.Low, a.Level);
    }

    [Fact]
    public async Task AssessVendor()
    {
        Assert.Equal(Levels.None, (await SoftwareAssessor.AssessVendorAsync(new Software { Name = "x" }, false)).Level);
        Assert.Equal(Levels.Medium,
            (await SoftwareAssessor.AssessVendorAsync(new Software { Name = "x", UrlInfo = "https://example.com" }, false)).Level);
        Assert.Equal(Levels.Low,
            (await SoftwareAssessor.AssessVendorAsync(new Software { Name = "x", UrlInfo = "http://example.com" }, false)).Level);
    }

    [Fact]
    public void LevelRules()
    {
        Assert.Equal(Levels.High, SecurityRules.Level([new Check("a", CheckStatus.Ok), new Check("b", CheckStatus.Warn)]));
        Assert.Equal(Levels.Medium, SecurityRules.Level(Enumerable.Repeat(new Check("w", CheckStatus.Warn), 3)));
        Assert.Equal(Levels.Low, SecurityRules.Level(Enumerable.Repeat(new Check("w", CheckStatus.Warn), 4)));
        Assert.Equal(Levels.Low, SecurityRules.Level([new Check("f", CheckStatus.Fail)]));
    }
}

public class CatalogTests
{
    private const string ChocoFeed = """
        <?xml version="1.0"?>
        <feed xmlns="http://www.w3.org/2005/Atom"
              xmlns:d="http://schemas.microsoft.com/ado/2007/08/dataservices"
              xmlns:m="http://schemas.microsoft.com/ado/2007/08/dataservices/metadata">
          <entry>
            <id>https://community.chocolatey.org/api/v2/Packages(Id='notepadplusplus',Version='8.8.5')</id>
            <title>notepadplusplus</title>
            <m:properties>
              <d:Version>8.8.5</d:Version>
              <d:Title>Notepad++</d:Title>
              <d:ProjectUrl>https://notepad-plus-plus.org/</d:ProjectUrl>
              <d:GalleryDetailsUrl>https://community.chocolatey.org/packages/notepadplusplus/8.8.5</d:GalleryDetailsUrl>
            </m:properties>
          </entry>
          <entry>
            <id>https://community.chocolatey.org/api/v2/Packages(Id='notepadplusplus',Version='8.8.4')</id>
            <title>notepadplusplus</title>
            <m:properties><d:Version>8.8.4</d:Version></m:properties>
          </entry>
        </feed>
        """;

    private static CatalogPackage Scoop(JsonObject manifest) => new("scoop", "demo", "demo", "1.0", "Scoop Main", Manifest: manifest);

    [Fact]
    public void ScoopFilenameSearchRanksExactMatch()
    {
        string[] paths = ["bucket/7zip.json", "bucket/7zip-extra.json", "bucket/notepadplusplus.json"];
        Assert.Equal(["7zip", "7zip-extra"], CatalogClient.ScoopSlugs("7zip", paths));
        Assert.Equal(["7zip"], CatalogClient.ScoopSlugs("7-Zip", paths));
    }

    [Fact]
    public async Task ScoopManifestRequiresHttpsAndSha256()
    {
        var package = Scoop(new JsonObject { ["version"] = "1.0", ["url"] = "https://example.com/demo.zip", ["hash"] = new string('a', 64) });
        var assessment = await CatalogClient.AssessScoopAsync(package, verifyTls: false);
        Assert.Equal(Levels.Medium, assessment.Level);
        Assert.Contains(assessment.Checks, c => c.Label.ToString().Contains("SHA256"));
    }

    [Fact]
    public async Task ScoopScriptOrMissingHashIsLow()
    {
        var script = Scoop(new JsonObject
        {
            ["version"] = "1.0", ["url"] = "https://example.com/demo.zip", ["hash"] = new string('a', 64),
            ["post_install"] = new JsonArray("Write-Host installed"),
        });
        var noHash = Scoop(new JsonObject { ["version"] = "1.0", ["url"] = "https://example.com/demo.zip" });
        Assert.Equal(Levels.Low, (await CatalogClient.AssessScoopAsync(script, verifyTls: false)).Level);
        Assert.Equal(Levels.Low, (await CatalogClient.AssessScoopAsync(noHash, verifyTls: false)).Level);
    }

    [Fact]
    public void ChocolateyFeedDeduplicatesVersions()
    {
        var packages = CatalogClient.ParseChocolateyFeed(ChocoFeed);
        var p = Assert.Single(packages);
        Assert.Equal("notepadplusplus", p.Id);
        Assert.Equal("8.8.5", p.Version);
        Assert.Equal("Notepad++", p.Name);
        Assert.Contains("community.chocolatey.org/packages", p.DetailsUrl);
    }

    [Fact]
    public void ChocolateyIsAlwaysLowTrust()
    {
        var assessment = CatalogClient.AssessChocolatey(new CatalogPackage("chocolatey", "Notepad++", "notepadplusplus", "8.8.5", "Chocolatey Community"));
        Assert.Equal(Levels.Low, assessment.Level);
        Assert.Contains(assessment.Checks, c => c.Label.ToString().Contains("PowerShell"));
    }
}
