using System.Text.Json.Nodes;
using BezpiecznyAktualizator.Core.History;
using BezpiecznyAktualizator.Core.Localization;
using BezpiecznyAktualizator.Core.Models;
using BezpiecznyAktualizator.Core.Policies;
using BezpiecznyAktualizator.Core.Risk;
using BezpiecznyAktualizator.Core.Scheduling;
using BezpiecznyAktualizator.Core.Security;
using BezpiecznyAktualizator.Core.Winget;

namespace BezpiecznyAktualizator.Tests;

public class NvdTests
{
    [Fact]
    public void EpssParsesScoresOnlyForValidCveIdsAndRanges()
    {
        const string json = """
            {"data":[
              {"cve":"CVE-2025-1234","epss":"0.12345","percentile":"0.98765"},
              {"cve":"not-a-cve","epss":"0.8","percentile":"0.9"},
              {"cve":"CVE-2025-1235","epss":"1.2","percentile":"0.5"},
              {"cve":"CVE-2025-1236","epss":"0.2","percentile":"invalid"}
            ]}
            """;
        var parsed = EpssClient.Parse(JsonNode.Parse(json)!);
        var score = Assert.Single(parsed);
        Assert.Equal("CVE-2025-1234", score.Id);
        Assert.Equal(0.12345, score.Score);
        Assert.Equal(0.98765, score.Percentile);
    }

    [Theory]
    [InlineData("https://github.com/owner/project", "owner/project")]
    [InlineData("https://github.com/owner/project.git", "owner/project")]
    [InlineData("https://github.com/owner/project/tree/main", null)]
    [InlineData("http://github.com/owner/project", null)]
    [InlineData("https://github.com.evil.example/owner/project", null)]
    [InlineData("https://github.com/owner/project?redirect=evil", null)]
    [InlineData("https://github.com/../project", null)]
    public void OsvUsesOnlyExactHttpsGitHubRepository(string homepage, string? expected) =>
        Assert.Equal(expected, OsvClient.GitHubRepository(homepage));

    [Fact]
    public void OsvParsesUniqueFindingsAndCveAliases()
    {
        const string json = """
            {"vulns":[
              {"id":"GHSA-1234-abcd-efgh","summary":"A vulnerability","aliases":["CVE-2025-1234"]},
              {"id":"GHSA-1234-abcd-efgh","summary":"duplicate","aliases":[]},
              {"id":"OSV-2025-1","details":"Details only"}
            ]}
            """;
        var parsed = OsvClient.Parse(JsonNode.Parse(json)!);
        Assert.Equal(2, parsed.Count);
        Assert.Equal("A vulnerability", parsed[0].Summary);
        Assert.Equal(["CVE-2025-1234"], parsed[0].Aliases);
        Assert.Equal("Details only", parsed[1].Summary);
    }

    [Theory]
    [InlineData("7-Zip 23.01 (x64)", "7-Zip")]
    [InlineData("Notepad++ (64-bit x64)", "Notepad++")]
    [InlineData("VLC media player", "VLC media player")]
    [InlineData("Python 3.12.4 (64-bit)", "Python")]
    [InlineData("PuTTY release 0.81 (64-bit)", "PuTTY release")]
    public void BaseNameStripsVersionsAndArchitecture(string name, string expected) =>
        Assert.Equal(expected, NvdClient.BaseName(name));

    [Theory]
    [InlineData("23.01", "23.01")]
    [InlineData("v2.26.1 (x64)", "2.26.1")]
    [InlineData("Unknown", "")]
    public void CpeVersionKeepsDigitsAndDots(string version, string expected) =>
        Assert.Equal(expected, NvdClient.CpeVersion(version));

    [Fact]
    public void KnownCpeUsesBuiltInMap()
    {
        Assert.Equal("7-zip:7-zip", NvdClient.KnownCpe("7-Zip 23.01 (x64)"));
        Assert.Equal("mozilla:firefox", NvdClient.KnownCpe("Mozilla Firefox (x64 pl)"));
        Assert.Null(NvdClient.KnownCpe("Zupełnie nieznany program"));
    }

    [Fact]
    public void PickCpePrefersExactProductAndRejectsAmbiguous()
    {
        string[] cpes =
        [
            "cpe:2.3:a:keepass:keepass:2.50:*:*:*:*:*:*:*",
            "cpe:2.3:a:keepass:keepass:2.51:*:*:*:*:*:*:*",
            "cpe:2.3:a:keepassxc:keepassxc:2.7:*:*:*:*:*:*:*",
            "cpe:2.3:a:other:keepass_plugin:1.0:*:*:*:*:*:*:*",
        ];
        Assert.Equal("keepass:keepass", NvdClient.PickCpe("KeePass", "Dominik Reichl", cpes));
        Assert.Null(NvdClient.PickCpe("Something Else", "", cpes));

        string[] ambiguous = ["cpe:2.3:a:alpha:tool:1:*:*:*:*:*:*:*", "cpe:2.3:a:beta:tool:1:*:*:*:*:*:*:*"];
        Assert.Null(NvdClient.PickCpe("Tool", "Gamma Inc.", ambiguous));
        Assert.Equal("beta:tool", NvdClient.PickCpe("Tool", "Beta Software", ambiguous));
        // Wpisy dotyczące systemów operacyjnych (o) i sprzętu (h) są pomijane.
        Assert.Null(NvdClient.PickCpe("Tool", "", ["cpe:2.3:o:alpha:tool:1:*:*:*:*:*:*:*"]));
    }

    private const string CvesJson = """
        {"vulnerabilities":[
          {"cve":{"id":"CVE-2024-0001","vulnStatus":"Analyzed","published":"2024-01-02T10:00:00.000",
            "descriptions":[{"lang":"es","value":"x"},{"lang":"en","value":"Buffer overflow"}],
            "metrics":{"cvssMetricV31":[{"type":"Secondary","cvssData":{"baseScore":5.0,"baseSeverity":"MEDIUM"}},
                                        {"type":"Primary","cvssData":{"baseScore":7.8,"baseSeverity":"HIGH"}}],
                       "cvssMetricV2":[{"type":"Primary","cvssData":{"baseScore":9.3},"baseSeverity":"HIGH"}]}}},
          {"cve":{"id":"CVE-2023-0002","vulnStatus":"Analyzed","published":"2023-05-01T00:00:00.000","cisaExploitAdd":"2023-06-01",
            "descriptions":[{"lang":"en","value":"Exploited RCE"}],
            "metrics":{"cvssMetricV2":[{"type":"Primary","cvssData":{"baseScore":6.8},"baseSeverity":"MEDIUM"}]}}},
          {"cve":{"id":"CVE-2022-0003","vulnStatus":"Rejected","descriptions":[]}},
          {"cve":{"id":"CVE-2022-0004","vulnStatus":"Awaiting Analysis","descriptions":[]}}
        ]}
        """;

    [Fact]
    public void ParseCvesOrdersByExploitationAndScore()
    {
        var items = NvdClient.ParseCves(JsonNode.Parse(CvesJson)!);
        Assert.Equal(["CVE-2023-0002", "CVE-2024-0001", "CVE-2022-0004"], items.Select(i => i.Id));
        Assert.True(items[0].Exploited);
        Assert.Equal(6.8, items[0].Score);
        Assert.Equal("MEDIUM", items[0].Severity);
        Assert.Equal(7.8, items[1].Score); // CVSS 3.1 przed 2.0, wpis Primary przed Secondary
        Assert.Equal("Buffer overflow", items[1].Description);
        Assert.Equal(0, items[2].Score);
        Assert.Equal("https://nvd.nist.gov/vuln/detail/CVE-2024-0001", items[1].Url);

        var report = new VulnerabilityReport { Cpe = "a:b", Version = "1", Items = items, CheckedAt = DateTimeOffset.UtcNow };
        Assert.True(report.Checked);
        Assert.True(report.IsUrgent);
        Assert.True(report.Exploited);
        Assert.Equal(7.8, report.MaxScore);
    }

    [Fact]
    public void ParseCvesSkipsConfigurationsForOtherPlatforms()
    {
        // CVE-MAC (jak CVE-2018-0701): Windows 3.0.0-4.31.55, macOS >= 2.0.0 - nie dotyczy BlueStacks 5.22 na Windows.
        const string json = """
            {"vulnerabilities":[
              {"cve":{"id":"CVE-MAC","descriptions":[],"configurations":[
                {"operator":"AND","nodes":[
                  {"operator":"OR","cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:bluestacks:bluestacks:*:*:*:*:*:*:*:*","versionStartIncluding":"3.0.0","versionEndIncluding":"4.31.55"}]},
                  {"operator":"OR","cpeMatch":[{"vulnerable":false,"criteria":"cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*"}]}]},
                {"operator":"AND","nodes":[
                  {"operator":"OR","cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:bluestacks:bluestacks:*:*:*:*:*:*:*:*","versionStartIncluding":"2.0.0"}]},
                  {"operator":"OR","cpeMatch":[{"vulnerable":false,"criteria":"cpe:2.3:o:apple:macos:-:*:*:*:*:*:*:*"}]}]}]}},
              {"cve":{"id":"CVE-WIN","descriptions":[],"configurations":[
                {"operator":"AND","nodes":[
                  {"operator":"OR","cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:bluestacks:bluestacks:*:*:*:*:*:*:*:*","versionEndExcluding":"5.23"}]},
                  {"operator":"OR","cpeMatch":[{"vulnerable":false,"criteria":"cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*"}]}]}]}},
              {"cve":{"id":"CVE-ANY","descriptions":[],"configurations":[
                {"nodes":[{"operator":"OR","cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:bluestacks:bluestacks:5.22.168.1001:*:*:*:*:*:*:*"}]}]}]}},
              {"cve":{"id":"CVE-NOCONF","descriptions":[]}},
              {"cve":{"id":"CVE-PLATFORM","descriptions":[],"configurations":[
                {"operator":"AND","nodes":[
                  {"operator":"OR","cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:vercel:next.js:12.2.3:*:*:*:*:node.js:*:*"}]},
                  {"operator":"OR","cpeMatch":[{"vulnerable":false,"criteria":"cpe:2.3:a:bluestacks:bluestacks:*:*:*:*:*:*:*:*","versionStartIncluding":"1.0"}]}]}]}},
              {"cve":{"id":"CVE-ANDROID","descriptions":[],"configurations":[
                {"nodes":[{"operator":"OR","cpeMatch":[
                  {"vulnerable":true,"criteria":"cpe:2.3:a:bluestacks:bluestacks:*:*:*:*:*:android:*:*","versionEndExcluding":"6.0"},
                  {"vulnerable":true,"criteria":"cpe:2.3:a:bluestacks:bluestacks:*:*:*:*:*:*:*:*","versionEndExcluding":"5.0"}]}]}]}}
            ]}
            """;
        var items = NvdClient.ParseCves(JsonNode.Parse(json)!, ["bluestacks:bluestacks"], "5.22.168.1001");
        Assert.Equal(["CVE-ANY", "CVE-NOCONF", "CVE-WIN"], items.Select(i => i.Id).Order());
        Assert.Equal(6, NvdClient.ParseCves(JsonNode.Parse(json)!).Count);

        Assert.True(NvdClient.CompareVersions("26.0.0.1", "26.001.20000") < 0);
        Assert.Equal(0, NvdClient.CompareVersions("4.31", "4.31.0"));
        Assert.True(NvdClient.CompareVersions("10.2", "9.9") > 0);
    }

    [Theory]
    [InlineData("Python 3.14.3", "3.14-64", "3.14.3")]
    [InlineData("IntelliJ IDEA 2026.2.3", "262.10968.63", "2026.2.3")]
    [InlineData("7-Zip 26.05 (x64)", "26.05", "26.05")]
    [InlineData("Microsoft .NET Core Runtime - 3.1.32 (x64)", "3.1.32.31915", "3.1.32.31915")]
    [InlineData("Mozilla Firefox (x64 pl)", "158.0", "158.0")]
    [InlineData("Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.40.33810", "14.40.33810.0", "14.40.33810.0")]
    public void ProductVersionPrefersMoreSpecificNameVersion(string name, string version, string expected) =>
        Assert.Equal(expected, NvdClient.ProductVersion(name, version));

    [Fact]
    public async Task MsixPackagesAreNotChecked()
    {
        var report = await NvdClient.CheckAsync(new Software { Name = "Adobe Acrobat Reader", Version = "26.0.0.1", Origin = "winget (MSIX/Store)" });
        Assert.NotNull(report.Error);
        Assert.False(report.Checked);
    }

    [Fact]
    public void SoftwareRiskStateAndDisplay()
    {
        var s = new Software { Name = "x", Version = "1" };
        Assert.Equal("", s.RiskState);
        s.Vulnerabilities = new VulnerabilityReport { Cpe = "a:b", Items = [new CveItem("CVE-1", 9.8, "CRITICAL", "", null, true)] };
        Assert.True(s.IsUrgent);
        Assert.Equal("urgent", s.RiskState);
        Assert.Contains("9.8", s.RiskDisplay.Replace(',', '.'));
        var eol = new Software { Name = "y", Lifecycle = new LifecycleInfo { State = LifecycleState.Eol } };
        Assert.True(eol.IsUnsupported);
        Assert.Equal("unsupported", eol.RiskState);
        Assert.Equal("", new Software { Name = "z", Lifecycle = new LifecycleInfo { State = LifecycleState.Supported } }.RiskState);
    }
}

public class LifecycleTests
{
    private const string ProductsJson = """
        {"result":[
          {"name":"firefox","label":"Mozilla Firefox","aliases":[],"category":"app",
           "identifiers":[{"type":"cpe","id":"cpe:2.3:a:mozilla:firefox"}],
           "links":{"html":"https://endoflife.date/firefox"},
           "releases":[{"name":"140","label":"140","isEol":false,"eolFrom":null,"latest":{"name":"140.1","date":"2025-07-01"}},
                       {"name":"128","label":"128 (ESR)","isEol":true,"eolFrom":"2025-09-16","latest":{"name":"128.14"}}]},
          {"name":"python","label":"Python","aliases":[],"category":"lang","identifiers":[],
           "releases":[{"name":"3.13","label":"3.13","isEol":false,"eolFrom":"2029-10-31","latest":{"name":"3.13.5"}},
                       {"name":"3.8","label":"3.8","isEol":true,"eolFrom":"2024-10-07","latest":{"name":"3.8.20"}}]},
          {"name":"dotnet","label":".NET","aliases":[],"category":"framework","identifiers":[],
           "releases":[{"name":"8","label":".NET 8","isEol":false,"eolFrom":"2026-11-10"},
                       {"name":"6","label":".NET 6","isEol":true,"eolFrom":"2024-11-12"}]},
          {"name":"deadapp","label":"Dead App","aliases":["deadapplication"],"category":"app","identifiers":[],
           "releases":[{"name":"2","label":"2","isEol":true}]},
          {"name":"windows","label":"Windows","aliases":[],"category":"os","identifiers":[],
           "releases":[{"name":"10","label":"10","isEol":false}]},
          {"name":"go","label":"Go","aliases":[],"category":"lang","identifiers":[],"releases":[]}
        ]}
        """;

    private static readonly List<EolProduct> Products = LifecycleClient.ParseProducts(JsonNode.Parse(ProductsJson)!);
    private static readonly DateOnly Today = new(2025, 12, 1);

    [Fact]
    public void ParseProductsReadsCpeAndReleases()
    {
        var firefox = Products.Single(p => p.Name == "firefox");
        Assert.Equal("mozilla:firefox", firefox.Cpe);
        Assert.Equal(2, firefox.Releases.Count);
        Assert.Equal(new DateOnly(2025, 9, 16), firefox.Releases[1].EolFrom);
        Assert.Equal("https://endoflife.date/python", Products.Single(p => p.Name == "python").Link);
    }

    [Theory]
    [InlineData("Mozilla Firefox (x64 pl)", "Mozilla", "firefox")]
    [InlineData("Python 3.8.10 (64-bit)", "Python Software Foundation", "python")]
    [InlineData("Microsoft .NET Runtime - 6.0.36 (x64)", "Microsoft Corporation", "dotnet")]
    [InlineData("Dead App 2.1", "", "deadapp")]
    [InlineData("Windows 10 Update Assistant", "Microsoft", null)] // kategoria os jest pomijana
    [InlineData("Python Launcher Tools", "", null)]                // po nazwie produktu musi być wersja lub dopisek
    [InlineData("Google Chrome", "Google LLC", null)]
    [InlineData("Go Programming Language", "", null)]             // krótkie etykiety (< 3 znaki) są ignorowane
    public void MatchProductByLabelAndAliases(string name, string publisher, string? expected) =>
        Assert.Equal(expected, LifecycleClient.MatchProduct(new Software { Name = name, Publisher = publisher }, Products)?.Name);

    [Fact]
    public void MatchReleaseUsesLongestNumericPrefix()
    {
        var python = Products.Single(p => p.Name == "python");
        Assert.Equal("3.8", LifecycleClient.MatchRelease(python, "Python 3.8.10", "3.8.10150.0")?.Name);
        Assert.Equal("3.13", LifecycleClient.MatchRelease(python, "Python", "3.13.5")?.Name);
        Assert.Null(LifecycleClient.MatchRelease(python, "Python", "3.1.4"));
        var dotnet = Products.Single(p => p.Name == "dotnet");
        Assert.Equal("6", LifecycleClient.MatchRelease(dotnet, ".NET", "6.0.36")?.Name);
    }

    [Fact]
    public void EvaluateDetectsEolSupportedAndAbandoned()
    {
        var python = Products.Single(p => p.Name == "python");
        var old = LifecycleClient.Evaluate(python, python.Releases[1], Today);
        Assert.Equal(LifecycleState.Eol, old.State);
        Assert.Contains("3.13", old.Reason.ToString());
        Assert.Equal(LifecycleState.Supported, LifecycleClient.Evaluate(python, python.Releases[0], Today).State);

        // Data końca wsparcia w przeszłości oznacza EOL, nawet gdy isEol jeszcze nie ustawiono.
        var firefox = Products.Single(p => p.Name == "firefox");
        var esr = firefox.Releases[1] with { IsEol = false };
        Assert.Equal(LifecycleState.Eol, LifecycleClient.Evaluate(firefox, esr, Today).State);
        // Krótko po wydaniu następcy to zwykła zaległa aktualizacja, a nie brak wsparcia.
        var recent = LifecycleClient.Evaluate(firefox, firefox.Releases[1], new DateOnly(2025, 10, 1));
        Assert.Equal(LifecycleState.Supported, recent.State);
        Assert.Contains("140", recent.Reason.ToString());

        var dead = Products.Single(p => p.Name == "deadapp");
        Assert.Equal(LifecycleState.Abandoned, LifecycleClient.Evaluate(dead, dead.Releases[0], Today).State);

        // Wsparcie rozszerzone (isMaintained) - np. Java 8 po końcu wsparcia standardowego.
        var java = LifecycleClient.ParseProducts(JsonNode.Parse("""
            {"result":[{"name":"oracle-jdk","label":"Oracle JDK","category":"lang","releases":[
              {"name":"8","label":"8 (LTS)","isEol":true,"eolFrom":"2022-03-31","isMaintained":true,"eoesFrom":"2030-12-31"}]}]}
            """)!)[0];
        var extended = LifecycleClient.Evaluate(java, java.Releases[0], Today);
        Assert.Equal(LifecycleState.Supported, extended.State);
        Assert.Equal(new DateOnly(2030, 12, 31), extended.EolFrom);
        Assert.Equal(LifecycleState.Abandoned,
            LifecycleClient.Evaluate(java, java.Releases[0] with { IsMaintained = false }, Today).State);
    }

    [Fact]
    public void ActivityMarksArchivedAndStaleProjectsAsAbandoned()
    {
        Assert.Equal(LifecycleState.Abandoned, LifecycleClient.FromActivity("GitHub", null, true, "", Today)!.State);
        Assert.Equal(LifecycleState.Abandoned, LifecycleClient.FromActivity("winget", new DateOnly(2020, 1, 1), false, "", Today)!.State);
        Assert.Equal(LifecycleState.Supported, LifecycleClient.FromActivity("GitHub", new DateOnly(2025, 6, 1), false, "", Today)!.State);
        Assert.Null(LifecycleClient.FromActivity("winget", null, false, "", Today));
    }

    [Fact]
    public void WingetReleaseDateIsReadFromShowOutput()
    {
        var info = WingetClient.ParseShow(WingetParsingTests.ShowOutput + "\nInstaller:\n  Installer Type: nullsoft\n  Release Date: 2024-03-05\n");
        Assert.Equal(new DateOnly(2024, 3, 5), LifecycleClient.WingetReleaseDate(info));
        Assert.Null(LifecycleClient.WingetReleaseDate(new Dictionary<string, string> { ["Version"] = "1.0" }));
    }

    [Fact]
    public void GitHubRepoFromVendorUrls()
    {
        Assert.Equal("notepad-plus-plus/notepad-plus-plus",
            LifecycleClient.GitHubRepo(new Software { Name = "x", UrlInfo = "https://github.com/notepad-plus-plus/notepad-plus-plus.git" }));
        Assert.Null(LifecycleClient.GitHubRepo(new Software { Name = "x", UrlInfo = "https://example.com" }));
    }
}

public class DefenderTests
{
    [Fact]
    public void CleanScan()
    {
        var r = DefenderScanner.Parse(0, "Scan starting...\r\nScan finished.\r\nScanning C:\\x.exe found no threats.\r\n");
        Assert.Equal(DefenderVerdict.Clean, r.Verdict);
    }

    [Fact]
    public void ThreatDetected()
    {
        const string output = """
            Scan starting...
            Scan finished.
            Scanning C:\x.exe found 1 threats.

            <===========================LIST OF DETECTED THREATS==========================>
            ----------------------------- Threat information ------------------------------
            Threat                  : Virus:DOS/EICAR_Test_File
            Resources               : 1 total
                file                : C:\x.exe
            """;
        var r = DefenderScanner.Parse(2, output);
        Assert.Equal(DefenderVerdict.Threat, r.Verdict);
        Assert.Equal(["Virus:DOS/EICAR_Test_File"], r.Threats);
        Assert.Equal(CheckStatus.Fail, InstallerVerifier.DefenderCheck(r).Status);
    }

    [Fact]
    public void FailureWhenDefenderIsDisabled()
    {
        // Gdy aktywny jest inny antywirus, MpCmdRun kończy się kodem 2 - tym samym co przy wykryciu zagrożenia.
        var r = DefenderScanner.Parse(2, "CmdTool: Failed with hr = 0x80004005. Check C:\\...\\MpCmdRun.log for more information\r\n");
        Assert.Equal(DefenderVerdict.Unavailable, r.Verdict);
        Assert.Contains("0x80004005", r.Detail);
        Assert.Equal(CheckStatus.Warn, InstallerVerifier.DefenderCheck(r).Status);
        Assert.Equal(CheckStatus.Ok, InstallerVerifier.DefenderCheck(new DefenderScan(DefenderVerdict.Clean, [], "")).Status);
    }

    [Fact]
    public void UnavailableScanIsNotAPass()
    {
        var clean = new InstallerVerification { Completed = true };
        Assert.True(clean.Passed);
        Assert.False(clean.PassedWithoutScan);

        var noScan = new InstallerVerification { Completed = true, DefenderUnavailable = true };
        Assert.False(noScan.Passed);
        Assert.True(noScan.PassedWithoutScan);

        var threat = new InstallerVerification { Completed = true };
        threat.Checks.Add(InstallerVerifier.DefenderCheck(new DefenderScan(DefenderVerdict.Threat, ["EICAR"], "")));
        Assert.False(threat.Passed);
        Assert.False(threat.PassedWithoutScan);
    }

    [Fact]
    public void ScheduledInstallWithoutScanRequiresExplicitConsent()
    {
        using var cleanArtifact = TestVerifiedInstaller();
        using var noScanArtifact = TestVerifiedInstaller();
        using var blockedArtifact = TestVerifiedInstaller();
        using var storeArtifact = TestVerifiedInstaller();
        var noScan = new InstallerVerification { Completed = true, DefenderUnavailable = true, VerifiedInstaller = noScanArtifact };
        var blockedNoScan = new InstallerVerification
        {
            Completed = true, DefenderUnavailable = true, VerifiedInstaller = blockedArtifact,
        };
        blockedNoScan.Checks.Add(new Check(L.Txt("x"), CheckStatus.Fail, null));
        var incomplete = new InstallerVerification { DefenderUnavailable = true };

        Assert.False(SilentUpdatePolicy.MayInstall(noScan, new ScheduleOptions()));
        Assert.True(SilentUpdatePolicy.MayInstall(noScan, new ScheduleOptions { AllowWithoutDefenderScan = true }));
        Assert.False(SilentUpdatePolicy.MayInstall(blockedNoScan, new ScheduleOptions { AllowWithoutDefenderScan = true }));
        Assert.False(SilentUpdatePolicy.MayInstall(incomplete, new ScheduleOptions { AllowWithoutDefenderScan = true }));
        Assert.True(SilentUpdatePolicy.MayInstall(
            new InstallerVerification { Completed = true, VerifiedInstaller = cleanArtifact }, new ScheduleOptions()));
        Assert.False(SilentUpdatePolicy.MayInstall(
            new InstallerVerification { Completed = true, StoreManaged = true, VerifiedInstaller = storeArtifact },
            new ScheduleOptions { AllowWithoutDefenderScan = true }));
        Assert.False(SilentUpdatePolicy.IsCandidate(new Software
        {
            WingetId = "test.package", WingetSource = "msstore", Version = "1.0", AvailableVersion = "1.1",
            WingetDetected = true,
        }, new UpdatePolicies(), DateTimeOffset.UtcNow));
    }

    private static VerifiedInstaller TestVerifiedInstaller()
    {
        const string yaml = """
            PackageIdentifier: test.package
            PackageVersion: 1.0
            Installers:
              - InstallerUrl: https://example.org/setup.exe
                InstallerSha256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
            """;
        var directory = Path.Combine(Path.GetTempPath(), "ba-policy-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "manifest.yaml");
        File.WriteAllText(path, yaml);
        var manifestSha256 = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(path)));
        return new VerifiedInstaller(directory, path, "test.package", "1.0",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", manifestSha256);
    }
}

public class RollbackTests
{
    [Fact]
    public void CorruptHistoryIsReportedAndNeverOverwritten()
    {
        var original = UpdateHistory.FilePath;
        var path = Path.Combine(Path.GetTempPath(), $"ba-history-corrupt-{Guid.NewGuid():N}.json");
        const string corrupt = "{ not valid json";
        UpdateHistory.FilePath = path;
        try
        {
            File.WriteAllText(path, corrupt);
            Assert.Throws<InvalidDataException>(() => UpdateHistory.Load());
            Assert.Throws<InvalidDataException>(() => UpdateHistory.Add(new UpdateRecord { Name = "Do not replace" }));
            Assert.Equal(corrupt, File.ReadAllText(path));
        }
        finally
        {
            UpdateHistory.FilePath = original;
            File.Delete(path);
        }
    }

    [Fact]
    public async Task ConcurrentHistoryWritesAreSerialized()
    {
        var original = UpdateHistory.FilePath;
        var directory = Path.Combine(Path.GetTempPath(), $"ba-history-concurrent-{Guid.NewGuid():N}");
        UpdateHistory.FilePath = Path.Combine(directory, "history.json");
        try
        {
            await Task.WhenAll(Enumerable.Range(0, 20).Select(index => Task.Run(() =>
                UpdateHistory.Add(new UpdateRecord { Name = $"App {index}", WingetId = $"app.{index}" }))));
            Assert.Equal(20, UpdateHistory.Load().Count);
        }
        finally
        {
            UpdateHistory.FilePath = original;
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void ParseVersionsFromWingetShow()
    {
        const string output = "   - \r\nFound 7-Zip [7zip.7zip]\r\nVersion\r\n-------\r\n24.09\r\n24.08\r\n23.01\r\n";
        Assert.Equal(["24.09", "24.08", "23.01"], WingetClient.ParseVersions(output));
        Assert.Empty(WingetClient.ParseVersions("No package found matching input criteria."));
    }

    [Theory]
    [InlineData("23.01", "23.01")]
    [InlineData("23.1.0", "23.01")]
    [InlineData("v24.08", "24.08")]
    [InlineData("22.00", null)]
    public void FindVersionIgnoresTrailingAndLeadingZeros(string wanted, string? expected) =>
        Assert.Equal(expected, UpdateHistory.FindVersion(["24.09", "24.08", "23.01"], wanted));

    [Fact]
    public void HistoryRoundtripAndRollback()
    {
        var original = UpdateHistory.FilePath;
        var path = Path.Combine(Path.GetTempPath(), $"ba-history-{Guid.NewGuid():N}.json");
        UpdateHistory.FilePath = path;
        try
        {
            Assert.Empty(UpdateHistory.Load());
            var first = new UpdateRecord { Name = "7-Zip", WingetId = "7zip.7zip", FromVersion = "23.01", ToVersion = "24.08",
                                           Time = DateTimeOffset.UtcNow.AddDays(-2) };
            var second = new UpdateRecord { Name = "7-Zip", WingetId = "7zip.7zip", FromVersion = "24.08", ToVersion = "24.09" };
            UpdateHistory.Add(first);
            UpdateHistory.Add(second);
            UpdateHistory.Add(new UpdateRecord { Name = "No id", FromVersion = "1", ToVersion = "2" });

            var loaded = UpdateHistory.Load();
            Assert.Equal(3, loaded.Count);
            Assert.False(loaded.Single(r => r.Name == "No id").CanRollback);
            Assert.Equal(second.Id, UpdateHistory.LastRollbackable(loaded, "7ZIP.7zip")!.Id);
            Assert.Contains("\"Upgrade\"", File.ReadAllText(path));

            UpdateHistory.MarkRolledBack(second.Id);
            loaded = UpdateHistory.Load();
            Assert.True(loaded.Single(r => r.Id == second.Id).RolledBack);
            Assert.Equal(first.Id, UpdateHistory.LastRollbackable(loaded, "7zip.7zip")!.Id);
            Assert.False(new UpdateRecord { Kind = UpdateKind.Rollback, WingetId = "a", FromVersion = "2", ToVersion = "1" }.CanRollback);
        }
        finally
        {
            UpdateHistory.FilePath = original;
            File.Delete(path);
        }
    }
}
