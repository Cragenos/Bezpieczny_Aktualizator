using System.Runtime.InteropServices;
using System.Text.Json;
using BezpiecznyAktualizator.Core.Localization;
using BezpiecznyAktualizator.Core.Risk;
using BezpiecznyAktualizator.Core.Updates;

namespace BezpiecznyAktualizator.Tests;

public class WindowsUpdateTests
{
    private static readonly Guid FirstId = Guid.Parse("11111111-2222-3333-4444-555555555555");
    private static readonly Guid SecondId = Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");

    [Theory]
    [InlineData(0, StandaloneUpdateStatus.Succeeded)]
    [InlineData(3010, StandaloneUpdateStatus.RestartRequired)]
    [InlineData(2359301, StandaloneUpdateStatus.RestartRequired)]
    [InlineData(2359302, StandaloneUpdateStatus.AlreadyInstalled)]
    [InlineData(-2145124329, StandaloneUpdateStatus.NotApplicable)]
    [InlineData(5, StandaloneUpdateStatus.Failed)]
    public void StandaloneInstallerExitCodesAreClassified(int code, StandaloneUpdateStatus expected) =>
        Assert.Equal(expected, WindowsUpdateStandalone.ClassifyExitCode(code));

    [Fact]
    public void SelectionRoundTripsAndRejectsInvalidOrDuplicateIdentities()
    {
        WindowsUpdateIdentity[] selection = [new(FirstId, 1), new(SecondId, int.MaxValue)];
        Assert.Equal(selection, WindowsUpdateAgent.ParseSelection(WindowsUpdateAgent.SerializeSelection(selection)));
        Assert.Throws<WindowsUpdateException>(() => WindowsUpdateAgent.ParseSelection(""));
        Assert.Throws<WindowsUpdateException>(() => WindowsUpdateAgent.ParseSelection($"{FirstId:D}:-1"));
        Assert.Throws<WindowsUpdateException>(() => WindowsUpdateAgent.ParseSelection($"{FirstId:D}:1,malicious"));
        Assert.Throws<WindowsUpdateException>(() => WindowsUpdateAgent.SerializeSelection([new(FirstId, 1), new(FirstId, 1)]));
        Assert.Throws<WindowsUpdateException>(() => WindowsUpdateAgent.SerializeSelection([new(Guid.Empty, 1)]));
        Assert.Throws<WindowsUpdateException>(() => WindowsUpdateAgent.SerializeSelection(
            Enumerable.Range(0, WindowsUpdateAgent.MaxSelection + 1).Select(i => new WindowsUpdateIdentity(FirstId, i)).ToList()));
        Assert.Throws<WindowsUpdateException>(() => WindowsUpdateAgent.Execute((WindowsUpdateAction)99, [new(FirstId, 1)]));
    }

    [Fact]
    public void MapsKbAndBundledCvesAndReportsMissingCveMetadata()
    {
        var update = new FakeUpdate(FirstId, 7)
        {
            Title = "Windows update", Cves = new(["CVE-2025-1111"]), Kb = new(["12345", "12345"]),
        };
        update.BundledUpdates.Add(new FakeUpdate(SecondId, 1)
        {
            Cves = new(["CVE-2025-2222", "cve-2025-1111"]),
        });
        var item = WindowsUpdateAgent.ToItem((object)update);
        Assert.Equal(new WindowsUpdateIdentity(FirstId, 7), item.Identity);
        Assert.Equal(["12345"], item.KbIds);
        Assert.Equal(["CVE-2025-1111", "CVE-2025-2222"], item.CveIds);
        Assert.EndsWith("q=KB12345", item.CatalogUrl);
        Assert.Equal("", item.CveError);

        update.BundledUpdates.Item[0].FailCves = true;
        item = WindowsUpdateAgent.ToItem((object)update);
        Assert.Contains("CVE metadata unavailable", item.CveError);
        Assert.Equal(["CVE-2025-1111"], item.CveIds);

        update.Cves = new();
        item = WindowsUpdateAgent.ToItem((object)update);
        Assert.Empty(item.CveIds);
        Assert.Equal(L.T("Brak danych CVE"), item.CveText);
    }

    [Fact]
    public void DownloadsAndInstallsOnlyRequestedApplicableRevisions()
    {
        var update = new FakeUpdate(FirstId, 1) { EulaAccepted = false, EulaText = "License" };
        var session = new FakeSession(update);
        var id = new WindowsUpdateIdentity(FirstId, 1);
        var stale = new WindowsUpdateIdentity(FirstId, 2);

        var beforeDownload = WindowsUpdateAgent.ExecuteCore(WindowsUpdateAction.Install, [id], session, NewCollection);
        Assert.False(beforeDownload.Succeeded);
        Assert.Equal(0, session.InstallCalls);
        Assert.False(update.EulaAccepted);

        var downloaded = WindowsUpdateAgent.ExecuteCore(WindowsUpdateAction.Download, [id, stale], session, NewCollection);
        Assert.True(downloaded.Outcomes[0].Succeeded);
        Assert.False(downloaded.Outcomes[1].Succeeded);
        Assert.False(downloaded.Succeeded);
        Assert.True(update.IsDownloaded);
        Assert.True(update.EulaAccepted);
        Assert.Equal(1, session.DownloadCalls);
        Assert.Equal("IsInstalled=0 and Type='Software' and IsHidden=0", session.Searcher.LastCriteria);
        Assert.True(session.Searcher.Online);

        update.RebootRequired = true;
        var installed = WindowsUpdateAgent.ExecuteCore(WindowsUpdateAction.Install, [id], session, NewCollection);
        Assert.True(installed.Succeeded);
        Assert.True(installed.RebootRequired);
        Assert.Equal(1, session.InstallCalls);
        Assert.Equal(1, session.DownloadCalls);
    }

    [Fact]
    public void MissingLicenseAndUnconfirmedDownloadAreExplicitFailures()
    {
        var noLicense = new FakeUpdate(FirstId, 1) { EulaAccepted = false, EulaText = "" };
        var failedDownload = new FakeUpdate(SecondId, 1) { ConfirmDownload = false };
        var session = new FakeSession(noLicense, failedDownload);
        var report = WindowsUpdateAgent.ExecuteCore(WindowsUpdateAction.Download,
            [new(FirstId, 1), new(SecondId, 1)], session, NewCollection);
        Assert.False(report.Succeeded);
        Assert.All(report.Outcomes, outcome => Assert.False(outcome.Succeeded));
        Assert.False(noLicense.EulaAccepted);
        Assert.Equal(L.T("Nie można odczytać wymaganych warunków licencji. Aktualizacja nie zostanie wykonana."), report.Outcomes[0].Message);
        Assert.Contains(L.T("Windows Update nie potwierdził pobrania pakietu."), report.Outcomes[1].Message);
        Assert.Equal(1, session.DownloadCalls);
    }

    [Fact]
    public void SearchWarningsAreIncludedInOperationResults()
    {
        var update = new FakeUpdate(FirstId, 1);
        var session = new FakeSession(update);
        session.Searcher.Result.ResultCode = 3;
        session.Searcher.Result.Warnings.Add(new FakeWarning { Message = "Partial results", HResult = 5 });
        var report = WindowsUpdateAgent.ExecuteCore(WindowsUpdateAction.Download, [new(FirstId, 1)], session, NewCollection);
        Assert.Equal(2, report.Warnings.Count);
        Assert.Contains("Partial results (0x00000005)", report.Warnings);
        Assert.True(report.Succeeded);
    }

    [Fact]
    public void OfflineScanUsesTheProvidedCatalogAndAlwaysRemovesItsTemporaryService()
    {
        var update = new FakeUpdate(FirstId, 3) { Kb = new(["12345"]) };
        var session = new FakeSession(update);
        var manager = new FakeServiceManager();
        var result = WindowsUpdateAgent.SearchOfflineCore("C:\\scan\\wsusscn2.cab", manager, session);

        Assert.False(session.Searcher.Online);
        Assert.Equal(3, session.Searcher.ServerSelection);
        Assert.Equal(manager.Service.ServiceID, session.Searcher.ServiceID);
        Assert.Equal("IsInstalled=0", session.Searcher.LastCriteria);
        Assert.True(result.Updates.Single().IsOfflineScan);
        Assert.Equal(1, manager.RemoveCalls);
        Assert.Equal(manager.Service.ServiceID, manager.RemovedServiceId);
    }

    [Fact]
    public void OfflineScanRemovesItsTemporaryServiceWhenSearchFails()
    {
        var session = new FakeSession(new FakeUpdate(FirstId, 3));
        session.Searcher.Result.ResultCode = 4;
        var manager = new FakeServiceManager();

        Assert.Throws<WindowsUpdateException>(() =>
            WindowsUpdateAgent.SearchOfflineCore("C:\\scan\\wsusscn2.cab", manager, session));
        Assert.Equal(1, manager.RemoveCalls);
        Assert.Equal(manager.Service.ServiceID, manager.RemovedServiceId);
    }

    [Fact]
    public void MsrcCachePreservesReleaseDateAndKbMappings()
    {
        var cached = new MsrcWindowsUpdateClient.MsrcReleaseCache
        {
            FetchedAtUtc = DateTimeOffset.Parse("2026-05-01T12:00:00Z"),
            CvesByKb = new Dictionary<string, List<string>>
            {
                ["12345"] = ["CVE-2025-1111", "CVE-2025-2222"],
            },
        };
        var json = JsonSerializer.Serialize(cached, RiskHttp.JsonOptions);
        var restored = JsonSerializer.Deserialize<MsrcWindowsUpdateClient.MsrcReleaseCache>(json, RiskHttp.JsonOptions);
        Assert.NotNull(restored);
        Assert.Equal(cached.FetchedAtUtc, restored.FetchedAtUtc);
        Assert.Equal(cached.CvesByKb["12345"], restored.CvesByKb["12345"]);
    }

    [Fact]
    public void MsrcCorrelatesCvesOnlyThroughExactKbRemediationIds()
    {
        const string response = """
            {
              "Vulnerability": [
                {
                  "CVE": "CVE-2025-1111",
                  "Remediations": [
                    { "Description": { "Value": "5123456" } },
                    { "Description": { "Value": "KB5123457" } }
                  ]
                },
                {
                  "CVE": "CVE-2025-2222",
                  "Remediations": [
                    { "URL": "https://support.microsoft.com/help/5123456" }
                  ]
                },
                {
                  "CVE": "not-a-cve",
                  "Remediations": [
                    { "Description": { "Value": "5123456" } }
                  ]
                }
              ]
            }
            """;

        var map = MsrcWindowsUpdateClient.ParseReleaseMap(response);

        Assert.Equal(["CVE-2025-1111", "CVE-2025-2222"], map["5123456"]);
        Assert.Equal(["CVE-2025-1111"], map["5123457"]);
        Assert.Empty(MsrcWindowsUpdateClient.FindKbIds("release 2025-01", "https://example.test/no-kb"));
        Assert.Equal("12345", MsrcWindowsUpdateClient.NormalizeKb("KB12345"));
        Assert.Throws<RiskException>(() => MsrcWindowsUpdateClient.ParseReleaseMap("{}"));
    }

    private static object NewCollection() => new FakeCollection<FakeUpdate>();

    public sealed class FakeCollection<T>
    {
        public FakeCollection(IEnumerable<T>? values = null) => Item = values?.ToList() ?? [];
        public List<T> Item { get; }
        public int Count => Item.Count;
        public int Add(T value) { Item.Add(value); return Item.Count - 1; }
    }

    public sealed class FakeIdentity(Guid id, int revision)
    {
        public string UpdateID { get; } = id.ToString("D");
        public int RevisionNumber { get; } = revision;
    }

    public sealed class FakeUpdate(Guid id, int revision)
    {
        public FakeIdentity Identity { get; } = new(id, revision);
        public string Title { get; set; } = "Update";
        public string Description { get; set; } = "Description";
        public string SupportUrl { get; set; } = "https://support.microsoft.com/";
        public string MsrcSeverity { get; set; } = "Critical";
        public string EulaText { get; set; } = "";
        public bool EulaAccepted { get; set; } = true;
        public bool IsDownloaded { get; set; }
        public bool IsMandatory { get; set; }
        public long MaxDownloadSize { get; set; } = 1048576;
        public DateTime LastDeploymentChangeTime { get; set; } = new(2026, 10, 13, 0, 0, 0, DateTimeKind.Utc);
        public FakeCollection<string> Kb { get; set; } = new();
        public FakeCollection<string> KBArticleIDs => Kb;
        public FakeCollection<string> Cves { get; set; } = new();
        public bool FailCves { get; set; }
        public FakeCollection<string> CveIDs => FailCves ? throw new COMException("CVE metadata unavailable") : Cves;
        public FakeCollection<FakeUpdate> BundledUpdates { get; } = new();
        public bool ConfirmDownload { get; set; } = true;
        public bool RebootRequired { get; set; }
        public void AcceptEula() => EulaAccepted = true;
    }

    public sealed class FakeWarning
    {
        public string Message { get; set; } = "";
        public int HResult { get; set; }
    }

    public sealed class FakeSearchResult(IEnumerable<FakeUpdate> updates)
    {
        public int ResultCode { get; set; } = 2;
        public FakeCollection<FakeUpdate> Updates { get; } = new(updates);
        public FakeCollection<FakeWarning> Warnings { get; } = new();
    }

    public sealed class FakeSearcher(FakeSearchResult result)
    {
        public FakeSearchResult Result { get; } = result;
        public bool Online { get; set; }
        public int ServerSelection { get; set; }
        public string ServiceID { get; set; } = "";
        public string LastCriteria { get; private set; } = "";
        public FakeSearchResult Search(string criteria) { LastCriteria = criteria; return Result; }
    }

    public sealed class FakeResult(bool reboot = false)
    {
        public int ResultCode { get; set; } = 2;
        public int HResult { get; set; }
        public bool RebootRequired { get; set; } = reboot;
    }

    public sealed class FakeOperationResult(IEnumerable<FakeResult> results)
    {
        private readonly List<FakeResult> _results = results.ToList();
        public bool RebootRequired => _results.Any(r => r.RebootRequired);
        public FakeResult GetUpdateResult(int index) => _results[index];
    }

    public sealed class FakeDownloader(FakeSession session)
    {
        public FakeCollection<FakeUpdate> Updates { get; set; } = new();
        public FakeOperationResult Download()
        {
            session.DownloadCalls++;
            foreach (var update in Updates.Item) update.IsDownloaded = update.ConfirmDownload;
            return new FakeOperationResult(Updates.Item.Select(_ => new FakeResult()));
        }
    }

    public sealed class FakeInstaller(FakeSession session)
    {
        public FakeCollection<FakeUpdate> Updates { get; set; } = new();
        public FakeOperationResult Install()
        {
            session.InstallCalls++;
            return new FakeOperationResult(Updates.Item.Select(u => new FakeResult(u.RebootRequired)));
        }
    }

    public sealed class FakeSession(params FakeUpdate[] updates)
    {
        public FakeSearcher Searcher { get; } = new(new FakeSearchResult(updates));
        public int DownloadCalls { get; set; }
        public int InstallCalls { get; set; }
        public FakeSearcher CreateUpdateSearcher() => Searcher;
        public FakeDownloader CreateUpdateDownloader() => new(this);
        public FakeInstaller CreateUpdateInstaller() => new(this);
    }

    public sealed class FakeScanService(string id)
    {
        public string ServiceID { get; } = id;
    }

    public sealed class FakeServiceManager
    {
        public FakeScanService Service { get; } = new(Guid.NewGuid().ToString("D"));
        public int RemoveCalls { get; private set; }
        public string RemovedServiceId { get; private set; } = "";
        public FakeScanService AddScanPackageService(string name, string cabinetPath, int flags)
        {
            Assert.StartsWith("Bezpieczny Aktualizator ", name);
            Assert.EndsWith(".cab", cabinetPath, StringComparison.OrdinalIgnoreCase);
            Assert.Equal(0, flags);
            return Service;
        }
        public void RemoveService(string serviceId)
        {
            RemoveCalls++;
            RemovedServiceId = serviceId;
        }
    }
}
