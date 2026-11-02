using BezpiecznyAktualizator.Core.Models;
using BezpiecznyAktualizator.Core.History;
using BezpiecznyAktualizator.Core.Policies;
using BezpiecznyAktualizator.Core.Scheduling;
using BezpiecznyAktualizator.Core.Security;
using BezpiecznyAktualizator.Core.Store;
using BezpiecznyAktualizator.Core.Winget;

namespace BezpiecznyAktualizator.Tests;

public class MicrosoftStoreTests
{
    private const string Source = """
        {"Name":"msstore","Type":"Microsoft.Rest","Arg":"https://storeedgefd.dsx.mp.microsoft.com/v9.0",
         "Identifier":"StoreEdgeFD","Explicit":false,"TrustLevel":["Trusted"]}
        """;
    private const string Id = "9WZDNCRFHVJL";

    private static string Table(params (string Name, string Id, string Current, string Available, string Source)[] rows)
    {
        static string Row(string name, string id, string current, string available, string source) =>
            $"{name,-30} {id,-18} {current,-12} {available,-12} {source}";
        return Row("Name", "Id", "Version", "Available", "Source") + "\n" +
               new string('-', 90) + "\n" +
               string.Join("\n", rows.Select(r => Row(r.Name, r.Id, r.Current, r.Available, r.Source))) + "\n";
    }

    private static string UpgradeTable(params (string Name, string Id, string Current, string Available, string Source)[] rows) =>
        Table(rows) + $"{rows.Length} upgrades available.\n";

    private static Software Update() => new()
    {
        Name = "Example", WingetId = Id, WingetSource = "msstore", WingetDetected = true,
        Version = "1.0", AvailableVersion = "1.2", SecurityLevel = Levels.High,
    };

    [Fact]
    public void AcceptsOfficialSource()
    {
        MicrosoftStoreClient.ValidateSource(Source);
        MicrosoftStoreClient.ValidateSource(Source.Replace("/v9.0\"", "/v9.0/\""));
    }

    [Theory]
    [InlineData("https://storeedgefd.dsx.mp.microsoft.com/v9.0", "http://storeedgefd.dsx.mp.microsoft.com/v9.0")]
    [InlineData("https://storeedgefd.dsx.mp.microsoft.com/v9.0", "https://storeedgefd.dsx.mp.microsoft.com.evil.example/v9.0")]
    [InlineData("https://storeedgefd.dsx.mp.microsoft.com/v9.0", "https://attacker@storeedgefd.dsx.mp.microsoft.com/v9.0")]
    [InlineData("https://storeedgefd.dsx.mp.microsoft.com/v9.0", "https://storeedgefd.dsx.mp.microsoft.com/v9.0?redirect=evil")]
    [InlineData("StoreEdgeFD", "OtherSource")]
    [InlineData("Microsoft.Rest", "Other.Type")]
    [InlineData("\"Name\":\"msstore\"", "\"Name\":\"other\"")]
    public void RejectsAlteredStoreSource(string original, string replacement) =>
        Assert.Throws<WingetException>(() => MicrosoftStoreClient.ValidateSource(Source.Replace(original, replacement)));

    [Theory]
    [InlineData("{}")]
    [InlineData("not json")]
    [InlineData("[]")]
    public void RejectsMissingOrMalformedSourceMetadata(string value) =>
        Assert.Throws<WingetException>(() => MicrosoftStoreClient.ValidateSource(value));

    [Fact]
    public async Task FindsOnlyKnownStoreVersionsAndPinsTheSource()
    {
        var calls = new List<IReadOnlyList<string>>();
        MicrosoftStoreClient.CommandRunner run = (args, _) =>
        {
            calls.Add(args);
            return Task.FromResult(args[0] == "source"
                ? (0, Source)
                : (0, UpgradeTable(("Example", Id, "1.0", "1.2", "msstore"),
                                   ("No version", "9NBLGGH4NNS1", "Unknown", "2.0", "msstore"))));
        };
        var result = await MicrosoftStoreClient.FindUpdatesCoreAsync(run);
        var app = Assert.Single(result.Updates);
        Assert.Equal(1, result.UnknownVersions);
        Assert.Equal(Id, app.WingetId);
        Assert.Equal("1.2", app.AvailableVersion);
        Assert.Equal(Levels.High, app.SecurityLevel);
        Assert.Equal(["source", "export", "--name", "msstore", "--disable-interactivity"], calls[0]);
        Assert.Equal(["upgrade", "--source", "msstore", "--accept-source-agreements", "--disable-interactivity"], calls[1]);
        Assert.DoesNotContain("--include-unknown", calls[1]);
    }

    [Fact]
    public async Task NoApplicationsFoundIsAnEmptyResult()
    {
        MicrosoftStoreClient.CommandRunner run = (args, _) => Task.FromResult(args[0] == "source"
            ? (0, Source)
            : (unchecked((int)0x8A150014), "No packages found"));
        var result = await MicrosoftStoreClient.FindUpdatesCoreAsync(run);
        Assert.Empty(result.Updates);
        Assert.Equal(0, result.UnknownVersions);
    }

    [Fact]
    public async Task NoTableOutputIsReturnedForDisplayRatherThanAssumedToBeAnEmptyResult()
    {
        MicrosoftStoreClient.CommandRunner run = (args, _) => Task.FromResult(args[0] == "source"
            ? (0, Source)
            : (0, "No applicable upgrade found."));
        var result = await MicrosoftStoreClient.FindUpdatesCoreAsync(run);
        Assert.Empty(result.Updates);
        Assert.Equal("No applicable upgrade found.", result.UnparsedOutput);
    }

    [Theory]
    [InlineData("")]
    [InlineData("  \r\n ")]
    public async Task SuccessfulCommandWithoutOutputIsAnError(string output)
    {
        MicrosoftStoreClient.CommandRunner run = (args, _) => Task.FromResult(args[0] == "source"
            ? (0, Source)
            : (0, output));
        await Assert.ThrowsAsync<WingetException>(() => MicrosoftStoreClient.FindUpdatesCoreAsync(run));
    }

    [Fact]
    public async Task SourceFailureStopsBeforeSearching()
    {
        var calls = 0;
        MicrosoftStoreClient.CommandRunner run = (_, _) =>
        {
            calls++;
            return Task.FromResult((0, Source.Replace("StoreEdgeFD", "Untrusted")));
        };
        await Assert.ThrowsAsync<WingetException>(() => MicrosoftStoreClient.FindUpdatesCoreAsync(run));
        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task PartialOutputDoesNotHideCommandErrors()
    {
        MicrosoftStoreClient.CommandRunner run = (args, _) => Task.FromResult(args[0] == "source"
            ? (0, Source)
            : (1, UpgradeTable(("Example", Id, "1.0", "1.2", "msstore"))));
        await Assert.ThrowsAsync<WingetException>(() => MicrosoftStoreClient.FindUpdatesCoreAsync(run));
    }

    [Theory]
    [InlineData("evil")]
    [InlineData("9WZDNCRFHVJ…")]
    [InlineData("--force")]
    public void RejectsInvalidProductIds(string id) => Assert.False(MicrosoftStoreClient.IsProductId(id));

    [Theory]
    [InlineData("Unknown")]
    [InlineData("1.2…")]
    [InlineData("--force")]
    [InlineData("1.2  --force")]
    public void RejectsVersionsThatCannotBeSafelyPinned(string version) =>
        Assert.False(MicrosoftStoreClient.IsSpecificVersion(version));

    [Fact]
    public async Task RejectsRowsFromAnotherSource()
    {
        MicrosoftStoreClient.CommandRunner run = (args, _) => Task.FromResult(args[0] == "source"
            ? (0, Source)
            : (0, UpgradeTable(("Example", Id, "1.0", "1.2", "winget"))));
        await Assert.ThrowsAsync<WingetException>(() => MicrosoftStoreClient.FindUpdatesCoreAsync(run));
    }

    [Theory]
    [InlineData("1 upgrades available.")]
    [InlineData("Доступны обновления: 1.")]
    [InlineData("1 アップグレードを利用できます。")]
    public async Task ParsesLocalizedHeadersAndWideNamesWithoutRelyingOnColumnOffsets(string summary)
    {
        var output = "Application Name Id 現在のバージョン Available Version Source\n" +
                     new string('-', 80) + "\n" +
                     "日本語アプリ     9WZDNCRFHVJL     1.0     1.2\n" + summary + "\n";
        MicrosoftStoreClient.CommandRunner run = (args, _) => Task.FromResult(args[0] == "source" ? (0, Source) : (0, output));
        var item = Assert.Single((await MicrosoftStoreClient.FindUpdatesCoreAsync(run)).Updates);
        Assert.Equal("日本語アプリ", item.Name);
        Assert.Equal("1.2", item.AvailableVersion);
    }

    [Fact]
    public async Task EquivalentVersionsAreNotAdvertisedAsAnUpdate()
    {
        MicrosoftStoreClient.CommandRunner run = (args, _) => Task.FromResult(args[0] == "source"
            ? (0, Source)
            : (0, UpgradeTable(("Example", Id, "v1.0.0", "1.0", ""))));
        Assert.Empty((await MicrosoftStoreClient.FindUpdatesCoreAsync(run)).Updates);
    }

    [Fact]
    public async Task LongApplicationNameDoesNotLookLikeAnExtraProductId()
    {
        MicrosoftStoreClient.CommandRunner run = (args, _) => Task.FromResult(args[0] == "source"
            ? (0, Source)
            : (0, UpgradeTable(("Example VisualStudio", Id, "1.0", "1.2", ""))));
        Assert.Equal("Example VisualStudio", Assert.Single((await MicrosoftStoreClient.FindUpdatesCoreAsync(run)).Updates).Name);
    }

    [Theory]
    [InlineData("Example 9WZDNCRFHVJL 1.0 1.2 msstore\nBroken 9NBLGGH4NNS… 2.0 3.0 msstore\n2 upgrades available.")]
    [InlineData("Example 9WZDNCRFHVJL 1.0 1.2 msstore\n2 upgrades available.")]
    [InlineData("Example 9WZDNCRFHVJL 1.0 1.2 msstore")]
    [InlineData("Example 9WZDNCRFHVJL 1.0 1.2 msstore\n1 upgrades available.\nOther table\n-----\nOther")]
    public async Task RejectsTruncatedMismatchedOrMultipleTables(string body)
    {
        var output = "Name Id Version Available Source\n---------------------------------------------\n" + body;
        MicrosoftStoreClient.CommandRunner run = (args, _) => Task.FromResult(args[0] == "source" ? (0, Source) : (0, output));
        await Assert.ThrowsAsync<WingetException>(() => MicrosoftStoreClient.FindUpdatesCoreAsync(run));
    }

    [Fact]
    public async Task ProductDataWithoutATableIsNotAnEmptyResult()
    {
        MicrosoftStoreClient.CommandRunner run = (args, _) => Task.FromResult(args[0] == "source"
            ? (0, Source)
            : (0, "Example 9WZDNCRFHVJL 1.0 1.2"));
        await Assert.ThrowsAsync<WingetException>(() => MicrosoftStoreClient.FindUpdatesCoreAsync(run));
    }

    [Fact]
    public async Task RechecksTheSourceAndPinsTheSelectedVersion()
    {
        var calls = 0;
        MicrosoftStoreClient.CommandRunner run = (args, _) =>
        {
            calls++;
            Assert.Equal(["source", "export", "--name", "msstore", "--disable-interactivity"], args);
            return Task.FromResult((0, Source));
        };
        MicrosoftStoreClient.UpgradeRunner upgrade = (id, _, source, version, _) =>
        {
            Assert.Equal(Id, id);
            Assert.Equal("msstore", source);
            Assert.Equal("1.2", version);
            var args = WingetClient.UpgradeArguments(id, source, version);
            Assert.Equal(["upgrade", "--id", Id, "--exact", "--silent", "--accept-package-agreements",
                          "--accept-source-agreements", "--disable-interactivity", "--source", "msstore", "--version", "1.2"], args);
            Assert.DoesNotContain("--force", args);
            Assert.DoesNotContain("--include-unknown", args);
            return Task.FromResult(0);
        };
        Assert.Equal(0, await MicrosoftStoreClient.UpgradeCoreAsync(Update(), _ => { }, run, upgrade));
        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task ReadsInstalledVersionForTheExactStoreProduct()
    {
        var calls = new List<IReadOnlyList<string>>();
        MicrosoftStoreClient.CommandRunner run = (args, _) =>
        {
            calls.Add(args);
            return Task.FromResult(args[0] == "source"
                ? (0, Source)
                : (0, Table(("Example", Id, "1.2", "", "msstore"))));
        };
        Assert.Equal("1.2", await MicrosoftStoreClient.InstalledVersionCoreAsync(Update(), run));
        Assert.Equal(["list", "--id", Id, "--exact", "--source", "msstore",
                      "--accept-source-agreements", "--disable-interactivity"], calls[1]);
    }

    [Fact]
    public async Task UnknownInstalledVersionIsNotReportedAsConfirmed()
    {
        MicrosoftStoreClient.CommandRunner run = (args, _) => Task.FromResult(args[0] == "source"
            ? (0, Source)
            : (0, Table(("Example", Id, "Unknown", "", "msstore"))));
        Assert.Null(await MicrosoftStoreClient.InstalledVersionCoreAsync(Update(), run));
    }

    [Fact]
    public async Task InvalidOrChangedSourceNeverRunsAnUpgrade()
    {
        var called = false;
        MicrosoftStoreClient.CommandRunner run = (_, _) => Task.FromResult((0, Source.Replace("StoreEdgeFD", "Other")));
        MicrosoftStoreClient.UpgradeRunner upgrade = (_, _, _, _, _) =>
        {
            called = true;
            return Task.FromResult(0);
        };
        await Assert.ThrowsAsync<WingetException>(() => MicrosoftStoreClient.UpgradeCoreAsync(Update(), _ => { }, run, upgrade));
        Assert.False(called);
        var bad = Update();
        bad.AvailableVersion = "--force";
        await Assert.ThrowsAsync<WingetException>(() => MicrosoftStoreClient.UpgradeCoreAsync(bad, _ => { }, run, upgrade));
        Assert.False(called);
    }

    [Fact]
    public void StoreUpdatesRespectExclusionsHoldsAndManualTrust()
    {
        var app = Update();
        var policies = new UpdatePolicies { ManualRequireTrusted = true };
        Assert.True(policies.Evaluate(app, automatic: false, DateTimeOffset.UtcNow).Allowed);
        policies.Excluded.Add(new ExclusionRule { WingetId = Id });
        Assert.Equal(PolicyVerdict.Excluded, policies.Evaluate(app, automatic: false, DateTimeOffset.UtcNow).Verdict);
        policies.Excluded.Clear();
        policies.Holds.Add(new VersionHold { WingetId = Id, Version = "1.0" });
        Assert.Equal(PolicyVerdict.Held, policies.Evaluate(app, automatic: false, DateTimeOffset.UtcNow).Verdict);
    }

    [Theory]
    [InlineData("1.2")]
    [InlineData("1.*")]
    [InlineData("*")]
    public void ActiveStoreHoldsBlockEvenWhenTheListedVersionMatches(string version)
    {
        var now = DateTimeOffset.UtcNow;
        var app = Update();
        var policies = new UpdatePolicies();
        policies.Holds.Add(new VersionHold { WingetId = Id, Version = version });
        Assert.Equal(PolicyVerdict.Held, policies.Evaluate(app, automatic: false, now).Verdict);
        Assert.Equal(PolicyVerdict.Held, policies.CheckRules(app, now).Verdict);
        Assert.False(SilentUpdatePolicy.IsCandidate(app, policies, now));
        app.WingetSource = "winget";
        Assert.True(policies.CheckRules(app, now).Allowed);
    }

    [Fact]
    public void ExpiredStoreHoldDoesNotBlockUpdates()
    {
        var now = DateTimeOffset.UtcNow;
        var policies = new UpdatePolicies();
        policies.Holds.Add(new VersionHold { WingetId = Id, Version = "1.2", Until = now.AddSeconds(-1) });
        Assert.True(policies.CheckRules(Update(), now).Allowed);
    }

    [Fact]
    public void StoreHistoryNeverOffersAutomaticRollback()
    {
        var record = new UpdateRecord { WingetId = Id, Source = "MSSTORE", FromVersion = "1.0", ToVersion = "1.2" };
        Assert.False(record.CanRollback);
        Assert.Null(UpdateHistory.LastRollbackable([record], Id));
        record.Source = "winget";
        Assert.True(record.CanRollback);
    }
}
