using BezpiecznyAktualizator.Core.Models;
using BezpiecznyAktualizator.Core.Policies;
using BezpiecznyAktualizator.Core.Scheduling;

namespace BezpiecznyAktualizator.Tests;

public class PolicyTests
{
    private static readonly DateTimeOffset Now = new(2026, 5, 1, 12, 0, 0, TimeSpan.Zero);

    private static Software Make(string id, string version, string available, string level = "") => new()
    {
        Name = id, Version = version, AvailableVersion = available, WingetId = id, WingetDetected = true,
        WingetSource = "winget", SecurityLevel = level,
    };

    [Theory]
    [InlineData("", "24.09", false)]
    [InlineData("24.*", "24.09", true)]
    [InlineData("24.*", "24.9.1", true)]
    [InlineData("24.*", "25.00", false)]
    [InlineData("24.*", "240.1", false)]
    [InlineData("24.08", "24.08", true)]
    [InlineData("24.08", "24.8.0", true)]
    [InlineData("24.08", "24.09", false)]
    [InlineData("*", "99", true)]
    public void HoldPatterns(string pattern, string available, bool allowed) =>
        Assert.Equal(allowed, new VersionHold { WingetId = "x", Version = pattern }.Allows(available));

    [Fact]
    public void HoldBlocksUntilItExpires()
    {
        var p = new UpdatePolicies { Holds = [new VersionHold { WingetId = "7zip.7zip", Until = Now.AddDays(1) }] };
        var s = Make("7zip.7zip", "24.08", "24.09");
        Assert.Equal(PolicyVerdict.Held, p.CheckRules(s, Now).Verdict);
        Assert.Contains("24.08", p.CheckRules(s, Now).Reason.ToString());
        Assert.True(p.CheckRules(s, Now.AddDays(2)).Allowed);
        Assert.False(SilentUpdatePolicy.IsCandidate(s, p, Now));
        Assert.True(SilentUpdatePolicy.IsCandidate(s, p, Now.AddDays(2)));
        // Bez dostępnej aktualizacji wstrzymanie niczego nie blokuje, ale jest opisane w kolumnie.
        Assert.True(p.CheckRules(Make("7zip.7zip", "24.08", ""), Now).Allowed);
        Assert.NotEqual("", p.Describe(Make("7zip.7zip", "24.08", ""), Now));
    }

    [Fact]
    public void ExclusionWinsAndIsCaseInsensitive()
    {
        var p = new UpdatePolicies
        {
            Excluded = [new ExclusionRule { WingetId = "Git.Git", Reason = "test" }],
            Holds = [new VersionHold { WingetId = "git.git", Version = "2.*" }],
        };
        var d = p.CheckRules(Make("GIT.GIT", "2.0", "2.1", "Wysoki"), Now);
        Assert.Equal(PolicyVerdict.Excluded, d.Verdict);
        Assert.Contains("test", d.Reason.ToString());
        Assert.Equal(PolicyVerdict.Excluded, p.Evaluate(Make("git.git", "2.0", "2.1", "Wysoki"), automatic: false, Now).Verdict);
        Assert.True(p.CheckRules(Make("Git.LFS", "1", "2"), Now).Allowed);
    }

    [Fact]
    public void TrustIsRequiredForAutomaticAndOptionallyForManualUpdates()
    {
        var p = new UpdatePolicies();
        Assert.Equal(PolicyVerdict.Allowed, p.Evaluate(Make("a", "1", "2", "Wysoki"), true, Now).Verdict);
        Assert.Equal(PolicyVerdict.Untrusted, p.Evaluate(Make("a", "1", "2", "Średni"), true, Now).Verdict);
        Assert.Equal(PolicyVerdict.Unassessed, p.Evaluate(Make("a", "1", "2", ""), true, Now).Verdict);
        Assert.Equal(PolicyVerdict.Unassessed, p.Evaluate(Make("a", "1", "2", "?"), true, Now).Verdict);
        Assert.Equal(PolicyVerdict.Allowed, p.Evaluate(Make("a", "1", "2", "Niski"), false, Now).Verdict);

        p.ManualRequireTrusted = true;
        Assert.Equal(PolicyVerdict.Untrusted, p.Evaluate(Make("a", "1", "2", "Niski"), false, Now).Verdict);
        p.AutoTrust = AutoTrustLevel.HighOrMedium;
        Assert.Equal(PolicyVerdict.Allowed, p.Evaluate(Make("a", "1", "2", "Średni"), false, Now).Verdict);
    }

    [Fact]
    public void MachinePolicyIsStricterAndManaged()
    {
        var user = new UpdatePolicies
        {
            AutoTrust = AutoTrustLevel.HighOrMedium,
            Excluded = [new ExclusionRule { WingetId = "A" }, new ExclusionRule { WingetId = "B", Reason = "user" }],
            Holds = [new VersionHold { WingetId = "C", Version = "1.*" }],
        };
        var machine = new UpdatePolicies
        {
            SetsAutoTrust = true,
            ManualRequireTrusted = true,
            Excluded = [new ExclusionRule { WingetId = "b", Reason = "admin" }],
            Holds = [new VersionHold { WingetId = "D" }],
        };
        var merged = user.MergeMachine(machine);
        Assert.True(merged.HasMachinePolicy);
        Assert.Equal(AutoTrustLevel.High, merged.AutoTrust);
        Assert.True(merged.AutoTrustManaged);
        Assert.True(merged.ManualRequireTrusted);
        Assert.True(merged.ManualTrustManaged);
        Assert.Equal(2, merged.Excluded.Count);
        Assert.Equal("admin", merged.ExclusionFor("B")!.Reason);
        Assert.True(merged.ExclusionFor("B")!.Managed);
        Assert.False(merged.ExclusionFor("A")!.Managed);
        Assert.Contains("administrator", merged.Describe(Make("B", "1", "2"), Now));

        var saved = merged.UserPart();
        Assert.Equal(["A"], saved.Excluded.Select(e => e.WingetId));
        Assert.Equal(["C"], saved.Holds.Select(h => h.WingetId));

        // Łagodniejsze ustawienia komputera nie osłabiają zasad użytkownika.
        var lenient = new UpdatePolicies { AutoTrust = AutoTrustLevel.HighOrMedium };
        Assert.Equal(AutoTrustLevel.High, new UpdatePolicies().MergeMachine(lenient).AutoTrust);
        Assert.Same(user, user.MergeMachine(null));

        // Plik komputera bez "autoTrust" nie narzuca poziomu zaufania.
        var onlyRules = UpdatePolicies.MachineFromJson("""{ "excluded": [ { "wingetId": "X" } ] }""")!;
        Assert.False(onlyRules.SetsAutoTrust);
        var keep = new UpdatePolicies { AutoTrust = AutoTrustLevel.HighOrMedium }.MergeMachine(onlyRules);
        Assert.Equal(AutoTrustLevel.HighOrMedium, keep.AutoTrust);
        Assert.False(keep.AutoTrustManaged);
        Assert.True(UpdatePolicies.MachineFromJson("""{ "AutoTrust": "High" }""")!.SetsAutoTrust);
    }

    [Fact]
    public void MachinePolicyFileErrorsAreReported()
    {
        var original = UpdatePolicies.MachineFilePath;
        var path = Path.Combine(Path.GetTempPath(), $"ba-policies-{Guid.NewGuid():N}.json");
        try
        {
            UpdatePolicies.MachineFilePath = path;
            Assert.Null(UpdatePolicies.LoadMachine(out var error));
            Assert.Null(error);

            File.WriteAllText(path, "{ not json");
            Assert.Null(UpdatePolicies.LoadMachine(out error));
            Assert.Contains(path, error);

            File.WriteAllText(path, """{ "autoTrust": "High", "excluded": [ { "wingetId": "Git.Git" } ] }""");
            Assert.True(UpdatePolicies.LoadMachine(out error)!.IsExcluded("git.git"));
            Assert.Null(error);
        }
        finally
        {
            UpdatePolicies.MachineFilePath = original;
            File.Delete(path);
        }
    }

    [Fact]
    public void JsonRoundTripNormalizes()
    {
        var p = new UpdatePolicies
        {
            AutoTrust = AutoTrustLevel.HighOrMedium,
            Excluded = [new ExclusionRule { WingetId = " Git.Git " }, new ExclusionRule { WingetId = "git.git" }, new ExclusionRule { WingetId = "" }],
            Holds = [new VersionHold { WingetId = "7zip.7zip", Version = "24.*", Until = Now }],
        };
        var json = p.ToJson();
        Assert.Contains("\"highOrMedium\"", json, StringComparison.OrdinalIgnoreCase);
        var back = UpdatePolicies.FromJson(json);
        Assert.Equal(AutoTrustLevel.HighOrMedium, back.AutoTrust);
        Assert.Equal(["Git.Git"], back.Excluded.Select(e => e.WingetId));
        Assert.Equal("24.*", back.Holds.Single().Version);
        Assert.Equal(Now, back.Holds.Single().Until);
    }

    [Fact]
    public void LegacyScheduleSettingsMigrateToPolicies()
    {
        var o = new ScheduleOptions { AllowMediumTrust = true, Excluded = ["Mozilla.Firefox", " ", "mozilla.firefox"] };
        var p = new UpdatePolicies();
        Assert.True(o.MigrateTo(p));
        Assert.Equal(AutoTrustLevel.HighOrMedium, p.AutoTrust);
        Assert.Equal(["Mozilla.Firefox"], p.Excluded.Select(e => e.WingetId));
        Assert.Null(o.Excluded);
        Assert.Null(o.AllowMediumTrust);
        Assert.False(o.MigrateTo(p));
    }
}
