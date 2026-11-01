using System.Xml.Linq;
using BezpiecznyAktualizator.Core.Models;
using BezpiecznyAktualizator.Core.Policies;
using BezpiecznyAktualizator.Core.Scheduling;
using BezpiecznyAktualizator.Core.Security;

namespace BezpiecznyAktualizator.Tests;

public class ScheduleTests
{
    private static readonly XNamespace Ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";

    [Fact]
    public void TaskXmlIsValidIdleTaskForLoggedOnUser()
    {
        var xml = ScheduledTask.BuildXml(@"C:\Program Files\A & B\BezpiecznyAktualizator.exe", "S-1-5-21-1-2-3-1001",
                                         new ScheduleOptions { IdleMinutes = 15 });
        var doc = XDocument.Parse(xml);
        var task = doc.Root!;
        Assert.Equal(Ns + "Task", task.Name);
        Assert.NotNull(task.Element(Ns + "Triggers")!.Element(Ns + "IdleTrigger"));

        var principal = task.Element(Ns + "Principals")!.Element(Ns + "Principal")!;
        Assert.Equal("S-1-5-21-1-2-3-1001", principal.Element(Ns + "UserId")!.Value);
        Assert.Equal("InteractiveToken", principal.Element(Ns + "LogonType")!.Value);
        Assert.Equal("HighestAvailable", principal.Element(Ns + "RunLevel")!.Value);

        var settings = task.Element(Ns + "Settings")!;
        Assert.Equal("PT15M", settings.Element(Ns + "IdleSettings")!.Element(Ns + "Duration")!.Value);
        Assert.Equal("false", settings.Element(Ns + "IdleSettings")!.Element(Ns + "StopOnIdleEnd")!.Value);
        Assert.Equal("true", settings.Element(Ns + "DisallowStartIfOnBatteries")!.Value);
        Assert.Equal("IgnoreNew", settings.Element(Ns + "MultipleInstancesPolicy")!.Value);

        var exec = task.Element(Ns + "Actions")!.Element(Ns + "Exec")!;
        Assert.Equal("\"C:\\Program Files\\A & B\\BezpiecznyAktualizator.exe\"", exec.Element(Ns + "Command")!.Value);
        Assert.Equal(ScheduledTask.RunArgument, exec.Element(Ns + "Arguments")!.Value);
        Assert.Contains("A &amp; B", xml);
    }

    [Fact]
    public void NormalizeClampsValues()
    {
        var o = new ScheduleOptions { IdleMinutes = 0, MinIntervalHours = 100000 }.Normalize();
        Assert.Equal(1, o.IdleMinutes);
        Assert.Equal(720, o.MinIntervalHours);
    }

    [Fact]
    public void OnlyUpgradableNotExcludedSoftwareIsCandidate()
    {
        var p = new UpdatePolicies { Excluded = [new ExclusionRule { WingetId = "Git.Git" }] };
        var now = DateTimeOffset.Now;
        Software Make(string id, string available) => new()
        {
            Name = id, Version = "1.0", AvailableVersion = available, WingetId = id, WingetDetected = true, WingetSource = "winget",
        };
        Assert.True(SilentUpdatePolicy.IsCandidate(Make("7zip.7zip", "2.0"), p, now));
        Assert.False(SilentUpdatePolicy.IsCandidate(Make("git.git", "2.0"), p, now));
        Assert.False(SilentUpdatePolicy.IsCandidate(Make("7zip.7zip", ""), p, now));
    }

    [Theory]
    [InlineData("Wysoki", false, true)]
    [InlineData("Średni", false, false)]
    [InlineData("Średni", true, true)]
    [InlineData("Niski", true, false)]
    [InlineData("", true, false)]
    public void TrustPolicy(string level, bool allowMedium, bool accepted)
    {
        Assert.Equal("Wysoki", Levels.High);
        var p = new UpdatePolicies { AutoTrust = allowMedium ? AutoTrustLevel.HighOrMedium : AutoTrustLevel.High };
        Assert.Equal(accepted, p.TrustAccepted(level));
    }

    [Fact]
    public void IsDueRespectsMinimumInterval()
    {
        var now = new DateTimeOffset(2026, 5, 1, 12, 0, 0, TimeSpan.Zero);
        Assert.True(new ScheduleState().IsDue(now, 24));
        Assert.False(new ScheduleState { LastRun = now.AddHours(-23) }.IsDue(now, 24));
        Assert.True(new ScheduleState { LastRun = now.AddHours(-24) }.IsDue(now, 24));
        Assert.True(new ScheduleState { LastRun = now.AddDays(2) }.IsDue(now, 24)); // zmieniony zegar systemowy
    }

    [Fact]
    public void StateRoundTripsThroughFile()
    {
        var original = ScheduleState.FilePath;
        var dir = Directory.CreateTempSubdirectory("ba_schedule_test_");
        try
        {
            ScheduleState.FilePath = Path.Combine(dir.FullName, "state.json");
            Assert.Null(ScheduleState.Load().LastRun);
            var run = new DateTimeOffset(2026, 5, 1, 3, 15, 0, TimeSpan.FromHours(2));
            new ScheduleState
            {
                LastRun = run, Installed = true, Updates = 3, Updated = ["A 1 → 2"], Skipped = ["B"], DriverUpdates = 1, Interrupted = true,
            }.Save();
            var loaded = ScheduleState.Load();
            Assert.Equal(run, loaded.LastRun);
            Assert.True(loaded.Installed);
            Assert.Equal(3, loaded.Updates);
            Assert.Equal(["A 1 → 2"], loaded.Updated);
            Assert.Equal(["B"], loaded.Skipped);
            Assert.Equal(1, loaded.DriverUpdates);
            Assert.True(loaded.Interrupted);
            Assert.Contains("3", loaded.Summary());

            File.WriteAllText(ScheduleState.FilePath, "{ uszkodzony");
            Assert.Null(ScheduleState.Load().LastRun);
        }
        finally
        {
            ScheduleState.FilePath = original;
            dir.Delete(true);
        }
    }
}
