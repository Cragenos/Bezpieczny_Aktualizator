using BezpiecznyAktualizator.Core.Backup;

namespace BezpiecznyAktualizator.Tests;

public class SystemRestorePointTests
{
    private static readonly DateTime Now = new(2026, 11, 16, 12, 0, 0);

    [Fact]
    public void NewerPointThanBeforeIsCreated()
    {
        var result = SystemRestorePoint.Evaluate(0, Now.AddDays(-3), Now.AddSeconds(-5), Now);
        Assert.Equal(RestorePointOutcome.Created, result.Outcome);

        Assert.Equal(RestorePointOutcome.Created, SystemRestorePoint.Evaluate(0, null, Now, Now).Outcome);
    }

    [Fact]
    public void UnchangedPointWithinReuseWindowIsRecent()
    {
        var recent = Now.AddHours(-23);
        var result = SystemRestorePoint.Evaluate(0, recent, recent, Now);
        Assert.Equal(RestorePointOutcome.Recent, result.Outcome);
        Assert.Equal(recent, result.PointTime);
        Assert.True(result.Succeeded);
    }

    [Theory]
    [InlineData(-25.0, 0u)]   // za stary
    [InlineData(1.0, 0u)]     // z przyszłości (zła data systemowa)
    [InlineData(-30.0, 1058u)]
    public void OldFutureOrMissingPointFails(double hoursOffset, uint code)
    {
        var point = Now.AddHours(hoursOffset);
        Assert.Equal(RestorePointOutcome.Failed, SystemRestorePoint.Evaluate(code, point, point, Now).Outcome);
        Assert.False(SystemRestorePoint.Evaluate(code, null, null, Now).Succeeded);
    }

    [Theory]
    [InlineData(RestorePointOutcome.Created)]
    [InlineData(RestorePointOutcome.Recent)]
    [InlineData(RestorePointOutcome.Failed)]
    public void ExitCodeRoundTrips(RestorePointOutcome outcome) =>
        Assert.Equal(outcome, SystemRestorePoint.FromExitCode(SystemRestorePoint.ToExitCode(outcome)).Outcome);

    [Fact]
    public void UnknownExitCodeFails()
    {
        Assert.Equal(RestorePointOutcome.Failed, SystemRestorePoint.FromExitCode(1).Outcome);
        Assert.Equal(RestorePointOutcome.Failed, SystemRestorePoint.FromExitCode(-1).Outcome);
    }

    [Theory]
    [InlineData("drivers", true)]
    [InlineData("WindowsUpdate", true)]
    [InlineData("1", false)]
    [InlineData("99", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    [InlineData("unknown", false)]
    public void ParsesOnlyNamedPurposes(string? value, bool expected) =>
        Assert.Equal(expected, SystemRestorePoint.TryParsePurpose(value, out _));

    [Fact]
    public void GateCreatesRestorePointOnlyOnce()
    {
        var calls = 0;
        var gate = new RestorePointGate(() =>
        {
            calls++;
            return new RestorePointResult(RestorePointOutcome.Failed, null, "x");
        });
        Assert.False(gate.Attempted);
        gate.Ensure();
        gate.Ensure();
        Assert.True(gate.Attempted);
        Assert.Equal(1, calls);
    }
}
