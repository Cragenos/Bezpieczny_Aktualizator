using System.Runtime.InteropServices;
using BezpiecznyAktualizator.Core.Localization;
using BezpiecznyAktualizator.Core.Security;

namespace BezpiecznyAktualizator.Tests;

public class AntivirusInventoryTests
{
    [Theory]
    [InlineData(0, AntivirusProtectionState.On)]
    [InlineData(1, AntivirusProtectionState.Off)]
    [InlineData(2, AntivirusProtectionState.Snoozed)]
    [InlineData(3, AntivirusProtectionState.Expired)]
    [InlineData(-1, AntivirusProtectionState.Unknown)]
    [InlineData(42, AntivirusProtectionState.Unknown)]
    public void MapsWindowsProtectionStates(int raw, AntivirusProtectionState expected) =>
        Assert.Equal(expected, AntivirusInventory.MapProtectionState(raw));

    [Theory]
    [InlineData(0, AntivirusSignatureStatus.OutOfDate)]
    [InlineData(1, AntivirusSignatureStatus.UpToDate)]
    [InlineData(-1, AntivirusSignatureStatus.Unknown)]
    [InlineData(42, AntivirusSignatureStatus.Unknown)]
    public void MapsWindowsSignatureStates(int raw, AntivirusSignatureStatus expected) =>
        Assert.Equal(expected, AntivirusInventory.MapSignatureStatus(raw));

    [Fact]
    public void DistinguishesUnavailableServiceFromOtherErrors()
    {
        AntivirusInventory.EnsureServiceAvailable(0);
        var unavailable = Assert.Throws<AntivirusInventoryException>(() => AntivirusInventory.EnsureServiceAvailable(1));
        Assert.Contains(L.T("Usługa Centrum zabezpieczeń Windows nie działa."), unavailable.Message);
        var failure = Assert.Throws<COMException>(() => AntivirusInventory.EnsureServiceAvailable(unchecked((int)0x80004005)));
        Assert.Equal(unchecked((int)0x80004005), failure.ErrorCode);
        Assert.Contains("80004005", failure.Message);
        Assert.Throws<COMException>(() => AntivirusInventory.EnsureServiceAvailable(2));
    }

    [Fact]
    public void ReportsProductsAndNeverTreatsDetectionAsAScan()
    {
        var report = AntivirusInventory.Describe(
        [
            new("Example Antivirus", AntivirusProtectionState.On, AntivirusSignatureStatus.UpToDate),
            new("Other Antivirus", AntivirusProtectionState.Snoozed, AntivirusSignatureStatus.OutOfDate),
            new("Unknown Antivirus", AntivirusProtectionState.Unknown, AntivirusSignatureStatus.Unknown),
            new("Expired Antivirus", AntivirusProtectionState.Expired, AntivirusSignatureStatus.OutOfDate),
        ]).ToString();

        Assert.Contains("Example Antivirus", report);
        Assert.Contains(L.T("włączona"), report);
        Assert.Contains(L.T("Aktualne"), report);
        Assert.Contains(L.T("tymczasowo wstrzymana"), report);
        Assert.Contains(L.T("Nieaktualne"), report);
        Assert.Contains(L.T("wygasła"), report);
        Assert.Contains(L.T("stan nieznany"), report);
        Assert.Contains(L.T("nieznane"), report);
        Assert.Contains(L.T("Wykrycie programu nie oznacza, że instalator został przeskanowany."), report);
    }

    [Fact]
    public void EmptyInventoryDoesNotClaimNoAntivirusExists()
    {
        var report = AntivirusInventory.Describe([]).ToString();
        Assert.Contains(L.T("Zabezpieczenia Windows nie zgłaszają antywirusów; niezarejestrowane programy mogą nie być widoczne."), report);
        Assert.Contains(L.T("Wykrycie programu nie oznacza, że instalator został przeskanowany."), report);
    }

    [Fact]
    public async Task InventoryErrorsAreVisibleAndRemainWarnings()
    {
        var verification = new InstallerVerification { Completed = true };
        await InstallerVerifier.AddDefenderResultAsync(verification, new DefenderScan(DefenderVerdict.Unavailable, [], "unavailable"),
            () => throw new AntivirusInventoryException("security center error"));
        var check = Assert.IsType<Check>(verification.AntivirusInventoryCheck);
        Assert.Equal(CheckStatus.Warn, check.Status);
        Assert.Contains("security center error", check.Detail!.ToString());
        Assert.False(verification.Passed);
        Assert.True(verification.PassedWithoutScan);
    }

    [Fact]
    public async Task ActiveAntivirusDoesNotPassUnavailableDefenderScan()
    {
        var verification = new InstallerVerification { Completed = true };
        await InstallerVerifier.AddDefenderResultAsync(verification, new DefenderScan(DefenderVerdict.Unavailable, [], "unavailable"),
            () => [new("Example Antivirus", AntivirusProtectionState.On, AntivirusSignatureStatus.UpToDate)]);
        var check = Assert.IsType<Check>(verification.AntivirusInventoryCheck);
        Assert.Equal(CheckStatus.Warn, check.Status);
        Assert.Contains(check, verification.Checks);
        Assert.Contains("Example Antivirus", check.Detail!.ToString());
        Assert.False(verification.Passed);
        Assert.True(verification.PassedWithoutScan);

        verification.Checks.Add(InstallerVerifier.DefenderCheck(new DefenderScan(DefenderVerdict.Threat, ["threat"], "")));
        Assert.True(verification.Blocked);
        Assert.False(verification.Passed);
        Assert.False(verification.PassedWithoutScan);
    }

    [Theory]
    [InlineData(DefenderVerdict.Clean, false)]
    [InlineData(DefenderVerdict.Threat, true)]
    public async Task InventoryIsNotQueriedWhenDefenderCompletes(DefenderVerdict verdict, bool blocked)
    {
        var queried = false;
        var verification = new InstallerVerification { Completed = true };
        await InstallerVerifier.AddDefenderResultAsync(verification, new DefenderScan(verdict, [], ""),
            () => { queried = true; return []; });
        Assert.False(queried);
        Assert.Null(verification.AntivirusInventoryCheck);
        Assert.False(verification.DefenderUnavailable);
        Assert.Equal(blocked, verification.Blocked);
        Assert.Equal(!blocked, verification.Passed);
    }

    [Fact]
    public async Task InventoryLookupHonorsCancellation()
    {
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            InstallerVerifier.AddDefenderResultAsync(new InstallerVerification(),
                new DefenderScan(DefenderVerdict.Unavailable, [], "unavailable"), () => [], cancellation.Token));
    }
}
