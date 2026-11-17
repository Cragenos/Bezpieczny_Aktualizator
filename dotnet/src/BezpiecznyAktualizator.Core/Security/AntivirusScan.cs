using BezpiecznyAktualizator.Core.Localization;

namespace BezpiecznyAktualizator.Core.Security;

public enum AntivirusVerdict { Clean, Threat, Unavailable }

public sealed record AntivirusScanResult(AntivirusVerdict Verdict, IReadOnlyList<Check> Checks, bool DefenderUnavailable);

/// <summary>
/// Skanowanie pobranego pliku zainstalowanym antywirusem: Microsoft Defender, a gdy jest niedostępny -
/// zaufany skaner ESET, a następnie interfejs AMSI aktywnego antywirusa zarejestrowanego w Zabezpieczeniach Windows.
/// </summary>
public static class AntivirusScan
{
    public static async Task<AntivirusScanResult> ScanFileAsync(string path, Action<string>? progress = null,
                                                                CancellationToken ct = default)
    {
        progress?.Invoke(L.T("Skanowanie instalatora programem Microsoft Defender..."));
        var scan = await DefenderScanner.ScanFileAsync(path, ct);
        var checks = new List<Check> { InstallerVerifier.DefenderCheck(scan) };
        if (scan.Verdict != DefenderVerdict.Unavailable)
            return new(scan.Verdict == DefenderVerdict.Clean ? AntivirusVerdict.Clean : AntivirusVerdict.Threat, checks, false);

        checks.Add(await Task.Run(() => InstallerVerifier.AntivirusCheck(AntivirusInventory.GetRegisteredProducts), ct));
        var (verdict, fallback) = await ScanWithFallbackAsync(path, progress, ct);
        checks.AddRange(fallback);
        return new(verdict, checks, true);
    }

    /// <summary>Skanowanie innymi antywirusami, gdy Microsoft Defender jest niedostępny.</summary>
    public static async Task<(AntivirusVerdict Verdict, IReadOnlyList<Check> Checks)> ScanWithFallbackAsync(
        string path, Action<string>? progress = null, CancellationToken ct = default)
    {
        progress?.Invoke(L.T("Skanowanie instalatora programem ESET..."));
        var eset = await EsetScanner.ScanFileAsync(path, ct);
        var checks = new List<Check> { EsetScanner.Check(eset) };
        if (eset.Verdict != EsetVerdict.Unavailable)
            return (eset.Verdict == EsetVerdict.Clean ? AntivirusVerdict.Clean : AntivirusVerdict.Threat, checks);

        progress?.Invoke(L.T("Skanowanie instalatora przez interfejs AMSI aktywnego antywirusa..."));
        var amsi = await AmsiScanner.ScanFileAsync(path, ct);
        checks.Add(AmsiScanner.Check(amsi));
        return (amsi.Verdict switch
        {
            AmsiVerdict.Clean => AntivirusVerdict.Clean,
            AmsiVerdict.Threat => AntivirusVerdict.Threat,
            _ => AntivirusVerdict.Unavailable,
        }, checks);
    }

    /// <summary>Metody skanowania gotowe do użycia (do raportów gotowości).</summary>
    public static IReadOnlyList<string> AvailableMethods(IReadOnlyList<AntivirusProduct> products)
    {
        var methods = new List<string>();
        if (products.Any(p => p.Protection == AntivirusProtectionState.On && AmsiScanner.IsDefender(p)) &&
            DefenderScanner.FindMpCmdRun() is not null)
            methods.Add("Microsoft Defender (MpCmdRun)");
        if (EsetScanner.IsActiveEset(products) && EsetScanner.IsTrustedScannerAvailable())
            methods.Add("ESET (ecls)");
        methods.AddRange(AmsiScanner.AvailableEngines(products).Select(name => $"AMSI: {name}"));
        return methods;
    }
}
