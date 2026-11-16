using System.Diagnostics;
using System.Security;
using System.Text;
using BezpiecznyAktualizator.Core.Localization;

namespace BezpiecznyAktualizator.Core.Security;

public enum EsetVerdict { Clean, Threat, Unavailable }

public sealed record EsetScan(EsetVerdict Verdict, int ExitCode, string Detail);

public static class EsetScanner
{
    private const string ExpectedSigner = "ESET, spol. s r.o.";
    private static readonly TimeSpan Timeout = TimeSpan.FromMinutes(5);

    public static bool IsActiveEset(IEnumerable<AntivirusProduct> products) =>
        products.Any(product => product.Protection == AntivirusProtectionState.On &&
                                product.Name.Contains("ESET", StringComparison.OrdinalIgnoreCase));

    internal static bool IsTrustedScannerSignature(SignatureInfo signature) =>
        signature.State == SignatureState.Valid &&
        signature.Signer.Equals(ExpectedSigner, StringComparison.OrdinalIgnoreCase);

    public static bool IsTrustedScannerAvailable() => FindScanner() is not null;

    internal static List<string> ScanArguments(string path) =>
        ["/no-subdir", "/clean-mode=none", "/log-console", "/no-log-all", Path.GetFullPath(path)];

    public static EsetScan Parse(int exitCode) => exitCode switch
    {
        0 => new(EsetVerdict.Clean, exitCode, L.T("Nie wykryto zagrożeń.")),
        1 or 50 => new(EsetVerdict.Threat, exitCode, L.F("ESET wykrył zagrożenie (kod {0}).", exitCode)),
        _ => new(EsetVerdict.Unavailable, exitCode, L.F("Skanowanie ESET nie zakończyło się pomyślnie (kod {0}).", exitCode)),
    };

    internal static Check Check(EsetScan scan)
    {
        var status = scan.Verdict switch
        {
            EsetVerdict.Clean => CheckStatus.Ok,
            EsetVerdict.Threat => CheckStatus.Fail,
            _ => CheckStatus.Warn,
        };
        return new Check(L.Txt("Skanowanie ESET"), status, LocText.Raw(scan.Detail));
    }

    public static async Task<EsetScan> ScanFileAsync(string path, CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
            return new EsetScan(EsetVerdict.Unavailable, -1, L.T("Skanowanie ESET jest dostępne tylko w systemie Windows."));

        IReadOnlyList<AntivirusProduct> products;
        try { products = AntivirusInventory.GetRegisteredProducts(); }
        catch (AntivirusInventoryException ex)
        {
            return new EsetScan(EsetVerdict.Unavailable, -1, ex.Message);
        }
        if (!IsActiveEset(products))
            return new EsetScan(EsetVerdict.Unavailable, -1,
                L.T("ESET nie jest aktywny lub nie został zgłoszony do Zabezpieczeń Windows."));

        string? scanner;
        try { scanner = FindScanner(); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or SecurityException or
                                       System.Security.Cryptography.CryptographicException or System.ComponentModel.Win32Exception)
        {
            return new EsetScan(EsetVerdict.Unavailable, -1,
                L.F("Nie można zweryfikować podpisu skanera ESET: {0}", ex.Message));
        }
        if (scanner is null)
            return new EsetScan(EsetVerdict.Unavailable, -1, L.T("Nie znaleziono zaufanego skanera ESET."));

        if (!File.Exists(path))
            return new EsetScan(EsetVerdict.Unavailable, -1, L.T("Nie znaleziono instalatora do skanowania."));

        var startInfo = new ProcessStartInfo(scanner)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };
        foreach (var argument in ScanArguments(path))
            startInfo.ArgumentList.Add(argument);

        try
        {
            using var process = Process.Start(startInfo);
            if (process is null)
                return new EsetScan(EsetVerdict.Unavailable, -1, L.T("Nie można uruchomić skanera ESET."));

            var stdout = process.StandardOutput.ReadToEndAsync(ct);
            var stderr = process.StandardError.ReadToEndAsync(ct);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(Timeout);
            try
            {
                await process.WaitForExitAsync(timeout.Token);
            }
            catch (OperationCanceledException)
            {
                try { process.Kill(true); } catch (InvalidOperationException) { }
                if (ct.IsCancellationRequested) throw;
                return new EsetScan(EsetVerdict.Unavailable, -1, L.T("Przekroczono limit czasu skanowania ESET."));
            }
            _ = await stdout + await stderr;
            return Parse(process.ExitCode);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or IOException or UnauthorizedAccessException or SecurityException)
        {
            return new EsetScan(EsetVerdict.Unavailable, -1, L.F("Nie można uruchomić skanera ESET: {0}", ex.Message));
        }
    }

    private static string? FindScanner()
    {
        var names = new[]
        {
            Path.Combine("ESET", "ESET Security", "ecls.exe"),
            Path.Combine("ESET", "ESET Endpoint Antivirus", "ecls.exe"),
            Path.Combine("ESET", "ESET NOD32 Antivirus", "ecls.exe"),
        };
        var roots = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
        };
        foreach (var path in roots.Where(root => !string.IsNullOrWhiteSpace(root))
                                  .SelectMany(root => names.Select(name => Path.Combine(root, name))))
        {
            if (!File.Exists(path)) continue;
            var signature = Authenticode.Verify(path);
            if (IsTrustedScannerSignature(signature)) return path;
        }
        return null;
    }
}
