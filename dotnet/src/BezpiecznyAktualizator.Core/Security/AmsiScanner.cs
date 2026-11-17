using System.IO.MemoryMappedFiles;
using System.Runtime.InteropServices;
using System.Security;
using System.Text.RegularExpressions;
using BezpiecznyAktualizator.Core.Localization;
using Microsoft.Win32;

namespace BezpiecznyAktualizator.Core.Security;

public enum AmsiVerdict { Clean, Threat, Unavailable }

public sealed record AmsiScan(AmsiVerdict Verdict, string Engine, string Detail);

public sealed record AmsiProvider(Guid Clsid, string Path, SignatureInfo Signature);

/// <summary>
/// Skanowanie pliku przez interfejs AMSI (Antimalware Scan Interface), do którego podłącza się zainstalowany antywirus.
/// Wynik „czysto” jest uznawany tylko wtedy, gdy aktywny antywirus z Zabezpieczeń Windows ma zarejestrowanego,
/// prawidłowo podpisanego dostawcę AMSI tego samego wydawcy - inaczej AMSI zwróciłby „brak zagrożeń” bez skanowania.
/// </summary>
public static partial class AmsiScanner
{
    private const string ProvidersKey = @"SOFTWARE\Microsoft\AMSI\Providers";
    private const int DetectedThreshold = 32768;
    private const int BlockedByAdminStart = 16384;
    private const int BlockedByAdminEnd = 20479;

    private static readonly HashSet<string> GenericWords = new(StringComparer.OrdinalIgnoreCase)
    {
        "inc", "ltd", "llc", "gmbh", "srl", "s.r.o", "spol", "corp", "corporation", "company", "software", "security",
        "antivirus", "lab", "labs", "limited", "the", "and", "technologies", "group", "plc", "sas", "a.s", "s.a",
    };

    [DllImport("amsi.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int AmsiInitialize(string appName, out IntPtr amsiContext);

    [DllImport("amsi.dll", ExactSpelling = true)]
    private static extern void AmsiUninitialize(IntPtr amsiContext);

    [DllImport("amsi.dll", ExactSpelling = true)]
    private static extern int AmsiOpenSession(IntPtr amsiContext, out IntPtr amsiSession);

    [DllImport("amsi.dll", ExactSpelling = true)]
    private static extern void AmsiCloseSession(IntPtr amsiContext, IntPtr amsiSession);

    [DllImport("amsi.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int AmsiScanBuffer(IntPtr amsiContext, IntPtr buffer, uint length, string contentName,
                                             IntPtr amsiSession, out int result);

    internal static AmsiScan Classify(int result, string engine) => result switch
    {
        >= DetectedThreshold => new(AmsiVerdict.Threat, engine, L.F("{0} wykrył zagrożenie (AMSI {1}).", engine, result)),
        >= BlockedByAdminStart and <= BlockedByAdminEnd => new(AmsiVerdict.Threat, engine,
            L.F("Plik został zablokowany przez zasady administratora (AMSI {0}).", result)),
        _ => new(AmsiVerdict.Clean, engine, L.T("Nie wykryto zagrożeń.")),
    };

    internal static bool IsDefender(AntivirusProduct product) =>
        product.Name.Contains("Defender", StringComparison.OrdinalIgnoreCase);

    private static IEnumerable<string> Words(string text) =>
        WordPattern().Matches(text).Select(m => m.Value.Trim('.')).Where(w => w.Length >= 3 && !GenericWords.Contains(w));

    /// <summary>Aktywny antywirus, który dostarcza dostawcę AMSI (dopasowanie wydawcy podpisu do nazwy produktu).</summary>
    internal static AntivirusProduct? MatchProduct(AmsiProvider provider, IEnumerable<AntivirusProduct> products)
    {
        if (provider.Signature.State != SignatureState.Valid || provider.Signature.Signer.Length == 0) return null;
        var active = products.Where(p => p.Protection == AntivirusProtectionState.On).ToList();
        if (provider.Signature.Signer.StartsWith("Microsoft ", StringComparison.OrdinalIgnoreCase))
            return active.FirstOrDefault(IsDefender);
        var signerWords = Words(provider.Signature.Signer).ToHashSet(StringComparer.OrdinalIgnoreCase);
        return active.Where(p => !IsDefender(p)).FirstOrDefault(p => Words(p.Name).Any(signerWords.Contains));
    }

    public static IReadOnlyList<AmsiProvider> FindProviders()
    {
        var providers = new List<AmsiProvider>();
        if (!OperatingSystem.IsWindows()) return providers;
        try
        {
            using var machine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
            using var key = machine.OpenSubKey(ProvidersKey, writable: false);
            if (key is null) return providers;
            foreach (var name in key.GetSubKeyNames())
            {
                if (!Guid.TryParse(name, out var clsid)) continue;
                using var server = machine.OpenSubKey($@"SOFTWARE\Classes\CLSID\{clsid:B}\InprocServer32", writable: false);
                if (server?.GetValue(null) is not string value || value.Trim().Length == 0) continue;
                var path = Environment.ExpandEnvironmentVariables(value.Trim().Trim('"'));
                if (!System.IO.Path.IsPathFullyQualified(path) || !File.Exists(path)) continue;
                providers.Add(new AmsiProvider(clsid, path, Authenticode.Verify(path)));
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or SecurityException)
        {
        }
        return providers;
    }

    /// <summary>Nazwy aktywnych antywirusów, które mogą skanować przez AMSI.</summary>
    public static IReadOnlyList<string> AvailableEngines(IReadOnlyList<AntivirusProduct> products) =>
        FindProviders().Select(p => MatchProduct(p, products)?.Name).OfType<string>()
            .Distinct(StringComparer.OrdinalIgnoreCase).ToList();

    internal static Check Check(AmsiScan scan)
    {
        var label = scan.Engine.Length > 0
            ? L.Txt("Skanowanie AMSI ({0})", scan.Engine)
            : L.Txt("Skanowanie AMSI aktywnego antywirusa");
        var status = scan.Verdict switch
        {
            AmsiVerdict.Clean => CheckStatus.Ok,
            AmsiVerdict.Threat => CheckStatus.Fail,
            _ => CheckStatus.Warn,
        };
        return new Check(label, status, LocText.Raw(scan.Detail));
    }

    public static Task<AmsiScan> ScanFileAsync(string path, CancellationToken ct = default) =>
        Task.Run(() => ScanFile(path), ct);

    private static AmsiScan ScanFile(string path)
    {
        if (!OperatingSystem.IsWindows())
            return new(AmsiVerdict.Unavailable, "", L.T("Skanowanie AMSI jest dostępne tylko w systemie Windows."));
        IReadOnlyList<string> engines;
        try
        {
            engines = AvailableEngines(AntivirusInventory.GetRegisteredProducts());
        }
        catch (AntivirusInventoryException ex)
        {
            return new(AmsiVerdict.Unavailable, "", ex.Message);
        }
        if (engines.Count == 0)
            return new(AmsiVerdict.Unavailable, "",
                L.T("Żaden aktywny antywirus nie udostępnia zaufanego dostawcy AMSI."));
        var engine = string.Join(", ", engines);

        try
        {
            var length = new FileInfo(path).Length;
            if (length == 0 || length > uint.MaxValue)
                return new(AmsiVerdict.Unavailable, engine, L.T("Rozmiar pliku nie pozwala na skanowanie AMSI."));

            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            using var mapping = MemoryMappedFile.CreateFromFile(stream, null, 0, MemoryMappedFileAccess.Read,
                HandleInheritability.None, leaveOpen: false);
            using var view = mapping.CreateViewAccessor(0, length, MemoryMappedFileAccess.Read);
            var handle = view.SafeMemoryMappedViewHandle;
            var added = false;
            handle.DangerousAddRef(ref added);
            try
            {
                var buffer = handle.DangerousGetHandle() + (nint)view.PointerOffset;
                var hr = AmsiInitialize("BezpiecznyAktualizator", out var context);
                if (hr != 0) return Failure(engine, hr);
                try
                {
                    hr = AmsiOpenSession(context, out var session);
                    if (hr != 0) return Failure(engine, hr);
                    try
                    {
                        hr = AmsiScanBuffer(context, buffer, (uint)length, System.IO.Path.GetFileName(path), session,
                            out var result);
                        return hr == 0 ? Classify(result, engine) : Failure(engine, hr);
                    }
                    finally { AmsiCloseSession(context, session); }
                }
                finally { AmsiUninitialize(context); }
            }
            finally
            {
                if (added) handle.DangerousRelease();
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or DllNotFoundException or
                                       EntryPointNotFoundException or SEHException)
        {
            return new(AmsiVerdict.Unavailable, engine, L.F("Skanowanie AMSI nie powiodło się: {0}", ex.Message));
        }
    }

    private static AmsiScan Failure(string engine, int hr) =>
        new(AmsiVerdict.Unavailable, engine, L.F("Skanowanie AMSI nie powiodło się: 0x{0:X8}", unchecked((uint)hr)));

    [GeneratedRegex(@"[\p{L}\p{N}.]+")]
    private static partial Regex WordPattern();
}
