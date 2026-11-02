using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using BezpiecznyAktualizator.Core.Localization;
using BezpiecznyAktualizator.Core.Logging;
using BezpiecznyAktualizator.Core.Security;

namespace BezpiecznyAktualizator.Services;

/// <summary>
/// Ochrona wydania przed analizą i modyfikacją: kontrola integralności pliku (podpis Authenticode i odcisk
/// certyfikatu wydawcy) oraz wykrywanie debugera. Działa tylko w wydaniu chronionym (stała PROTECTED).
/// </summary>
internal static class SelfProtection
{
    [DllImport("kernel32.dll")]
    private static extern bool IsDebuggerPresent();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CheckRemoteDebuggerPresent(IntPtr process, ref bool present);

    private static Timer? _watch;

#if PROTECTED
    public static bool Enabled => true;
#else
    public static bool Enabled => false;
#endif

    /// <summary>Certyfikaty wydawcy z bieżącego wydania oraz bezpiecznie zaplanowanej rotacji.</summary>
    public static IReadOnlyList<string> ExpectedSigners
    {
        get
        {
            var value = Metadata("SignerThumbprints");
            if (value.Length == 0) value = Metadata("SignerThumbprint");
            return value.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Where(IntegrityCheck.IsThumbprint).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        }
    }

    public static string Author => typeof(SelfProtection).Assembly.GetCustomAttribute<AssemblyCompanyAttribute>()?.Company ?? "";

    public static string Copyright => typeof(SelfProtection).Assembly.GetCustomAttribute<AssemblyCopyrightAttribute>()?.Copyright ?? "";

    public static string Version => typeof(SelfProtection).Assembly.GetName().Version?.ToString(3) ?? "";

    private static string Metadata(string key) =>
        typeof(SelfProtection).Assembly.GetCustomAttributes<AssemblyMetadataAttribute>()
            .FirstOrDefault(a => a.Key == key)?.Value ?? "";

    public static bool DebuggerAttached()
    {
        var remote = false;
        return Debugger.IsAttached || IsDebuggerPresent() ||
               CheckRemoteDebuggerPresent(Process.GetCurrentProcess().Handle, ref remote) && remote;
    }

    /// <summary>Sprawdza plik programu i obecność debugera. Zwraca opis problemu albo null.</summary>
    public static string? Check()
    {
        if (!Enabled) return null;
        if (DebuggerAttached()) return L.T("Wykryto debuger podłączony do programu.");
        var path = Environment.ProcessPath;
        if (string.IsNullOrEmpty(path)) return L.T("Nie można ustalić ścieżki pliku programu.");
        return IntegrityCheck.Problem(Authenticode.Verify(path, checkRevocation: false),
            Authenticode.SignerThumbprint(path), ExpectedSigners);
    }

    /// <summary>Okresowo sprawdza, czy w trakcie działania nie podłączono debugera; jeśli tak, kończy proces.</summary>
    public static void StartDebuggerWatch()
    {
        if (!Enabled || _watch is not null) return;
        _watch = new Timer(_ =>
        {
            if (!DebuggerAttached()) return;
            Syslog.Write(SyslogSeverity.Alert, LogEvent.Integrity, L.T("Wykryto debuger podłączony do programu.") + " " + L.T("Program został zamknięty."));
            Environment.Exit(3);
        }, null, TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(2));
    }
}
