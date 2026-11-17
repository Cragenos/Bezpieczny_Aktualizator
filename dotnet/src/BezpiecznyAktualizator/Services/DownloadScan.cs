using System.IO;
using System.Windows;
using BezpiecznyAktualizator.Core.Localization;
using BezpiecznyAktualizator.Core.Logging;
using BezpiecznyAktualizator.Core.Security;

namespace BezpiecznyAktualizator.Services;

/// <summary>Skanowanie pobranego pliku zainstalowanym antywirusem przed jego uruchomieniem.</summary>
internal static class DownloadScan
{
    /// <summary>Zwraca true, gdy plik można zainstalować (czysty albo użytkownik zaakceptował brak skanowania).</summary>
    public static async Task<bool> ScanAsync(DependencyObject owner, string path, Action<string, SyslogSeverity, string?> log,
                                             CancellationToken ct = default)
    {
        var name = Path.GetFileName(path);
        var result = await AntivirusScan.ScanFileAsync(path, text => log($"{name}: {text}", SyslogSeverity.Informational, LogEvent.Antivirus), ct);
        foreach (var check in result.Checks)
        {
            var (icon, severity) = check.Status switch
            {
                CheckStatus.Ok => ("[OK]", SyslogSeverity.Informational),
                CheckStatus.Warn => ("[!]", SyslogSeverity.Warning),
                _ => ("[" + L.T("BŁĄD") + "]", SyslogSeverity.Error),
            };
            var detail = check.Detail?.ToString() ?? "";
            log($"  {icon} {check.Label}{(detail.Length > 0 ? ": " + detail : "")}", severity, LogEvent.Antivirus);
        }
        switch (result.Verdict)
        {
            case AntivirusVerdict.Clean:
                return true;
            case AntivirusVerdict.Threat:
                log(L.F("Instalacja {0} zablokowana - antywirus wykrył zagrożenie.", name), SyslogSeverity.Alert, LogEvent.Antivirus);
                Ui.Error(owner, L.T("Skanowanie antywirusowe"),
                    L.F("Instalacja {0} zablokowana - antywirus wykrył zagrożenie.", name) + "\n\n" + L.T("Szczegóły w zakładce „Dziennik”."));
                return false;
        }
        var install = Ui.Confirm(owner, L.T("Skanowanie antywirusowe"),
            L.F("Żaden zaufany skaner antywirusowy (Microsoft Defender, ESET ani interfejs AMSI aktywnego antywirusa) nie był dostępny, więc plik {0} nie został przeskanowany.", name) +
            "\n\n" + L.T("Zainstalować bez skanowania antywirusowego?"), warning: true);
        log(install
                ? L.F("Użytkownik zezwolił na instalację {0} bez skanowania antywirusowego.", name)
                : L.F("Użytkownik wstrzymał instalację {0} bez skanowania antywirusowego.", name),
            install ? SyslogSeverity.Warning : SyslogSeverity.Notice, LogEvent.Antivirus);
        return install;
    }
}
