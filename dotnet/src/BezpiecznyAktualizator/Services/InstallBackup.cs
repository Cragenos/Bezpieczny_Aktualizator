using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Windows;
using BezpiecznyAktualizator.Core.Backup;
using BezpiecznyAktualizator.Core.Localization;
using BezpiecznyAktualizator.Core.Logging;

namespace BezpiecznyAktualizator.Services;

/// <summary>Kopia bezpieczeństwa (punkt przywracania systemu) wykonywana przed instalacją lub aktualizacją.</summary>
internal static class InstallBackup
{
    private static readonly SemaphoreSlim EnsureLock = new(1, 1);

    /// <summary>Plik wykonywalny bieżącego programu (przy uruchomieniu przez dotnet - appHost .exe).</summary>
    public static string? SelfExecutable()
    {
        var executable = Environment.ProcessPath;
        if (executable is null) return null;
        if (!Path.GetFileNameWithoutExtension(executable).Equals("dotnet", StringComparison.OrdinalIgnoreCase))
            return executable;
        var assembly = Assembly.GetEntryAssembly()?.Location;
        var appHost = string.IsNullOrEmpty(assembly) ? "" : Path.ChangeExtension(assembly, ".exe");
        return File.Exists(appHost) ? appHost : null;
    }

    public static bool IsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    /// <summary>
    /// Tworzy punkt przywracania (jeśli włączono to w ustawieniach). Zwraca false, gdy instalacja ma zostać przerwana,
    /// bo kopia się nie powiodła, a użytkownik nie zgodził się kontynuować bez niej.
    /// </summary>
    public static async Task<bool> EnsureAsync(DependencyObject owner, RestorePointPurpose purpose,
                                               Action<string, SyslogSeverity, string?> log)
    {
        await EnsureLock.WaitAsync();
        try
        {
            return await EnsureCoreAsync(owner, purpose, log);
        }
        finally
        {
            EnsureLock.Release();
        }
    }

    private static async Task<bool> EnsureCoreAsync(DependencyObject owner, RestorePointPurpose purpose,
                                                    Action<string, SyslogSeverity, string?> log)
    {
        if (!Settings.BackupBeforeInstall) return true;
        var now = DateTime.Now;
        var isAdministrator = IsAdministrator();
        if (isAdministrator)
        {
            try
            {
                var latestPoint = await Task.Run(SystemRestorePoint.LatestPointTime);
                if (SystemRestorePoint.IsRecent(latestPoint, now))
                {
                    log(L.F("Kopia bezpieczeństwa: używany jest punkt przywracania z {0:yyyy-MM-dd HH:mm}.", latestPoint),
                        SyslogSeverity.Informational, LogEvent.Backup);
                    return true;
                }
            }
            catch (Exception ex) when (ex is ManagementException or COMException or UnauthorizedAccessException or
                                           PlatformNotSupportedException)
            {
                log(L.F("Nie można sprawdzić istniejącego punktu przywracania: {0}", ex.Message),
                    SyslogSeverity.Warning, LogEvent.Backup);
            }
        }
        log(L.T("Tworzenie punktu przywracania systemu..."), SyslogSeverity.Informational, LogEvent.Backup);
        var result = await Task.Run(() => isAdministrator ? SystemRestorePoint.Create(purpose) : CreateElevated(purpose));
        if (result.Succeeded)
        {
            log(result.Detail, SyslogSeverity.Notice, LogEvent.Backup);
            return true;
        }
        log(result.Detail, SyslogSeverity.Warning, LogEvent.Backup);
        var proceed = Ui.Confirm(owner, L.T("Kopia bezpieczeństwa"),
            result.Detail + "\n\n" + L.T("Kontynuować instalację bez kopii bezpieczeństwa (punktu przywracania)?"), warning: true);
        log(proceed
                ? L.T("Użytkownik zezwolił na instalację bez punktu przywracania.")
                : L.T("Instalację przerwano, ponieważ nie utworzono punktu przywracania."),
            proceed ? SyslogSeverity.Warning : SyslogSeverity.Notice, LogEvent.Backup);
        return proceed;
    }

    private static RestorePointResult CreateElevated(RestorePointPurpose purpose)
    {
        var executable = SelfExecutable();
        if (executable is null)
            return new(RestorePointOutcome.Failed, null, L.T("Nie znaleziono pliku wykonywalnego programu."));
        var start = new ProcessStartInfo(executable) { UseShellExecute = true, Verb = "runas" };
        start.ArgumentList.Add(SystemRestorePoint.CreateArgument);
        start.ArgumentList.Add(purpose.ToString());
        try
        {
            using var process = Process.Start(start);
            if (process is null)
                return new(RestorePointOutcome.Failed, null, L.T("Nie udało się uruchomić instalatora."));
            process.WaitForExit();
            return SystemRestorePoint.FromExitCode(process.ExitCode);
        }
        catch (Win32Exception ex)
        {
            return new(RestorePointOutcome.Failed, null, ex.NativeErrorCode == 1223
                ? L.T("Anulowano monit kontroli konta użytkownika (UAC).")
                : L.F("Nie utworzono punktu przywracania: {0}", ex.Message));
        }
    }
}
