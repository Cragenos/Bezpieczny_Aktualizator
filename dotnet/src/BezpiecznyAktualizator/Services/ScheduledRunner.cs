using System.Net.Http;
using System.Security.Principal;
using BezpiecznyAktualizator.Core.Drivers;
using BezpiecznyAktualizator.Core.Inventory;
using BezpiecznyAktualizator.Core.Localization;
using BezpiecznyAktualizator.Core.Logging;
using BezpiecznyAktualizator.Core.Scheduling;
using BezpiecznyAktualizator.Core.Security;
using BezpiecznyAktualizator.Core.Updates;
using BezpiecznyAktualizator.Core.Winget;

namespace BezpiecznyAktualizator.Services;

/// <summary>
/// Tryb bez okna uruchamiany przez Harmonogram zadań (<c>--scheduled</c>): czeka na bezczynność użytkownika,
/// sprawdza dostępne wersje i instaluje tylko aktualizacje z zaufanych, zweryfikowanych źródeł.
/// Wszystkie działania trafiają do dziennika syslog (MSGID SCHEDULED).
/// </summary>
public static class ScheduledRunner
{
    /// <summary>Krótsza przerwa w aktywności oznacza, że użytkownik wrócił do komputera.</summary>
    private static readonly TimeSpan ActiveThreshold = TimeSpan.FromSeconds(60);
    private static readonly TimeSpan MaxIdleWait = TimeSpan.FromHours(2);

    public static async Task<int> RunAsync(bool now)
    {
        using var mutex = new Mutex(true, @"Local\BezpiecznyAktualizator.Scheduled", out var first);
        if (!first)
        {
            Syslog.Info(LogEvent.Scheduled, L.T("Ciche sprawdzanie już trwa - pominięto kolejne uruchomienie."));
            return 0;
        }

        var options = Settings.Schedule.Normalize();
        if (!options.Enabled && !now)
        {
            Syslog.Info(LogEvent.Scheduled, L.T("Ciche sprawdzanie jest wyłączone w ustawieniach."));
            return 0;
        }
        var state = ScheduleState.Load();
        if (!now && !state.IsDue(DateTimeOffset.Now, options.MinIntervalHours))
        {
            Syslog.Debug(LogEvent.Scheduled, L.F("Pominięto - od ostatniego cichego sprawdzania nie minęło {0} godz.", options.MinIntervalHours));
            return 0;
        }
        if (!now && !await WaitForIdleAsync(TimeSpan.FromMinutes(options.IdleMinutes)))
        {
            Syslog.Info(LogEvent.Scheduled, L.T("Pominięto - użytkownik korzysta z komputera."));
            return 0;
        }

        var elevated = IsElevated();
        var install = options.Mode == ScheduleMode.InstallTrusted;
        if (install && !elevated)
        {
            // Bez uprawnień instalatory wyświetliłyby monit UAC, na który nikt nie odpowie.
            Syslog.Warning(LogEvent.Scheduled, L.T("Brak uprawnień administratora - ciche sprawdzanie tylko wyszuka aktualizacje, bez instalacji."));
            install = false;
        }
        var constraintSkip = install ? GetInstallationConstraintSkip(options, DateTimeOffset.Now) : null;
        if (constraintSkip is not null)
        {
            state.LastAttempt = DateTimeOffset.Now;
            state.SkipReason = constraintSkip;
            state.Save();
            Syslog.Notice(LogEvent.Scheduled, L.F("Pominięto ciche instalacje: {0}", constraintSkip));
            Syslog.Notice(LogEvent.Scheduled, state.Summary());
            await SendNotificationsAsync(state.Summary());
            return 0;
        }
        Syslog.Notice(LogEvent.Scheduled, L.F("Rozpoczęto ciche sprawdzanie ({0}; tryb: {1}).",
            now ? L.T("uruchomione ręcznie") : L.T("bezczynność komputera"),
            install ? L.T("instalacja z zaufanych źródeł") : L.T("tylko sprawdzanie")));

        var result = new ScheduleState { LastRun = DateTimeOffset.Now, LastAttempt = DateTimeOffset.Now, Installed = install };
        try
        {
            await UpdateSoftwareAsync(options, install, now, result);
            await CheckWindowsUpdatesAsync(options, install, now, result);
            if (options.CheckDrivers && !result.Interrupted)
                await Task.Run(() => CheckDrivers(options, install, now, result));
        }
        catch (Exception ex)
        {
            result.Error = ex.Message;
            Syslog.Error(LogEvent.Scheduled, L.T("Błąd cichego sprawdzania."), ex);
        }
        result.Save();
        Syslog.Notice(LogEvent.Scheduled, result.Summary());
        await SendNotificationsAsync(result.Summary());
        return result.Error.Length > 0 ? 1 : 0;
    }

    private static async Task SendNotificationsAsync(string summary)
    {
        foreach (var error in await NotificationService.SendAsync(Settings.Notifications, summary))
            Syslog.Warning(LogEvent.Scheduled, error);
    }

    /// <summary>Czeka, aż użytkownik będzie nieaktywny przez wymagany czas; false, gdy w międzyczasie wrócił.</summary>
    private static async Task<bool> WaitForIdleAsync(TimeSpan required)
    {
        var deadline = DateTime.UtcNow + MaxIdleWait;
        var previous = IdleTime.Current;
        while (DateTime.UtcNow < deadline)
        {
            var idle = IdleTime.Current;
            if (idle >= required) return true;
            if (idle < previous) return false;
            previous = idle;
            await Task.Delay(TimeSpan.FromSeconds(30));
        }
        return false;
    }

    private static bool UserReturned(bool now) => !now && IdleTime.Current < ActiveThreshold;

    private static string? GetInstallationConstraintSkip(ScheduleOptions options, DateTimeOffset now)
    {
        if (!options.IsWithinMaintenanceWindow(now))
            return L.F("poza oknem serwisowym {0}-{1}", options.WindowStart, options.WindowEnd);
        if (options.SkipOnBattery && !SystemConditions.IsOnAcPower())
            return L.T("komputer nie jest podłączony do zasilania sieciowego");
        if (options.SkipOnMeteredNetwork && SystemConditions.CurrentNetworkCost() != MeteredNetworkState.Unmetered)
            return L.T("sieć ma taryfowy lub nieznany koszt");
        return null;
    }

    private static async Task CheckWindowsUpdatesAsync(ScheduleOptions options, bool install, bool now,
                                                        ScheduleState result)
    {
            if (!options.CheckWindowsUpdates) return;
            WindowsUpdateSearchResult search;
            try
            {
                search = await Task.Run(WindowsUpdateAgent.Search);
            }
            catch (WindowsUpdateException ex)
            {
                result.WindowsUpdateError = ex.Message;
                Syslog.Error(LogEvent.Scheduled, L.T("Nie udało się sprawdzić aktualizacji Windows."), ex);
                return;
            }

            result.WindowsUpdateChecked = true;
            result.WindowsUpdates = search.Updates.Count;
            foreach (var warning in search.Warnings)
                Syslog.Warning(LogEvent.Scheduled, warning);
            Syslog.Info(LogEvent.Scheduled, L.F("Windows Update: znaleziono {0} dostępnych aktualizacji.", result.WindowsUpdates));

            if (!install || !options.InstallWindowsUpdates || search.Updates.Count == 0) return;
            var candidates = search.Updates.Where(ScheduledWindowsUpdatePolicy.IsInstallCandidate).ToList();
            foreach (var update in search.Updates.Except(candidates))
                Syslog.Info(LogEvent.Scheduled, L.F("Pominięto aktualizację Windows {0}: instalacja automatyczna wymaga oznaczenia jako obowiązkowa i uprzedniej akceptacji licencji.", update.Title));
            if (candidates.Count == 0) return;

            foreach (var update in candidates)
            {
                if (UserReturned(now))
                {
                    result.Interrupted = true;
                    Syslog.Notice(LogEvent.Scheduled, L.T("Przerwano instalację aktualizacji Windows, ponieważ użytkownik wrócił do komputera."));
                    return;
                }

                try
                {
                    var report = await Task.Run(() => WindowsUpdateAgent.Execute(
                        WindowsUpdateAction.Install, [update.Identity]));
                    foreach (var warning in report.Warnings)
                        Syslog.Warning(LogEvent.Scheduled, warning);
                    foreach (var outcome in report.Outcomes)
                    {
                        if (outcome.Succeeded)
                        {
                            result.WindowsUpdatesInstalled++;
                            Syslog.Notice(LogEvent.Scheduled, L.F("Zainstalowano aktualizację Windows: {0}.", outcome.Title));
                        }
                        else
                        {
                            var detail = outcome.Message;
                            if (outcome.HResult != 0)
                                detail = $"{detail} (0x{unchecked((uint)outcome.HResult):X8})".Trim();
                            result.WindowsUpdateError = L.F("Niepowodzenie instalacji {0}: {1}", outcome.Title, detail);
                            Syslog.Error(LogEvent.Scheduled, result.WindowsUpdateError);
                        }
                    }
                    result.WindowsUpdateRebootRequired |= report.RebootRequired;
                    if (!report.Succeeded || report.RebootRequired) break;
                }
                catch (WindowsUpdateException ex)
                {
                    result.WindowsUpdateError = ex.Message;
                    Syslog.Error(LogEvent.Scheduled, L.T("Nie udało się zainstalować aktualizacji Windows."), ex);
                    break;
                }
            }
        }

    private static async Task UpdateSoftwareAsync(ScheduleOptions options, bool install, bool now, ScheduleState result)
    {
        if (!WingetClient.IsAvailable())
        {
            Syslog.Warning(LogEvent.Scheduled, L.T("winget nie jest dostępny - sprawdzanie aktualizacji w repozytoriach wyłączone."));
            return;
        }
        var installed = await Task.Run(SoftwareInventory.ScanInstalled);
        var (items, _) = await WingetClient.CheckUpdatesAsync(installed);
        result.Updates = items.Count(s => s.HasUpdate);
        var policies = Settings.Policies;
        var nowTime = DateTimeOffset.Now;
        var candidates = items.Where(s => SilentUpdatePolicy.IsCandidate(s, policies, nowTime)).ToList();
        Syslog.Info(LogEvent.Scheduled, L.F("Dostępne aktualizacje: {0}; do cichej instalacji kwalifikuje się: {1}.",
                                            result.Updates, candidates.Count));
        foreach (var s in items.Where(s => s.CanUpgrade))
        {
            if (SilentUpdatePolicy.IsStoreManaged(s))
            {
                Syslog.Warning(LogEvent.Scheduled, L.F("Pominięto {0} - aktualizacje Microsoft Store wymagają ręcznego potwierdzenia w zakładce Microsoft Store.", s.Name));
                continue;
            }
            var rule = policies.CheckRules(s, nowTime);
            if (!rule.Allowed)
                Syslog.Info(LogEvent.Policy, L.F("Pominięto {0}: {1}", s.Name, rule.Reason.ToString()));
        }
        if (!install) return;

        foreach (var s in candidates)
        {
            if (UserReturned(now))
            {
                result.Interrupted = true;
                Syslog.Notice(LogEvent.Scheduled, L.T("Przerwano, ponieważ użytkownik wrócił do komputera."));
                return;
            }
            var label = $"{s.Name} {s.Version} → {s.AvailableVersion}";
            try
            {
                await SoftwareAssessor.AssessSoftwareAsync(s, verifyTls: true);
            }
            catch (Exception ex) when (ex is WingetException or HttpRequestException or TaskCanceledException)
            {
                s.SecurityLevel = "";
                Syslog.Warning(LogEvent.Scheduled, L.F("Nie udało się ocenić źródła {0}: {1}", s.Name, ex.Message));
            }
            if (!policies.TrustAccepted(s.SecurityLevel))
            {
                result.Skipped.Add(label);
                Syslog.Warning(LogEvent.Scheduled, L.F("Pominięto {0} - poziom zaufania źródła: {1}.", s.Name,
                    s.SecurityLevel.Length > 0 ? L.T(s.SecurityLevel) : L.T("nie oceniono")));
                continue;
            }

            var verification = await InstallerVerifier.VerifyAsync(s.WingetId!, s.WingetSource);
            using var verifiedInstaller = verification.VerifiedInstaller;
            foreach (var c in verification.Checks.Where(c => c.Status != CheckStatus.Ok))
                Syslog.Warning(LogEvent.Verify, $"{s.Name}: {c.Label}: {c.Detail}");
            if (!SilentUpdatePolicy.MayInstall(verification, options))
            {
                // Bez użytkownika nie instalujemy niczego, czego nie dało się w pełni zweryfikować i przeskanować.
                result.Skipped.Add(label);
                if (verification.PassedWithoutScan)
                    Syslog.Warning(LogEvent.Scheduled, L.F("Pominięto {0} - Microsoft Defender jest niedostępny, a instalacja bez skanowania antywirusowego nie jest dozwolona w ustawieniach harmonogramu.", s.Name));
                else
                    Syslog.Warning(LogEvent.Scheduled, L.F("Pominięto {0} - instalator nie przeszedł weryfikacji plików kontrolnych{1}.",
                        s.Name, verification.Error is { } err ? ": " + err : ""));
                continue;
            }
            if (verification.PassedWithoutScan)
                Syslog.Warning(LogEvent.Scheduled, L.F("Instalacja {0} bez skanowania Microsoft Defender (zgoda w ustawieniach harmonogramu).", s.Name));

            if (UserReturned(now))
            {
                result.Interrupted = true;
                Syslog.Notice(LogEvent.Scheduled, L.T("Przerwano przed instalacją, ponieważ użytkownik wrócił do komputera."));
                return;
            }

            Syslog.Notice(LogEvent.Upgrade, L.F("Cicha aktualizacja {0} ({1}), SHA256 {2}...", label, s.WingetId, verification.Sha256));
            var code = -1;
            for (var attempt = 0; attempt <= options.MaxRetries; attempt++)
            {
                if (attempt > 0)
                {
                    var delay = ScheduleOptions.RetryDelay(attempt);
                    Syslog.Warning(LogEvent.Upgrade, L.F("Ponowienie {0}/{1} dla {2} za {3} s.",
                        attempt, options.MaxRetries, s.Name, (int)delay.TotalSeconds));
                    await Task.Delay(delay);
                    if (UserReturned(now))
                    {
                        result.Interrupted = true;
                        Syslog.Notice(LogEvent.Scheduled, L.T("Przerwano ponawianie, ponieważ użytkownik wrócił do komputera."));
                        break;
                    }
                    result.Retries++;
                }
                code = await WingetClient.UpgradeVerifiedAsync(verifiedInstaller!, line => Syslog.Debug(LogEvent.Upgrade, line));
                if (code == 0) break;
                Syslog.Warning(LogEvent.Upgrade, L.F("Próba {0}/{1} aktualizacji {2} zakończyła się kodem 0x{3:X8}.",
                    attempt + 1, options.MaxRetries + 1, s.Name, code));
            }
            if (code == 0)
            {
                result.Updated.Add(label);
                Syslog.Notice(LogEvent.Upgrade, L.F("Zaktualizowano {0} ({1}).", s.Name, s.WingetId));
                Views.SoftwareView.RecordUpgrade(s, verification.Version, verification.Sha256, scheduled: true);
            }
            else
            {
                result.Failed.Add(label);
                Syslog.Error(LogEvent.Upgrade, L.F("Niepowodzenie: {0} (kod 0x{1:X8})", s.Name, code));
                if (result.Interrupted) return;
            }
        }
    }

    private static void CheckDrivers(ScheduleOptions options, bool install, bool now, ScheduleState result)
    {
        try
        {
            var updates = WindowsUpdateDrivers.Search();
            result.DriverUpdates = updates.Count;
            Syslog.Info(LogEvent.Scheduled, L.F("Windows Update: znaleziono {0} sterowników do zainstalowania.", updates.Count));
            if (!install || !options.InstallDrivers || updates.Count == 0) return;
            if (UserReturned(now))
            {
                result.Interrupted = true;
                return;
            }
            var results = WindowsUpdateDrivers.InstallInProcess(updates.Select(u => u.UpdateId).ToList(), restorePoint: true,
                                                                line => Syslog.Info(LogEvent.DriverInstall, line));
            result.DriversInstalled = results.Count(r => r.Succeeded);
            if (results.Any(r => r.RebootRequired))
                Syslog.Warning(LogEvent.DriverInstall, L.T("Do zakończenia instalacji sterowników wymagane jest ponowne uruchomienie komputera."));
        }
        catch (DriverException ex)
        {
            Syslog.Error(LogEvent.Scheduled, ex.Message, ex);
        }
    }

    private static bool IsElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }
}
