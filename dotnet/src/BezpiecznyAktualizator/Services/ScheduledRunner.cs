using System.Net.Http;
using System.Security.Principal;
using BezpiecznyAktualizator.Core.Agent;
using BezpiecznyAktualizator.Core.Backup;
using BezpiecznyAktualizator.Core.Drivers;
using BezpiecznyAktualizator.Core.History;
using BezpiecznyAktualizator.Core.Inventory;
using BezpiecznyAktualizator.Core.Localization;
using BezpiecznyAktualizator.Core.Logging;
using BezpiecznyAktualizator.Core.Models;
using BezpiecznyAktualizator.Core.Policies;
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
        if (state.LoadError.Length > 0) return 1;
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
        var constraintSkip = install
            ? GetInstallationConstraintSkip(options, DateTimeOffset.Now, SystemConditions.IsOnAcPower,
                SystemConditions.CurrentNetworkCost)
            : null;
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

        var started = DateTimeOffset.Now;
        var result = new ScheduleState { LastRun = started, LastAttempt = started, Installed = install };
        var backup = install && Settings.BackupBeforeInstall
            ? new RestorePointGate(() => SystemRestorePoint.Create(RestorePointPurpose.Scheduled))
            : null;
        try
        {
            await UpdateSoftwareAsync(options, install, now, result, backup);
            await CheckWindowsUpdatesAsync(options, install, now, result, backup);
            if (options.CheckDrivers && !result.Interrupted)
                await Task.Run(() => CheckDrivers(options, install, now, result, backup));
        }
        catch (Exception ex)
        {
            result.Error = ex.Message;
            Syslog.Error(LogEvent.Scheduled, L.T("Błąd cichego sprawdzania."), ex);
        }
        result.Save();
        Syslog.Notice(LogEvent.Scheduled, result.Summary());
        await SendNotificationsAsync(result.Summary());
        return GetExitCode(result);
    }

    internal static int GetExitCode(ScheduleState state) => state.HasErrors ? 1 : 0;

    internal delegate Task<LocalAgentReview> AgentReviewer(LocalAgentOptions options, IReadOnlyList<LocalAgentCandidate> candidates);

    /// <summary>
    /// Pozostawia tylko pakiety zatwierdzone przez lokalnego agenta AI. Gdy agent jest niedostępny lub odpowiada
    /// nieprawidłowo, ciche instalacje programów są pomijane (agent nigdy nie dodaje pakietów do listy).
    /// </summary>
    internal static async Task<List<Software>> ApplyAgentReviewAsync(LocalAgentOptions agent, List<Software> candidates,
                                                                     ScheduleState result, AgentReviewer? reviewer = null)
    {
        reviewer ??= (options, items) => LocalAgentClient.ReviewAsync(options, items);
        static string Label(Software s) => $"{s.Name} {s.Version} → {s.AvailableVersion}";
        var batch = candidates.Take(LocalAgentClient.MaxCandidates).ToList();
        Syslog.Info(LogEvent.Agent, L.F("Lokalny agent AI ({0}) ocenia aktualizacje: {1}.", agent.Model, batch.Count));
        LocalAgentReview review;
        try
        {
            review = await reviewer(agent, batch.Select(LocalAgentCandidate.From).ToList());
        }
        catch (LocalAgentException ex)
        {
            result.SkipReason = L.F("lokalny agent AI jest niedostępny: {0}", ex.Message);
            result.Skipped.AddRange(candidates.Select(Label));
            Syslog.Warning(LogEvent.Agent, L.F("Pominięto ciche instalacje: {0}", result.SkipReason));
            return [];
        }

        var approved = new List<Software>();
        foreach (var s in candidates)
        {
            if (batch.Contains(s) && review.Approves(s.WingetId))
            {
                approved.Add(s);
                Syslog.Notice(LogEvent.Agent, L.F("Agent AI zatwierdził {0}: {1}", Label(s), review.ReasonFor(s.WingetId)));
            }
            else
            {
                result.Skipped.Add(Label(s));
                Syslog.Notice(LogEvent.Agent, L.F("Agent AI odłożył {0}: {1}", Label(s), review.ReasonFor(s.WingetId)));
            }
        }
        return approved;
    }

    /// <summary>
    /// Punkt przywracania przed pierwszą cichą instalacją w przebiegu. Zwraca powód pominięcia instalacji,
    /// gdy kopii nie udało się utworzyć (bez kopii ciche instalacje nie są wykonywane).
    /// </summary>
    internal static string? EnsureBackup(RestorePointGate? gate, ScheduleState? result = null)
    {
        if (gate is null) return null;
        var first = !gate.Attempted;
        var backup = gate.Ensure();
        if (first)
            Syslog.Write(backup.Succeeded ? SyslogSeverity.Notice : SyslogSeverity.Warning, LogEvent.Backup, backup.Detail);
        if (!backup.Succeeded && result is not null) result.BackupFailed = true;
        return backup.Succeeded ? null : L.F("brak punktu przywracania systemu: {0}", backup.Detail);
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

    internal static string? GetInstallationConstraintSkip(
        ScheduleOptions options, DateTimeOffset now, Func<bool> isOnAcPower, Func<MeteredNetworkState> networkCost)
    {
        if (!options.IsWithinMaintenanceWindow(now))
            return L.F("poza oknem serwisowym {0}-{1}", options.WindowStart, options.WindowEnd);
        if (options.SkipOnBattery && !isOnAcPower())
            return L.T("komputer nie jest podłączony do zasilania sieciowego");
        if (options.SkipOnMeteredNetwork && networkCost() != MeteredNetworkState.Unmetered)
            return L.T("sieć ma taryfowy lub nieznany koszt");
        return null;
    }

    private static async Task CheckWindowsUpdatesAsync(ScheduleOptions options, bool install, bool now,
                                                        ScheduleState result, RestorePointGate? backup)
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

            for (var index = 0; index < candidates.Count; index++)
            {
                var update = candidates[index];
                if (UserReturned(now))
                {
                    result.Interrupted = true;
                    Syslog.Notice(LogEvent.Scheduled, L.T("Przerwano instalację aktualizacji Windows, ponieważ użytkownik wrócił do komputera."));
                    return;
                }

                var constraintSkip = GetInstallationConstraintSkip(options, DateTimeOffset.Now,
                    SystemConditions.IsOnAcPower, SystemConditions.CurrentNetworkCost);
                constraintSkip ??= await Task.Run(() => EnsureBackup(backup, result));
                if (constraintSkip is not null)
                {
                    result.SkipReason = constraintSkip;
                    result.Skipped.AddRange(candidates.Skip(index).Select(item => item.Title));
                    Syslog.Notice(LogEvent.Scheduled, L.F("Pominięto ciche instalacje: {0}", constraintSkip));
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

    private static async Task UpdateSoftwareAsync(ScheduleOptions options, bool install, bool now, ScheduleState result,
                                                  RestorePointGate? backup)
    {
        if (!WingetClient.IsAvailable())
        {
            Syslog.Warning(LogEvent.Scheduled, L.T("winget nie jest dostępny - sprawdzanie aktualizacji w repozytoriach wyłączone."));
            return;
        }
        var installed = await Task.Run(() => SoftwareInventory.ScanInstalled());
        var (items, _) = await WingetClient.CheckUpdatesAsync(installed);
        result.Updates = items.Count(s => s.HasUpdate);
        var policies = Settings.LoadPolicies(out var machinePolicyError);
        if (install && machinePolicyError is not null)
        {
            result.Error = L.F("Nie można wczytać zasad komputera. Aktualizowanie zablokowane: {0}", machinePolicyError);
            result.Skipped.AddRange(items.Where(item => item.CanUpgrade)
                .Select(item => $"{item.Name} {item.Version} → {item.AvailableVersion}"));
            Syslog.Error(LogEvent.Policy, result.Error);
            return;
        }
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
        if (candidates.Count > 0 && Settings.LocalAgent is { Enabled: true, ReviewScheduledUpdates: true } agent)
        {
            candidates = await ApplyAgentReviewAsync(agent, candidates, result);
        }
        if (candidates.Count > 0)
        {
            try { await WingetClient.EnsureLocalManifestFilesEnabledAsync(); }
            catch (WingetException ex)
            {
                result.Error = ex.Message;
                result.Skipped.AddRange(candidates.Select(s => $"{s.Name} {s.Version} → {s.AvailableVersion}"));
                Syslog.Error(LogEvent.Scheduled, ex.Message);
                return;
            }
        }

        foreach (var s in candidates)
        {
            if (UserReturned(now))
            {
                result.Interrupted = true;
                Syslog.Notice(LogEvent.Scheduled, L.T("Przerwano, ponieważ użytkownik wrócił do komputera."));
                return;
            }
            policies = Settings.LoadPolicies(out machinePolicyError);
            if (machinePolicyError is not null)
            {
                result.Error = L.F("Nie można wczytać zasad komputera. Aktualizowanie zablokowane: {0}", machinePolicyError);
                result.Skipped.AddRange(candidates.SkipWhile(candidate => candidate != s)
                    .Select(item => $"{item.Name} {item.Version} → {item.AvailableVersion}"));
                Syslog.Error(LogEvent.Policy, result.Error);
                return;
            }
            var currentDecision = policies.CheckRules(s, DateTimeOffset.Now);
            if (!currentDecision.Allowed)
            {
                result.Skipped.Add($"{s.Name} {s.Version} → {s.AvailableVersion}");
                Syslog.Notice(LogEvent.Policy, L.F("Pominięto {0}: {1}", s.Name, currentDecision.Reason.ToString()));
                continue;
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
            policies = Settings.LoadPolicies(out machinePolicyError);
            if (machinePolicyError is not null)
            {
                result.Error = L.F("Nie można wczytać zasad komputera. Aktualizowanie zablokowane: {0}", machinePolicyError);
                result.Skipped.Add(label);
                Syslog.Error(LogEvent.Policy, result.Error);
                return;
            }
            var postAssessmentDecision = policies.Evaluate(s, automatic: true, DateTimeOffset.Now);
            if (!postAssessmentDecision.Allowed)
            {
                result.Skipped.Add(label);
                Syslog.Warning(LogEvent.Policy, L.F("Pominięto {0}: {1}", s.Name, postAssessmentDecision.Reason.ToString()));
                continue;
            }

            var verification = await InstallerVerifier.VerifyAsync(s.WingetId!, s.WingetSource, version: s.AvailableVersion,
                installedInstallerType: s.InstalledInstallerType);
            using var verifiedInstaller = verification.VerifiedInstaller;
            foreach (var c in verification.Checks.Where(c => c.Status != CheckStatus.Ok))
                Syslog.Warning(LogEvent.Verify, $"{s.Name}: {c.Label}: {c.Detail}");
            if (!SilentUpdatePolicy.MayInstall(verification, options))
            {
                // Bez użytkownika nie instalujemy niczego, czego nie dało się w pełni zweryfikować i przeskanować.
                result.Skipped.Add(label);
                if (verification.PassedWithoutScan)
                    Syslog.Warning(LogEvent.Scheduled,
                        L.F("Pominięto {0} - instalator nie został zeskanowany, a instalacja bez skanowania nie jest dozwolona w ustawieniach harmonogramu.", s.Name));
                else
                    Syslog.Warning(LogEvent.Scheduled, L.F("Pominięto {0} - instalator nie przeszedł weryfikacji plików kontrolnych{1}.",
                        s.Name, verification.Error is { } err ? ": " + err : ""));
                continue;
            }
            if (verification.PassedWithoutScan)
                Syslog.Warning(LogEvent.Scheduled,
                    L.F("Instalacja {0} bez skanowania antywirusowego (jawnie dozwolona w ustawieniach harmonogramu).", s.Name));

            policies = Settings.LoadPolicies(out machinePolicyError);
            var beforeInstallDecision = policies.Evaluate(s, automatic: true, DateTimeOffset.Now, machinePolicyError);
            if (beforeInstallDecision.Verdict == PolicyVerdict.MachinePolicyUnavailable)
            {
                result.Error = beforeInstallDecision.Reason.ToString();
                result.Skipped.AddRange(candidates.SkipWhile(candidate => candidate != s)
                    .Select(item => $"{item.Name} {item.Version} → {item.AvailableVersion}"));
                Syslog.Error(LogEvent.Policy, result.Error);
                return;
            }
            if (!beforeInstallDecision.Allowed)
            {
                result.Skipped.Add(label);
                Syslog.Notice(LogEvent.Policy, L.F("Pominięto {0}: {1}", s.Name, beforeInstallDecision.Reason.ToString()));
                continue;
            }

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
                var constraintSkip = GetInstallationConstraintSkip(options, DateTimeOffset.Now,
                    SystemConditions.IsOnAcPower, SystemConditions.CurrentNetworkCost);
                constraintSkip ??= await Task.Run(() => EnsureBackup(backup, result));
                if (constraintSkip is not null)
                {
                    result.SkipReason = constraintSkip;
                    if (code != -1) result.Failed.Add(label);
                    var remaining = candidates.SkipWhile(candidate => candidate != s);
                    if (code != -1) remaining = remaining.Skip(1);
                    result.Skipped.AddRange(remaining.Select(item => $"{item.Name} {item.Version} → {item.AvailableVersion}"));
                    Syslog.Notice(LogEvent.Scheduled, L.F("Pominięto ciche instalacje: {0}", constraintSkip));
                    return;
                }
                code = await WingetClient.UpgradeVerifiedAsync(verifiedInstaller!, line => Syslog.Debug(LogEvent.Upgrade, line));
                if (code == 0) break;
                Syslog.Warning(LogEvent.Upgrade, L.F("Próba {0}/{1} aktualizacji {2} zakończyła się kodem 0x{3:X8}.",
                    attempt + 1, options.MaxRetries + 1, s.Name, code));
            }
            if (code == 0)
            {
                string? confirmedVersion = null;
                try
                {
                    confirmedVersion = await WingetClient.InstalledVersionAsync(s.WingetId!, s.WingetSource);
                }
                catch (WingetException ex)
                {
                    Syslog.Warning(LogEvent.Upgrade, L.F("Nie udało się potwierdzić wersji {0}: {1}", s.Name, ex.Message));
                }

                if (UpdateHistory.IsUpgradeVersionConfirmed(confirmedVersion, verification.Version, s.Version))
                {
                    result.Updated.Add(label);
                    Syslog.Notice(LogEvent.Upgrade, L.F("Zaktualizowano {0} ({1}).", s.Name, s.WingetId));
                    Views.SoftwareView.RecordUpgrade(s, confirmedVersion!, verification.Sha256, scheduled: true);
                }
                else
                {
                    result.Failed.Add(label);
                    Syslog.Warning(LogEvent.Upgrade, L.F("Nie udało się potwierdzić wersji {0}: {1}", s.Name, confirmedVersion ?? verification.Version));
                }
            }
            else
            {
                result.Failed.Add(label);
                Syslog.Error(LogEvent.Upgrade, L.F("Niepowodzenie: {0} (kod 0x{1:X8})", s.Name, code));
                if (result.Interrupted) return;
            }
        }
    }

    private static void CheckDrivers(ScheduleOptions options, bool install, bool now, ScheduleState result,
                                     RestorePointGate? backup)
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
            var constraintSkip = GetInstallationConstraintSkip(options, DateTimeOffset.Now,
                SystemConditions.IsOnAcPower, SystemConditions.CurrentNetworkCost) ?? EnsureBackup(backup, result);
            if (constraintSkip is not null)
            {
                result.SkipReason = constraintSkip;
                result.Skipped.AddRange(updates.Select(update => update.Title));
                Syslog.Notice(LogEvent.Scheduled, L.F("Pominięto ciche instalacje: {0}", constraintSkip));
                return;
            }
            // Punkt przywracania tworzy bramka przebiegu (gdy kopie są włączone), a nie zadanie instalacji.
            var results = WindowsUpdateDrivers.InstallInProcess(updates.Select(u => u.UpdateId).ToList(), restorePoint: false,
                                                                line => Syslog.Info(LogEvent.DriverInstall, line));
            result.DriversInstalled = results.Count(r => r.Succeeded);
            var failures = results.Where(r => !r.Succeeded).ToList();
            if (failures.Count > 0)
            {
                result.Failed.AddRange(failures.Select(r => r.Title.Length > 0 ? r.Title : L.T("Błąd")));
                result.DriverError = string.Join("; ", failures.Select(r =>
                    $"{r.Title}: {(r.Error.Length > 0 ? r.Error : r.ResultText)}"));
                Syslog.Error(LogEvent.Scheduled, L.F("Błąd: {0}", result.DriverError));
            }
            if (results.Any(r => r.RebootRequired))
                Syslog.Warning(LogEvent.DriverInstall, L.T("Do zakończenia instalacji sterowników wymagane jest ponowne uruchomienie komputera."));
        }
        catch (DriverException ex)
        {
            result.DriverError = ex.Message;
            Syslog.Error(LogEvent.Scheduled, ex.Message, ex);
        }
    }

    private static bool IsElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }
}
