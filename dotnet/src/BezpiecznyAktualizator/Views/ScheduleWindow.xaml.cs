using System.ComponentModel;
using System.Diagnostics;
using System.Security.Principal;
using System.Windows;
using System.Windows.Controls;
using BezpiecznyAktualizator.Core.Localization;
using BezpiecznyAktualizator.Core.Logging;
using BezpiecznyAktualizator.Core.Policies;
using BezpiecznyAktualizator.Core.Scheduling;
using BezpiecznyAktualizator.Services;

namespace BezpiecznyAktualizator.Views;

/// <summary>Konfiguracja cichego sprawdzania i aktualizacji podczas bezczynności (Harmonogram zadań Windows).</summary>
public partial class ScheduleWindow : Window
{
    private readonly ScheduleOptions _saved = Settings.Schedule;
    private bool? _taskExists;

    public ScheduleWindow()
    {
        InitializeComponent();
        Scroller.MaxHeight = Math.Max(320, SystemParameters.WorkArea.Height - 160);
        foreach (var m in ScheduleOptions.IdleChoices) IdleBox.Items.Add(new ComboBoxItem { Content = m.ToString(), Tag = m });
        foreach (var h in ScheduleOptions.IntervalChoices) IntervalBox.Items.Add(new ComboBoxItem { Content = h.ToString(), Tag = h });
        Load(_saved);
        LastRunText.Text = ScheduleState.Load().Summary();
        Loaded += async (_, _) =>
        {
            _taskExists = await ScheduledTask.ExistsAsync();
            UpdateTaskInfo();
        };
        UpdateTaskInfo();
    }

    private void Load(ScheduleOptions o)
    {
        EnabledBox.IsChecked = o.Enabled;
        ModeCheck.IsChecked = o.Mode == ScheduleMode.CheckOnly;
        ModeInstall.IsChecked = o.Mode == ScheduleMode.InstallTrusted;
        NoScanBox.IsChecked = o.AllowWithoutDefenderScan;
        Select(IdleBox, o.IdleMinutes);
        Select(IntervalBox, o.MinIntervalHours);
        DriversCheckBox.IsChecked = o.CheckDrivers;
        DriversInstallBox.IsChecked = o.InstallDrivers;
        UpdatePolicySummary();
        UpdateState();
    }

    private void UpdatePolicySummary()
    {
        var p = Settings.Policies;
        PolicySummary.Text = L.F("Instalowane są tylko aktualizacje ze źródeł o zaufaniu: {0}. Wykluczone programy: {1}; wstrzymane wersje: {2}.",
            p.AutoTrust == AutoTrustLevel.HighOrMedium ? L.T("Wysokim lub średnim") : L.T("Wysokim"),
            p.Excluded.Count, p.Holds.Count);
    }

    private void Policies_Click(object sender, RoutedEventArgs e)
    {
        new PoliciesWindow { Owner = this }.ShowDialog();
        UpdatePolicySummary();
    }

    /// <summary>Zaznacza wartość z listy; wartość spoza listy (np. wpisana w settings.json) zostaje dodana.</summary>
    private static void Select(ComboBox box, int value)
    {
        var item = box.Items.OfType<ComboBoxItem>().FirstOrDefault(i => (int)i.Tag == value);
        if (item is null)
        {
            item = new ComboBoxItem { Content = value.ToString(), Tag = value };
            box.Items.Add(item);
        }
        box.SelectedItem = item;
    }

    private ScheduleOptions Collect() => new ScheduleOptions
    {
        Enabled = EnabledBox.IsChecked == true,
        Mode = ModeInstall.IsChecked == true ? ScheduleMode.InstallTrusted : ScheduleMode.CheckOnly,
        AllowWithoutDefenderScan = ModeInstall.IsChecked == true && NoScanBox.IsChecked == true,
        IdleMinutes = (int)((ComboBoxItem)IdleBox.SelectedItem).Tag,
        MinIntervalHours = (int)((ComboBoxItem)IntervalBox.SelectedItem).Tag,
        CheckDrivers = DriversCheckBox.IsChecked == true,
        InstallDrivers = DriversCheckBox.IsChecked == true && DriversInstallBox.IsChecked == true,
    }.Normalize();

    private void UpdateState()
    {
        OptionsCard.IsEnabled = EnabledBox.IsChecked == true;
        var install = ModeInstall.IsChecked == true;
        NoScanBox.IsEnabled = install;
        DriversInstallBox.IsEnabled = install && DriversCheckBox.IsChecked == true;
    }

    private void UpdateTaskInfo()
    {
        var status = _taskExists switch
        {
            true => L.T("zarejestrowane"),
            false => L.T("niezarejestrowane"),
            null => L.T("stan nieznany"),
        };
        TaskInfo.Text = L.F("Zadanie „{0}” ({1}) działa z najwyższymi uprawnieniami zalogowanego użytkownika, dlatego jego utworzenie lub usunięcie wymaga jednorazowego potwierdzenia UAC.",
                            ScheduledTask.TaskName, status);
    }

    private void Enabled_Click(object sender, RoutedEventArgs e) => UpdateState();

    private void Mode_Click(object sender, RoutedEventArgs e) => UpdateState();

    private async void Save_Click(object sender, RoutedEventArgs e)
    {
        var options = Collect();
        IsEnabled = false;
        try
        {
            var register = options.Enabled && (!_saved.Enabled || _saved.IdleMinutes != options.IdleMinutes || _taskExists == false);
            var unregister = !options.Enabled && (_saved.Enabled || _taskExists == true) && _taskExists != false;
            if (register)
            {
                await ScheduledTask.RegisterAsync(Environment.ProcessPath!, CurrentUserSid(), options);
                Syslog.Notice(LogEvent.Settings, L.F("Zarejestrowano zadanie Harmonogramu zadań {0} (bezczynność: {1} min).",
                                                     ScheduledTask.TaskName, options.IdleMinutes));
            }
            else if (unregister)
            {
                await ScheduledTask.UnregisterAsync();
                Syslog.Notice(LogEvent.Settings, L.F("Usunięto zadanie Harmonogramu zadań {0}.", ScheduledTask.TaskName));
            }
            Settings.Schedule = options;
            Syslog.Notice(LogEvent.Settings, L.F("Ciche aktualizacje: {0}; tryb: {1}; bezczynność: {2} min; odstęp: {3} godz.; sterowniki: {4}/{5}.",
                options.Enabled ? L.T("włączone") : L.T("wyłączone"),
                options.Mode == ScheduleMode.InstallTrusted ? L.T("instalacja z zaufanych źródeł") : L.T("tylko sprawdzanie"),
                options.IdleMinutes, options.MinIntervalHours,
                options.CheckDrivers ? L.T("tak") : L.T("nie"), options.InstallDrivers ? L.T("tak") : L.T("nie")));
            if (options.AllowWithoutDefenderScan)
                Syslog.Warning(LogEvent.Settings, L.T("Ciche aktualizacje: zezwolono na instalację bez skanowania Microsoft Defender, gdy jest on niedostępny."));
            DialogResult = true;
        }
        catch (OperationCanceledException ex)
        {
            Syslog.Warning(LogEvent.Settings, ex.Message);
            Ui.Warn(this, Title, ex.Message + "\n\n" + L.T("Ustawienia harmonogramu nie zostały zmienione."));
        }
        catch (Exception ex) when (ex is InvalidOperationException or Win32Exception or System.IO.IOException)
        {
            Syslog.Error(LogEvent.Settings, L.T("Nie udało się skonfigurować Harmonogramu zadań."), ex);
            Ui.Error(this, Title, L.T("Nie udało się skonfigurować Harmonogramu zadań.") + "\n\n" + ex.Message);
        }
        finally
        {
            IsEnabled = true;
        }
    }

    private void RunNow_Click(object sender, RoutedEventArgs e)
    {
        // Uruchomienie ręczne korzysta z ustawień widocznych w oknie (bez zmiany stanu włączenia zadania).
        var options = Collect();
        options.Enabled = _saved.Enabled;
        Settings.Schedule = options;
        var psi = new ProcessStartInfo(Environment.ProcessPath!)
        {
            UseShellExecute = true,
            Verb = options.Mode == ScheduleMode.InstallTrusted || options.InstallDrivers ? "runas" : "",
        };
        psi.ArgumentList.Add(ScheduledTask.RunArgument);
        psi.ArgumentList.Add(ScheduledTask.NowArgument);
        try
        {
            Process.Start(psi)?.Dispose();
            Syslog.Notice(LogEvent.Scheduled, L.T("Ręcznie uruchomiono ciche sprawdzanie."));
            Ui.Info(this, Title, L.T("Ciche sprawdzanie zostało uruchomione w tle. Jego wynik zostanie zapisany w dzienniku zdarzeń i pokazany przy następnym uruchomieniu programu."));
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            Syslog.Warning(LogEvent.Scheduled, L.T("Anulowano monit kontroli konta użytkownika (UAC)."));
        }
    }

    private static string CurrentUserSid()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return identity.User?.Value ?? throw new InvalidOperationException(L.T("Nie można ustalić identyfikatora użytkownika."));
    }
}
