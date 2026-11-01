using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Windows;
using System.Windows.Controls;
using BezpiecznyAktualizator.Core.Localization;
using BezpiecznyAktualizator.Core.Logging;
using BezpiecznyAktualizator.Core.Scheduling;
using BezpiecznyAktualizator.Core.Updates;
using BezpiecznyAktualizator.Services;

namespace BezpiecznyAktualizator;

public partial class MainWindow : Window
{
    private bool _started;
    private bool _checking;
    private bool _checkingAppUpdate;
    private bool _allowClose;
    private bool _trayNoticeShown;
    private Func<string>? _bannerText;

    public MainWindow()
    {
        InitializeComponent();
        // Domyślny rozmiar okna dopasowany do ekranu (pasek narzędzi mieści się w jednym wierszu od ~1440 px).
        var area = SystemParameters.WorkArea;
        Width = Math.Max(MinWidth, Math.Min(1440, area.Width - 40));
        Height = Math.Max(MinHeight, Math.Min(880, area.Height - 40));
        LanguageBox.ItemsSource = L.Languages;
        LanguageBox.SelectedItem = L.Languages.First(l => l.Code == L.Language);
        LogFileButton.ToolTip = Syslog.FilePath;
        AutoSoftware.IsChecked = Settings.CheckSoftwareOnStart;
        AutoDrivers.IsChecked = Settings.CheckDriversOnStart;
        AutoAppUpdates.IsChecked = Settings.CheckAppUpdatesOnStart;
        ThemeBox.SelectedIndex = (int)Settings.Theme;
        L.LanguageChanged += () => { if (_bannerText is not null) BannerText.Text = _bannerText(); };
    }

    // ------------------------------------------- automatyczne sprawdzanie wersji po uruchomieniu
    private async void OnContentRendered(object? sender, EventArgs e)
    {
        if (_started) return;
        _started = true;
        var lastAppUpdateCheck = Settings.LastAppUpdateCheck;
        if (Settings.CheckAppUpdatesOnStart && !string.IsNullOrWhiteSpace(ApplicationUpdateService.Repository) &&
            (lastAppUpdateCheck is null || DateTimeOffset.UtcNow - lastAppUpdateCheck >= TimeSpan.FromHours(24) ||
             lastAppUpdateCheck > DateTimeOffset.UtcNow))
            _ = CheckApplicationUpdateAsync(showUpToDate: false);
        var software = Settings.CheckSoftwareOnStart;
        var drivers = Settings.CheckDriversOnStart;
        if (!software && !drivers)
        {
            Syslog.Info(LogEvent.App, L.T("Automatyczne sprawdzanie wersji po uruchomieniu jest wyłączone."));
            ShowScheduledResult();
            await Task.WhenAll(Software.StartupAsync(checkUpdates: false), Drivers.StartupAsync(checkUpdates: false));
            return;
        }
        await CheckVersionsAsync(software, drivers);
        ShowScheduledResult();
    }

    /// <summary>Pokazuje na pasku informacyjnym wynik cichego sprawdzania, które odbyło się od ostatniego otwarcia okna.</summary>
    private void ShowScheduledResult()
    {
        var state = ScheduleState.Load();
        if (state.LastRun is not { } run || Settings.ScheduleSeen is { } seen && seen >= run) return;
        Settings.ScheduleSeen = run;
        var kind = state.Error.Length > 0 || state.Failed.Count > 0 ? BannerKind.Warning
                 : state.Updated.Count > 0 ? BannerKind.Success : BannerKind.Updates;
        if (StartupBanner.Visibility == Visibility.Visible && _bannerText is { } current)
            ShowBanner(() => current() + "\n" + state.Summary(), ShowSoftwareUpdates.IsVisible ? 1 : 0,
                       ShowDriverUpdates.IsVisible ? 1 : 0, kind == BannerKind.Warning ? kind : CurrentKind);
        else
            ShowBanner(state.Summary, 0, 0, kind);
    }

    private void Schedule_Click(object sender, RoutedEventArgs e)
    {
        new Views.ScheduleWindow { Owner = this }.ShowDialog();
        Software.PoliciesChanged();
    }

    private void Policies_Click(object sender, RoutedEventArgs e)
    {
        if (new Views.PoliciesWindow { Owner = this }.ShowDialog() == true) Software.PoliciesChanged();
    }

    private void About_Click(object sender, RoutedEventArgs e) => new Views.AboutWindow { Owner = this }.ShowDialog();

    internal void ShowFromTray()
    {
        if (!IsVisible) Show();
        if (WindowState == WindowState.Minimized) WindowState = WindowState.Normal;
        Activate();
    }

    internal void CheckApplicationUpdateFromTray()
    {
        ShowFromTray();
        _ = CheckApplicationUpdateAsync(showUpToDate: true);
    }

    private async Task CheckApplicationUpdateAsync(bool showUpToDate)
    {
        if (_checkingAppUpdate) return;
        _checkingAppUpdate = true;
        try
        {
            if (string.IsNullOrWhiteSpace(ApplicationUpdateService.Repository))
            {
                if (showUpToDate)
                    Ui.Info(this, L.T("Aktualizacja programu"),
                        L.T("Aby sprawdzać aktualizacje programu, ustaw GitHub owner/name w Directory.Build.props (UpdateRepository)."));
                return;
            }
            if (!showUpToDate) Settings.LastAppUpdateCheck = DateTimeOffset.UtcNow;
            var release = await ApplicationUpdateService.CheckAsync();
            if (release is null)
            {
                if (showUpToDate)
                    Ui.Info(this, L.T("Aktualizacja programu"), L.T("Używasz najnowszej dostępnej wersji programu."));
                return;
            }

            Syslog.Notice(LogEvent.AppUpdate, L.F("Dostępna aktualizacja programu: {0} (obecna wersja: {1}).",
                release.Version, ApplicationUpdateService.CurrentVersion));
            if (!showUpToDate)
            {
                if (Application.Current is App app)
                    app.TrayIcon?.ShowBalloon(
                        L.T("Dostępna aktualizacja programu"),
                        L.F("Dostępna jest wersja {0}. Otwórz menu ikony programu, aby sprawdzić aktualizację.", release.Version));
                return;
            }

            if (!ApplicationUpdateService.IsMsiInstallation())
            {
                var open = Ui.Confirm(this, L.T("Aktualizacja programu"),
                    L.F("Dostępna jest wersja {0}, ale automatyczne aktualizacje wymagają instalacji programu z pakietu MSI. Czy otworzyć stronę wydania?", release.Version),
                    warning: true);
                if (open) Process.Start(new ProcessStartInfo(release.ReleaseUrl) { UseShellExecute = true })?.Dispose();
                return;
            }

            if (!Ui.Confirm(this, L.T("Aktualizacja programu"),
                    L.F("Dostępna jest wersja {0}. Pobrać i zainstalować podpisaną aktualizację MSI teraz?", release.Version),
                    warning: true))
                return;

            var signer = SelfProtection.ExpectedSigner;
            Syslog.Info(LogEvent.AppUpdate, L.T("Pobieranie i weryfikowanie podpisanego instalatora MSI."));
            var installer = await ApplicationUpdateService.DownloadAndVerifyAsync(release, signer);
            Syslog.Notice(LogEvent.AppUpdate, L.F("Podpis i suma SHA-256 aktualizacji {0} są poprawne; uruchamiam instalator Windows.", release.Version));
            ApplicationUpdateService.StartMsiUpgrade(installer);
        }
        catch (Exception ex) when (ex is HttpRequestException or IOException or InvalidDataException or
                                       CryptographicException or UnauthorizedAccessException or
                                       InvalidOperationException or System.ComponentModel.Win32Exception or
                                       System.Text.Json.JsonException or OperationCanceledException)
        {
            Syslog.Error(LogEvent.AppUpdate, L.T("Nie udało się sprawdzić lub zainstalować aktualizacji programu."), ex);
            if (showUpToDate) Ui.Error(this, L.T("Aktualizacja programu"), ex.Message);
        }
        finally
        {
            _checkingAppUpdate = false;
        }
    }

    private void AutoAppUpdates_Click(object sender, RoutedEventArgs e)
    {
        Settings.CheckAppUpdatesOnStart = AutoAppUpdates.IsChecked;
        Syslog.Info(LogEvent.Settings, L.F("Automatyczne sprawdzanie aktualizacji programu po uruchomieniu: {0}.",
                                           YesNo(AutoAppUpdates.IsChecked)));
    }

    private void Window_StateChanged(object? sender, EventArgs e)
    {
        if (WindowState != WindowState.Minimized) return;
        Hide();
        ShowTrayHint();
    }

    private void Window_Closing(object? sender, System.ComponentModel.CancelEventArgs e)
    {
        if (_allowClose) return;
        e.Cancel = true;
        Hide();
        ShowTrayHint();
    }

    private void ShowTrayHint()
    {
        if (_trayNoticeShown) return;
        _trayNoticeShown = true;
        if (Application.Current is App app)
            app.TrayIcon?.ShowBalloon(
                L.T("Bezpieczny Aktualizator działa w zasobniku systemowym."),
                L.T("Kliknij dwukrotnie ikonę, aby otworzyć okno. Użyj menu ikony, aby zakończyć program."));
    }

    internal void ExitFromTray()
    {
        _allowClose = true;
        Close();
    }

    /// <summary>Skanuje oba widoki i sprawdza dostępne wersje programów (winget) i/lub sterowników (Windows Update) równolegle.</summary>
    private async Task CheckVersionsAsync(bool software, bool drivers)
    {
        if (_checking || Software.IsBusy || Drivers.IsBusy) return;
        _checking = true;
        try
        {
            Syslog.Notice(LogEvent.App, L.F("Automatyczne sprawdzanie wersji: programy - {0}, sterowniki - {1}.",
                                            YesNo(software), YesNo(drivers)));
            ShowBanner(() => L.T("Trwa sprawdzanie dostępnych wersji w tle..."), 0, 0, BannerKind.Busy);
            var softwareTask = Software.StartupAsync(checkUpdates: software);
            var driversTask = Drivers.StartupAsync(checkUpdates: drivers);
            await Task.WhenAll(softwareTask, driversTask);
            int? sw = software ? softwareTask.Result : null;
            int? drv = drivers ? driversTask.Result : null;
            var summary = StartupSummary(software, sw, drivers, drv);
            Syslog.Notice(LogEvent.App, summary());
            var kind = software && sw is null || drivers && drv is null ? BannerKind.Warning
                     : sw > 0 || drv > 0 ? BannerKind.Updates : BannerKind.Success;
            ShowBanner(summary, sw ?? 0, drv ?? 0, kind);
        }
        finally
        {
            _checking = false;
        }
    }

    private static string YesNo(bool value) => value ? L.T("tak") : L.T("nie");

    internal static Func<string> StartupSummary(bool software, int? sw, bool drivers, int? drv) => () =>
    {
        var parts = new List<string>();
        if (software)
            parts.Add(sw is { } s ? L.F("aktualizacje programów: {0}", s) : L.T("programy: nie udało się sprawdzić"));
        if (drivers)
            parts.Add(drv is { } d ? L.F("nowsze sterowniki: {0}", d) : L.T("sterowniki: nie udało się sprawdzić"));
        var text = L.F("Sprawdzanie wersji zakończone ({0:HH:mm}) - {1}.", DateTime.Now, string.Join(", ", parts));
        if ((!software || sw == 0) && (!drivers || drv == 0)) text += " " + L.T("Wszystko jest aktualne.");
        else if (sw is null && software || drv is null && drivers) text += " " + L.T("Szczegóły w zakładce „Dziennik”.");
        return text;
    };

    private enum BannerKind { Busy, Updates, Success, Warning }

    private BannerKind CurrentKind { get; set; }

    private void ShowBanner(Func<string> text, int softwareUpdates, int driverUpdates, BannerKind kind)
    {
        _bannerText = text;
        BannerText.Text = text();
        ShowSoftwareUpdates.Visibility = softwareUpdates > 0 ? Visibility.Visible : Visibility.Collapsed;
        ShowDriverUpdates.Visibility = driverUpdates > 0 ? Visibility.Visible : Visibility.Collapsed;
        // Ikona (Segoe Fluent Icons) i kolory zależne od motywu, jak w kontrolce InfoBar.
        var (glyph, background, foreground) = kind switch
        {
            BannerKind.Busy => ("\uE895", "InfoBarInformationalSeverityBackgroundBrush", "AccentFillColorDefaultBrush"),
            BannerKind.Updates => ("\uE896", "InfoBarInformationalSeverityBackgroundBrush", "AccentFillColorDefaultBrush"),
            BannerKind.Success => ("\uE930", "InfoBarSuccessSeverityBackgroundBrush", "SystemFillColorSuccessBrush"),
            _ => ("\uE7BA", "InfoBarWarningSeverityBackgroundBrush", "SystemFillColorCautionBrush"),
        };
        CurrentKind = kind;
        BannerIcon.Text = glyph;
        StartupBanner.SetResourceReference(Border.BackgroundProperty, background);
        BannerIcon.SetResourceReference(TextBlock.ForegroundProperty, foreground);
        StartupBanner.Visibility = Visibility.Visible;
    }

    private void CloseBanner_Click(object sender, RoutedEventArgs e)
    {
        StartupBanner.Visibility = Visibility.Collapsed;
        _bannerText = null;
    }

    private void ShowSoftwareUpdates_Click(object sender, RoutedEventArgs e)
    {
        Tabs.SelectedIndex = 0;
        Software.ShowOnlyUpdates();
    }

    private void ShowDriverUpdates_Click(object sender, RoutedEventArgs e)
    {
        Tabs.SelectedIndex = 1;
        Drivers.ShowOnlyUpdates();
    }

    private void AutoCheck_Click(object sender, RoutedEventArgs e)
    {
        var menu = AutoCheckButton.ContextMenu;
        menu.PlacementTarget = AutoCheckButton;
        menu.Placement = System.Windows.Controls.Primitives.PlacementMode.Bottom;
        menu.IsOpen = true;
    }

    private void AutoOption_Click(object sender, RoutedEventArgs e)
    {
        Settings.CheckSoftwareOnStart = AutoSoftware.IsChecked;
        Settings.CheckDriversOnStart = AutoDrivers.IsChecked;
        Syslog.Info(LogEvent.Settings, L.F("Automatyczne sprawdzanie po uruchomieniu: programy - {0}, sterowniki - {1}.",
                                           YesNo(AutoSoftware.IsChecked), YesNo(AutoDrivers.IsChecked)));
    }

    private async void CheckNow_Click(object sender, RoutedEventArgs e)
    {
        if (_checking || Software.IsBusy || Drivers.IsBusy)
        {
            Ui.Info(this, L.T("Sprawdź teraz"), L.T("Trwa inna operacja. Spróbuj ponownie po jej zakończeniu."));
            return;
        }
        await CheckVersionsAsync(true, true);
    }

    private void Theme_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (!IsLoaded || ThemeBox.SelectedItem is not ComboBoxItem { Tag: string tag } || !Enum.TryParse<AppTheme>(tag, out var theme)) return;
        Theme.Apply(theme);
        Settings.Theme = theme;
        Syslog.Info(LogEvent.Settings, L.F("Zmieniono motyw okna: {0}.", ((ComboBoxItem)ThemeBox.SelectedItem).Content));
    }

    private void Language_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (LanguageBox.SelectedItem is not LanguageInfo language || language.Code == L.Language) return;
        L.Language = language.Code;
        Settings.SaveLanguage(language.Code);
        Syslog.Info(LogEvent.Settings, L.F("Zmieniono język interfejsu: {0} ({1}).", language.NativeName, language.Code));
    }

    /// <summary>Otwiera Eksplorator z zaznaczonym plikiem dziennika syslog.</summary>
    private void LogFile_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            Directory.CreateDirectory(Syslog.Directory);
            var args = File.Exists(Syslog.FilePath) ? $"/select,\"{Syslog.FilePath}\"" : $"\"{Syslog.Directory}\"";
            Process.Start(new ProcessStartInfo("explorer.exe", args) { UseShellExecute = true })?.Dispose();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception)
        {
            Ui.Error(this, L.T("Błąd"), ex.Message);
        }
    }
}