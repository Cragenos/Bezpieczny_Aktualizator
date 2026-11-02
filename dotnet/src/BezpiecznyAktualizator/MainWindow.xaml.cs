using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Controls;
using BezpiecznyAktualizator.Core.Localization;
using BezpiecznyAktualizator.Core.Logging;
using BezpiecznyAktualizator.Core.History;
using BezpiecznyAktualizator.Core.Scheduling;
using BezpiecznyAktualizator.Core.Updates;
using BezpiecznyAktualizator.Services;
using Microsoft.Win32;

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
        PreviewAppUpdates.IsChecked = Settings.IncludePreviewReleases;
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
        PoliciesChanged();
    }

    private void Policies_Click(object sender, RoutedEventArgs e)
    {
        if (new Views.PoliciesWindow { Owner = this }.ShowDialog() == true) PoliciesChanged();
    }

    internal void PoliciesChanged()
    {
        Software.PoliciesChanged();
        Store.PoliciesChanged();
    }

    private void LogHistory_Click(object sender, RoutedEventArgs e) =>
        new Views.LogHistoryWindow { Owner = this }.ShowDialog();

    private void Notifications_Click(object sender, RoutedEventArgs e) =>
        new Views.NotificationWindow { Owner = this }.ShowDialog();

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
            var check = await ApplicationUpdateService.CheckLatestAsync(Settings.IncludePreviewReleases);
            if (check.Status == ReleaseCheckStatus.NoRelease)
            {
                Syslog.Warning(LogEvent.AppUpdate, Settings.IncludePreviewReleases
                    ? L.T("Brak nowszego wydania w wybranym kanale aktualizacji.")
                    : L.T("Brak opublikowanego stabilnego wydania aktualizacji."));
                if (showUpToDate)
                    Ui.Warn(this, L.T("Aktualizacja programu"),
                        Settings.IncludePreviewReleases
                            ? L.T("Repozytorium jest dostępne, ale nie ma nowszego wydania w wybranym kanale.")
                            : L.T("Repozytorium jest dostępne, ale nie opublikowano jeszcze stabilnego wydania."));
                return;
            }
            if (check.Status == ReleaseCheckStatus.RepositoryUnavailable)
            {
                Syslog.Error(LogEvent.AppUpdate, L.F("Nie znaleziono repozytorium aktualizacji GitHub: {0}.", ApplicationUpdateService.Repository));
                if (showUpToDate)
                    Ui.Error(this, L.T("Aktualizacja programu"),
                        L.F("Nie znaleziono repozytorium GitHub {0}. Sprawdź ustawienie UpdateRepository.", ApplicationUpdateService.Repository));
                return;
            }
            if (check.Status == ReleaseCheckStatus.MissingInstaller)
            {
                Syslog.Error(LogEvent.AppUpdate, L.T("Nowsze wydanie nie zawiera wymaganego instalatora MSI lub pliku SHA-256."));
                if (showUpToDate)
                    Ui.Error(this, L.T("Aktualizacja programu"),
                        L.T("Nowsze wydanie nie zawiera poprawnego instalatora MSI i sumy SHA-256. Sprawdź pliki wydania."));
                return;
            }
            if (check.Status == ReleaseCheckStatus.UpToDate)
            {
                Syslog.Info(LogEvent.AppUpdate, L.T("Nie znaleziono nowszej wersji programu."));
                if (showUpToDate)
                    Ui.Info(this, L.T("Aktualizacja programu"), L.T("Używasz najnowszej dostępnej wersji programu."));
                return;
            }
            var release = check.Release ?? throw new InvalidDataException("Release check returned no installer.");

            Syslog.Notice(LogEvent.AppUpdate, L.F("Dostępna aktualizacja programu: {0} (obecna wersja: {1}).",
                release.Tag, ApplicationUpdateService.CurrentVersion));
            var notes = ReleaseNotesSnippet(release.Notes);
            var notesText = notes.Length == 0 ? "" : "\n\n" + L.F("Informacje o wydaniu: {0}", notes);
            if (!showUpToDate)
            {
                if (Application.Current is App app)
                    app.TrayIcon?.ShowBalloon(
                        L.T("Dostępna aktualizacja programu"),
                        L.F("Dostępna jest wersja {0}. Otwórz menu ikony programu, aby sprawdzić aktualizację.", release.Tag));
                return;
            }

            if (release.IsPrerelease)
            {
                var openPreview = Ui.Confirm(this, L.T("Testowe wydanie programu"),
                    L.F("Dostępne jest testowe wydanie {0}. Nie jest instalowane automatycznie; otworzyć stronę wydania i pobrać je ręcznie?", release.Tag) + notesText,
                    warning: true);
                if (openPreview) Ui.OpenUrl(release.ReleaseUrl);
                return;
            }

            if (!ApplicationUpdateService.IsMsiInstallation())
            {
                var open = Ui.Confirm(this, L.T("Aktualizacja programu"),
                    L.F("Dostępna jest wersja {0}, ale automatyczne aktualizacje wymagają instalacji programu z pakietu MSI. Czy otworzyć stronę wydania?", release.Tag) + notesText,
                    warning: true);
                if (open) Process.Start(new ProcessStartInfo(release.ReleaseUrl) { UseShellExecute = true })?.Dispose();
                return;
            }

            if (!Ui.Confirm(this, L.T("Aktualizacja programu"),
                    L.F("Dostępna jest wersja {0}. Pobrać i zainstalować podpisaną aktualizację MSI teraz?", release.Tag) + notesText,
                    warning: true))
                return;

            var signers = SelfProtection.ExpectedSigners;
            Syslog.Info(LogEvent.AppUpdate, L.T("Pobieranie i weryfikowanie podpisanego instalatora MSI."));
            var installer = await ApplicationUpdateService.DownloadAndVerifyAsync(release, signers);
            var localData = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "BezpiecznyAktualizator");
            var settings = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "BezpiecznyAktualizator", "settings.json");
            var backup = UpdateStateBackup.Create(Path.Combine(localData, "Backups"), settings, localData, DateTimeOffset.Now);
            if (!UpdateStateBackup.Verify(backup.Path))
                throw new InvalidDataException("Updater settings backup verification failed.");
            Syslog.Notice(LogEvent.AppUpdate, L.F("Zapisano kopię ustawień i historii aktualizacji: {0} (SHA-256 {1}).",
                backup.Path, backup.Sha256));
            Syslog.Notice(LogEvent.AppUpdate, L.F("Podpis i suma SHA-256 aktualizacji {0} są poprawne; uruchamiam instalator Windows.", release.Version));
            ApplicationUpdateService.StartMsiUpgrade(installer);
        }
        catch (Exception ex) when (ex is HttpRequestException or IOException or InvalidDataException or
                                       CryptographicException or UnauthorizedAccessException or
                                       InvalidOperationException or System.ComponentModel.Win32Exception or
                                       System.Text.Json.JsonException or OperationCanceledException)
        {
            Syslog.Error(LogEvent.AppUpdate, L.T("Nie udało się sprawdzić lub zainstalować aktualizacji programu."), ex);
            if (showUpToDate)
            {
                var message = ex switch
                {
                    HttpRequestException => L.F("Błąd połączenia z GitHub Releases: {0}", ex.Message),
                    OperationCanceledException => L.T("Przekroczono limit czasu połączenia lub anulowano operację."),
                    InvalidDataException or System.Text.Json.JsonException => L.F("Wydanie aktualizacji ma nieprawidłowe dane: {0}", ex.Message),
                    CryptographicException => L.F("Nie udało się zweryfikować podpisu aktualizacji: {0}", ex.Message),
                    _ => ex.Message,
                };
                Ui.Error(this, L.T("Aktualizacja programu"), message);
            }
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

    private void PreviewAppUpdates_Click(object sender, RoutedEventArgs e)
    {
        Settings.IncludePreviewReleases = PreviewAppUpdates.IsChecked == true;
        Syslog.Info(LogEvent.Settings, L.F("Uwzględnianie testowych wydań programu: {0}.",
            YesNo(PreviewAppUpdates.IsChecked == true)));
    }

    private static string ReleaseNotesSnippet(string notes)
    {
        var plain = Regex.Replace(notes, @"\s+", " ").Trim();
        const int maximumLength = 600;
        return plain.Length <= maximumLength ? plain : plain[..maximumLength] + "…";
    }

    private void ExportDiagnostics_Click(object sender, RoutedEventArgs e)
    {
        if (!Ui.Confirm(this, L.T("Pakiet diagnostyczny"),
                L.T("Pakiet zawiera wersję aplikacji, wersję systemu i ostatnie ostrzeżenia/błędy. Nie zawiera ustawień, klucza API, historii aktualizacji ani listy zainstalowanych programów. Wpisy mogą zawierać nazwy programów lub ścieżki; przed udostępnieniem sprawdź zapisany plik. Kontynuować?"),
                warning: true))
            return;

        var dialog = new SaveFileDialog
        {
            Title = L.T("Zapisz pakiet diagnostyczny"),
            FileName = "BezpiecznyAktualizator-diagnostics.zip",
            DefaultExt = ".zip",
            AddExtension = true,
            Filter = "ZIP (*.zip)|*.zip",
        };
        if (dialog.ShowDialog(this) != true) return;
        try
        {
            var path = DiagnosticsBundle.Create(dialog.FileName, Syslog.ReadRecentIssues());
            Syslog.Info(LogEvent.Report, L.F("Zapisano pakiet diagnostyczny: {0}", path));
            Ui.Info(this, L.T("Pakiet diagnostyczny"), L.F("Zapisano pakiet diagnostyczny: {0}", path));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException or
                                       System.Security.SecurityException or ArgumentException)
        {
            Syslog.Error(LogEvent.Report, L.T("Nie udało się utworzyć pakietu diagnostycznego."), ex);
            Ui.Error(this, L.T("Błąd"), L.F("Nie udało się utworzyć pakietu diagnostycznego: {0}", ex.Message));
        }
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

    internal bool CanStartWindowsUpdate(FrameworkElement requester, bool notify = true)
    {
        if ((requester != Drivers && Drivers.IsBusy) || (requester != WindowsUpdates && WindowsUpdates.IsBusy))
        {
            if (notify) Ui.Info(requester, L.T("Windows Update"), L.T("Trwa inna operacja Windows Update. Spróbuj ponownie po jej zakończeniu."));
            return false;
        }
        return true;
    }

    internal bool CanStartWinget(FrameworkElement requester)
    {
        if ((requester != Software && Software.IsBusy) || (requester != Store && Store.IsBusy))
        {
            Ui.Info(requester, L.T("Microsoft Store"), L.T("Trwa inna operacja. Spróbuj ponownie po jej zakończeniu."));
            return false;
        }
        return true;
    }

    /// <summary>Skanuje oba widoki i sprawdza dostępne wersje programów (winget) i/lub sterowników (Windows Update) równolegle.</summary>
    private async Task CheckVersionsAsync(bool software, bool drivers)
    {
        if (_checking || Software.IsBusy || Drivers.IsBusy || WindowsUpdates.IsBusy || Store.IsBusy) return;
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
        if (_checking || Software.IsBusy || Drivers.IsBusy || WindowsUpdates.IsBusy || Store.IsBusy)
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