using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using BezpiecznyAktualizator.Core.Localization;
using BezpiecznyAktualizator.Core.Logging;
using BezpiecznyAktualizator.Core.Updates;
using BezpiecznyAktualizator.Services;
using Microsoft.Win32;

namespace BezpiecznyAktualizator.Views;

public partial class WindowsUpdateView : UserControl
{
    private readonly BackgroundRunner _runner;
    private List<WindowsUpdateItem> _items = [];
    private ListCollectionView? _view;
    private bool _searched;
    private bool _offlineScan;

    public WindowsUpdateView()
    {
        InitializeComponent();
        _runner = new BackgroundRunner(this, Toolbar, Progress, StatusText, LogBox, SummaryText, LogEvent.WindowsUpdate);
        SetItems([]);
        L.LanguageChanged += Refresh;
    }

    public bool IsBusy => _runner.IsBusy;

    private string SummaryText() => !_searched
        ? L.T("Kliknij „Szukaj aktualizacji Windows”.")
        : _offlineScan
            ? L.F("Skan offline: {0} brakujących aktualizacji zabezpieczeń | z danymi CVE: {1}",
                _items.Count, _items.Count(HasCveData))
            : L.F("Aktualizacje: {0} | pobrane: {1} | z danymi CVE: {2}",
                _items.Count, _items.Count(i => i.IsDownloaded), _items.Count(HasCveData));

    private static bool HasCveData(WindowsUpdateItem item) =>
        item.CveIds.Count > 0 || item.MsrcCveIds.Count > 0;

    private void SetItems(List<WindowsUpdateItem> items)
    {
        _items = items;
        _view = new ListCollectionView(_items) { Filter = item => Matches((WindowsUpdateItem)item) };
        Table.ItemsSource = _view;
        Refresh();
    }

    private bool Matches(WindowsUpdateItem item)
    {
        var text = FilterBox.Text.Trim();
        if (text.Length == 0) return true;
        return new[] { item.Title, item.KbText, item.CveText, item.Severity, item.Identity.ToString() }
            .Any(value => value.Contains(text, StringComparison.CurrentCultureIgnoreCase));
    }

    private void Refresh()
    {
        if (_view is null) return;
        _view.Refresh();
        CountLabel.Text = L.F("Wyświetlono {0} z {1}", _view.Count, _items.Count);
        _runner.UpdateSummary();
        ShowDetails();
    }

    private void Filter_Changed(object sender, TextChangedEventArgs e)
    {
        if (_view is not null) Refresh();
    }

    private void Table_SelectionChanged(object sender, SelectionChangedEventArgs e) => ShowDetails();

    private void ShowDetails()
    {
        if (Table.SelectedItem is not WindowsUpdateItem item)
        {
            Details.Text = "";
            return;
        }
        var lines = new List<string> { item.Title, "" };
        lines.AddRange(Ui.FormatFields([
            (L.T("Identyfikator aktualizacji"), item.Identity.ToString()),
            ("KB", item.KbText.Length > 0 ? item.KbText : L.T("(brak)")),
            ("CVE", item.CveText),
            (L.T("CVE (dokładne dopasowanie MSRC do KB)"), string.Join(", ", item.MsrcCveIds)),
            (L.T("Ważność"), item.Severity.Length > 0 ? item.Severity : L.T("Nieznany")),
            (L.T("Rozmiar"), item.SizeText),
            (L.T("Status"), item.DownloadText),
            (L.T("Wymagana"), item.IsMandatory ? L.T("tak") : L.T("nie")),
            (L.T("Wsparcie"), item.SupportUrl),
            (L.T("Katalog Microsoft Update"), item.CatalogUrl),
        ]));
        if (item.CveIds.Count == 0)
            lines.Add("\n" + L.T("Windows Update nie udostępnił identyfikatorów CVE dla tej aktualizacji; nie jest to potwierdzenie braku podatności."));
        if (item.CveError.Length > 0)
            lines.Add("\n" + L.F("Nie udało się odczytać części metadanych CVE: {0}", item.CveError));
        if (item.MsrcError.Length > 0)
            lines.Add("\n" + L.F("Nie udało się uzyskać korelacji MSRC: {0}", item.MsrcError));
        if (item.IsOfflineScan)
            lines.Add("\n" + L.T("Wynik skanowania podpisanego katalogu offline. Katalog zawiera wyłącznie metadane aktualizacji zabezpieczeń, nie ich instalatory."));
        if (item.Description.Length > 0) lines.Add("\n" + item.Description);
        if (item.EulaText.Length > 0)
            lines.Add("\n" + L.T("Warunki licencji aktualizacji:") + "\n" + item.EulaText);
        Details.Text = string.Join(Environment.NewLine, lines);
    }

    private List<WindowsUpdateItem> Selected() => Table.SelectedItems.Cast<WindowsUpdateItem>().ToList();

    private bool CanStart() => Window.GetWindow(this) is not MainWindow main || main.CanStartWindowsUpdate(this);

    private async void Search_Click(object sender, RoutedEventArgs e) => await SearchAsync(interactive: true);

    private async Task SearchAsync(bool interactive)
    {
        if (!CanStart()) return;
        WindowsUpdateSearchResult? result = null;
        var ok = await _runner.RunWithProgressAsync(LogEvent.WindowsUpdate, L.T("Wyszukiwanie aktualizacji Windows..."),
            async progress =>
            {
                progress.Report(L.T("Odczytywanie listy aktualizacji z usługi Windows Update..."));
                result = await Task.Run(WindowsUpdateAgent.Search);
                progress.Report(L.T("Pobieranie metadanych CVE z MSRC..."));
                var warnings = await MsrcWindowsUpdateClient.EnrichAsync(result.Updates);
                if (warnings.Count > 0)
                    result = result with { Warnings = result.Warnings.Concat(warnings).ToList() };
            }, typeof(WindowsUpdateException));
        if (!ok || result is null) return;
        _searched = true;
        _offlineScan = false;
        SetItems(result.Updates.ToList());
        foreach (var warning in result.Warnings) _runner.Log(warning, SyslogSeverity.Warning);
        foreach (var item in _items.Where(i => i.CveError.Length > 0))
            _runner.Log(L.F("Niepełne metadane CVE dla {0}: {1}", item.Title, item.CveError), SyslogSeverity.Warning);
        _runner.Log(L.F("Windows Update: znaleziono {0} dostępnych aktualizacji.", _items.Count));
        if (result.Warnings.Count > 0)
            Ui.Warn(this, L.T("Windows Update"), string.Join("\n", result.Warnings));
        else if (interactive && _items.Count == 0)
            Ui.Info(this, L.T("Windows Update"), L.T("Windows Update nie oferuje obecnie aktualizacji oprogramowania dla tego komputera."));
    }

    private async void Download_Click(object sender, RoutedEventArgs e) =>
        await RunOperationAsync(WindowsUpdateAction.Download);

    private async void Install_Click(object sender, RoutedEventArgs e) =>
        await RunOperationAsync(WindowsUpdateAction.Install);

    private async Task RunOperationAsync(WindowsUpdateAction action)
    {
        if (!CanStart()) return;
        var selected = Selected();
        if (selected.Count == 0)
        {
            Ui.Info(this, L.T("Brak zaznaczenia"), L.T("Zaznacz aktualizacje Windows na liście."));
            return;
        }
        if (selected.Any(item => item.IsOfflineScan))
        {
            Ui.Warn(this, L.T("Windows Update"),
                L.T("Wyniki skanowania offline służą wyłącznie do raportowania. Pobieranie i instalacja wymagają ponownego wyszukania aktualizacji online."));
            return;
        }
        if (selected.Count > WindowsUpdateAgent.MaxSelection)
        {
            Ui.Warn(this, L.T("Windows Update"), L.F("Jednorazowo można wybrać najwyżej {0} aktualizacji.", WindowsUpdateAgent.MaxSelection));
            return;
        }
        if (action == WindowsUpdateAction.Install && selected.Any(i => !i.IsDownloaded))
        {
            Ui.Warn(this, L.T("Windows Update"), L.T("Najpierw pobierz wszystkie zaznaczone aktualizacje."));
            return;
        }
        var pendingLicenses = selected.Where(i => !i.EulaAccepted).ToList();
        if (pendingLicenses.Any(i => string.IsNullOrWhiteSpace(i.EulaText)))
        {
            Ui.Warn(this, L.T("Warunki licencji"), L.T("Nie można odczytać wymaganych warunków licencji. Aktualizacja nie zostanie wykonana."));
            return;
        }
        var operation = action == WindowsUpdateAction.Download ? L.T("Pobieranie aktualizacji Windows") : L.T("Instalacja aktualizacji Windows");
        var text = string.Join("\n", selected.Take(15).Select(i => "• " + i.Title));
        if (selected.Count > 15) text += "\n…";
        text += "\n\n" + L.T("Operacja używa skonfigurowanej usługi Windows Update i wymaga potwierdzenia UAC.");
        if (action == WindowsUpdateAction.Install)
            text += "\n" + L.T("Instalacja może wymagać ponownego uruchomienia komputera.");
        if (pendingLicenses.Count > 0)
            text += "\n\n" + L.F("{0} aktualizacji wymaga akceptacji licencji. Pełne warunki są w szczegółach każdej pozycji. Kontynuując, akceptujesz te warunki.", pendingLicenses.Count);
        if (!Ui.Confirm(this, operation, text + "\n\n" + L.T("Kontynuować?"), warning: true)) return;

        var ids = selected.Select(i => i.Identity).ToList();
        var exitCode = -1;
        BottomTabs.SelectedIndex = 1;
        var ok = await _runner.RunAsync(LogEvent.WindowsUpdate, operation,
            async () => exitCode = await StartElevatedAsync(action, ids), typeof(WindowsUpdateException));
        if (!ok) return;
        if (exitCode is 0 or 3010)
            _runner.Log(L.T("Operacja Windows Update zakończyła się pomyślnie."), SyslogSeverity.Notice);
        else
            _runner.Log(L.F("Operacja Windows Update nie zakończyła się w pełni pomyślnie (kod {0}).", exitCode), SyslogSeverity.Warning);
        if (exitCode is 3010 or 3011)
            Ui.Warn(this, L.T("Windows Update"), L.T("Wymagane jest ponowne uruchomienie komputera, aby zakończyć instalację."));
        else if (exitCode != 0)
            Ui.Warn(this, L.T("Windows Update"), L.F("Operacja Windows Update nie zakończyła się w pełni pomyślnie (kod {0}).", exitCode));
        await SearchAsync(interactive: false);
    }

    private static async Task<int> StartElevatedAsync(WindowsUpdateAction action, IReadOnlyList<WindowsUpdateIdentity> ids)
    {
        var executable = Environment.ProcessPath ?? throw new WindowsUpdateException(L.T("Nieznana ścieżka programu."));
        if (Path.GetFileNameWithoutExtension(executable).Equals("dotnet", StringComparison.OrdinalIgnoreCase))
        {
            var assembly = Assembly.GetEntryAssembly()?.Location;
            var appHost = string.IsNullOrEmpty(assembly) ? "" : Path.ChangeExtension(assembly, ".exe");
            if (!File.Exists(appHost)) throw new WindowsUpdateException(L.T("Nie znaleziono pliku wykonywalnego programu."));
            executable = appHost;
        }
        var start = new ProcessStartInfo(executable) { UseShellExecute = true, Verb = "runas" };
        start.ArgumentList.Add(WindowsUpdateAgent.OperationArgument);
        start.ArgumentList.Add(action == WindowsUpdateAction.Download ? "download" : "install");
        start.ArgumentList.Add(WindowsUpdateAgent.SerializeSelection(ids));
        try
        {
            using var process = Process.Start(start) ?? throw new WindowsUpdateException(L.T("Nie udało się uruchomić instalatora."));
            await process.WaitForExitAsync();
            return process.ExitCode;
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            throw new WindowsUpdateException(L.T("Anulowano monit kontroli konta użytkownika (UAC)."), ex);
        }
    }

    private async void InstallFile_Click(object sender, RoutedEventArgs e)
    {
        if (!CanStart()) return;
        var dialog = new OpenFileDialog
        {
            Title = L.T("Wybierz plik MSU z Katalogu Microsoft Update"),
            Filter = "MSU (*.msu)|*.msu", CheckFileExists = true,
        };
        if (dialog.ShowDialog(Window.GetWindow(this)) != true) return;
        if (!Ui.Confirm(this, L.T("Instalacja pliku MSU"),
                L.F("Uruchomić instalator Windows Update dla pliku:\n{0}\n\nWybierz tylko plik pobrany z oficjalnego Katalogu Microsoft Update. Instalator systemowy sprawdzi pakiet i może wymagać ponownego uruchomienia.", dialog.FileName),
                warning: true)) return;
        var exitCode = -1;
        var ok = await _runner.RunAsync(LogEvent.WindowsUpdate, L.T("Instalacja pliku MSU"),
            async () => exitCode = await StartStandaloneAsync(dialog.FileName), typeof(WindowsUpdateException));
        if (!ok) return;
        var status = WindowsUpdateStandalone.ClassifyExitCode(exitCode);
        var message = status switch
        {
            StandaloneUpdateStatus.Succeeded => L.T("Instalator Windows zakończył instalację."),
            StandaloneUpdateStatus.RestartRequired => L.T("Wymagane jest ponowne uruchomienie komputera, aby zakończyć instalację."),
            StandaloneUpdateStatus.AlreadyInstalled => L.T("Ta aktualizacja jest już zainstalowana."),
            StandaloneUpdateStatus.NotApplicable => L.T("Aktualizacja nie pasuje do tego komputera lub jest już zainstalowana."),
            _ => L.F("Instalator Windows zwrócił błąd 0x{0:X8}.", unchecked((uint)exitCode)),
        };
        var severity = status switch
        {
            StandaloneUpdateStatus.Failed => SyslogSeverity.Error,
            StandaloneUpdateStatus.NotApplicable => SyslogSeverity.Warning,
            _ => SyslogSeverity.Notice,
        };
        _runner.Log(message, severity);
        if (status is StandaloneUpdateStatus.Succeeded or StandaloneUpdateStatus.AlreadyInstalled)
            Ui.Info(this, L.T("Instalacja pliku MSU"), message);
        else Ui.Warn(this, L.T("Instalacja pliku MSU"), message);
        if (status is StandaloneUpdateStatus.Succeeded or StandaloneUpdateStatus.RestartRequired)
            await SearchAsync(interactive: false);
    }

    private static async Task<int> StartStandaloneAsync(string file)
    {
        var executable = Path.Combine(Environment.SystemDirectory, "wusa.exe");
        var start = new ProcessStartInfo(executable) { UseShellExecute = true, Verb = "runas" };
        start.ArgumentList.Add(file);
        try
        {
            using var process = Process.Start(start) ?? throw new WindowsUpdateException(L.T("Nie udało się uruchomić instalatora."));
            await process.WaitForExitAsync();
            return process.ExitCode;
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            throw new WindowsUpdateException(L.T("Anulowano monit kontroli konta użytkownika (UAC)."), ex);
        }
    }

    private void Catalog_Click(object sender, RoutedEventArgs e)
    {
        var selected = Selected();
        if (selected.Count > 5 && !Ui.Confirm(this, L.T("Katalog Microsoft Update"), L.F("Otworzyć {0} kart przeglądarki?", selected.Count)))
            return;
        try
        {
            if (selected.Count == 0) Ui.OpenUrl(MicrosoftUpdateCatalog.Search(""));
            else foreach (var item in selected) Ui.OpenUrl(item.CatalogUrl);
        }
        catch (Win32Exception ex) { Ui.Error(this, L.T("Błąd"), ex.Message); }
    }

    private void Offline_Click(object sender, RoutedEventArgs e) =>
        new OfflinePackageWindow(Selected()) { Owner = Window.GetWindow(this) }.ShowDialog();

    private async void OfflineScan_Click(object sender, RoutedEventArgs e)
    {
        if (!CanStart()) return;
        var dialog = new OpenFileDialog
        {
            Title = L.T("Wybierz katalog skanowania Windows Update"),
            Filter = "Katalog skanowania Windows Update (*.cab)|*.cab",
            CheckFileExists = true,
        };
        if (dialog.ShowDialog(Window.GetWindow(this)) != true) return;
        WindowsUpdateSearchResult? result = null;
        var ok = await _runner.RunWithProgressAsync(LogEvent.WindowsUpdate, L.T("Skanowanie komputera przy użyciu katalogu offline..."),
            async progress =>
            {
                progress.Report(L.T("Wyszukiwanie brakujących aktualizacji w katalogu offline..."));
                result = await Task.Run(() => WindowsUpdateAgent.SearchOffline(dialog.FileName));
            },
            typeof(WindowsUpdateException));
        if (!ok || result is null) return;
        _searched = true;
        _offlineScan = true;
        SetItems(result.Updates.ToList());
        foreach (var warning in result.Warnings) _runner.Log(warning, SyslogSeverity.Warning);
        _runner.Log(L.F("Skan offline Windows Update: znaleziono {0} brakujących aktualizacji zabezpieczeń.", _items.Count));
        Ui.Info(this, L.T("Skanowanie Windows Update offline"),
            L.F("Skan zakończony. Znaleziono {0} brakujących aktualizacji zabezpieczeń. Katalog nie zawiera plików instalacyjnych; wyniki możesz zapisać jako raport.", _items.Count));
    }

    private async void Export_Click(object sender, RoutedEventArgs e)
    {
        if (!_searched)
        {
            Ui.Info(this, L.T("Brak wyników"), L.T("Najpierw wyszukaj aktualizacje lub wykonaj skan offline."));
            return;
        }
        var dialog = new SaveFileDialog
        {
            Title = L.T("Eksportuj raport Windows Update"), DefaultExt = ".json", AddExtension = true,
            Filter = "JSON (*.json)|*.json",
            FileName = $"windows_update_{DateTime.Now:yyyyMMdd_HHmm}.json",
            OverwritePrompt = true,
        };
        if (dialog.ShowDialog(Window.GetWindow(this)) != true) return;
        var report = new
        {
            generatedUtc = DateTimeOffset.UtcNow,
            scanType = _offlineScan ? "offline-security-catalog" : "configured-windows-update-service",
            updates = _items.Select(item => new
            {
                item.Title,
                updateId = item.Identity.UpdateId,
                revision = item.Identity.Revision,
                item.KbIds,
                cveIds = item.CveIds,
                item.Severity,
                item.LastDeploymentChangeTime,
                item.IsDownloaded,
                item.IsMandatory,
                item.CveError,
            }),
        };
        try
        {
            var json = JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true });
            await File.WriteAllTextAsync(dialog.FileName, json, new UTF8Encoding(false));
            _runner.Log(L.F("Wyeksportowano raport Windows Update: {0}", dialog.FileName));
            Ui.Info(this, L.T("Eksportuj raport"), L.T("Raport został zapisany. Sprawdź jego zawartość przed udostępnieniem; może ujawniać stan aktualizacji komputera."));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _runner.Log(L.F("Nie udało się zapisać raportu Windows Update: {0}", ex.Message), SyslogSeverity.Error);
            Ui.Error(this, L.T("Błąd"), ex.Message);
        }
    }
}
