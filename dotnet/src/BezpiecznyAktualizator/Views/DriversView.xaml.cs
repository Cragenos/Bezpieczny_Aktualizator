using System.Collections;
using System.ComponentModel;
using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using BezpiecznyAktualizator.Core.Drivers;
using BezpiecznyAktualizator.Core.Localization;
using BezpiecznyAktualizator.Core.Logging;
using BezpiecznyAktualizator.Core.Security;
using BezpiecznyAktualizator.Services;

namespace BezpiecznyAktualizator.Views;

public partial class DriversView : UserControl
{
    private readonly BackgroundRunner _runner;
    private List<Driver> _items = [];
    private ListCollectionView _view;
    private bool _updatesChecked;

    public DriversView()
    {
        InitializeComponent();
        _runner = new BackgroundRunner(this, Toolbar, Progress, StatusText, LogBox, SummaryText, LogEvent.DriverScan);
        _view = CreateView();
        L.LanguageChanged += RefreshTable;
    }

    /// <summary>
    /// Wywoływane po uruchomieniu programu: skanuje sterowniki i (opcjonalnie) sprawdza nowsze wersje w Windows Update.
    /// Zwraca liczbę dostępnych sterowników albo null, gdy sprawdzenie nie zostało wykonane.
    /// </summary>
    public async Task<int?> StartupAsync(bool checkUpdates)
    {
        if (!await ScanAsync() || !checkUpdates) return null;
        return await SearchUpdatesAsync(interactive: false);
    }

    public bool IsBusy => _runner.IsBusy;

    /// <summary>Pokazuje tylko urządzenia z dostępną aktualizacją lub problemem.</summary>
    public void ShowOnlyUpdates() => OnlyUpdates.IsChecked = true;

    // ------------------------------------------------------------------ lista
    private ListCollectionView CreateView()
    {
        var view = new ListCollectionView(_items) { Filter = o => Matches((Driver)o) };
        Table.ItemsSource = view;
        return view;
    }

    private void SetItems(List<Driver> items)
    {
        var selected = SelectedItems();
        _items = items;
        foreach (var d in _items) DriverAssessor.Apply(d);
        _view = CreateView();
        Restore(selected);
        RefreshTable();
    }

    internal static bool IsGeneric(Driver d) =>
        d.Provider.Equals("Microsoft", StringComparison.OrdinalIgnoreCase) && d.Update is null && d.ErrorCode == 0;

    private bool Matches(Driver d)
    {
        if (OnlyUpdates.IsChecked == true && !(d.HasUpdate || d.HasProblem)) return false;
        if (HideGeneric.IsChecked == true && IsGeneric(d)) return false;
        var needle = FilterBox.Text.Trim();
        if (needle.Length == 0) return true;
        IEnumerable<string> values = [d.DeviceName, d.DeviceClass, d.Version, d.Date, d.AvailableDisplay, d.Status,
                                      d.ProviderDisplay, d.SignatureText, d.SecurityLevelDisplay, .. d.HardwareIds];
        return values.Any(v => v.Contains(needle, StringComparison.CurrentCultureIgnoreCase));
    }

    private void RefreshTable()
    {
        var selected = SelectedItems();
        _view.Refresh();
        Restore(selected);
        CountLabel.Text = L.F("Wyświetlono {0} z {1}", _view.Count, _items.Count);
        _runner.UpdateSummary();
        ShowDetails();
    }

    private void Restore(IEnumerable<Driver> selected)
    {
        Table.SelectedItems.Clear();
        foreach (var d in selected)
            if (_view.Contains(d)) Table.SelectedItems.Add(d);
    }

    private List<Driver> SelectedItems() => Table.SelectedItems.Cast<Driver>().ToList();

    private string SummaryText()
    {
        var wu = _updatesChecked ? "" : " " + L.T("(kliknij „Szukaj aktualizacji”)");
        return L.F("Urządzeń: {0} | z aktualizacją: {1}", _items.Count, _items.Count(d => d.HasUpdate)) + wu + " | " +
               L.F("z problemem: {0} | niepodpisanych sterowników: {1}",
                   _items.Count(d => d.ErrorCode != 0), _items.Count(d => d.IsSigned == false));
    }

    private void Filter_Changed(object sender, RoutedEventArgs e)
    {
        if (_view is not null) RefreshTable();
    }

    private void Table_SelectionChanged(object sender, SelectionChangedEventArgs e) => ShowDetails();

    /// <summary>Wersje sortowane numerycznie (10.0.2 &gt; 9.1), pozostałe kolumny alfabetycznie.</summary>
    private void Table_Sorting(object sender, DataGridSortingEventArgs e)
    {
        var path = e.Column.SortMemberPath;
        if (path is not (nameof(Driver.Version) or nameof(Driver.AvailableDisplay))) return;
        e.Handled = true;
        var direction = e.Column.SortDirection == ListSortDirection.Ascending
            ? ListSortDirection.Descending : ListSortDirection.Ascending;
        foreach (var c in Table.Columns) c.SortDirection = null;
        e.Column.SortDirection = direction;
        _view.CustomSort = new VersionComparer(path, direction);
    }

    private sealed class VersionComparer(string path, ListSortDirection direction) : IComparer
    {
        public int Compare(object? x, object? y)
        {
            static string Get(object? o, string p) => o is Driver d
                ? p == nameof(Driver.Version) ? d.Version : d.AvailableDisplay
                : "";
            var result = DriverMatcher.CompareVersions(Get(x, path), Get(y, path));
            return direction == ListSortDirection.Ascending ? result : -result;
        }
    }

    private void UiLog(string line)
    {
        if (Dispatcher.CheckAccess()) _runner.Log(line);
        else Dispatcher.BeginInvoke(() => _runner.Log(line));
    }

    private void ShowDetails()
    {
        if (Table.SelectedItem is not Driver d) return;
        var lines = new List<string> { d.DeviceName, "" };
        lines.AddRange(Ui.FormatFields([
            (L.T("Klasa urządzenia"), d.DeviceClass),
            (L.T("Producent urządzenia"), d.Manufacturer),
            (L.T("Dostawca sterownika"), d.Provider),
            (L.T("Wersja / data"), $"{d.Version} / {d.Date}"),
            (L.T("Plik INF"), d.InfName),
            (L.T("Podpis"), d.SignatureText + (d.Signer.Length > 0 ? $" ({d.Signer})" : "")),
            (L.T("Status"), d.Status),
            (L.T("Identyfikator"), d.DeviceId),
        ]));
        lines.Add(L.T("Identyfikatory sprzętu:"));
        lines.AddRange(d.HardwareIds.Count > 0 ? d.HardwareIds.Take(6).Select(h => $"    {h}") : ["    " + L.T("(brak)")]);
        if (d.Update is { } u)
        {
            lines.AddRange([
                "", L.T("AKTUALIZACJA Z WINDOWS UPDATE:"),
                $"    {u.Title}",
                "    " + L.F("Model: {0} | Dostawca: {1} | Klasa: {2}", u.Model, u.Provider, u.DriverClass),
                "    " + L.F("Wersja: {0} | Data: {1} | Rozmiar: {2}", u.Version.Length > 0 ? u.Version : "?", u.Date, u.SizeText),
                "    " + L.F("Identyfikator aktualizacji: {0}", u.UpdateId),
            ]);
            if (u.SupportUrl.Length > 0) lines.Add("    " + L.F("Wsparcie: {0}", u.SupportUrl));
        }
        lines.AddRange(["", L.F("Katalog Microsoft Update: {0}", d.CatalogUrl()), "", new string('-', 60),
                        d.SecurityReport.Length > 0 ? d.SecurityReport : DriverAssessor.Assess(d).Report()]);
        Details.Text = string.Join(Environment.NewLine, lines);
    }

    // --------------------------------------------------------------- akcje
    private async void Scan_Click(object sender, RoutedEventArgs e) => await ScanAsync();

    private async Task<bool> ScanAsync()
    {
        List<Driver>? result = null;
        var ok = await _runner.RunAsync(LogEvent.DriverScan, L.T("Skanowanie sterowników (WMI)..."),
                                        async () => result = await Task.Run(DriverInventory.Scan), typeof(DriverException));
        if (!ok || result is null) return false;
        _updatesChecked = false;
        SetItems(result);
        _runner.Log(L.F("Znaleziono {0} urządzeń ze sterownikami.", result.Count));
        var unsigned = result.Where(d => d.IsSigned == false).Select(d => d.DeviceName).ToList();
        if (unsigned.Count > 0) _runner.Log(L.F("Niepodpisane sterowniki: {0}", string.Join(", ", unsigned)), SyslogSeverity.Warning);
        return true;
    }

    private async void Search_Click(object sender, RoutedEventArgs e) => await SearchUpdatesAsync(interactive: true);

    private async Task<int?> SearchUpdatesAsync(bool interactive)
    {
        if (Window.GetWindow(this) is MainWindow main && !main.CanStartWindowsUpdate(this, interactive)) return null;
        List<Driver>? installed = null;
        List<DriverUpdate>? updates = null;
        var current = _items;
        var ok = await _runner.RunAsync(LogEvent.DriverCheck, L.T("Wyszukiwanie sterowników w Windows Update (może potrwać kilka minut)..."), async () =>
        {
            installed = current.Count > 0 ? current : await Task.Run(DriverInventory.Scan);
            updates = await Task.Run(WindowsUpdateDrivers.Search);
        }, typeof(DriverException));
        if (!ok || installed is null || updates is null) return null;
        _updatesChecked = true;
        SetItems(DriverMatcher.MatchUpdates(installed, updates));
        _runner.Log(L.F("Windows Update: znaleziono {0} sterowników do zainstalowania.", updates.Count), msgId: LogEvent.DriverCheck);
        foreach (var u in updates) _runner.Log($"  • {u.Title} [{u.HardwareId}]", msgId: LogEvent.DriverCheck);
        if (updates.Count == 0 && interactive)
            Ui.Info(this, L.T("Sterowniki aktualne"),
                    L.T("Windows Update nie oferuje nowszych sterowników dla tego komputera.") + "\n\n" +
                    L.T("Najnowsze wersje od producenta możesz sprawdzić w Katalogu Microsoft Update (przycisk „Katalog Microsoft Update”) lub na stronie producenta sprzętu."));
        return updates.Count;
    }

    private async void InstallSelected_Click(object sender, RoutedEventArgs e)
    {
        var selected = SelectedItems().Where(d => d.HasUpdate).ToList();
        if (selected.Count == 0)
        {
            Ui.Info(this, L.T("Brak aktualizacji"), L.T("Zaznacz urządzenia z dostępną aktualizacją z Windows Update.") + "\n" +
                                                    L.T("Najpierw kliknij „Szukaj aktualizacji (Windows Update)”."));
            return;
        }
        await InstallAsync(selected);
    }

    private async void InstallAll_Click(object sender, RoutedEventArgs e)
    {
        var selected = _items.Where(d => d.HasUpdate).ToList();
        if (selected.Count == 0)
        {
            Ui.Info(this, L.T("Brak aktualizacji"), L.T("Brak sterowników do zainstalowania.") + "\n" +
                                                    L.T("Najpierw kliknij „Szukaj aktualizacji (Windows Update)”."));
            return;
        }
        await InstallAsync(selected);
    }

    internal static string InstallConfirmation(IReadOnlyCollection<Driver> selection, bool restorePoint)
    {
        var updates = selection.Select(d => d.Update!).DistinctBy(u => u.UpdateId).ToList();
        var lines = updates.Select(u => $"• {u.Title} ({u.SizeText})").ToList();
        var text = L.T("Zostaną pobrane i zainstalowane z Windows Update (pakiety podpisane przez Microsoft):") + "\n\n" +
                   string.Join("\n", lines.Take(15)) + (lines.Count > 15 ? "\n…" : "") + "\n\n" +
                   L.T("Wymagane są uprawnienia administratora (monit UAC). Instalacja sterownika może chwilowo odłączyć urządzenie (np. ekran lub sieć) i wymagać ponownego uruchomienia.");
        if (restorePoint) text += "\n" + L.T("Przed instalacją zostanie utworzony punkt przywracania systemu.");
        var eula = updates.Count(u => !u.EulaAccepted);
        if (eula > 0)
            text += "\n\n" + L.F("UWAGA: {0} pakiet(y) wymagają akceptacji licencji producenta. Kontynuując, akceptujesz te licencje.", eula);
        if (selection.Any(d => d.SecurityLevel == Levels.Low))
            text += "\n\n" + L.T("UWAGA: część pozycji ma niski poziom zaufania - sprawdź szczegóły oceny.");
        return text + "\n\n" + L.T("Kontynuować?");
    }

    private async Task InstallAsync(List<Driver> selection)
    {
        if (Window.GetWindow(this) is MainWindow main && !main.CanStartWindowsUpdate(this)) return;
        var restore = RestorePoint.IsChecked == true;
        if (!Ui.Confirm(this, L.T("Instalacja sterowników"), InstallConfirmation(selection, restore), warning: true)) return;
        var ids = selection.Select(d => d.Update!.UpdateId).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var executable = Environment.ProcessPath ?? throw new InvalidOperationException(L.T("Nieznana ścieżka programu."));
        BottomTabs.SelectedIndex = 1;

        List<DriverInstallResult>? results = null;
        var ok = await _runner.RunAsync(LogEvent.DriverInstall, L.F("Instalowanie {0} sterowników przez Windows Update...", ids.Count), async () =>
            results = await WindowsUpdateDrivers.InstallElevatedAsync(executable, ids, restore, UiLog),
            typeof(DriverException));
        if (!ok || results is null) return;

        var succeeded = 0;
        var reboot = false;
        foreach (var r in results)
        {
            if (r.Succeeded) succeeded++;
            reboot |= r.RebootRequired;
            var extra = r.ResultCode != 2 ? $" (HRESULT 0x{(uint)r.HResult:X8})" : "";
            _runner.Log($"{r.Title}: {r.ResultText}{extra}" + (r.Error.Length > 0 ? $" - {r.Error}" : ""),
                        r.Succeeded ? SyslogSeverity.Notice : SyslogSeverity.Error, LogEvent.DriverInstall);
        }
        var summary = L.F("Zainstalowano {0} z {1} sterowników.", succeeded, ids.Count);
        if (reboot) summary += "\n\n" + L.T("Wymagane jest ponowne uruchomienie komputera, aby zakończyć instalację.");
        summary += "\n\n" + L.T("Szczegóły w zakładce „Dziennik”.");
        if (succeeded == ids.Count) Ui.Info(this, L.T("Instalacja sterowników"), summary);
        else Ui.Warn(this, L.T("Instalacja sterowników"), summary);
        BottomTabs.SelectedIndex = 1;
        await ScanAsync();
    }

    private void Catalog_Click(object sender, RoutedEventArgs e)
    {
        var selected = SelectedItems();
        if (selected.Count == 0)
        {
            Ui.Info(this, L.T("Brak zaznaczenia"), L.T("Zaznacz urządzenie na liście."));
            return;
        }
        if (selected.Count > 5 && !Ui.Confirm(this, "Katalog Microsoft Update", L.F("Otworzyć {0} kart przeglądarki?", selected.Count)))
            return;
        foreach (var d in selected)
        {
            var url = d.CatalogUrl();
            _runner.Log(L.F("Katalog Microsoft Update: {0}", url), msgId: LogEvent.DriverCheck);
            Ui.OpenUrl(url);
        }
    }

    private void DeviceManager_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            Process.Start(new ProcessStartInfo("devmgmt.msc") { UseShellExecute = true })?.Dispose();
        }
        catch (Win32Exception ex)
        {
            Ui.Error(this, L.T("Błąd"), ex.Message);
        }
    }

    internal static Dictionary<string, object?> ReportRow(Driver d) => new()
    {
        ["urzadzenie"] = d.DeviceName, ["klasa"] = d.DeviceClass, ["wersja"] = d.Version, ["data"] = d.Date,
        ["dostawca"] = d.Provider, ["producent"] = d.Manufacturer, ["inf"] = d.InfName,
        ["podpis"] = d.SignatureText, ["status"] = d.Status, ["zaufanie"] = d.SecurityLevelDisplay,
        ["id_sprzetu"] = string.Join(";", d.HardwareIds),
        ["aktualizacja"] = d.Update?.Title ?? "", ["id_aktualizacji"] = d.Update?.UpdateId ?? "",
    };

    private void Export_Click(object sender, RoutedEventArgs e)
    {
        var path = Ui.AskSavePath(this, L.T("Eksportuj raport sterowników"), $"{L.T("sterowniki")}_{DateTime.Now:yyyyMMdd_HHmm}.csv");
        if (path is null) return;
        try
        {
            Ui.WriteReport(path, _items.Select(ReportRow).ToList());
        }
        catch (Exception ex) when (ex is System.IO.IOException or UnauthorizedAccessException)
        {
            Ui.Error(this, L.T("Błąd zapisu"), ex.Message);
            return;
        }
        _runner.Log(L.F("Zapisano raport: {0}", path), msgId: LogEvent.Report);
    }
}
