using System.ComponentModel;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using BezpiecznyAktualizator.Core.Catalogs;
using BezpiecznyAktualizator.Core.History;
using BezpiecznyAktualizator.Core.Inventory;
using BezpiecznyAktualizator.Core.Localization;
using BezpiecznyAktualizator.Core.Logging;
using BezpiecznyAktualizator.Core.Models;
using BezpiecznyAktualizator.Core.Policies;
using BezpiecznyAktualizator.Core.Risk;
using BezpiecznyAktualizator.Core.Scheduling;
using BezpiecznyAktualizator.Core.Security;
using BezpiecznyAktualizator.Core.Winget;
using BezpiecznyAktualizator.Services;

namespace BezpiecznyAktualizator.Views;

public partial class SoftwareView : UserControl
{
    private readonly BackgroundRunner _runner;
    private List<Software> _items = [];
    private ListCollectionView _view;
    /// <summary>Wyniki sprawdzenia podatności i wsparcia - przenoszone na nowe listy po ponownym skanowaniu.</summary>
    private readonly Dictionary<string, (VulnerabilityReport? Vulnerabilities, LifecycleInfo? Lifecycle)> _risk = [];

    private static string RiskKey(Software s) => $"{s.Name}|{s.Version}";

    public SoftwareView()
    {
        InitializeComponent();
        _runner = new BackgroundRunner(this, Toolbar, Progress, StatusText, LogBox, SummaryText, LogEvent.Scan, CanStartWinget);
        _view = CreateView();
        L.LanguageChanged += RefreshTable;
    }

    /// <summary>
    /// Wywoływane po uruchomieniu programu: skanuje oprogramowanie i (opcjonalnie) sprawdza dostępne wersje.
    /// Zwraca liczbę dostępnych aktualizacji albo null, gdy sprawdzenie nie zostało wykonane.
    /// </summary>
    public async Task<int?> StartupAsync(bool checkUpdates)
    {
        var checkedOk = await ScanAsync(checkUpdates);
        return checkedOk ? _items.Count(s => s.HasUpdate && !s.PolicyBlocked) : null;
    }

    // ------------------------------------------------------------------ lista
    private ListCollectionView CreateView()
    {
        var view = new ListCollectionView(_items) { Filter = o => Matches((Software)o) };
        Table.ItemsSource = view;
        return view;
    }

    private void SetItems(List<Software> items)
    {
        var selected = SelectedItems();
        foreach (var s in items)
            if (_risk.TryGetValue(RiskKey(s), out var r)) (s.Vulnerabilities, s.Lifecycle) = r;
        _items = items;
        _view = CreateView();
        Restore(selected);
        RefreshTable();
    }

    private static IEnumerable<string> RowValues(Software s) =>
        [s.Name, s.Version, s.AvailableDisplay, s.Status, s.PolicyDisplay, s.RiskDisplay, s.Publisher, s.SourceDisplay, s.SecurityLevelDisplay, s.IdDisplay];

    /// <summary>Przypisuje programom opis i skutek zasad aktualizacji.</summary>
    private void ApplyPolicies()
    {
        var policies = Settings.Policies;
        var now = DateTimeOffset.Now;
        foreach (var s in _items)
        {
            s.PolicyDisplay = policies.Describe(s, now);
            s.PolicyBlocked = !policies.CheckRules(s, now).Allowed;
        }
    }

    private bool Matches(Software s)
    {
        if (OnlyUpdates.IsChecked == true && !s.HasUpdate) return false;
        if (OnlyRisky.IsChecked == true && s.RiskState.Length == 0) return false;
        var needle = FilterBox.Text.Trim();
        return needle.Length == 0 || RowValues(s).Any(v => v.Contains(needle, StringComparison.CurrentCultureIgnoreCase));
    }

    private void RefreshTable()
    {
        var selected = SelectedItems();
        ApplyPolicies();
        _view.Refresh();
        Restore(selected);
        CountLabel.Text = L.F("Wyświetlono {0} z {1}", _view.Count, _items.Count);
        _runner.UpdateSummary();
        ShowDetails();
    }

    private void Restore(IEnumerable<Software> selected)
    {
        Table.SelectedItems.Clear();
        foreach (var s in selected)
            if (_view.Contains(s)) Table.SelectedItems.Add(s);
    }

    private void Select(Software s)
    {
        Table.SelectedItems.Clear();
        if (!_view.Contains(s)) return;
        Table.SelectedItem = s;
        Table.ScrollIntoView(s);
    }

    private List<Software> SelectedItems() => Table.SelectedItems.Cast<Software>().ToList();

    private List<Software> RequireSelection()
    {
        var selected = SelectedItems();
        if (selected.Count == 0) Ui.Info(this, L.T("Brak zaznaczenia"), L.T("Zaznacz co najmniej jeden program na liście."));
        return selected;
    }

    private string SummaryText()
    {
        var updates = _items.Count(s => s.HasUpdate);
        var tracked = _items.Count(s => !string.IsNullOrEmpty(s.WingetId));
        return L.F("Programów: {0} | śledzonych w repozytoriach: {1} | z aktualizacją: {2}", _items.Count, tracked, updates);
    }

    private void Filter_Changed(object sender, RoutedEventArgs e)
    {
        if (_view is not null) RefreshTable();
    }

    private void Table_SelectionChanged(object sender, SelectionChangedEventArgs e) => ShowDetails();

    private async void Table_DoubleClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        if (Table.SelectedItem is not null && !_runner.IsBusy) await AssessSelectedAsync();
    }

    private void UiLog(string line)
    {
        if (Dispatcher.CheckAccess()) _runner.Log(line);
        else Dispatcher.BeginInvoke(() => _runner.Log(line));
    }

    private void ShowDetails()
    {
        if (Table.SelectedItem is not Software s) return;
        static string Dash(string? v) => string.IsNullOrEmpty(v) ? "-" : v;
        var fields = new List<(string Label, string Value)>
        {
            (L.T("Nazwa"), s.Name),
            (L.T("Wersja"), Dash(s.Version)),
            (L.T("Wydawca"), Dash(s.Publisher)),
            (L.T("Lokalizacja"), Dash(s.InstallLocation)),
            (L.T("Data instalacji"), Dash(s.InstallDate)),
            (L.T("Pochodzenie wpisu"), Dash(s.Origin)),
            (L.T("Id winget"), L.F("{0}  (źródło: {1})", Dash(s.WingetId), Dash(s.WingetSource))),
            (L.T("Dostępna wersja"), Dash(s.AvailableVersion)),
        };
        foreach (var (label, url) in new[] { (L.T("Strona informacji"), s.UrlInfo), (L.T("Aktualizacje"), s.UrlUpdate), (L.T("Pomoc"), s.HelpLink) })
            if (url.Length > 0) fields.Add((label, url));
        if (s.CatalogUrl.Length > 0) fields.Add((L.T("Strona pakietu"), s.CatalogUrl));
        var lines = Ui.FormatFields(fields);
        if (s.SearchHint.Length > 0) lines.AddRange(["", s.SearchHint.ToString()]);
        if (s.PolicyDisplay.Length > 0)
        {
            var decision = Settings.Policies.CheckRules(s, DateTimeOffset.Now);
            lines.AddRange(["", L.F("Zasada aktualizacji: {0}", s.PolicyDisplay)]);
            if (!decision.Allowed) lines.Add(decision.Reason.ToString());
        }
        var rule = new string('=', 70);
        lines.AddRange(RiskDetails(s, rule));
        try
        {
            if (UpdateHistory.LastRollbackable(UpdateHistory.Load(), s.WingetId) is { } last)
                lines.AddRange(["", L.F("Poprzednia wersja: {0} (zaktualizowano {1:yyyy-MM-dd HH:mm}) - można ją przywrócić przyciskiem „Historia i wycofanie”.",
                                        last.FromVersion, last.Time.ToLocalTime())]);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            Syslog.Warning(LogEvent.Rollback, L.F("Nie udało się odczytać historii aktualizacji: {0}", ex.Message));
            lines.AddRange(["", L.T("Nie udało się odczytać historii aktualizacji."), ex.Message]);
        }
        if (s.SecurityReport.Length > 0) lines.AddRange(["", rule, L.T("OCENA ŹRÓDŁA AKTUALIZACJI"), rule, s.SecurityReport]);
        else lines.AddRange(["", L.T("Kliknij dwukrotnie lub użyj „Oceń źródło”, aby zweryfikować źródło aktualizacji.")]);
        Details.Text = string.Join(Environment.NewLine, lines);
    }

    private static List<string> RiskDetails(Software s, string rule)
    {
        var lines = new List<string>();
        if (s.Vulnerabilities is { } v)
        {
            lines.AddRange(["", rule, L.T("ZNANE PODATNOŚCI (NVD)"), rule]);
            if (v.Error is { } error) lines.Add(L.F("NVD: {0}", error));
            else
            {
                var origin = v.CpeOrigin switch
                {
                    "map" => L.T("wbudowana mapa programów"),
                    "nvd" => L.T("wyszukiwanie w słowniku CPE NVD"),
                    _ => v.CpeOrigin,
                };
                lines.Add(L.F("Produkt CPE: {0} (dopasowanie: {1}), wersja {2}", v.Cpe.Replace("|", ", "), origin, v.Version));
                if (v.Items.Count == 0) lines.Add(L.T("Nie znaleziono znanych podatności tej wersji."));
                else
                {
                    lines.Add(L.F("PILNE: znane podatności tej wersji: {0}, najwyższa ocena CVSS {1:0.0}.", v.Items.Count, v.MaxScore));
                    if (v.Exploited)
                        lines.Add(L.T("Co najmniej jedna luka jest aktywnie wykorzystywana przez atakujących (katalog CISA KEV)."));
                    lines.Add(L.T("Zalecana jest jak najszybsza aktualizacja."));
                    lines.Add("");
                    const int shown = 15;
                    foreach (var c in v.Items.Take(shown))
                    {
                        var desc = c.Description.Length > 180 ? c.Description[..180] + "…" : c.Description;
                        lines.Add($"  {c.Id}  CVSS {c.Score:0.0} {c.Severity}{(c.Exploited ? "  [KEV]" : "")}");
                        if (c.EpssScore is { } epss)
                            lines.Add(L.F("      EPSS: {0:P1} (percentyl {1:P1})", epss, c.EpssPercentile ?? 0));
                        if (desc.Length > 0) lines.Add("      " + desc);
                        lines.Add("      " + c.Url);
                    }
                    if (v.Items.Count > shown) lines.Add(L.F("... oraz {0} kolejnych.", v.Items.Count - shown));
                }
                if (v.EpssError is { } epssError)
                    lines.Add(L.F("Nie udało się pobrać ocen EPSS: {0}", epssError));
                lines.Add(L.T("Dopasowanie programu do CPE jest automatyczne - przed decyzją sprawdź szczegóły w NVD."));
            }
        }
        if (s.Vulnerabilities is { OsvRepository.Length: > 0 } osv)
        {
            lines.AddRange(["", rule, L.T("DODATKOWE PODATNOŚCI (OSV)"), rule]);
            lines.Add(L.F("Repozytorium: {0}; pewność dopasowania: {1}.",
                osv.OsvRepository, osv.OsvConfidence == "medium" ? L.T("umiarkowana — adres GitHub z metadanych pakietu") : osv.OsvConfidence));
            if (osv.OsvError is { } osvError) lines.Add(osvError.ToString());
            else if (osv.OsvItems.Count == 0) lines.Add(L.T("Nie znaleziono podatności dla dokładnego repozytorium i wersji."));
            foreach (var item in osv.OsvItems.Take(15))
            {
                lines.Add($"  {item.Id}: {item.Summary}");
                if (item.Aliases.Count > 0) lines.Add("      " + L.F("Alias CVE: {0}", string.Join(", ", item.Aliases)));
                lines.Add("      " + item.Url);
            }
            if (osv.OsvItems.Count > 15) lines.Add(L.F("... oraz {0} kolejnych.", osv.OsvItems.Count - 15));
        }
        if (s.Lifecycle is { } life)
        {
            lines.AddRange(["", rule, L.T("WSPARCIE PRODUCENTA (EOL)"), rule]);
            var state = life.State switch
            {
                LifecycleState.Eol => L.T("NIEOBSŁUGIWANY (koniec wsparcia)"),
                LifecycleState.Abandoned => L.T("PRAWDOPODOBNIE PORZUCONY"),
                LifecycleState.Supported => L.T("wspierany"),
                _ => L.T("nieznany"),
            };
            var fields = new List<(string, string)> { (L.T("Stan"), state), (L.T("Źródło danych"), life.Origin) };
            if (life.Product.Length > 0) fields.Add((L.T("Produkt"), life.Product));
            if (life.Cycle.Length > 0) fields.Add((L.T("Cykl wydań"), life.Cycle));
            if (life.Latest.Length > 0) fields.Add((L.T("Najnowsza wersja cyklu"), life.Latest));
            if (life.Link.Length > 0) fields.Add((L.T("Szczegóły"), life.Link));
            lines.AddRange(Ui.FormatFields(fields));
            lines.Add(life.Reason.ToString());
            if (life.State is LifecycleState.Eol or LifecycleState.Abandoned)
                lines.Add(L.T("Program bez wsparcia nie otrzymuje poprawek bezpieczeństwa - rozważ aktualizację do wspieranej wersji lub zamiennik."));
        }
        return lines;
    }

    // --------------------------------------------------------------- akcje
    private async void Scan_Click(object sender, RoutedEventArgs e) => await ScanAsync();

    /// <summary>Skanuje rejestr; zwraca true, jeśli sprawdzenie aktualizacji w repozytoriach zakończyło się sukcesem.</summary>
    private async Task<bool> ScanAsync(bool checkUpdates = true)
    {
        List<Software>? result = null;
        var ok = await _runner.RunAsync(LogEvent.Scan, L.T("Skanowanie zainstalowanego oprogramowania..."),
                                        async () => result = await Task.Run(SoftwareInventory.ScanInstalled));
        if (!ok || result is null) return false;
        SetItems(result);
        _runner.Log(L.F("Znaleziono {0} programów w rejestrze.", result.Count));
        if (!checkUpdates) return false;
        if (WingetClient.IsAvailable()) return await CheckUpdatesAsync();
        _runner.Log(L.T("winget nie jest dostępny - sprawdzanie aktualizacji w repozytoriach wyłączone."), SyslogSeverity.Warning);
        return false;
    }

    private async void CheckUpdates_Click(object sender, RoutedEventArgs e) => await CheckUpdatesAsync();

    private async Task<bool> CheckUpdatesAsync()
    {
        if (!WingetClient.IsAvailable())
        {
            Ui.Warn(this, L.T("Brak winget"),
                    L.T("Nie znaleziono programu winget (Windows Package Manager).") + "\n" +
                    L.T("Zainstaluj „Instalator aplikacji” (App Installer) z Microsoft Store."));
            return false;
        }
        (List<Software> Items, int PackageCount)? result = null;
        var ok = await _runner.RunAsync(LogEvent.UpdateCheck, L.T("Sprawdzanie aktualizacji w repozytoriach winget / Microsoft Store..."), async () =>
        {
            var baseItems = _items.Where(s => s.IsRegistryEntry).ToList();
            if (baseItems.Count == 0) baseItems = await Task.Run(SoftwareInventory.ScanInstalled);
            result = await WingetClient.CheckUpdatesAsync(baseItems);
        }, typeof(WingetException));
        if (!ok || result is not { } r) return false;
        SetItems(r.Items);
        _runner.Log(L.F("winget rozpoznał {0} pakietów; dostępnych aktualizacji: {1}.", r.PackageCount, r.Items.Count(s => s.HasUpdate)), msgId: LogEvent.UpdateCheck);
        return true;
    }

    public bool IsBusy => _runner.IsBusy;

    private bool CanStartWinget() => Window.GetWindow(this) is not MainWindow main || main.CanStartWinget(this);

    /// <summary>Pokazuje tylko programy z dostępną aktualizacją.</summary>
    public void ShowOnlyUpdates() => OnlyUpdates.IsChecked = true;

    private async void Assess_Click(object sender, RoutedEventArgs e) => await AssessSelectedAsync();

    private async Task AssessSelectedAsync()
    {
        var selected = RequireSelection();
        if (selected.Count == 0) return;
        var verify = VerifyTls.IsChecked == true;
        var ok = await _runner.RunAsync(LogEvent.Assess, L.F("Ocena źródeł aktualizacji ({0})...", selected.Count), async () =>
        {
            foreach (var s in selected)
            {
                _runner.SetStatus(L.F("Ocena źródła: {0}...", s.Name));
                await SoftwareAssessor.AssessSoftwareAsync(s, verify);
            }
        }, typeof(WingetException));
        foreach (var s in selected.Where(s => s.SecurityLevel.Length > 0))
            _runner.Log(L.F("Ocena źródła „{0}”: {1}", s.Name, s.SecurityLevelDisplay), msgId: LogEvent.Assess);
        RefreshTable();
        if (ok) BottomTabs.SelectedIndex = 0;
    }

    private async void AssessAll_Click(object sender, RoutedEventArgs e)
    {
        var targets = _items.Where(s => s.HasUpdate && !string.IsNullOrEmpty(s.WingetId)).ToList();
        if (targets.Count == 0)
        {
            Ui.Info(this, L.T("Brak aktualizacji"), L.T("Brak programów z dostępną aktualizacją."));
            return;
        }
        var verify = VerifyTls.IsChecked == true;
        await _runner.RunAsync(LogEvent.Assess, L.F("Ocena źródeł {0} aktualizacji...", targets.Count), async () =>
        {
            for (var i = 0; i < targets.Count; i++)
            {
                var s = targets[i];
                _runner.SetStatus(L.F("Ocena źródła {0}/{1}: {2}...", i + 1, targets.Count, s.Name));
                try
                {
                    await SoftwareAssessor.AssessSoftwareAsync(s, verify);
                }
                catch (WingetException ex)
                {
                    s.SecurityLevel = "?";
                    s.SecurityReport = ex.Message;
                }
                _runner.Log(L.F("Ocena źródła „{0}”: {1}", s.Name, s.SecurityLevelDisplay), msgId: LogEvent.Assess);
            }
        });
        RefreshTable();
    }

    private async void Risk_Click(object sender, RoutedEventArgs e)
    {
        if (_items.Count == 0) return;
        var targets = SelectedItems();
        if (targets.Count <= 1 && targets.Count < _items.Count)
        {
            var all = _items.Where(s => s.Version.Length > 0).ToList();
            var minutes = Math.Max(1, (int)Math.Ceiling(NvdClient.EstimateSeconds(all.Select(RiskKey).Distinct().Count()) / 60.0));
            var question = targets.Count == 0
                ? L.F("Nie zaznaczono programów. Sprawdzić wszystkie ({0})?", all.Count)
                : L.F("Sprawdzić tylko „{0}”? Wybierz „Nie”, aby sprawdzić wszystkie programy ({1}).", targets[0].Name, all.Count);
            var answer = Ui.Ask(this, L.T("Sprawdź podatności i wsparcie"), question + "\n\n" +
                L.F("Pierwsze sprawdzenie wszystkich programów może potrwać do ok. {0} min - bez klucza API baza NVD przyjmuje 5 zapytań na 30 s. Wyniki są zapamiętywane na 24 godziny.", minutes),
                targets.Count == 0 ? MessageBoxButton.OKCancel : MessageBoxButton.YesNoCancel, MessageBoxImage.Question);
            if (answer == MessageBoxResult.Cancel) return;
            if (targets.Count == 0 || answer == MessageBoxResult.No) targets = all;
        }
        var groups = targets.GroupBy(RiskKey).ToList();
        var wingetAvailable = WingetClient.IsAvailable();
        await _runner.RunAsync(LogEvent.Vulnerability,
            L.F("Sprawdzanie podatności (NVD) i wsparcia (endoflife.date) dla {0} programów...", groups.Count), async () =>
        {
            for (var i = 0; i < groups.Count; i++)
            {
                var s = groups[i].First();
                _runner.SetStatus(L.F("Sprawdzanie {0}/{1}: {2}...", i + 1, groups.Count, s.Name));
                LifecycleInfo? life = null;
                EolProduct? product = null;
                try
                {
                    Func<Task<IReadOnlyDictionary<string, string>?>>? show = wingetAvailable && !string.IsNullOrEmpty(s.WingetId)
                        ? async () =>
                        {
                            var info = await WingetClient.ShowAsync(s.WingetId!, s.WingetSource);
                            if (info is not null)
                                s.Homepage = info.GetValueOrDefault("Homepage") ?? info.GetValueOrDefault("Publisher Url") ?? "";
                            return info;
                        }
                        : null;
                    (life, product) = await LifecycleClient.CheckAsync(s, show);
                }
                catch (Exception ex) when (ex is RiskException or WingetException)
                {
                    _runner.Log(L.F("Nie udało się sprawdzić wsparcia {0}: {1}", s.Name, ex.Message), SyslogSeverity.Warning, LogEvent.Vulnerability);
                }
                VulnerabilityReport report;
                try
                {
                    report = await NvdClient.CheckAsync(s, product?.Cpe);
                }
                catch (RiskException ex)
                {
                    report = new VulnerabilityReport { Version = NvdClient.ProductVersion(s.Name, s.Version), Error = ex.Message };
                    _runner.Log(L.F("Nie udało się sprawdzić podatności {0}: {1}", s.Name, ex.Message), SyslogSeverity.Warning, LogEvent.Vulnerability);
                }
                if (OsvClient.GitHubRepository(s.Homepage) is { } repository && report.Version.Length > 0)
                {
                    var parts = repository.Split('/');
                    report.OsvRepository = repository;
                    report.OsvConfidence = "medium";
                    try
                    {
                        report.OsvItems = (await OsvClient.CheckGitHubRepositoryAsync(parts[0], parts[1], report.Version)).ToList();
                    }
                    catch (Exception ex) when (ex is RiskException or ArgumentException)
                    {
                        report.OsvError = ex.Message;
                        _runner.Log(L.F("Nie udało się sprawdzić repozytorium {0} w OSV: {1}", repository, ex.Message),
                            SyslogSeverity.Warning, LogEvent.Vulnerability);
                    }
                }
                if (report.EpssError is { } epssError)
                    _runner.Log(L.F("Nie udało się pobrać ocen EPSS: {0}", epssError), SyslogSeverity.Warning, LogEvent.Vulnerability);
                _risk[groups[i].Key] = (report, life);
                foreach (var item in groups[i]) (item.Vulnerabilities, item.Lifecycle) = (report, life);

                if (report.IsUrgent && report.Items.Count > 0)
                    _runner.Log(L.F("PILNE: {0} {1} - NVD: {2}, OSV: {3}, najwyższa ocena CVSS {4:0.0}{5} ({6}).", s.Name, s.Version,
                        report.Items.Count, report.OsvItems.Count, report.MaxScore,
                        report.Exploited ? ", " + L.T("aktywnie wykorzystywane (CISA KEV)") : "",
                        string.Join(", ", report.Items.Concat(report.OsvItems.SelectMany(item =>
                            item.Aliases.Where(alias => alias.StartsWith("CVE-", StringComparison.OrdinalIgnoreCase))
                                .Select(alias => new CveItem(alias, 0, "", "", null, false))))
                            .Select(item => item.Id).Distinct(StringComparer.OrdinalIgnoreCase).Take(5))),
                        SyslogSeverity.Warning, LogEvent.Vulnerability);
                else if (report.IsUrgent)
                    _runner.Log(L.F("PILNE: {0} {1} - OSV: {2} znalezionych podatności dla {3}.",
                        s.Name, s.Version, report.OsvItems.Count, report.OsvRepository),
                        SyslogSeverity.Warning, LogEvent.Vulnerability);
                if (life?.State is LifecycleState.Eol or LifecycleState.Abandoned)
                    _runner.Log($"{s.Name} {s.Version}: {life.Reason}", SyslogSeverity.Warning, LogEvent.Vulnerability);
                RefreshTable();
            }
        });
        var checkedItems = groups.Select(g => g.First()).ToList();
        var urgent = checkedItems.Count(s => s.IsUrgent);
        var eol = checkedItems.Count(s => s.Lifecycle?.State == LifecycleState.Eol);
        var abandoned = checkedItems.Count(s => s.Lifecycle?.State == LifecycleState.Abandoned);
        var unknown = checkedItems.Count(s => s.Vulnerabilities is { Checked: false });
        var summary = L.F("Sprawdzono programów: {0}", checkedItems.Count) + "\n" +
                      L.F("Pilne - ze znalezionymi podatnościami (NVD/OSV): {0}", urgent) + "\n" +
                      L.F("Nieobsługiwane (EOL): {0}", eol) + "\n" +
                      L.F("Prawdopodobnie porzucone: {0}", abandoned) + "\n" +
                      L.F("Bez danych w NVD (nie sprawdzono podatności): {0}", unknown);
        _runner.Log(summary.Replace("\n", "; "), SyslogSeverity.Notice, LogEvent.Vulnerability);
        if (urgent + eol + abandoned > 0) OnlyRisky.IsChecked = true;
        Ui.Info(this, L.T("Zakończono"), summary + "\n\n" + L.T("Szczegóły w zakładce „Szczegóły i ocena źródła” po zaznaczeniu programu."));
    }

    // ------------------------------------------------------------------ zasady
    /// <summary>Odświeża kolumnę „Zasada” po zmianie zasad w innym oknie.</summary>
    public void PoliciesChanged() => RefreshTable();

    private void Policies_Click(object sender, RoutedEventArgs e)
    {
        if (new PoliciesWindow { Owner = Window.GetWindow(this) }.ShowDialog() == true) RefreshTable();
    }

    private void Table_ContextMenuOpening(object sender, ContextMenuEventArgs e)
    {
        var tracked = SelectedItems().Where(s => !string.IsNullOrEmpty(s.WingetId)).ToList();
        var policies = Settings.Policies;
        var now = DateTimeOffset.Now;
        ExcludeItem.IsEnabled = tracked.Any(s => !policies.IsExcluded(s.WingetId));
        HoldItem.IsEnabled = tracked.Any(s => s.Version.Length > 0 && policies.HoldFor(s.WingetId, now) is not { Managed: true });
        RemoveRuleItem.IsEnabled = tracked.Any(s => policies.ExclusionFor(s.WingetId) is { Managed: false } ||
                                                    policies.Holds.Any(h => !h.Managed && h.WingetId.Equals(s.WingetId, StringComparison.OrdinalIgnoreCase)));
    }

    private List<Software> TrackedSelection()
    {
        var tracked = RequireSelection().Where(s => !string.IsNullOrEmpty(s.WingetId)).ToList();
        if (tracked.Count == 0 && Table.SelectedItems.Count > 0)
            Ui.Info(this, L.T("Zasady aktualizacji"), L.T("Zasady dotyczą programów z identyfikatorem pakietu winget - użyj najpierw „Sprawdź aktualizacje” lub „Szukaj w repozytorium”."));
        return tracked;
    }

    private void Exclude_Click(object sender, RoutedEventArgs e)
    {
        var policies = Settings.Policies;
        var added = TrackedSelection().Where(s => !policies.IsExcluded(s.WingetId)).ToList();
        if (added.Count == 0) return;
        foreach (var s in added)
        {
            policies.Excluded.Add(new ExclusionRule { WingetId = s.WingetId!, Name = s.Name });
            _runner.Log(L.F("Dodano wykluczenie: {0}.", s.WingetId), SyslogSeverity.Notice, LogEvent.Policy);
        }
        Settings.Policies = policies;
        RefreshTable();
    }

    private void Hold_Click(object sender, RoutedEventArgs e)
    {
        var policies = Settings.Policies;
        var now = DateTimeOffset.Now;
        var held = TrackedSelection().Where(s => s.Version.Length > 0 && policies.HoldFor(s.WingetId, now) is not { Managed: true }).ToList();
        if (held.Count == 0) return;
        foreach (var s in held)
        {
            policies.Holds.RemoveAll(h => !h.Managed && h.WingetId.Equals(s.WingetId, StringComparison.OrdinalIgnoreCase));
            policies.Holds.Add(new VersionHold { WingetId = s.WingetId!, Name = s.Name, Version = s.Version });
            _runner.Log(L.F("Wstrzymano wersję {0}: {1}.", s.WingetId, s.Version), SyslogSeverity.Notice, LogEvent.Policy);
        }
        Settings.Policies = policies;
        RefreshTable();
    }

    private void RemoveRule_Click(object sender, RoutedEventArgs e)
    {
        var policies = Settings.Policies;
        var changed = false;
        foreach (var s in TrackedSelection())
        {
            if (policies.Excluded.RemoveAll(x => !x.Managed && x.WingetId.Equals(s.WingetId, StringComparison.OrdinalIgnoreCase)) > 0)
            {
                _runner.Log(L.F("Usunięto wykluczenie: {0}.", s.WingetId), SyslogSeverity.Notice, LogEvent.Policy);
                changed = true;
            }
            if (policies.Holds.RemoveAll(h => !h.Managed && h.WingetId.Equals(s.WingetId, StringComparison.OrdinalIgnoreCase)) > 0)
            {
                _runner.Log(L.F("Zniesiono wstrzymanie wersji: {0}.", s.WingetId), SyslogSeverity.Notice, LogEvent.Policy);
                changed = true;
            }
        }
        if (!changed) return;
        Settings.Policies = policies;
        RefreshTable();
    }

    private async void History_Click(object sender, RoutedEventArgs e)
    {
        var current = Table.SelectedItem as Software;
        List<UpdateRecord> records;
        try { records = UpdateHistory.Load(); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException or TimeoutException)
        {
            Syslog.Warning(LogEvent.Rollback, L.F("Nie udało się odczytać historii aktualizacji: {0}", ex.Message));
            Ui.Error(this, L.T("Historia aktualizacji"), L.F("Nie udało się bezpiecznie odczytać historii: {0}", ex.Message));
            return;
        }
        var dialog = new HistoryWindow(records, current?.WingetId) { Owner = Window.GetWindow(this) };
        if (dialog.ShowDialog() != true || dialog.SelectedRecord is not { } record) return;
        await RollbackAsync(record);
    }

    private async Task RollbackAsync(UpdateRecord record)
    {
        if (!WingetClient.IsAvailable())
        {
            Ui.Warn(this, L.T("Brak winget"), L.T("Nie znaleziono programu winget (Windows Package Manager)."));
            return;
        }
        string? version = null;
        var ok = await _runner.RunAsync(LogEvent.Rollback, L.F("Sprawdzanie dostępności wersji {0} {1}...", record.Name, record.FromVersion), async () =>
            version = UpdateHistory.FindVersion(await WingetClient.ListVersionsAsync(record.WingetId, record.Source), record.FromVersion),
            typeof(WingetException));
        if (!ok) return;
        if (version is null)
        {
            _runner.Log(L.F("Wersja {0} programu {1} nie jest już dostępna w repozytorium winget.", record.FromVersion, record.Name),
                        SyslogSeverity.Warning, LogEvent.Rollback);
            Ui.Warn(this, L.T("Wycofanie niemożliwe"),
                L.F("Wersja {0} programu {1} nie jest już dostępna w repozytorium winget - nie można jej automatycznie przywrócić.", record.FromVersion, record.Name));
            return;
        }
        var msg = L.F("Program {0} zostanie przywrócony z wersji {1} do wersji {2}.", record.Name, record.ToVersion, version) + "\n\n" +
                  L.T("Starsza wersja może zawierać luki bezpieczeństwa usunięte w nowszej. Wycofuj aktualizację tylko wtedy, gdy nowa wersja sprawia problemy.") + "\n\n" +
                  L.T("Instalator może poprosić o uprawnienia administratora (UAC). Kontynuować?");
        if (!Ui.Confirm(this, L.T("Wycofaj aktualizację"), msg, true)) return;
        BottomTabs.SelectedIndex = 1;

        var verify = VerifyChecksums.IsChecked == true;
        VerifiedInstaller? verifiedInstaller = null;
        var code = -1;
        var blocked = false;
        try
        {
            ok = await _runner.RunAsync(LogEvent.Rollback, L.F("Przywracanie {0} {1}...", record.Name, version), async () =>
            {
                if (verify)
                {
                    verifiedInstaller = await VerifyInstallerAsync(record.Name, record.WingetId, record.Source, version);
                    if (verifiedInstaller is null)
                    {
                        blocked = true;
                        return;
                    }
                }
                _runner.Log(L.F("Przywracanie {0} ({1}) do wersji {2}...", record.Name, record.WingetId, version), SyslogSeverity.Notice, LogEvent.Rollback);
                code = verifiedInstaller is null
                    ? await WingetClient.InstallVersionAsync(record.WingetId, version, line => UiLog("  " + line), record.Source)
                    : await WingetClient.InstallVerifiedAsync(verifiedInstaller, line => UiLog("  " + line), allowDowngrade: true);
            }, typeof(WingetException));
        }
        finally { verifiedInstaller?.Dispose(); }
        if (!ok || blocked) return;
        if (code != 0)
        {
            _runner.Log(L.F("Niepowodzenie: {0} (kod 0x{1:X8})", record.Name, code), SyslogSeverity.Error, LogEvent.Rollback);
            Ui.Error(this, L.T("Wycofanie nie powiodło się"), L.F("Niepowodzenie: {0} (kod 0x{1:X8})", record.Name, code) + "\n\n" +
                     L.T("Szczegóły w zakładce „Dziennik”."));
            return;
        }
        try
        {
            UpdateHistory.RecordRollback(record.Id, new UpdateRecord
            {
                Kind = UpdateKind.Rollback, Name = record.Name, WingetId = record.WingetId, Source = record.Source,
                FromVersion = record.ToVersion, ToVersion = version,
            });
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException or TimeoutException)
        {
            _runner.Log(L.F("Wycofano {0}, ale nie udało się zapisać historii aktualizacji: {1}", record.Name, ex.Message),
                SyslogSeverity.Warning, LogEvent.Rollback);
            Ui.Warn(this, L.T("Historia aktualizacji"), L.F("Wycofano {0}, ale nie udało się zapisać historii: {1}", record.Name, ex.Message));
        }
        _runner.Log(L.F("Przywrócono {0} do wersji {1}.", record.Name, version), SyslogSeverity.Notice, LogEvent.Rollback);

        var policies = Settings.Policies;
        var existing = policies.HoldFor(record.WingetId, DateTimeOffset.Now);
        if (existing is not { Managed: true } && !policies.IsExcluded(record.WingetId) &&
            Ui.Confirm(this, L.T("Wycofaj aktualizację"),
                L.F("Przywrócono {0} do wersji {1}.", record.Name, version) + "\n\n" +
                L.F("Wstrzymać {0} na wersji {1}? Ani okno programu, ani harmonogram cichych aktualizacji nie zainstalują nowszej wersji, dopóki nie usuniesz wstrzymania w „Zasady aktualizacji”.",
                    record.Name, version), false))
        {
            policies.Holds.RemoveAll(h => !h.Managed && h.WingetId.Equals(record.WingetId, StringComparison.OrdinalIgnoreCase));
            policies.Holds.Add(new VersionHold
            {
                WingetId = record.WingetId, Name = record.Name, Version = version,
                Reason = L.F("Wycofano aktualizację do {0}", record.ToVersion),
            });
            Settings.Policies = policies;
            _runner.Log(L.F("Wstrzymano wersję {0}: {1}.", record.WingetId, version), SyslogSeverity.Notice, LogEvent.Policy);
        }
        else
        {
            Ui.Info(this, L.T("Zakończono"), L.F("Przywrócono {0} do wersji {1}.", record.Name, version));
        }
        await CheckUpdatesAsync();
    }

    private async void Upgrade_Click(object sender, RoutedEventArgs e)
    {
        var selected = RequireSelection();
        if (selected.Count == 0) return;
        var targets = selected.Where(s => s.CanUpgrade).ToList();
        var skipped = selected.Count - targets.Count;
        if (targets.Count == 0)
        {
            Ui.Info(this, L.T("Brak aktualizacji"),
                    L.T("Zaznaczone programy nie mają aktualizacji dostępnej przez zaufane repozytorium.") + "\n" +
                    L.T("Dla pozostałych użyj „Strona producenta”."));
            return;
        }
        if (targets.Any(SilentUpdatePolicy.IsStoreManaged))
        {
            Ui.Warn(this, L.T("Microsoft Store"),
                L.T("Aktualizacje Microsoft Store obsługuj w dedykowanej zakładce, gdzie wymagane jest osobne potwierdzenie. Aktualizacja z tego widoku została wstrzymana."));
            return;
        }

        var policies = Settings.Policies;
        if (policies.ManualRequireTrusted)
        {
            // Zasada wymaga zaufanego źródła - nieocenione źródła są oceniane przed decyzją.
            var unassessed = targets.Where(s => policies.CheckRules(s, DateTimeOffset.Now).Allowed &&
                                                (s.SecurityLevel.Length == 0 || s.SecurityLevel == "?")).ToList();
            if (unassessed.Count > 0)
            {
                var verifyTls = VerifyTls.IsChecked == true;
                await _runner.RunAsync(LogEvent.Assess, L.F("Ocena źródeł aktualizacji ({0})...", unassessed.Count), async () =>
                {
                    foreach (var s in unassessed)
                    {
                        _runner.SetStatus(L.F("Ocena źródła: {0}...", s.Name));
                        try
                        {
                            await SoftwareAssessor.AssessSoftwareAsync(s, verifyTls);
                        }
                        catch (WingetException ex)
                        {
                            s.SecurityLevel = "?";
                            s.SecurityReport = ex.Message;
                        }
                        _runner.Log(L.F("Ocena źródła „{0}”: {1}", s.Name, s.SecurityLevelDisplay), msgId: LogEvent.Assess);
                    }
                });
                RefreshTable();
            }
        }
        var now = DateTimeOffset.Now;
        var denied = targets.Select(s => (Item: s, Decision: policies.Evaluate(s, automatic: false, now)))
                            .Where(d => !d.Decision.Allowed).ToList();
        foreach (var (s, decision) in denied)
            _runner.Log(L.F("Pominięto {0}: {1}", s.Name, decision.Reason.ToString()), SyslogSeverity.Notice, LogEvent.Policy);
        targets = targets.Except(denied.Select(d => d.Item)).ToList();
        var deniedText = denied.Count == 0 ? "" :
            L.F("Pominięte zgodnie z zasadami aktualizacji: {0}", denied.Count) + "\n" +
            string.Join("\n", denied.Select(d => $"  • {d.Item.Name}: {d.Decision.Reason}"));
        if (targets.Count == 0)
        {
            Ui.Info(this, L.T("Zasady aktualizacji"), deniedText + "\n\n" + L.T("Zasady można zmienić w oknie „Zasady aktualizacji”."));
            return;
        }

        var low = targets.Any(s => s.SecurityLevel == Levels.Low);
        var msg = L.T("Zostaną zaktualizowane:") + "\n\n" + string.Join("\n", targets.Select(s =>
            $"  • {(s.IsUrgent ? "[" + L.T("PILNE") + "] " : "")}{s.Name}: {s.Version} → {s.AvailableVersion}  [{(s.SecurityLevel.Length > 0 ? s.SecurityLevelDisplay : L.T("nie oceniono"))}]"));
        if (skipped > 0) msg += "\n\n" + L.F("Pominięte (brak aktualizacji w repozytorium): {0}", skipped);
        if (deniedText.Length > 0) msg += "\n\n" + deniedText;
        if (targets.Any(s => s.SecurityLevel.Length == 0))
            msg += "\n\n" + L.T("Niektóre źródła nie zostały ocenione - zalecane jest wcześniejsze użycie „Oceń źródło”.");
        if (low) msg += "\n\n" + L.T("UWAGA: część źródeł ma NISKI poziom zaufania!");
        msg += "\n\n" + L.T("Instalatory mogą poprosić o uprawnienia administratora (UAC). Kontynuować?");
        if (!Ui.Confirm(this, L.T("Potwierdź aktualizację"), msg, low)) return;
        BottomTabs.SelectedIndex = 1;

        var verifyChecksums = VerifyChecksums.IsChecked == true;
        var results = new List<(Software Item, int Code)>();
        var blocked = new List<Software>();
        var ok = await _runner.RunAsync(LogEvent.Upgrade, L.F("Aktualizowanie {0} programów...", targets.Count), async () =>
        {
            foreach (var s in targets)
            {
                VerifiedInstaller? verifiedInstaller = null;
                var version = s.AvailableVersion;
                var sha256 = "";
                if (verifyChecksums)
                {
                    verifiedInstaller = await VerifyInstallerAsync(s.Name, s.WingetId!, s.WingetSource);
                    if (verifiedInstaller is null)
                    {
                        blocked.Add(s);
                        continue;
                    }
                    version = verifiedInstaller.Version;
                    sha256 = verifiedInstaller.Sha256;
                }
                try
                {
                    _runner.Log(L.F("Aktualizacja {0} ({1})...", s.Name, s.WingetId), SyslogSeverity.Notice);
                    var code = verifiedInstaller is null
                        ? await WingetClient.UpgradeAsync(s.WingetId!, line => UiLog("  " + line), s.WingetSource, version)
                        : await WingetClient.UpgradeVerifiedAsync(verifiedInstaller, line => UiLog("  " + line));
                    results.Add((s, code));
                    if (code == 0)
                    {
                        _runner.Log(L.F("Zaktualizowano {0} ({1}).", s.Name, s.WingetId), SyslogSeverity.Notice);
                        RecordUpgrade(s, version, sha256, scheduled: false);
                    }
                }
                finally { verifiedInstaller?.Dispose(); }
            }
        }, typeof(WingetException));
        if (!ok) return;
        var failed = results.Where(r => r.Code != 0).ToList();
        foreach (var (s, code) in failed)
            _runner.Log(L.F("Niepowodzenie: {0} (kod 0x{1:X8})", s.Name, code), SyslogSeverity.Error, LogEvent.Upgrade);
        var summary = L.F("Zaktualizowano: {0}", results.Count - failed.Count) + "\n" + L.F("Niepowodzenia: {0}", failed.Count);
        if (blocked.Count > 0)
            summary += "\n" + L.F("Wstrzymane po weryfikacji plików kontrolnych: {0}", blocked.Count) + "\n" +
                       string.Join("\n", blocked.Select(b => "  • " + b.Name));
        Ui.Info(this, L.T("Zakończono"), summary + "\n\n" + L.T("Szczegóły w zakładce „Dziennik”."));
        await CheckUpdatesAsync();
    }

    /// <summary>Zapamiętuje poprzednią wersję, aby można było wycofać aktualizację.</summary>
    internal static void RecordUpgrade(Software s, string version, string sha256, bool scheduled)
    {
        if (string.IsNullOrEmpty(s.WingetId) || s.Version.Length == 0) return;
        try
        {
            UpdateHistory.Add(new UpdateRecord
            {
                Kind = UpdateKind.Upgrade, Name = s.Name, WingetId = s.WingetId, Source = s.WingetSource,
                FromVersion = s.Version, ToVersion = version.Length > 0 ? version : s.AvailableVersion,
                Sha256 = sha256, Scheduled = scheduled,
            });
        }
        catch (Exception ex) when (ex is System.IO.IOException or UnauthorizedAccessException or InvalidDataException or TimeoutException)
        {
            Syslog.Warning(LogEvent.Rollback, L.F("Nie udało się zapisać historii aktualizacji: {0}", ex.Message));
        }
    }

    /// <summary>
    /// Weryfikuje instalator przed instalacją. Zwraca wersję do zainstalowania ("" = bez przypinania) i SHA256
    /// albo null, gdy instalacja ma zostać wstrzymana.
    /// </summary>
    private async Task<VerifiedInstaller?> VerifyInstallerAsync(string name, string wingetId, string source, string version = "")
    {
        _runner.Log(L.F("Weryfikacja plików kontrolnych: {0} ({1})...", name, wingetId), SyslogSeverity.Informational, LogEvent.Verify);
        var result = await InstallerVerifier.VerifyAsync(wingetId, source,
                                                         text => Dispatcher.BeginInvoke(() => _runner.SetStatus($"{name}: {text}")),
                                                         version: version);
        foreach (var c in result.Checks)
        {
            var (icon, severity) = c.Status switch
            {
                CheckStatus.Ok => ("[OK]", SyslogSeverity.Informational),
                CheckStatus.Warn => ("[!]", SyslogSeverity.Warning),
                _ => ("[" + L.T("BŁĄD") + "]", SyslogSeverity.Error),
            };
            var detail = c.Detail?.ToString() ?? "";
            _runner.Log($"  {icon} {c.Label}{(detail.Length > 0 ? ": " + detail : "")}", severity, LogEvent.Verify);
        }
        if (result.Blocked)
        {
            result.VerifiedInstaller?.Dispose();
            _runner.Log(L.F("Instalacja {0} wstrzymana - instalator nie przeszedł weryfikacji.", name), SyslogSeverity.Error, LogEvent.Verify);
            return null;
        }
        if (result.StoreManaged)
        {
            _runner.Log(L.F("Pominięto {0} - aktualizacje Microsoft Store wymagają dedykowanej zakładki.", name),
                SyslogSeverity.Warning, LogEvent.Verify);
            return null;
        }
        if (result.PassedWithoutScan)
        {
            var install = Ui.Confirm(this, L.T("Skanowanie Microsoft Defender"),
                L.F("Microsoft Defender jest niedostępny (np. wyłączony przez inny program antywirusowy), więc instalator {0} nie został przeskanowany przed instalacją.", name) +
                "\n\n" + L.T("Pozostałe kontrole zakończyły się pomyślnie. Zainstalować bez skanowania antywirusowego?"), warning: true);
            _runner.Log(install ? L.F("Użytkownik zezwolił na instalację {0} bez skanowania Microsoft Defender.", name)
                                : L.F("Użytkownik wstrzymał instalację {0}.", name),
                        install ? SyslogSeverity.Warning : SyslogSeverity.Notice, LogEvent.Verify);
            if (!install)
            {
                result.VerifiedInstaller?.Dispose();
                return null;
            }
        }
        if (result.Completed)
        {
            if (result.Sha256.Length > 0)
                _runner.Log(L.F("Instalator zweryfikowany: {0} {1}, SHA256 {2}", name, result.Version, result.Sha256),
                            SyslogSeverity.Notice, LogEvent.Verify);
            return result.VerifiedInstaller;
        }
        var reason = result.Error?.ToString() ?? "";
        _runner.Log(L.F("Nie udało się zweryfikować instalatora {0}: {1}", name, reason), SyslogSeverity.Warning, LogEvent.Verify);
        Ui.Warn(this, L.T("Weryfikacja plików kontrolnych"),
            L.F("Nie udało się zweryfikować instalatora {0}; aktualizacja została wstrzymana.", name) +
            "\n\n" + reason + "\n\n" +
            L.T("Aby pominąć dodatkową weryfikację, wyłącz ją świadomie w ustawieniach i zaakceptuj ostrzeżenie."));
        result.VerifiedInstaller?.Dispose();
        return null;
    }

    /// <summary>Wyłączenie weryfikacji wyłącza też skanowanie Defender, dlatego wymaga wyraźnego potwierdzenia.</summary>
    private void VerifyChecksums_Click(object sender, RoutedEventArgs e)
    {
        if (VerifyChecksums.IsChecked == true)
        {
            _runner.Log(L.T("Włączono weryfikację instalatorów przed instalacją."), SyslogSeverity.Notice, LogEvent.Settings);
            return;
        }
        var disable = Ui.Confirm(this, L.T("Weryfikacja plików kontrolnych"),
            L.T("Wyłączenie tej opcji wyłącza również skanowanie instalatorów programem Microsoft Defender. Instalatory nie będą sprawdzane przed instalacją.") +
            "\n\n" + L.T("Wyłączyć weryfikację?"), warning: true);
        VerifyChecksums.IsChecked = !disable;
        if (disable)
            _runner.Log(L.T("Użytkownik wyłączył weryfikację i skanowanie instalatorów przed instalacją."), SyslogSeverity.Warning, LogEvent.Settings);
    }

    internal static string SearchQuery(string name)
    {
        var query = Regex.Replace(name, @"\(.*?\)|\bv?\d+(?:\.\d+)+[\w.\-+]*", " ");
        query = Regex.Replace(query, @"\s+", " ").Trim();
        return query.Length > 0 ? query : name;
    }

    private async void Search_Click(object sender, RoutedEventArgs e)
    {
        var selected = RequireSelection();
        if (selected.Count == 0) return;
        var s = selected[0];
        var query = SearchQuery(s.Name);
        var results = new List<CatalogPackage>();
        var errors = new List<string>();
        var ok = await _runner.RunAsync(LogEvent.Search, L.F("Wyszukiwanie „{0}” w winget, Scoop Main i Chocolatey Community...", query), async () =>
        {
            async Task<IEnumerable<CatalogPackage>> Winget()
            {
                var found = await WingetClient.SearchAsync(query);
                return found.Select(p => new CatalogPackage("winget", p.Name, p.Id, p.Version, p.Source,
                    "https://github.com/microsoft/winget-pkgs/search?q=" + Uri.EscapeDataString(p.Id) + "&type=code"));
            }
            var providers = new List<(string Name, Func<Task<IEnumerable<CatalogPackage>>> Search)>();
            if (WingetClient.IsAvailable()) providers.Add(("winget", Winget));
            else errors.Add("winget: " + L.T("nie znaleziono programu."));
            providers.Add(("Scoop Main", async () => await CatalogClient.SearchScoopAsync(query)));
            providers.Add(("Chocolatey Community", async () => await CatalogClient.SearchChocolateyAsync(query)));
            var tasks = providers.Select(async p =>
            {
                try
                {
                    return (p.Name, Found: (await p.Search()).ToList(), Error: (string?)null);
                }
                catch (Exception ex) when (ex is CatalogException or WingetException)
                {
                    return (p.Name, Found: new List<CatalogPackage>(), Error: (string?)ex.Message);
                }
            }).ToList();
            foreach (var (name, found, error) in await Task.WhenAll(tasks))
            {
                results.AddRange(found);
                if (error is not null) errors.Add($"{name}: {error}");
            }
        });
        if (!ok) return;

        var dialog = new SearchWindow(s, query, results, errors) { Owner = Window.GetWindow(this) };
        if (dialog.ShowDialog() != true || dialog.SelectedPackage is not { } package) return;
        await LinkAsync(s, package);
    }

    private async Task LinkAsync(Software s, CatalogPackage p)
    {
        if (p.Manager == "winget")
        {
            s.WingetId = p.Id;
            s.WingetSource = p.Source;
            var knownVersion = p.Version.Length > 0 && !p.Version.Equals("unknown", StringComparison.OrdinalIgnoreCase);
            s.AvailableVersion = knownVersion && p.Version != s.Version ? p.Version : "";
            s.SearchHint = L.Txt("Ręcznie powiązano z pakietem {0} ({1}).", p.Id, p.Source) + " " +
                           L.Txt("Aby zainstalować najnowszą wersję: {0}", $"winget install --id {p.Id} --exact");
            RefreshTable();
            Select(s);
            await AssessSelectedAsync();
            return;
        }

        Assessment? assessment = null;
        var verify = VerifyTls.IsChecked == true;
        var ok = await _runner.RunAsync(LogEvent.Assess, L.F("Ocena pakietu {0} z {1}...", p.Id, p.Source), async () =>
            assessment = p.Manager == "scoop" ? await CatalogClient.AssessScoopAsync(p, verify) : CatalogClient.AssessChocolatey(p),
            typeof(CatalogException));
        if (!ok || assessment is null) return;
        s.SecurityLevel = assessment.Level;
        s.Assessment = assessment;
        s.CatalogId = p.Id;
        s.CatalogSource = p.Source;
        s.CatalogUrl = p.DetailsUrl;
        var command = p.Manager == "scoop"
            ? $"scoop install {p.Id}"
            : $"choco install {p.Id} --source https://community.chocolatey.org/api/v2/";
        s.SearchHint = L.Txt("Wynik wyszukiwania z {0}. Ta aplikacja nie uruchamia instalacji z tego źródła.", p.Source) + " " +
                       L.Txt("Jeśli zdecydujesz się na instalację, użyj menedżera po sprawdzeniu raportu: {0}", command);
        _runner.Log(L.F("Ocena źródła „{0}” ({1}): {2}", p.Id, p.Source, L.T(assessment.Level)), msgId: LogEvent.Assess);
        RefreshTable();
        Select(s);
        BottomTabs.SelectedIndex = 0;
    }

    private void Homepage_Click(object sender, RoutedEventArgs e)
    {
        var selected = RequireSelection();
        if (selected.Count == 0) return;
        var s = selected[0];
        var url = new[] { s.Homepage }.Concat(s.VendorUrls())
            .FirstOrDefault(u => Regex.IsMatch(u, "^https?://", RegexOptions.IgnoreCase));
        if (url is null)
        {
            Ui.Info(this, L.T("Brak adresu"), L.T("Brak zapisanego adresu strony producenta."));
            return;
        }
        if (!url.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            var httpsUrl = "https://" + url[(url.IndexOf("://", StringComparison.Ordinal) + 3)..];
            var answer = Ui.Ask(this, L.T("Niezaszyfrowane połączenie"),
                L.F("Adres {0} nie używa HTTPS - pobieranie plików przez HTTP jest ryzykowne.", url) + "\n\n" +
                L.F("Tak - otwórz bezpieczny wariant: {0}", httpsUrl) + "\n" + L.T("Nie - otwórz oryginalny adres"),
                MessageBoxButton.YesNoCancel, MessageBoxImage.Warning);
            if (answer == MessageBoxResult.Cancel) return;
            if (answer == MessageBoxResult.Yes) url = httpsUrl;
        }
        Ui.OpenUrl(url);
    }

    internal static Dictionary<string, object?> ReportRow(Software s) => new()
    {
        ["name"] = s.Name, ["version"] = s.Version, ["publisher"] = s.Publisher,
        ["install_location"] = s.InstallLocation, ["install_date"] = s.InstallDate, ["origin"] = s.Origin,
        ["reg_key"] = s.RegKey, ["url_info"] = s.UrlInfo, ["url_update"] = s.UrlUpdate, ["help_link"] = s.HelpLink,
        ["winget_id"] = s.WingetId, ["winget_source"] = s.WingetSource, ["available_version"] = s.AvailableVersion,
        ["winget_detected"] = s.WingetDetected, ["security_level"] = s.SecurityLevelDisplay,
        ["security_report"] = s.SecurityReport, ["catalog_id"] = s.CatalogId, ["catalog_source"] = s.CatalogSource,
        ["has_update"] = s.HasUpdate,
        ["cve_count"] = s.Vulnerabilities?.Checked == true ? s.Vulnerabilities.Items.Count : null,
        ["cve_max_cvss"] = s.Vulnerabilities?.Checked == true && s.Vulnerabilities.Items.Count > 0 ? s.Vulnerabilities.MaxScore : null,
        ["cve_ids"] = s.Vulnerabilities is { Checked: true } v ? string.Join(" ", v.Items.Select(c => c.Id)) : "",
        ["cve_exploited"] = s.Vulnerabilities?.Exploited,
        ["epss_max_score"] = s.Vulnerabilities?.Items.Where(c => c.EpssScore.HasValue).Select(c => c.EpssScore).DefaultIfEmpty().Max(),
        ["osv_repository"] = s.Vulnerabilities?.OsvRepository ?? "",
        ["osv_confidence"] = s.Vulnerabilities?.OsvConfidence ?? "",
        ["osv_count"] = s.Vulnerabilities?.OsvItems.Count,
        ["osv_ids"] = s.Vulnerabilities is { } osv ? string.Join(" ", osv.OsvItems.Select(c => c.Id)) : "",
        ["urgent"] = s.IsUrgent,
        ["lifecycle"] = s.Lifecycle?.State.ToString() ?? "",
        ["lifecycle_eol"] = s.Lifecycle?.EolFrom?.ToString("yyyy-MM-dd") ?? "",
    };

    private void Export_Click(object sender, RoutedEventArgs e)
    {
        if (_items.Count == 0) return;
        var path = Ui.AskSavePath(this, L.T("Eksportuj raport"), $"{L.T("raport_oprogramowania")}_{DateTime.Now:yyyyMMdd_HHmm}.csv");
        if (path is null) return;
        try
        {
            if (path.EndsWith(".pdf", StringComparison.OrdinalIgnoreCase))
                ReportPdf.Write(path, _items);
            else
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
