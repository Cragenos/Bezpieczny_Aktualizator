using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using BezpiecznyAktualizator.Core.History;
using BezpiecznyAktualizator.Core.Localization;
using BezpiecznyAktualizator.Core.Logging;
using BezpiecznyAktualizator.Core.Models;
using BezpiecznyAktualizator.Core.Store;
using BezpiecznyAktualizator.Core.Winget;
using BezpiecznyAktualizator.Services;

namespace BezpiecznyAktualizator.Views;

public partial class MicrosoftStoreView : UserControl
{
    private readonly BackgroundRunner _runner;
    private List<Software> _items = [];
    private ListCollectionView? _view;
    private bool _searched;

    public MicrosoftStoreView()
    {
        InitializeComponent();
        _runner = new BackgroundRunner(this, Toolbar, Progress, StatusText, LogBox, SummaryText, LogEvent.StoreUpdate, CanStart);
        SetItems([]);
        L.LanguageChanged += Refresh;
    }

    public bool IsBusy => _runner.IsBusy;

    private bool CanStart() => Window.GetWindow(this) is not MainWindow main || main.CanStartWinget(this);

    private string SummaryText() => _searched
        ? L.F("Aktualizacje Microsoft Store: {0}", _items.Count)
        : L.T("Kliknij „Sprawdź aktualizacje”.");

    private void SetItems(List<Software> items)
    {
        _items = items;
        _view = new ListCollectionView(_items) { Filter = item => Matches((Software)item) };
        Table.ItemsSource = _view;
        Refresh();
    }

    private bool Matches(Software item)
    {
        var text = FilterBox.Text.Trim();
        return text.Length == 0 || new[] { item.Name, item.WingetId ?? "", item.Version, item.AvailableVersion, item.PolicyDisplay }
            .Any(value => value.Contains(text, StringComparison.CurrentCultureIgnoreCase));
    }

    private void Refresh()
    {
        if (_view is null) return;
        if (_items.Count > 0)
        {
            var policies = Settings.Policies;
            var now = DateTimeOffset.Now;
            foreach (var item in _items)
            {
                item.PolicyDisplay = Settings.MachinePolicyError is null ? policies.Describe(item, now) : L.T("Błąd zasad");
                item.PolicyBlocked = Settings.MachinePolicyError is not null || !policies.Evaluate(item, automatic: false, now).Allowed;
            }
        }
        _view.Refresh();
        CountLabel.Text = L.F("Wyświetlono {0} z {1}", _view.Count, _items.Count);
        _runner.UpdateSummary();
        ShowDetails();
    }

    public void PoliciesChanged() => Refresh();

    private void View_IsVisibleChanged(object sender, DependencyPropertyChangedEventArgs e)
    {
        if (IsVisible && _view is not null) Refresh();
    }

    private void Filter_Changed(object sender, TextChangedEventArgs e)
    {
        if (_view is not null) Refresh();
    }

    private void Table_SelectionChanged(object sender, SelectionChangedEventArgs e) => ShowDetails();

    private void ShowDetails()
    {
        if (Table.SelectedItem is not Software item)
        {
            Details.Text = "";
            return;
        }
        var lines = Ui.FormatFields([
            (L.T("Nazwa"), item.Name),
            (L.T("Identyfikator pakietu"), item.WingetId ?? ""),
            (L.T("Wersja"), item.Version),
            (L.T("Dostępna wersja"), item.AvailableVersion),
            (L.T("Źródło aktualizacji"), "Microsoft Store"),
            (L.T("Zasada"), item.PolicyDisplay),
        ]);
        if (item.PolicyBlocked && Settings.MachinePolicyError is null)
            lines.Add("\n" + Settings.Policies.Evaluate(item, automatic: false, DateTimeOffset.Now).Reason.ToString());
        Details.Text = string.Join(Environment.NewLine, lines);
    }

    private async void Search_Click(object sender, RoutedEventArgs e) => await SearchAsync(interactive: true);

    private async Task SearchAsync(bool interactive)
    {
        if (!CanStart()) return;
        if (interactive && !Ui.Confirm(this, L.T("Microsoft Store"),
            L.T("WinGet może przekazać Microsoft informacje o zainstalowanych aplikacjach i zaakceptować warunki źródła. Kontynuować?"), warning: true))
            return;

        _searched = false;
        SetItems([]);
        StoreSearchResult? result = null;
        var ok = await _runner.RunAsync(LogEvent.StoreUpdate, L.T("Sprawdzanie aktualizacji Microsoft Store..."),
            async () => result = await MicrosoftStoreClient.FindUpdatesAsync(), typeof(WingetException));
        if (!ok || result is null) return;
        _searched = true;
        SetItems(result.Updates.ToList());
        _runner.Log(L.F("Aktualizacje Microsoft Store: {0}", _items.Count));
        if (result.UnparsedOutput is { } output)
        {
            var message = L.T("WinGet nie zwrócił listy aktualizacji. Sprawdź jego komunikat i Microsoft Store.") +
                          "\n\n" + output;
            _runner.Log(message, SyslogSeverity.Warning);
            Ui.Warn(this, L.T("Microsoft Store"), message);
        }
        else if (result.UnknownVersions > 0)
        {
            var message = L.F("Pominięto {0} pozycji bez potwierdzonych wersji. Sprawdź je w Microsoft Store.", result.UnknownVersions);
            _runner.Log(message, SyslogSeverity.Warning);
            Ui.Warn(this, L.T("Microsoft Store"), message);
        }
        else if (interactive && _items.Count == 0)
        {
            Ui.Info(this, L.T("Microsoft Store"),
                L.T("WinGet nie wykrył aktualizacji. Sprawdź również Microsoft Store."));
        }
    }

    private async void Upgrade_Click(object sender, RoutedEventArgs e)
    {
        if (!CanStart()) return;
        var selected = Table.SelectedItems.Cast<Software>().ToList();
        if (selected.Count == 0)
        {
            Ui.Info(this, L.T("Brak zaznaczenia"), L.T("Zaznacz co najmniej jeden program na liście."));
            return;
        }

        var policies = Settings.Policies;
        if (Settings.MachinePolicyError is { } error)
        {
            Ui.Error(this, L.T("Zasady aktualizacji"), L.F("Nie można wczytać zasad komputera. Aktualizowanie zablokowane: {0}", error));
            return;
        }
        var denied = selected.Select(item => (Item: item, Decision: policies.Evaluate(item, automatic: false, DateTimeOffset.Now)))
            .Where(x => !x.Decision.Allowed).ToList();
        foreach (var (item, decision) in denied)
            _runner.Log(L.F("Pominięto {0}: {1}", item.Name, decision.Reason.ToString()), SyslogSeverity.Notice, LogEvent.Policy);
        var targets = selected.Except(denied.Select(x => x.Item)).ToList();
        if (targets.Count == 0)
        {
            Ui.Info(this, L.T("Zasady aktualizacji"),
                string.Join("\n", denied.Select(x => $"  • {x.Item.Name}: {x.Decision.Reason}")));
            return;
        }

        var text = L.T("Zostaną zaktualizowane:") + "\n\n" +
                   string.Join("\n", targets.Select(item => $"  • {item.Name}: {item.Version} → {item.AvailableVersion}"));
        if (denied.Count > 0)
            text += "\n\n" + L.F("Pominięte zgodnie z zasadami aktualizacji: {0}", denied.Count);
        text += "\n\n" + L.T("WinGet może zaakceptować warunki pakietów, a Microsoft Store może zainstalować nowszą wersję niż na liście. Ten program nie skanuje pobranych plików. Kontynuować?");
        if (!Ui.Confirm(this, L.T("Potwierdź aktualizację"), text, warning: true)) return;

        var confirmed = 0;
        var unconfirmed = 0;
        var failed = 0;
        var skipped = 0;
        BottomTabs.SelectedIndex = 1;
        var ok = await _runner.RunAsync(LogEvent.StoreUpdate, L.F("Aktualizowanie {0} programów...", targets.Count), async () =>
        {
            foreach (var item in targets)
            {
                var currentPolicies = Settings.Policies;
                if (Settings.MachinePolicyError is { } policyError)
                    throw new WingetException(L.F("Nie można wczytać zasad komputera. Aktualizowanie zablokowane: {0}", policyError));
                var decision = currentPolicies.Evaluate(item, automatic: false, DateTimeOffset.Now);
                if (!decision.Allowed)
                {
                    skipped++;
                    _runner.Log(L.F("Pominięto {0}: {1}", item.Name, decision.Reason.ToString()), SyslogSeverity.Notice, LogEvent.Policy);
                    continue;
                }

                _runner.Log(L.F("Aktualizacja {0} ({1})...", item.Name, item.WingetId), SyslogSeverity.Notice);
                var code = await MicrosoftStoreClient.UpgradeAsync(item, UiLog);
                if (code != 0)
                {
                    failed++;
                    _runner.Log(L.F("Niepowodzenie: {0} (kod 0x{1:X8})", item.Name, code), SyslogSeverity.Error);
                    continue;
                }

                string? installed = null;
                try
                {
                    installed = await MicrosoftStoreClient.InstalledVersionAsync(item);
                }
                catch (WingetException ex)
                {
                    _runner.Log(L.F("Nie udało się potwierdzić wersji {0}: {1}", item.Name, ex.Message), SyslogSeverity.Warning);
                }
                if (installed is not null && UpdateHistory.FindVersion([installed], item.AvailableVersion) is not null)
                {
                    confirmed++;
                    SoftwareView.RecordUpgrade(item, item.AvailableVersion, "", scheduled: false);
                    _runner.Log(L.F("Zaktualizowano {0} ({1}).", item.Name, item.WingetId), SyslogSeverity.Notice);
                }
                else
                {
                    unconfirmed++;
                    _runner.Log(L.F("Nie potwierdzono zainstalowanej wersji {0}. Sprawdź Microsoft Store.", item.Name), SyslogSeverity.Warning);
                }
            }
        }, typeof(WingetException));
        if (!ok)
        {
            _searched = false;
            SetItems([]);
            return;
        }
        var summary = L.F("Zaktualizowano: {0}", confirmed) + "\n" +
                      L.F("Niepotwierdzone: {0}", unconfirmed) + "\n" +
                      L.F("Niepowodzenia: {0}", failed);
        if (skipped > 0) summary += "\n" + L.F("Pominięte zgodnie z zasadami aktualizacji: {0}", skipped);
        if (failed > 0 || unconfirmed > 0) Ui.Warn(this, L.T("Zakończono"), summary);
        else Ui.Info(this, L.T("Zakończono"), summary);
        await SearchAsync(interactive: false);
    }

    private void UiLog(string line)
    {
        if (Dispatcher.CheckAccess()) _runner.Log("  " + line);
        else Dispatcher.BeginInvoke(() => _runner.Log("  " + line));
    }

    private void OpenStore_Click(object sender, RoutedEventArgs e)
    {
        if (!Ui.Confirm(this, L.T("Microsoft Store"),
            L.T("Aktualizacje wykonane bezpośrednio w Microsoft Store nie podlegają zasadom tego programu. Kontynuować?"), warning: true))
            return;
        try
        {
            Ui.OpenUrl(MicrosoftStoreClient.UpdatesUri);
        }
        catch (Exception ex) when (ex is Win32Exception or InvalidOperationException or UnauthorizedAccessException)
        {
            _runner.Log(L.F("Nie udało się otworzyć Microsoft Store: {0}", ex.Message), SyslogSeverity.Error);
            Ui.Error(this, L.T("Microsoft Store"), L.F("Nie udało się otworzyć Microsoft Store: {0}", ex.Message));
        }
    }

    private void Policies_Click(object sender, RoutedEventArgs e)
    {
        if (new PoliciesWindow { Owner = Window.GetWindow(this) }.ShowDialog() != true) return;
        if (Window.GetWindow(this) is MainWindow main) main.PoliciesChanged();
        else Refresh();
    }
}
