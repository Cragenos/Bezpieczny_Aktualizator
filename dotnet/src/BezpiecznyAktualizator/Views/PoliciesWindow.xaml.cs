using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using BezpiecznyAktualizator.Core.Localization;
using BezpiecznyAktualizator.Core.Logging;
using BezpiecznyAktualizator.Core.Policies;
using BezpiecznyAktualizator.Services;
using Microsoft.Win32;

namespace BezpiecznyAktualizator.Views;

/// <summary>Edycja zasad aktualizacji: wykluczenia, wstrzymane wersje i wymagany poziom zaufania źródeł.</summary>
public partial class PoliciesWindow : Window
{
    public sealed class ExclusionRow
    {
        public string WingetId { get; set; } = "";
        public string Name { get; set; } = "";
        public string Reason { get; set; } = "";
        public DateTimeOffset Added { get; set; } = DateTimeOffset.Now;
        public bool Managed { get; init; }
        public string Origin => Managed ? L.T("administrator") : L.T("użytkownik");
    }

    public sealed class HoldRow
    {
        public string WingetId { get; set; } = "";
        public string Name { get; set; } = "";
        public string Version { get; set; } = "";
        public string Until { get; set; } = "";
        public string Reason { get; set; } = "";
        public DateTimeOffset Added { get; set; } = DateTimeOffset.Now;
        public bool Managed { get; init; }
        public string Origin => Managed ? L.T("administrator") : L.T("użytkownik");
    }

    private readonly ObservableCollection<ExclusionRow> _excluded = [];
    private readonly ObservableCollection<HoldRow> _holds = [];
    private readonly UpdatePolicies _original;

    public PoliciesWindow()
    {
        InitializeComponent();
        Scroller.MaxHeight = Math.Max(320, SystemParameters.WorkArea.Height - 160);
        _original = Settings.Policies;
        TrustBox.SelectedIndex = _original.AutoTrust == AutoTrustLevel.HighOrMedium ? 1 : 0;
        ManualTrustBox.IsChecked = _original.ManualRequireTrusted;
        TrustBox.IsEnabled = !_original.AutoTrustManaged;
        ManualTrustBox.IsEnabled = !_original.ManualTrustManaged;
        foreach (var e in _original.Excluded)
            _excluded.Add(new ExclusionRow { WingetId = e.WingetId, Name = e.Name, Reason = e.Reason, Added = e.Added, Managed = e.Managed });
        foreach (var h in _original.Holds)
            _holds.Add(new HoldRow
            {
                WingetId = h.WingetId, Name = h.Name, Version = h.Version, Reason = h.Reason, Added = h.Added, Managed = h.Managed,
                Until = h.Until is { } u ? u.ToLocalTime().ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) : "",
            });
        ExcludedGrid.ItemsSource = _excluded;
        HoldsGrid.ItemsSource = _holds;

        if (_original.HasMachinePolicy || Settings.MachinePolicyError is not null)
        {
            MachineCard.Visibility = Visibility.Visible;
            MachineText.Text = Settings.MachinePolicyError is { } error
                ? L.F("Nie udało się wczytać zasad komputera: {0}", error)
                : L.T("Część zasad została ustawiona przez administratora komputera. Nie można ich zmienić ani złagodzić w programie.");
        }
        MachineHint.Text = L.F("Administrator może narzucić zasady wszystkim użytkownikom komputera, zapisując je w pliku {0} (format jak w eksporcie).",
                               UpdatePolicies.MachineFilePath);
    }

    /// <summary>Reguły administratora są tylko do odczytu.</summary>
    private void Grid_BeginningEdit(object? sender, DataGridBeginningEditEventArgs e)
    {
        if (e.Row.Item is ExclusionRow { Managed: true } or HoldRow { Managed: true }) e.Cancel = true;
    }

    private void AddExclusion_Click(object sender, RoutedEventArgs e) => AddRow(ExcludedGrid, _excluded, new ExclusionRow());

    private void AddHold_Click(object sender, RoutedEventArgs e) => AddRow(HoldsGrid, _holds, new HoldRow());

    private static void AddRow<T>(DataGrid grid, ObservableCollection<T> rows, T row)
    {
        grid.CommitEdit(DataGridEditingUnit.Row, true);
        rows.Add(row);
        grid.SelectedItem = row;
        grid.ScrollIntoView(row);
        grid.CurrentCell = new DataGridCellInfo(row, grid.Columns[0]);
        grid.Focus();
        grid.BeginEdit();
    }

    private void RemoveExclusion_Click(object sender, RoutedEventArgs e)
    {
        if (ExcludedGrid.SelectedItem is ExclusionRow { Managed: false } row)
        {
            ExcludedGrid.CancelEdit();
            _excluded.Remove(row);
        }
    }

    private void RemoveHold_Click(object sender, RoutedEventArgs e)
    {
        if (HoldsGrid.SelectedItem is HoldRow { Managed: false } row)
        {
            HoldsGrid.CancelEdit();
            _holds.Remove(row);
        }
    }

    /// <summary>Zasady użytkownika z formularza; null, gdy dane są błędne (komunikat został pokazany).</summary>
    private UpdatePolicies? Collect()
    {
        ExcludedGrid.CommitEdit(DataGridEditingUnit.Row, true);
        HoldsGrid.CommitEdit(DataGridEditingUnit.Row, true);
        var holds = new List<VersionHold>();
        foreach (var h in _holds.Where(h => !h.Managed && h.WingetId.Trim().Length > 0))
        {
            DateTimeOffset? until = null;
            if (h.Until.Trim().Length > 0)
            {
                if (!DateTime.TryParseExact(h.Until.Trim(), "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var date))
                {
                    Ui.Warn(this, Title, L.F("Nieprawidłowa data „{0}” dla {1}. Użyj formatu RRRR-MM-DD.", h.Until, h.WingetId));
                    return null;
                }
                // Wstrzymanie obowiązuje do końca wskazanego dnia.
                until = new DateTimeOffset(date.AddDays(1));
            }
            holds.Add(new VersionHold
            {
                WingetId = h.WingetId, Name = h.Name, Version = h.Version, Reason = h.Reason, Added = h.Added, Until = until,
            });
        }
        return new UpdatePolicies
        {
            AutoTrust = TrustBox.SelectedIndex == 1 ? AutoTrustLevel.HighOrMedium : AutoTrustLevel.High,
            ManualRequireTrusted = ManualTrustBox.IsChecked == true,
            Excluded = _excluded.Where(x => !x.Managed && x.WingetId.Trim().Length > 0)
                .Select(x => new ExclusionRule { WingetId = x.WingetId, Name = x.Name, Reason = x.Reason, Added = x.Added }).ToList(),
            Holds = holds,
        }.Normalize();
    }

    private void Save_Click(object sender, RoutedEventArgs e)
    {
        if (Collect() is not { } policies) return;
        Settings.Policies = policies;
        LogChanges(_original, policies);
        DialogResult = true;
    }

    private static void LogChanges(UpdatePolicies before, UpdatePolicies after)
    {
        var oldExcluded = before.Excluded.Where(x => !x.Managed).Select(x => x.WingetId).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var newExcluded = after.Excluded.Select(x => x.WingetId).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var id in newExcluded.Except(oldExcluded))
            Syslog.Notice(LogEvent.Policy, L.F("Dodano wykluczenie: {0}.", id));
        foreach (var id in oldExcluded.Except(newExcluded))
            Syslog.Notice(LogEvent.Policy, L.F("Usunięto wykluczenie: {0}.", id));

        var oldHolds = before.Holds.Where(x => !x.Managed).ToDictionary(x => x.WingetId, x => x.Display, StringComparer.OrdinalIgnoreCase);
        foreach (var h in after.Holds)
            if (!oldHolds.TryGetValue(h.WingetId, out var display) || display != h.Display)
                Syslog.Notice(LogEvent.Policy, L.F("Wstrzymano wersję {0}: {1}.", h.WingetId, h.Display));
        foreach (var id in oldHolds.Keys.Where(id => after.Holds.All(h => !h.WingetId.Equals(id, StringComparison.OrdinalIgnoreCase))))
            Syslog.Notice(LogEvent.Policy, L.F("Zniesiono wstrzymanie wersji: {0}.", id));

        Syslog.Notice(LogEvent.Policy, L.F("Zasady aktualizacji: automatycznie ze źródeł o zaufaniu: {0}; ręczne wymagają zaufanego źródła: {1}; wykluczenia: {2}; wstrzymania: {3}.",
            after.AutoTrust == AutoTrustLevel.HighOrMedium ? L.T("Wysokim lub średnim") : L.T("Wysokim"),
            after.ManualRequireTrusted ? L.T("tak") : L.T("nie"), after.Excluded.Count, after.Holds.Count));
    }

    private void Export_Click(object sender, RoutedEventArgs e)
    {
        if (Collect() is not { } policies) return;
        var dialog = new SaveFileDialog
        {
            FileName = "policies.json",
            Filter = L.T("Plik JSON") + " (*.json)|*.json",
        };
        if (dialog.ShowDialog(this) != true) return;
        try
        {
            File.WriteAllText(dialog.FileName, policies.ToJson());
            Syslog.Info(LogEvent.Policy, L.F("Wyeksportowano zasady aktualizacji do {0}.", dialog.FileName));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Syslog.Error(LogEvent.Policy, L.F("Nie udało się zapisać pliku {0}.", dialog.FileName), ex);
            Ui.Error(this, Title, ex.Message);
        }
    }
}
