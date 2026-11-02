using System.Windows;
using System.Windows.Controls;
using BezpiecznyAktualizator.Core.History;
using BezpiecznyAktualizator.Core.Localization;
using BezpiecznyAktualizator.Core.Store;

namespace BezpiecznyAktualizator.Views;

/// <summary>Historia aktualizacji wykonanych przez aplikację; pozwala wybrać aktualizację do wycofania.</summary>
public partial class HistoryWindow : Window
{
    public sealed class Row(UpdateRecord record)
    {
        public UpdateRecord Record { get; } = record;
        public string TimeDisplay => Record.Time.ToLocalTime().ToString("yyyy-MM-dd HH:mm");
        public string KindDisplay => Record.Kind == UpdateKind.Rollback ? L.T("Wycofanie")
            : Record.Scheduled ? L.T("Aktualizacja (harmonogram)") : L.T("Aktualizacja");
        public string StatusDisplay => Record.RolledBack ? L.T("wycofano")
            : Record.Kind == UpdateKind.Upgrade && string.Equals(Record.Source, MicrosoftStoreClient.SourceName, StringComparison.OrdinalIgnoreCase)
                ? L.T("Wycofanie niemożliwe") : "";
    }

    public UpdateRecord? SelectedRecord { get; private set; }

    public HistoryWindow(IReadOnlyList<UpdateRecord> records, string? preselectWingetId)
    {
        InitializeComponent();
        var rows = records.OrderByDescending(r => r.Time).Select(r => new Row(r)).ToList();
        Records.ItemsSource = rows;
        if (rows.Count == 0) EmptyLabel.Visibility = Visibility.Visible;
        var preselect = UpdateHistory.LastRollbackable(records, preselectWingetId);
        if (preselect is not null)
        {
            var row = rows.First(r => r.Record == preselect);
            Records.SelectedItem = row;
            Records.ScrollIntoView(row);
        }
    }

    private void Records_SelectionChanged(object sender, SelectionChangedEventArgs e) =>
        RollbackButton.IsEnabled = Records.SelectedItem is Row { Record.CanRollback: true };

    private void Records_DoubleClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        if (RollbackButton.IsEnabled) Choose();
    }

    private void Rollback_Click(object sender, RoutedEventArgs e) => Choose();

    private void Choose()
    {
        if (Records.SelectedItem is not Row { Record.CanRollback: true } row) return;
        SelectedRecord = row.Record;
        DialogResult = true;
    }
}
