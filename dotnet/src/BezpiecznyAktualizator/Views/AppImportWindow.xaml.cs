using System.ComponentModel;
using System.Windows;
using BezpiecznyAktualizator.Core.Inventory;
using BezpiecznyAktualizator.Core.Localization;

namespace BezpiecznyAktualizator.Views;

internal sealed class AppImportOption(AppTransferEntry entry) : INotifyPropertyChanged
{
    private bool _isSelected;

    public AppTransferEntry Entry { get; } = entry;
    public bool IsSelected
    {
        get => _isSelected;
        set
        {
            if (_isSelected == value) return;
            _isSelected = value;
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IsSelected)));
        }
    }

    public event PropertyChangedEventHandler? PropertyChanged;
}

public partial class AppImportWindow : Window
{
    private readonly List<AppImportOption> _options;

    public IReadOnlyList<AppTransferEntry> SelectedApps =>
        _options.Where(option => option.IsSelected).Select(option => option.Entry).ToList();

    public AppImportWindow(AppTransferManifest manifest, IReadOnlyList<AppTransferEntry> missing)
    {
        InitializeComponent();
        Header.Text = L.F("Lista z komputera {0}: {1} pakietów; już zainstalowane: {2}; brakujące: {3}.",
            manifest.Machine, manifest.Apps.Count, manifest.Apps.Count - missing.Count, missing.Count);
        _options = missing.Select(app => new AppImportOption(app)).ToList();
        foreach (var option in _options)
            option.PropertyChanged += (_, _) => UpdateSelection();
        Packages.ItemsSource = _options;
        UpdateSelection();
    }

    private void UpdateSelection()
    {
        var count = _options.Count(option => option.IsSelected);
        SelectionCount.Text = L.F("Zaznaczono: {0}", count);
        ContinueButton.IsEnabled = count > 0;
    }

    private void SelectAll_Click(object sender, RoutedEventArgs e)
    {
        foreach (var option in _options) option.IsSelected = true;
    }

    private void ClearSelection_Click(object sender, RoutedEventArgs e)
    {
        foreach (var option in _options) option.IsSelected = false;
    }

    private void Continue_Click(object sender, RoutedEventArgs e)
    {
        if (SelectedApps.Count > 0) DialogResult = true;
    }
}
