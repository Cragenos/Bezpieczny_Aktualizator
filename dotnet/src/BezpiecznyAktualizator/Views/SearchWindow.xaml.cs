using System.Windows;
using BezpiecznyAktualizator.Core.Catalogs;
using BezpiecznyAktualizator.Core.Localization;
using BezpiecznyAktualizator.Core.Models;
using BezpiecznyAktualizator.Services;

namespace BezpiecznyAktualizator.Views;

/// <summary>Przegląda wyniki z kilku katalogów i pozwala powiązać wybrany pakiet z programem.</summary>
public partial class SearchWindow : Window
{
    private static readonly HashSet<string> PackagePageHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "github.com", "community.chocolatey.org",
    };

    public CatalogPackage? SelectedPackage { get; private set; }

    public SearchWindow(Software software, string query, IReadOnlyList<CatalogPackage> results, IReadOnlyList<string> errors)
    {
        InitializeComponent();
        Title = L.F("Wyniki wyszukiwania: {0}", query);
        Header.Text = L.F("Program: {0}  —  wybierz pasujący pakiet:", $"{software.Name} {software.Version}");
        Results.ItemsSource = results;
        if (results.Count == 0) EmptyLabel.Visibility = Visibility.Visible;
        if (errors.Count > 0)
        {
            ErrorsLabel.Text = L.F("Niektóre źródła są niedostępne: {0}", string.Join(" | ", errors));
            ErrorsLabel.Visibility = Visibility.Visible;
        }
    }

    /// <summary>Strona pakietu może prowadzić wyłącznie do oficjalnego katalogu przez HTTPS.</summary>
    internal static bool IsTrustedPackagePage(string url) =>
        Uri.TryCreate(url, UriKind.Absolute, out var uri) && uri.Scheme == Uri.UriSchemeHttps &&
        PackagePageHosts.Contains(uri.Host);

    private void Open_Click(object sender, RoutedEventArgs e)
    {
        if (Results.SelectedItem is not CatalogPackage { DetailsUrl.Length: > 0 } p) return;
        if (!IsTrustedPackagePage(p.DetailsUrl))
        {
            Ui.Error(this, L.T("Nieznany adres pakietu"), L.T("Odrzucono adres strony spoza oficjalnego katalogu."));
            return;
        }
        Ui.OpenUrl(p.DetailsUrl);
    }

    private void Link_Click(object sender, RoutedEventArgs e) => Link();

    private void Results_DoubleClick(object sender, System.Windows.Input.MouseButtonEventArgs e) => Link();

    private void Link()
    {
        if (Results.SelectedItem is not CatalogPackage p) return;
        SelectedPackage = p;
        DialogResult = true;
    }
}
