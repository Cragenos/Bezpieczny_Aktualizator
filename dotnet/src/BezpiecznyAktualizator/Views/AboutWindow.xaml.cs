using System.Runtime.InteropServices;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using BezpiecznyAktualizator.Core.Localization;
using BezpiecznyAktualizator.Core.Security;
using BezpiecznyAktualizator.Services;

namespace BezpiecznyAktualizator.Views;

/// <summary>Informacje o programie: autor, wersja, podpis cyfrowy i stan ochrony pliku programu.</summary>
public partial class AboutWindow : Window
{
    private readonly List<(string Label, string Value)> _all = [];

    public AboutWindow()
    {
        InitializeComponent();
        VersionText.Text = L.F("Wersja {0}", SelfProtection.Version);
        AddRow(AuthorGrid, L.T("Autor"), SelfProtection.Author);
        AddRow(AuthorGrid, L.T("Prawa autorskie"), SelfProtection.Copyright);
        AddRow(AuthorGrid, L.T("Środowisko"), $".NET {Environment.Version}, {RuntimeInformation.OSDescription}");
        AddRow(SecurityGrid, L.T("Podpis cyfrowy"), L.T("sprawdzanie..."));
        Loaded += async (_, _) => await ShowSecurityAsync();
    }

    private async Task ShowSecurityAsync()
    {
        var path = Environment.ProcessPath ?? "";
        var (signature, thumbprint) = await Task.Run(() => path.Length == 0
            ? (new SignatureInfo(SignatureState.Unsigned, 0, ""), "")
            : (Authenticode.Verify(path, checkRevocation: false), Authenticode.SignerThumbprint(path)));
        var expected = SelfProtection.ExpectedSigner;
        var tampered = IntegrityCheck.Problem(signature, thumbprint, expected) is not null;

        SecurityGrid.Children.Clear();
        SecurityGrid.RowDefinitions.Clear();
        _all.RemoveAll(r => r.Label == L.T("Podpis cyfrowy"));
        AddRow(SecurityGrid, L.T("Podpis cyfrowy"), signature.State switch
        {
            SignatureState.Valid => L.F("poprawny ({0})", signature.Signer),
            SignatureState.Unknown => L.F("plik nienaruszony, certyfikat wydawcy nie jest zaufany w systemie ({0})", signature.Signer),
            SignatureState.Invalid => L.T("NIEPRAWIDŁOWY - plik został zmieniony po podpisaniu"),
            _ => L.T("brak (wersja deweloperska)"),
        });
        if (thumbprint.Length > 0) AddRow(SecurityGrid, L.T("Odcisk certyfikatu"), thumbprint);
        AddRow(SecurityGrid, L.T("Ochrona przed inżynierią wsteczną"), SelfProtection.Enabled
            ? L.T("włączona: zaciemnianie kodu, szyfrowanie napisów, kontrola integralności, wykrywanie debugera")
            : L.T("wyłączona (wersja deweloperska)"));
        AddRow(SecurityGrid, L.T("Plik programu"), path);
        ProtectionIcon.Text = SelfProtection.Enabled && !tampered ? "\uE83D" : "\uE7BA";
        ProtectionIcon.SetResourceReference(TextBlock.ForegroundProperty, SelfProtection.Enabled && !tampered
            ? "SystemFillColorSuccessBrush" : "SystemFillColorCautionBrush");
    }

    private void AddRow(Grid grid, string label, string value)
    {
        _all.Add((label, value));
        var row = grid.RowDefinitions.Count;
        grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        var name = new TextBlock { Text = label, Margin = new Thickness(0, 2, 16, 2) };
        name.SetResourceReference(TextBlock.StyleProperty, "Secondary");
        var text = new TextBox
        {
            Text = value, IsReadOnly = true, BorderThickness = new Thickness(0), Background = null, Padding = new Thickness(0),
            Margin = new Thickness(0, 2, 0, 2), TextWrapping = TextWrapping.Wrap, MinHeight = 0,
        };
        System.Windows.Automation.AutomationProperties.SetName(text, label);
        Grid.SetRow(name, row);
        Grid.SetRow(text, row);
        Grid.SetColumn(text, 1);
        grid.Children.Add(name);
        grid.Children.Add(text);
    }

    private void Copy_Click(object sender, RoutedEventArgs e)
    {
        var text = new StringBuilder("Bezpieczny Aktualizator ").AppendLine(SelfProtection.Version);
        foreach (var line in Ui.FormatFields(_all)) text.AppendLine(line);
        Clipboard.SetText(text.ToString());
    }
}
