using System.Windows;

namespace BezpiecznyAktualizator.Views;

public partial class DiagnosticsPreviewWindow : Window
{
    public DiagnosticsPreviewWindow(string preview)
    {
        InitializeComponent();
        PreviewText.Text = preview;
    }

    private void Continue_Click(object sender, RoutedEventArgs e) => DialogResult = true;
}
