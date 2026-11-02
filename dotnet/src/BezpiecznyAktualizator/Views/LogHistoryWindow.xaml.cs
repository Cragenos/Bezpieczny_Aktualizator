using System.Diagnostics;
using System.Windows;
using BezpiecznyAktualizator.Core.Localization;
using BezpiecznyAktualizator.Core.Logging;
using BezpiecznyAktualizator.Services;

namespace BezpiecznyAktualizator.Views;

public partial class LogHistoryWindow : Window
{
    public LogHistoryWindow()
    {
        InitializeComponent();
        RefreshEntries();
    }

    private void Refresh_Click(object sender, RoutedEventArgs e) => RefreshEntries();

    private void RefreshEntries()
    {
        try
        {
            var lines = Syslog.ReadRecentIssues();
            Entries.Text = lines.Count == 0
                ? L.T("Brak ostrzeżeń i błędów w zapisanym dzienniku.")
                : string.Join(Environment.NewLine, lines);
            Entries.ScrollToHome();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            Ui.Error(this, L.T("Nie udało się odczytać dziennika"), ex.Message);
        }
    }

    private void OpenLog_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            Directory.CreateDirectory(Syslog.Directory);
            var args = File.Exists(Syslog.FilePath) ? $"/select,\"{Syslog.FilePath}\"" : $"\"{Syslog.Directory}\"";
            Process.Start(new ProcessStartInfo("explorer.exe", args) { UseShellExecute = true })?.Dispose();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception)
        {
            Ui.Error(this, L.T("Błąd"), ex.Message);
        }
    }
}
