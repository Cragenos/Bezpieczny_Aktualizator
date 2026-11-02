using System.Windows;
using BezpiecznyAktualizator.Core.Localization;
using BezpiecznyAktualizator.Core.Logging;
using BezpiecznyAktualizator.Services;

namespace BezpiecznyAktualizator.Views;

public partial class NotificationWindow : Window
{
    public NotificationWindow()
    {
        InitializeComponent();
        var options = Settings.Notifications;
        EnabledBox.IsChecked = options.Enabled;
        TeamsEnabledBox.IsChecked = options.TeamsEnabled;
        TeamsStatusText.Text = options.HasTeamsWebhook ? L.T("Webhook jest zapisany; wpisz nowy adres, aby go zastąpić.") : L.T("Webhook nie jest zapisany.");
        EmailEnabledBox.IsChecked = options.EmailEnabled;
        SmtpHostBox.Text = options.SmtpHost;
        SmtpPortBox.Text = options.SmtpPort.ToString();
        SmtpUserBox.Text = options.SmtpUser;
        SmtpFromBox.Text = options.SmtpFrom;
        SmtpToBox.Text = options.SmtpTo;
        SmtpStatusText.Text = options.HasSmtpPassword ? L.T("Hasło jest zapisane; wpisz nowe, aby je zastąpić.") : L.T("Hasło nie jest zapisane.");
    }

    private NotificationOptions Collect()
    {
        if (!int.TryParse(SmtpPortBox.Text, out var port) || port is < 1 or > 65535)
            throw new InvalidOperationException(L.T("Port SMTP musi być liczbą z zakresu 1–65535."));
        var options = Settings.Notifications;
        options.Enabled = EnabledBox.IsChecked == true;
        options.TeamsEnabled = TeamsEnabledBox.IsChecked == true;
        if (ClearTeamsBox.IsChecked == true) options.SetTeamsWebhook(null);
        else if (TeamsWebhookBox.Password.Length > 0) options.SetTeamsWebhook(TeamsWebhookBox.Password);
        options.EmailEnabled = EmailEnabledBox.IsChecked == true;
        options.SmtpHost = SmtpHostBox.Text;
        options.SmtpPort = port;
        options.SmtpUser = SmtpUserBox.Text;
        if (ClearSmtpPasswordBox.IsChecked == true) options.SetSmtpPassword(null);
        else if (SmtpPasswordBox.Password.Length > 0) options.SetSmtpPassword(SmtpPasswordBox.Password);
        options.SmtpFrom = SmtpFromBox.Text;
        options.SmtpTo = SmtpToBox.Text;
        options.SmtpUseTls = true;
        return options.Normalize();
    }

    private void Save_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var options = Collect();
            if (options.Enabled && (!options.TeamsEnabled && !options.EmailEnabled ||
                options.TeamsEnabled && !options.HasTeamsWebhook ||
                options.EmailEnabled && (options.SmtpHost.Length == 0 || !options.HasSmtpPassword ||
                    options.SmtpFrom.Length == 0 || options.SmtpTo.Length == 0)))
            {
                Ui.Warn(this, L.T("Niekompletna konfiguracja"), L.T("Włącz co najmniej jeden kanał i uzupełnij jego wymagane dane."));
                return;
            }
            Settings.SaveNotifications(options);
            TeamsWebhookBox.Clear();
            SmtpPasswordBox.Clear();
            Syslog.Notice(LogEvent.Settings, L.T("Zapisano ustawienia powiadomień; sekrety chroni DPAPI bieżącego konta Windows."));
            DialogResult = true;
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.Security.Cryptography.CryptographicException or
                                       System.ComponentModel.Win32Exception)
        {
            Ui.Error(this, L.T("Nie udało się zapisać powiadomień"), ex.Message);
        }
    }

    private async void Test_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var options = Collect();
            if (!options.TeamsEnabled && !options.EmailEnabled)
            {
                Ui.Warn(this, L.T("Niekompletna konfiguracja"), L.T("Włącz co najmniej jeden kanał i uzupełnij jego wymagane dane."));
                return;
            }
            if (!options.Enabled) options.Enabled = true;
            var errors = await NotificationService.SendAsync(options, L.T("Testowe powiadomienie z Bezpiecznego Aktualizatora."));
            if (errors.Count > 0)
            {
                foreach (var error in errors) Syslog.Warning(LogEvent.Settings, error);
                Ui.Warn(this, L.T("Nie udało się wysłać testu"), string.Join(Environment.NewLine, errors));
                return;
            }
            Ui.Info(this, L.T("Powiadomienie wysłane"), L.T("Wysyłanie zakończyło się pomyślnie."));
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.Security.Cryptography.CryptographicException or
                                       System.ComponentModel.Win32Exception)
        {
            Ui.Error(this, L.T("Nie udało się wysłać testu"), ex.Message);
        }
    }
}
