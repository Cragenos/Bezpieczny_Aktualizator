using System.Windows;
using BezpiecznyAktualizator.Core.Agent;
using BezpiecznyAktualizator.Core.Localization;
using BezpiecznyAktualizator.Core.Logging;
using BezpiecznyAktualizator.Services;

namespace BezpiecznyAktualizator.Views;

public partial class LocalAgentWindow : Window
{
    public LocalAgentWindow()
    {
        InitializeComponent();
        var options = Settings.LocalAgent;
        EnabledBox.IsChecked = options.Enabled;
        EndpointBox.Text = options.Endpoint;
        ModelBox.Text = options.Model;
        TimeoutBox.Text = options.TimeoutSeconds.ToString();
        ScheduledBox.IsChecked = options.ReviewScheduledUpdates;
        InstructionsBox.Text = options.Instructions;
    }

    private LocalAgentOptions Collect()
    {
        if (!LocalAgentOptions.TryGetEndpoint(EndpointBox.Text, out _))
            throw new InvalidOperationException(L.T("Adres API musi wskazywać ten komputer (localhost, 127.0.0.1 lub [::1]) i używać http lub https."));
        if (!int.TryParse(TimeoutBox.Text, out var timeout) || timeout is < 10 or > 600)
            throw new InvalidOperationException(L.T("Limit czasu musi być liczbą z zakresu 10–600 sekund."));
        return new LocalAgentOptions
        {
            Enabled = EnabledBox.IsChecked == true,
            Endpoint = EndpointBox.Text,
            Model = ModelBox.Text,
            TimeoutSeconds = timeout,
            ReviewScheduledUpdates = ScheduledBox.IsChecked == true,
            Instructions = InstructionsBox.Text,
        }.Normalize();
    }

    private void Save_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var options = Collect();
            if (options.Enabled && options.Model.Length == 0)
            {
                Ui.Warn(this, L.T("Niekompletna konfiguracja"), L.T("Wybierz lub wpisz nazwę modelu."));
                return;
            }
            Settings.LocalAgent = options;
            Syslog.Notice(LogEvent.Settings, options.Enabled
                ? L.F("Włączono lokalnego agenta AI: {0}, model {1}.", options.Endpoint, options.Model)
                : L.T("Lokalny agent AI jest wyłączony."));
            DialogResult = true;
        }
        catch (InvalidOperationException ex)
        {
            Ui.Warn(this, L.T("Niekompletna konfiguracja"), ex.Message);
        }
    }

    private async void Test_Click(object sender, RoutedEventArgs e)
    {
        LocalAgentOptions options;
        try { options = Collect(); }
        catch (InvalidOperationException ex)
        {
            Ui.Warn(this, L.T("Niekompletna konfiguracja"), ex.Message);
            return;
        }

        IsEnabled = false;
        StatusText.Text = L.T("Łączenie z lokalnym serwerem modeli...");
        try
        {
            var models = await LocalAgentClient.ListModelsAsync(options);
            var current = ModelBox.Text;
            ModelBox.ItemsSource = models;
            ModelBox.Text = current.Length > 0 ? current : models.FirstOrDefault() ?? "";
            StatusText.Text = models.Count == 0
                ? L.T("Połączono, ale serwer nie udostępnia żadnego modelu.")
                : L.F("Połączono. Dostępne modele: {0}.", models.Count);
            if (ModelBox.Text.Length > 0 && models.Count > 0 && !models.Contains(ModelBox.Text, StringComparer.OrdinalIgnoreCase))
                StatusText.Text += " " + L.F("Model „{0}” nie występuje na liście serwera.", ModelBox.Text);
        }
        catch (LocalAgentException ex)
        {
            StatusText.Text = L.F("Brak połączenia: {0}", ex.Message);
        }
        finally
        {
            IsEnabled = true;
        }
    }
}
