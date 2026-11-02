using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Windows;
using System.Windows.Controls;
using BezpiecznyAktualizator.Core.Localization;
using BezpiecznyAktualizator.Core.Logging;
using BezpiecznyAktualizator.Core.Updates;
using BezpiecznyAktualizator.Services;
using Microsoft.Win32;

namespace BezpiecznyAktualizator.Views;

public partial class OfflinePackageWindow : Window
{
    private readonly ObservableCollection<string> _files = [];
    private readonly IReadOnlyList<WindowsUpdateItem> _references;
    private readonly IReadOnlyList<OfflinePackageSigner> _signers;
    private bool _creating;

    public OfflinePackageWindow(IReadOnlyList<WindowsUpdateItem> references)
    {
        InitializeComponent();
        _references = references;
        _signers = OfflineUpdatePackage.GetAvailableSigners();
        SignerBox.ItemsSource = _signers;
        SignerBox.SelectedIndex = _signers.Count > 0 ? 0 : -1;
        FilesList.ItemsSource = _files;
        UpdateStatus();
        UpdateSignerInfo();
    }

    private void UpdateStatus() =>
        StatusText.Text = L.F("Plików: {0} | informacyjnych pozycji Windows Update: {1}", _files.Count, _references.Count);

    private void Add_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = L.T("Wybierz pobrane pakiety MSU lub CAB"),
            Filter = "MSU / CAB (*.msu;*.cab)|*.msu;*.cab",
            Multiselect = true, CheckFileExists = true,
        };
        if (dialog.ShowDialog(this) != true) return;
        var names = _files.Select(Path.GetFileName).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var path in dialog.FileNames)
        {
            if (!names.Add(Path.GetFileName(path)))
            {
                Ui.Warn(this, L.T("Paczka aktualizacji offline"),
                    L.F("Pliki w paczce muszą mieć różne nazwy: {0}", Path.GetFileName(path)));
                continue;
            }
            _files.Add(path);
        }
        UpdateStatus();
    }

    private void Remove_Click(object sender, RoutedEventArgs e)
    {
        if (FilesList.SelectedIndex >= 0) _files.RemoveAt(FilesList.SelectedIndex);
        UpdateStatus();
    }

    private void Move(int offset)
    {
        var from = FilesList.SelectedIndex;
        var to = from + offset;
        if (from < 0 || to < 0 || to >= _files.Count) return;
        _files.Move(from, to);
        FilesList.SelectedIndex = to;
    }

    private void Up_Click(object sender, RoutedEventArgs e) => Move(-1);
    private void Down_Click(object sender, RoutedEventArgs e) => Move(1);

    private void Signer_Changed(object sender, SelectionChangedEventArgs e) => UpdateSignerInfo();

    private void UpdateSignerInfo()
    {
        SignerFingerprint.Text = (SignerBox.SelectedItem as OfflinePackageSigner)?.Sha256 ?? "";
    }

    private async void Create_Click(object sender, RoutedEventArgs e)
    {
        if (_files.Count == 0)
        {
            Ui.Warn(this, L.T("Paczka aktualizacji offline"), L.T("Wybierz co najmniej jeden plik MSU lub CAB."));
            return;
        }
        if (SignerBox.SelectedItem is not OfflinePackageSigner signer)
        {
            Ui.Warn(this, L.T("Paczka aktualizacji offline"),
                L.T("W magazynie certyfikatów bieżącego użytkownika nie znaleziono ważnego certyfikatu podpisywania kodu z kluczem prywatnym."));
            return;
        }
        var dialog = new SaveFileDialog
        {
            Title = L.T("Zapisz paczkę aktualizacji offline"), DefaultExt = ".zip", AddExtension = true,
            Filter = "ZIP (*.zip)|*.zip", FileName = $"windows_update_offline_{DateTime.Now:yyyyMMdd_HHmm}.zip",
            OverwritePrompt = true,
        };
        if (dialog.ShowDialog(this) != true) return;
        _creating = true;
        FileButtons.IsEnabled = BottomButtons.IsEnabled = false;
        Progress.Visibility = Visibility.Visible;
        StatusText.Text = L.T("Tworzenie i sprawdzanie paczki offline...");
        try
        {
            var progress = new Progress<string>(message =>
            {
                if (_creating) StatusText.Text = message;
            });
            await OfflineUpdatePackage.CreateAsync(dialog.FileName, _files.ToList(), _references, signer.Certificate,
                overwrite: true, progress: progress);
            Syslog.Notice(LogEvent.WindowsUpdate, L.F("Utworzono paczkę aktualizacji offline: {0}", dialog.FileName));
            Ui.Info(this, L.T("Paczka aktualizacji offline"),
                L.F("Paczka została podpisana. Przekaż odcisk SHA-256 {0} niezależnym, zaufanym kanałem. Na komputerze offline zaufaj certyfikatowi wydawcy, zweryfikuj podpis Authenticode i uruchom Install-OfflineUpdates.cmd jako administrator. Po wymaganym restarcie uruchom instalator ponownie.",
                    signer.Sha256));
            _creating = false;
            DialogResult = true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or WindowsUpdateException or
                                   InvalidDataException or CryptographicException)
        {
            Syslog.Error(LogEvent.WindowsUpdate, L.T("Nie udało się utworzyć paczki offline."), ex);
            Ui.Error(this, L.T("Błąd"), L.F("Nie udało się utworzyć paczki offline: {0}", ex.Message));
        }
        finally
        {
            _creating = false;
            FileButtons.IsEnabled = BottomButtons.IsEnabled = true;
            Progress.Visibility = Visibility.Hidden;
            UpdateStatus();
        }
    }

    private void Window_Closing(object? sender, CancelEventArgs e)
    {
        if (!_creating) return;
        e.Cancel = true;
        Ui.Warn(this, L.T("Paczka aktualizacji offline"), L.T("Poczekaj na zakończenie tworzenia paczki."));
    }

    private void Window_Closed(object? sender, EventArgs e)
    {
        foreach (var signer in _signers) signer.Certificate.Dispose();
    }
}
