using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using BezpiecznyAktualizator.Core.Localization;
using BezpiecznyAktualizator.Core.Logging;
using BezpiecznyAktualizator.Core.Profiles;
using BezpiecznyAktualizator.Services;
using Microsoft.Win32;

namespace BezpiecznyAktualizator.Views;

/// <summary>Pozycja listy folderów profilu z polem wyboru.</summary>
public sealed class ProfileFolderOption(ProfileFolder folder, string path, bool isChecked)
{
    public ProfileFolder Folder { get; } = folder;
    public string Name => Folder.Name;
    public string Path { get; } = path;
    public bool IsChecked { get; set; } = isChecked;
}

public sealed record RestoreConflictOption(RestoreConflictMode Mode, string Name);

public partial class ProfileBackupView : UserControl
{
    private readonly BackgroundRunner _runner;
    private List<UserProfileInfo> _profiles = [];
    private bool _loaded;
    private string? _lastSummary;

    public ProfileBackupView()
    {
        InitializeComponent();
        _runner = new BackgroundRunner(this, Toolbar, Progress, StatusText, LogBox, () => _lastSummary ?? L.T("Gotowy."),
                                       LogEvent.ProfileBackup, cancelButton: CancelButton);
        FillConflictModes();
        L.LanguageChanged += () =>
        {
            FillConflictModes();
            if (_loaded) LoadFolders();
        };
    }

    public bool IsBusy => _runner.IsBusy;

    private void View_IsVisibleChanged(object sender, DependencyPropertyChangedEventArgs e)
    {
        if (!IsVisible || _loaded) return;
        _loaded = true;
        LoadUsers();
    }

    private void FillConflictModes()
    {
        var selected = (ConflictBox.SelectedItem as RestoreConflictOption)?.Mode ?? RestoreConflictMode.Skip;
        var options = new List<RestoreConflictOption>
        {
            new(RestoreConflictMode.Skip, L.T("Pomiń (zachowaj plik na tym komputerze)")),
            new(RestoreConflictMode.KeepBoth, L.T("Zachowaj oba (dodaj numer do nazwy)")),
            new(RestoreConflictMode.Overwrite, L.T("Zastąp (stary plik trafi do folderu kopii)")),
        };
        ConflictBox.ItemsSource = options;
        ConflictBox.SelectedItem = options.First(o => o.Mode == selected);
    }

    private void LoadUsers()
    {
        try
        {
            _profiles = UserProfiles.List();
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
        {
            _profiles = [];
            _runner.Log(L.F("Nie udało się odczytać listy profili: {0}", ex.Message), SyslogSeverity.Warning);
        }
        var source = SourceUser.SelectedItem as UserProfileInfo;
        var target = TargetUser.SelectedItem as UserProfileInfo;
        SourceUser.ItemsSource = _profiles;
        TargetUser.ItemsSource = _profiles;
        SourceUser.SelectedItem = _profiles.FirstOrDefault(p => p.Sid == source?.Sid) ?? _profiles.FirstOrDefault(p => p.IsCurrent) ?? _profiles.FirstOrDefault();
        TargetUser.SelectedItem = _profiles.FirstOrDefault(p => p.Sid == target?.Sid) ?? _profiles.FirstOrDefault(p => p.IsCurrent) ?? _profiles.FirstOrDefault();
        var admin = UserProfiles.IsAdministrator();
        ElevateButton.Visibility = admin ? Visibility.Collapsed : Visibility.Visible;
        _runner.Log(L.F("Znaleziono profile użytkowników: {0}. Uprawnienia administratora: {1}.", _profiles.Count,
                        admin ? L.T("tak") : L.T("nie")));
        LoadFolders();
    }

    private void LoadFolders()
    {
        var previous = (FolderList.ItemsSource as IEnumerable<ProfileFolderOption>)?.ToDictionary(o => o.Folder.Key, o => o.IsChecked);
        if (SourceUser.SelectedItem is not UserProfileInfo profile)
        {
            FolderList.ItemsSource = null;
            return;
        }
        FolderList.ItemsSource = UserProfiles.Folders
            .Select(f => new ProfileFolderOption(f, UserProfiles.ResolveFolder(profile, f),
                                                 previous?.GetValueOrDefault(f.Key, UserProfiles.IsDefault(f)) ?? UserProfiles.IsDefault(f)))
            .ToList();
        EstimateText.Text = "";
    }

    private List<ProfileFolderPath> SelectedFolders() =>
        (FolderList.ItemsSource as IEnumerable<ProfileFolderOption> ?? [])
            .Where(o => o.IsChecked).Select(o => new ProfileFolderPath(o.Folder.Key, o.Path)).ToList();

    private long? MaxFileSize => SkipLargeFiles.IsChecked == true ? ProfilePackage.LargeFileThreshold : null;

    private static string EstimateSummary(ProfileEstimate estimate) =>
        L.F("Plików: {0}, rozmiar przed kompresją: {1}.", estimate.Files, FormatSize(estimate.Bytes)) +
        (estimate.SkippedLinks > 0 ? " " + L.F("Pominięte dowiązania: {0}.", estimate.SkippedLinks) : "") +
        (estimate.SkippedLargeFiles > 0
            ? " " + L.F("Pominięte duże pliki: {0} ({1}).", estimate.SkippedLargeFiles, FormatSize(estimate.SkippedLargeBytes))
            : "");

    private void SourceUser_Changed(object sender, SelectionChangedEventArgs e) => LoadFolders();

    private void Folder_Changed(object sender, RoutedEventArgs e) => EstimateText.Text = "";

    private void RefreshUsers_Click(object sender, RoutedEventArgs e) => LoadUsers();

    private void Cancel_Click(object sender, RoutedEventArgs e) => _runner.CancelCurrentOperation();

    /// <summary>Dostęp do profilu innego użytkownika wymaga uprawnień administratora – proponuje ponowne uruchomienie.</summary>
    private bool EnsureAccess(UserProfileInfo profile)
    {
        if (profile.IsCurrent || UserProfiles.IsAdministrator()) return true;
        if (Ui.Confirm(this, L.T("Kopia profilu"),
                L.F("Dostęp do plików użytkownika {0} wymaga uprawnień administratora. Uruchomić program ponownie jako administrator?", profile.UserName)))
            RestartElevated();
        return false;
    }

    private void Elevate_Click(object sender, RoutedEventArgs e) => RestartElevated();

    private void RestartElevated()
    {
        if (Window.GetWindow(this) is MainWindow main && main.IsAnyOperationRunning)
        {
            Ui.Info(this, L.T("Kopia profilu"), L.T("Trwa inna operacja. Spróbuj ponownie po jej zakończeniu."));
            return;
        }
        try
        {
            Process.Start(new ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = true, Verb = "runas" })?.Dispose();
        }
        catch (System.ComponentModel.Win32Exception)
        {
            _runner.Log(L.T("Anulowano podniesienie uprawnień."), SyslogSeverity.Notice);
            return;
        }
        _runner.Log(L.T("Uruchomiono program z uprawnieniami administratora; bieżące okno zostanie zamknięte."), SyslogSeverity.Notice);
        (Window.GetWindow(this) as MainWindow)?.ExitFromTray();
    }

    private Progress<ProfilePackageProgress> StatusProgress(string action) => new(p =>
    {
        if (!_runner.IsBusy) return;
        _runner.SetStatus(L.F("{0}: {1}% – plików {2} z {3} ({4} z {5})", action, p.Percent, p.FilesDone, p.FilesTotal,
                              FormatSize(p.BytesDone), FormatSize(p.BytesTotal)));
    });

    internal static string FormatSize(long bytes)
    {
        string[] units = ["B", "KB", "MB", "GB", "TB"];
        double value = bytes;
        var unit = 0;
        while (value >= 1024 && unit < units.Length - 1)
        {
            value /= 1024;
            unit++;
        }
        return unit == 0 ? $"{bytes} B" : $"{value:0.0} {units[unit]}";
    }

    private async void Estimate_Click(object sender, RoutedEventArgs e)
    {
        if (SourceUser.SelectedItem is not UserProfileInfo profile || !EnsureAccess(profile)) return;
        var folders = SelectedFolders();
        if (folders.Count == 0)
        {
            Ui.Info(this, L.T("Kopia profilu"), L.T("Zaznacz co najmniej jeden folder."));
            return;
        }
        ProfileEstimate? estimate = null;
        var maxFileSize = MaxFileSize;
        await _runner.RunCancellableAsync(LogEvent.ProfileBackup, L.F("Szacowanie rozmiaru folderów użytkownika {0}...", profile.UserName),
            async token => estimate = await Task.Run(() => ProfilePackage.Estimate(folders, token, maxFileSize), token),
            typeof(IOException), typeof(UnauthorizedAccessException));
        if (estimate is null) return;
        EstimateText.Text = EstimateSummary(estimate);
        _runner.Log(EstimateText.Text);
        foreach (var missing in estimate.MissingFolders) _runner.Log(L.F("Folder nie istnieje: {0}", missing), SyslogSeverity.Notice);
    }

    private async void Create_Click(object sender, RoutedEventArgs e)
    {
        if (SourceUser.SelectedItem is not UserProfileInfo profile) return;
        var folders = SelectedFolders();
        if (folders.Count == 0)
        {
            Ui.Info(this, L.T("Kopia profilu"), L.T("Zaznacz co najmniej jeden folder."));
            return;
        }
        var password = CreatePassword.Password;
        if (password != CreatePasswordRepeat.Password)
        {
            Ui.Warn(this, L.T("Kopia profilu"), L.T("Hasła nie są zgodne."));
            return;
        }
        if (password.Length is > 0 and < 8)
        {
            Ui.Warn(this, L.T("Kopia profilu"), L.T("Hasło musi mieć co najmniej 8 znaków."));
            return;
        }
        if (password.Length == 0 && !Ui.Confirm(this, L.T("Kopia profilu"),
                L.T("Paczka nie będzie zaszyfrowana – każdy, kto ją otrzyma, odczyta pliki. Kontynuować bez hasła?"), warning: true))
            return;
        if (!EnsureAccess(profile)) return;
        var shortName = profile.UserName.Split('\\').Last();
        var dialog = new SaveFileDialog
        {
            Title = L.T("Zapisz paczkę profilu"),
            FileName = $"Profil-{shortName}-{DateTime.Now:yyyyMMdd-HHmm}{ProfilePackage.Extension}",
            DefaultExt = ProfilePackage.Extension, AddExtension = true,
            Filter = L.T("Paczka profilu") + $" (*{ProfilePackage.Extension})|*{ProfilePackage.Extension}",
        };
        if (dialog.ShowDialog(Window.GetWindow(this)) != true) return;
        var output = dialog.FileName;
        ProfileEstimate? estimate = null;
        var maxFileSize = MaxFileSize;
        var estimateOk = await _runner.RunCancellableAsync(LogEvent.ProfileBackup,
            L.F("Szacowanie rozmiaru folderów użytkownika {0}...", profile.UserName),
            async token => estimate = await Task.Run(() => ProfilePackage.Estimate(folders, token, maxFileSize), token),
            typeof(IOException), typeof(UnauthorizedAccessException));
        if (!estimateOk || estimate is null) return;
        EstimateText.Text = EstimateSummary(estimate);
        _runner.Log(EstimateText.Text);

        if (estimate.SkippedLargeFiles > 0 &&
            !Ui.Confirm(this, L.T("Pominięte duże pliki"),
                L.F("Filtr pominie {0} plików większych niż 1 GiB ({1}). Nie będą dostępne do przywrócenia. Kontynuować?",
                    estimate.SkippedLargeFiles, FormatSize(estimate.SkippedLargeBytes)), warning: true))
            return;

        long availableSpace;
        try
        {
            var root = Path.GetPathRoot(output);
            if (string.IsNullOrEmpty(root)) throw new IOException(L.T("Nie można ustalić dysku docelowego."));
            availableSpace = new DriveInfo(root).AvailableFreeSpace;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            Ui.Error(this, L.T("Kopia profilu"), L.F("Nie udało się sprawdzić wolnego miejsca na dysku: {0}", ex.Message));
            return;
        }
        if (estimate.Bytes > availableSpace &&
            !Ui.Confirm(this, L.T("Za mało wolnego miejsca"),
                L.F("Szacowany rozmiar danych ({0}) przekracza wolne miejsce na dysku ({1}). Paczka może być mniejsza po kompresji. Kontynuować?",
                    FormatSize(estimate.Bytes), FormatSize(availableSpace)), warning: true))
            return;
        var progress = StatusProgress(L.T("Pakowanie"));
        ProfilePackageResult? result = null;
        string? hash = null;
        var ok = await _runner.RunCancellableAsync(LogEvent.ProfileBackup,
            L.F("Tworzenie paczki profilu {0} ({1})...", profile.UserName, string.Join(", ", folders.Select(f => UserProfiles.Find(f.Key)!.Name))),
            async token =>
            {
                result = await Task.Run(() => ProfilePackage.Create(folders, output, profile.UserName, profile.ProfilePath,
                                                                    password.Length > 0 ? password : null, progress, token, estimate), token);
                hash = await Task.Run(() => ProfilePackage.ComputeSha256(output), token);
            },
            typeof(IOException), typeof(UnauthorizedAccessException), typeof(ProfilePackageException));
        if (!ok || result is null) return;
        foreach (var line in result.Skipped.Take(100)) _runner.Log(line, SyslogSeverity.Notice);
        if (result.Skipped.Count > 100) _runner.Log(L.F("… i {0} innych pominiętych elementów.", result.Skipped.Count - 100), SyslogSeverity.Notice);
        var size = result.Parts.Sum(part => new FileInfo(part).Length);
        _lastSummary = L.F("Utworzono paczkę: {0} plików, {1}.", result.Files, FormatSize(size));
        var details = new List<string>
        {
            _lastSummary,
            "",
        };
        var detailFields = new List<(string Label, string Value)>
        {
            (L.T("Plik"), output),
            (L.T("Rozmiar danych"), FormatSize(result.Bytes)),
            (L.T("Rozmiar paczki"), FormatSize(size)),
            (L.T("Części paczki"), result.Parts.Count.ToString()),
            (L.T("Szyfrowanie"), password.Length > 0 ? "AES-256-GCM (PBKDF2-SHA256)" : L.T("brak")),
            (L.T("Pominięte elementy"), result.Skipped.Count.ToString()),
            ("SHA256", hash ?? ""),
        };
        if (estimate.SkippedLargeFiles > 0)
            detailFields.Add((L.T("Pominięte duże pliki"), $"{estimate.SkippedLargeFiles} ({FormatSize(estimate.SkippedLargeBytes)})"));
        details.AddRange(Ui.FormatFields(detailFields));
        Details.Text = string.Join(Environment.NewLine, details);
        BottomTabs.SelectedIndex = 0;
        _runner.Log(L.F("Paczka zapisana: {0}; części: {1}; SHA256 {2}.", output, result.Parts.Count, hash), SyslogSeverity.Notice);
        _runner.UpdateSummary();
        CreatePassword.Clear();
        CreatePasswordRepeat.Clear();
        Ui.Info(this, L.T("Kopia profilu"), _lastSummary + "\n\n" +
                L.T("Przenieś wszystkie części paczki na drugi komputer, uruchom program i wybierz pierwszy plik .baprofile."));
    }

    private void BrowsePackage_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = L.T("Wybierz paczkę profilu"),
            Filter = L.T("Paczka profilu") + $" (*{ProfilePackage.Extension})|*{ProfilePackage.Extension}",
        };
        if (dialog.ShowDialog(Window.GetWindow(this)) == true) PackagePath.Text = dialog.FileName;
    }

    private void BrowseTarget_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFolderDialog { Title = L.T("Wybierz folder docelowy") };
        if (dialog.ShowDialog(Window.GetWindow(this)) == true) TargetFolder.Text = dialog.FolderName;
    }

    private string? PackageFile()
    {
        var path = PackagePath.Text;
        if (path.Length > 0 && File.Exists(path)) return path;
        Ui.Info(this, L.T("Kopia profilu"), L.T("Wybierz plik paczki profilu."));
        return null;
    }

    private void ShowManifest(ProfileVerification verification, string path)
    {
        var manifest = verification.Manifest;
        var lines = Ui.FormatFields([
            (L.T("Plik"), path),
            (L.T("Utworzono"), manifest.Created == DateTimeOffset.MinValue ? "?" : manifest.Created.ToLocalTime().ToString("g")),
            (L.T("Komputer"), manifest.Machine),
            (L.T("Użytkownik"), manifest.UserName),
            (L.T("Profil źródłowy"), manifest.SourceProfile),
            (L.T("Foldery"), string.Join(", ", manifest.Folders.Select(k => UserProfiles.Find(k)?.Name ?? k))),
            (L.T("Plików"), manifest.Files.Count.ToString()),
            (L.T("Rozmiar danych"), FormatSize(manifest.TotalBytes)),
            (L.T("Szyfrowanie"), verification.Encrypted ? "AES-256-GCM" : L.T("brak")),
            (L.T("Weryfikacja"), verification.Succeeded ? L.T("wszystkie sumy SHA256 zgodne") : L.F("problemy: {0}", verification.Problems.Count)),
        ]);
        lines.AddRange(verification.Problems.Take(50).Prepend(""));
        Details.Text = string.Join(Environment.NewLine, lines);
        BottomTabs.SelectedIndex = 0;
    }

    private async Task<ProfileVerification?> VerifyAsync(string path, string password)
    {
        ProfileVerification? verification = null;
        var progress = StatusProgress(L.T("Weryfikacja"));
        await _runner.RunCancellableAsync(LogEvent.ProfileBackup, L.F("Weryfikacja paczki {0}...", Path.GetFileName(path)),
            async token => verification = await Task.Run(() => ProfilePackage.Verify(path, password, progress, token), token),
            typeof(IOException), typeof(UnauthorizedAccessException), typeof(ProfilePackageException));
        if (verification is null) return null;
        ShowManifest(verification, path);
        foreach (var problem in verification.Problems.Take(100)) _runner.Log(problem, SyslogSeverity.Warning);
        _lastSummary = verification.Succeeded
            ? L.F("Paczka poprawna: {0} plików, {1}.", verification.Manifest.Files.Count, FormatSize(verification.Manifest.TotalBytes))
            : L.F("Paczka uszkodzona lub zmodyfikowana (problemy: {0}).", verification.Problems.Count);
        _runner.Log(_lastSummary, verification.Succeeded ? SyslogSeverity.Notice : SyslogSeverity.Warning);
        _runner.UpdateSummary();
        return verification;
    }

    private async void Verify_Click(object sender, RoutedEventArgs e)
    {
        if (PackageFile() is not { } path) return;
        await VerifyAsync(path, RestorePassword.Password);
    }

    private async void Restore_Click(object sender, RoutedEventArgs e)
    {
        if (PackageFile() is not { } path) return;
        List<ProfileFolderPath> targets;
        string backupRoot;
        string targetDescription;
        var stamp = DateTime.Now.ToString("yyyyMMdd-HHmmss");
        if (ToProfile.IsChecked == true)
        {
            if (TargetUser.SelectedItem is not UserProfileInfo profile)
            {
                Ui.Info(this, L.T("Kopia profilu"), L.T("Wybierz użytkownika docelowego."));
                return;
            }
            if (!EnsureAccess(profile)) return;
            targets = UserProfiles.Folders.Select(f => new ProfileFolderPath(f.Key, UserProfiles.ResolveFolder(profile, f))).ToList();
            backupRoot = Path.Combine(profile.ProfilePath, $"BezpiecznyAktualizator-kopia-przed-przywroceniem-{stamp}");
            targetDescription = profile.Display;
        }
        else
        {
            var folder = TargetFolder.Text;
            if (folder.Length == 0 || !Directory.Exists(folder))
            {
                Ui.Info(this, L.T("Kopia profilu"), L.T("Wybierz folder docelowy."));
                return;
            }
            targets = UserProfiles.Folders.Select(f => new ProfileFolderPath(f.Key, Path.Combine(folder, f.Key))).ToList();
            backupRoot = Path.Combine(folder, $"BezpiecznyAktualizator-kopia-przed-przywroceniem-{stamp}");
            targetDescription = folder;
        }
        var mode = (ConflictBox.SelectedItem as RestoreConflictOption)?.Mode ?? RestoreConflictMode.Skip;
        var password = RestorePassword.Password;

        var verification = await VerifyAsync(path, password);
        if (verification is null) return;
        if (!verification.Succeeded)
        {
            Ui.Warn(this, L.T("Kopia profilu"), L.T("Paczka nie przeszła weryfikacji – niczego nie przywrócono.") +
                    "\n\n" + string.Join("\n", verification.Problems.Take(10)));
            return;
        }
        var manifest = verification.Manifest;
        var where = string.Join("\n", targets.Where(t => manifest.Folders.Contains(t.Key)).Select(t => $"• {UserProfiles.Find(t.Key)!.Name}: {t.Path}"));
        if (!Ui.Confirm(this, L.T("Przywróć z paczki"),
                L.F("Przywrócić {0} plików ({1}) z komputera {2} (użytkownik {3})?", manifest.Files.Count, FormatSize(manifest.TotalBytes),
                    manifest.Machine, manifest.UserName) + "\n\n" + L.F("Cel: {0}", targetDescription) + "\n" + where + "\n\n" +
                L.F("Istniejące pliki: {0}", ((RestoreConflictOption)ConflictBox.SelectedItem).Name)))
            return;

        var progress = StatusProgress(L.T("Przywracanie"));
        ProfileRestoreResult? result = null;
        var ok = await _runner.RunCancellableAsync(LogEvent.ProfileBackup, L.F("Przywracanie paczki {0}...", Path.GetFileName(path)),
            async token => result = await Task.Run(() => ProfilePackage.Restore(path, targets, mode, backupRoot, password, progress, token), token),
            typeof(IOException), typeof(UnauthorizedAccessException), typeof(ProfilePackageException));
        if (!ok || result is null) return;
        foreach (var problem in result.Problems.Take(100)) _runner.Log(problem, SyslogSeverity.Warning);
        _lastSummary = L.F("Przywrócono plików: {0}, pominięto: {1}, z nową nazwą: {2}, przeniesiono do kopii: {3}, błędy: {4}.",
                           result.Restored, result.Skipped, result.Renamed, result.BackedUp, result.Problems.Count);
        _runner.Log(_lastSummary, result.Problems.Count == 0 ? SyslogSeverity.Notice : SyslogSeverity.Warning);
        if (result.BackupFolder is { } backup) _runner.Log(L.F("Zastąpione pliki zachowano w: {0}", backup), SyslogSeverity.Notice);
        _runner.UpdateSummary();
        RestorePassword.Clear();
        var message = _lastSummary + (result.BackupFolder is { } b ? "\n\n" + L.F("Zastąpione pliki zachowano w: {0}", b) : "");
        if (result.Problems.Count > 0) Ui.Warn(this, L.T("Przywróć z paczki"), message + "\n\n" + L.T("Szczegóły w zakładce „Dziennik”."));
        else Ui.Info(this, L.T("Przywróć z paczki"), message);
    }
}
