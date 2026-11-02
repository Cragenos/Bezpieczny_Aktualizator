using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Text.Json;
using System.Windows.Data;
using System.Windows.Markup;
using BezpiecznyAktualizator.Core.Localization;
using BezpiecznyAktualizator.Core.Logging;
using BezpiecznyAktualizator.Core.Policies;
using BezpiecznyAktualizator.Core.Scheduling;

namespace BezpiecznyAktualizator.Services;

/// <summary>Powiadamia powiązania XAML o zmianie języka (właściwość <see cref="Revision"/>).</summary>
public sealed class Loc : INotifyPropertyChanged
{
    public static Loc Instance { get; } = new();

    private Loc() => L.LanguageChanged += () => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Revision)));

    public string Revision => L.Language;

    public event PropertyChangedEventHandler? PropertyChanged;
}

/// <summary>Tłumaczy polski tekst źródłowy (parametr konwertera) na bieżący język.</summary>
public sealed class TranslateConverter : IValueConverter
{
    public static TranslateConverter Instance { get; } = new();

    public object Convert(object value, Type targetType, object? parameter, CultureInfo culture) =>
        L.T(parameter as string ?? "");

    public object ConvertBack(object value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

/// <summary>Użycie w XAML: <c>Content="{l:Tr 'Skanuj komputer'}"</c> - tekst odświeża się po zmianie języka.</summary>
[MarkupExtensionReturnType(typeof(string))]
public sealed class TrExtension(string text) : MarkupExtension
{
    public string Text { get; set; } = text;

    public override object ProvideValue(IServiceProvider serviceProvider) =>
        new Binding(nameof(Loc.Revision))
        {
            Source = Loc.Instance, Mode = BindingMode.OneWay,
            Converter = TranslateConverter.Instance, ConverterParameter = Text,
        }.ProvideValue(serviceProvider);
}

/// <summary>Ustawienia użytkownika w %APPDATA%\BezpiecznyAktualizator\settings.json.</summary>
public static class Settings
{
    private static readonly string FilePath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "BezpiecznyAktualizator", "settings.json");

    // Zapisywana w settings.json: nazwy właściwości nie mogą być zmieniane przez zaciemnianie kodu.
    [System.Reflection.Obfuscation(Exclude = true)]
    private sealed class Data
    {
        public string? Language { get; set; }
        public bool? CheckSoftwareOnStart { get; set; }
        public bool? CheckDriversOnStart { get; set; }
        public bool? CheckAppUpdatesOnStart { get; set; }
        public bool? IncludePreviewReleases { get; set; }
        public DateTimeOffset? LastAppUpdateCheck { get; set; }
        public string? Theme { get; set; }
        public ScheduleOptions? Schedule { get; set; }
        public UpdatePolicies? Policies { get; set; }
        public DateTimeOffset? ScheduleSeen { get; set; }
        public string? NvdApiKey { get; set; }
        public NotificationOptions? Notifications { get; set; }
    }

    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase, PropertyNameCaseInsensitive = true, WriteIndented = true,
    };

    private static Data Read()
    {
        try
        {
            var data = File.Exists(FilePath) ? JsonSerializer.Deserialize<Data>(File.ReadAllText(FilePath), Options) ?? new() : new();
            // Wykluczenia i poziom zaufania z dawnych ustawień harmonogramu trafiają do zasad (zapis przy najbliższej zmianie).
            if (data.Schedule is { } schedule && (schedule.Excluded is not null || schedule.AllowMediumTrust is not null))
                schedule.MigrateTo(data.Policies ??= new UpdatePolicies());
            return data;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            return new();
        }
    }

    /// <summary>Zapisany język albo język systemu Windows (jeśli obsługiwany), w przeciwnym razie angielski.</summary>
    public static string LoadLanguage() => L.Normalize(Read().Language) ?? L.SystemLanguage();

    public static void SaveLanguage(string code) => Update(d => d.Language = code);

    /// <summary>Automatyczne sprawdzanie aktualizacji programów po uruchomieniu (domyślnie włączone).</summary>
    public static bool CheckSoftwareOnStart
    {
        get => Read().CheckSoftwareOnStart ?? true;
        set => Update(d => d.CheckSoftwareOnStart = value);
    }

    /// <summary>Automatyczne sprawdzanie sterowników w Windows Update po uruchomieniu (domyślnie włączone).</summary>
    public static bool CheckDriversOnStart
    {
        get => Read().CheckDriversOnStart ?? true;
        set => Update(d => d.CheckDriversOnStart = value);
    }

    /// <summary>Sprawdza podpisane wydania aplikacji przy uruchomieniu (domyślnie włączone).</summary>
    public static bool CheckAppUpdatesOnStart
    {
        get => Read().CheckAppUpdatesOnStart ?? true;
        set => Update(d => d.CheckAppUpdatesOnStart = value);
    }

    /// <summary>Uwzględnia wydania oznaczone przez GitHub jako testowe; ich instalacja zawsze wymaga ręcznego pobrania.</summary>
    public static bool IncludePreviewReleases
    {
        get => Read().IncludePreviewReleases ?? false;
        set => Update(d => d.IncludePreviewReleases = value);
    }

    public static DateTimeOffset? LastAppUpdateCheck
    {
        get => Read().LastAppUpdateCheck;
        set => Update(d => d.LastAppUpdateCheck = value);
    }

    /// <summary>Motyw okna: „system” (domyślnie, jak w Windows), „light” albo „dark”.</summary>
    public static AppTheme Theme
    {
        get => Read().Theme?.ToLowerInvariant() switch { "light" => AppTheme.Light, "dark" => AppTheme.Dark, _ => AppTheme.System };
        set => Update(d => d.Theme = value.ToString().ToLowerInvariant());
    }

    /// <summary>Ciche sprawdzanie i aktualizacja podczas bezczynności (Harmonogram zadań Windows).</summary>
    public static ScheduleOptions Schedule
    {
        get => (Read().Schedule ?? new ScheduleOptions()).Normalize();
        set => Update(d => d.Schedule = value.Normalize());
    }

    /// <summary>Czas ostatniego cichego uruchomienia, którego wynik został już pokazany w oknie programu.</summary>
    public static DateTimeOffset? ScheduleSeen
    {
        get => Read().ScheduleSeen;
        set => Update(d => d.ScheduleSeen = value);
    }

    private static string? _machinePolicyError;

    /// <summary>
    /// Zasady aktualizacji użytkownika połączone z zasadami komputera (%ProgramData%) - te drugie mają pierwszeństwo.
    /// Zapis dotyczy wyłącznie części użytkownika.
    /// </summary>
    public static UpdatePolicies Policies
    {
        get
        {
            var user = (Read().Policies ?? new UpdatePolicies()).Normalize();
            var machine = UpdatePolicies.LoadMachine(out var error);
            if (error is not null && error != _machinePolicyError)
                Syslog.Error(LogEvent.Policy, L.F("Nie udało się wczytać zasad komputera: {0}", error));
            _machinePolicyError = error;
            return user.MergeMachine(machine);
        }
        set => Update(d => d.Policies = value.UserPart());
    }

    /// <summary>Błąd odczytu zasad komputera z ostatniego wczytania (null - brak błędu).</summary>
    public static string? MachinePolicyError => _machinePolicyError;

    /// <summary>Opcjonalny klucz API NVD (settings.json: "NvdApiKey") - zwiększa limit zapytań z 5 do 50 na 30 s.</summary>
    public static string? NvdApiKey => Read().NvdApiKey;

    public static NotificationOptions Notifications => (Read().Notifications ?? new NotificationOptions()).Normalize();

    public static void SaveNotifications(NotificationOptions value) =>
        Update(d => d.Notifications = value.Normalize());

    private static void Update(Action<Data> change)
    {
        try
        {
            var data = Read();
            change(data);
            Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
            File.WriteAllText(FilePath, JsonSerializer.Serialize(data, Options));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }
}
