using System.Text.Json;
using BezpiecznyAktualizator.Core.Localization;

namespace BezpiecznyAktualizator.Core.Inventory;

public sealed record AppTransferEntry(string Id, string Name, string Source, string Version);

public sealed record AppTransferManifest(int SchemaVersion, DateTimeOffset CreatedAt, string Machine,
                                         IReadOnlyList<AppTransferEntry> Apps);

public static class AppTransferManifestFile
{
    public const string Extension = ".baapps.json";
    public const int CurrentSchemaVersion = 1;
    public const int MaxApps = 500;
    private const long MaxFileBytes = 2 * 1024 * 1024;
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
        MaxDepth = 16,
        WriteIndented = true,
    };

    public static AppTransferManifest Create(IEnumerable<AppTransferEntry> apps, string machine)
    {
        ArgumentNullException.ThrowIfNull(apps);
        var manifest = new AppTransferManifest(CurrentSchemaVersion, DateTimeOffset.UtcNow, machine, apps.ToArray());
        Validate(manifest);
        return manifest;
    }

    public static void Write(string path, AppTransferManifest manifest)
    {
        Validate(manifest);
        File.WriteAllText(path, JsonSerializer.Serialize(manifest, JsonOptions));
    }

    public static AppTransferManifest Read(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length > MaxFileBytes) throw new InvalidDataException(L.T("Plik listy aplikacji przekracza dozwolony rozmiar."));
        var content = new byte[checked((int)stream.Length)];
        stream.ReadExactly(content);
        AppTransferManifest manifest;
        try
        {
            manifest = JsonSerializer.Deserialize<AppTransferManifest>(content, JsonOptions)
                       ?? throw new InvalidDataException(L.T("Plik listy aplikacji jest pusty."));
        }
        catch (JsonException ex)
        {
            throw new InvalidDataException(L.T("Nieprawidłowy format pliku listy aplikacji."), ex);
        }
        Validate(manifest);
        return manifest;
    }

    private static void Validate(AppTransferManifest manifest)
    {
        if (manifest.SchemaVersion != CurrentSchemaVersion)
            throw new InvalidDataException(L.T("Nieobsługiwana wersja formatu listy aplikacji."));
        if (manifest.CreatedAt == default || string.IsNullOrWhiteSpace(manifest.Machine) ||
            manifest.Machine.Length > 256 || manifest.Machine.Any(char.IsControl))
            throw new InvalidDataException(L.T("Nieprawidłowe informacje nagłówka listy aplikacji."));
        if (manifest.Apps is null || manifest.Apps.Count > MaxApps)
            throw new InvalidDataException(L.T("Liczba pakietów na liście aplikacji jest nieprawidłowa."));

        var ids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var app in manifest.Apps)
        {
            if (app is null || !IsValidId(app.Id) || app.Name is null ||
                app.Name.Length is 0 or > 300 || app.Name.Any(char.IsControl) ||
                !string.Equals(app.Source, "winget", StringComparison.Ordinal) ||
                app.Version is null || app.Version.Length > 128 || app.Version.Any(char.IsControl))
                throw new InvalidDataException(L.T("Plik zawiera nieprawidłowy pakiet lub źródło inne niż winget."));
            if (!ids.Add(app.Id))
                throw new InvalidDataException(L.T("Plik zawiera powielony identyfikator pakietu."));
        }
    }

    private static bool IsValidId(string? id) =>
        !string.IsNullOrWhiteSpace(id) && id.Length <= 256 &&
        char.IsAsciiLetterOrDigit(id[0]) &&
        id.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '-' or '_' or '+');
}
