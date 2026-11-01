using System.Text.Json;
using System.Text.Json.Serialization;

namespace BezpiecznyAktualizator.Core.History;

[JsonConverter(typeof(JsonStringEnumConverter<UpdateKind>))]
public enum UpdateKind { Upgrade, Rollback }

/// <summary>Wpis historii: zmiana wersji programu wykonana przez aplikację.</summary>
public sealed class UpdateRecord
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public DateTimeOffset Time { get; set; } = DateTimeOffset.Now;
    public UpdateKind Kind { get; set; }
    public string Name { get; set; } = "";
    public string WingetId { get; set; } = "";
    public string Source { get; set; } = "";
    /// <summary>Wersja zainstalowana przed zmianą - do niej można wrócić.</summary>
    public string FromVersion { get; set; } = "";
    public string ToVersion { get; set; } = "";
    public string Sha256 { get; set; } = "";
    /// <summary>Zmiana wykonana przez harmonogram cichych aktualizacji.</summary>
    public bool Scheduled { get; set; }
    /// <summary>Aktualizacja została później wycofana.</summary>
    public bool RolledBack { get; set; }

    [JsonIgnore]
    public bool CanRollback => Kind == UpdateKind.Upgrade && !RolledBack && WingetId.Length > 0 && FromVersion.Length > 0 &&
                               FromVersion != ToVersion;
}

/// <summary>
/// Historia aktualizacji w %LOCALAPPDATA%\BezpiecznyAktualizator\update-history.json.
/// Zapisują ją zarówno okno programu, jak i ciche uruchomienie z harmonogramu, dlatego
/// każda zmiana odbywa się pod nazwanym mutexem.
/// </summary>
public static class UpdateHistory
{
    public const int MaxEntries = 500;

    public static string FilePath { get; set; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "BezpiecznyAktualizator", "update-history.json");

    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase, PropertyNameCaseInsensitive = true, WriteIndented = true,
    };

    public static List<UpdateRecord> Load()
    {
        try
        {
            return File.Exists(FilePath)
                ? JsonSerializer.Deserialize<List<UpdateRecord>>(File.ReadAllText(FilePath), Options) ?? []
                : [];
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            return [];
        }
    }

    private static void Modify(Action<List<UpdateRecord>> change)
    {
        using var mutex = new Mutex(false, @"Local\BezpiecznyAktualizator.UpdateHistory");
        var owned = false;
        try
        {
            try
            {
                owned = mutex.WaitOne(TimeSpan.FromSeconds(10));
            }
            catch (AbandonedMutexException)
            {
                owned = true;
            }
            var list = Load();
            change(list);
            if (list.Count > MaxEntries) list.RemoveRange(0, list.Count - MaxEntries);
            Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
            var temp = FilePath + ".tmp";
            File.WriteAllText(temp, JsonSerializer.Serialize(list, Options));
            File.Move(temp, FilePath, true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
        }
        finally
        {
            if (owned) mutex.ReleaseMutex();
        }
    }

    public static void Add(UpdateRecord record) => Modify(list => list.Add(record));

    public static void MarkRolledBack(Guid id) => Modify(list =>
    {
        foreach (var r in list.Where(r => r.Id == id)) r.RolledBack = true;
    });

    /// <summary>Ostatnia aktualizacja danego pakietu, którą można wycofać.</summary>
    public static UpdateRecord? LastRollbackable(IEnumerable<UpdateRecord> records, string? wingetId) =>
        string.IsNullOrEmpty(wingetId) ? null
            : records.Where(r => r.CanRollback && r.WingetId.Equals(wingetId, StringComparison.OrdinalIgnoreCase))
                     .OrderByDescending(r => r.Time).FirstOrDefault();

    /// <summary>
    /// Szuka wersji w repozytorium odpowiadającej zapamiętanej (dokładnie albo z pominięciem końcowych zer, np. 23.01 = 23.01.0).
    /// </summary>
    public static string? FindVersion(IEnumerable<string> available, string wanted)
    {
        var list = available.ToList();
        var exact = list.FirstOrDefault(v => v.Equals(wanted, StringComparison.OrdinalIgnoreCase));
        if (exact is not null) return exact;
        static string Canon(string v)
        {
            var parts = v.Trim().TrimStart('v', 'V').Split('.').ToList();
            while (parts.Count > 1 && parts[^1].All(c => c == '0')) parts.RemoveAt(parts.Count - 1);
            return string.Join('.', parts.Select(p => p.TrimStart('0') is { Length: > 0 } t ? t : "0")).ToLowerInvariant();
        }
        var target = Canon(wanted);
        return target.Length == 0 ? null : list.FirstOrDefault(v => Canon(v) == target);
    }
}
