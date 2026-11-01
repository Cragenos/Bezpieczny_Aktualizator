using System.Text.Json;
using System.Text.Json.Serialization;
using BezpiecznyAktualizator.Core.History;
using BezpiecznyAktualizator.Core.Localization;
using BezpiecznyAktualizator.Core.Models;
using BezpiecznyAktualizator.Core.Security;

namespace BezpiecznyAktualizator.Core.Policies;

/// <summary>Minimalny poziom zaufania źródła dla aktualizacji instalowanych automatycznie.</summary>
[JsonConverter(typeof(JsonStringEnumConverter<AutoTrustLevel>))]
public enum AutoTrustLevel { High, HighOrMedium }

/// <summary>Program, który nigdy nie jest aktualizowany przez aplikację.</summary>
public sealed class ExclusionRule
{
    public string WingetId { get; set; } = "";
    public string Name { get; set; } = "";
    public string Reason { get; set; } = "";
    public DateTimeOffset Added { get; set; } = DateTimeOffset.Now;

    /// <summary>Reguła pochodzi z zasad komputera (administrator) - nie można jej zmienić w programie.</summary>
    [JsonIgnore] public bool Managed { get; set; }
}

/// <summary>
/// Wstrzymanie wersji („pin”). Pusta wersja - program zostaje na zainstalowanej wersji.
/// Wzorzec z gwiazdką (np. „24.*”) - dozwolone są tylko aktualizacje w tej gałęzi.
/// Konkretna wersja (np. „24.08”) - dozwolona jest tylko aktualizacja dokładnie do niej.
/// </summary>
public sealed class VersionHold
{
    public string WingetId { get; set; } = "";
    public string Name { get; set; } = "";
    public string Version { get; set; } = "";
    public string Reason { get; set; } = "";
    public DateTimeOffset Added { get; set; } = DateTimeOffset.Now;
    /// <summary>Wstrzymanie wygasa po tej dacie (null - bezterminowo).</summary>
    public DateTimeOffset? Until { get; set; }

    [JsonIgnore] public bool Managed { get; set; }

    public bool IsActive(DateTimeOffset now) => Until is null || now < Until;

    /// <summary>Czy aktualizacja do <paramref name="available"/> jest zgodna z wstrzymaniem.</summary>
    public bool Allows(string available)
    {
        var pattern = Version.Trim();
        if (pattern.Length == 0 || available.Trim().Length == 0) return false;
        if (!pattern.EndsWith('*')) return UpdateHistory.FindVersion([available], pattern) is not null;
        var prefix = Canon(pattern.TrimEnd('*').TrimEnd('.'));
        if (prefix.Length == 0) return true;
        var target = Canon(available);
        return target.Length >= prefix.Length && target.Take(prefix.Length).SequenceEqual(prefix);
    }

    public string Display =>
        (Version.Trim().Length == 0 ? L.T("na zainstalowanej wersji") : Version.Trim()) +
        (Until is { } u ? " " + L.F("(do {0:yyyy-MM-dd})", u.ToLocalTime()) : "");

    private static string[] Canon(string v) =>
        v.Trim().TrimStart('v', 'V').Split('.', StringSplitOptions.RemoveEmptyEntries)
         .Select(p => p.TrimStart('0') is { Length: > 0 } t ? t.ToLowerInvariant() : "0").ToArray();
}

public enum PolicyVerdict { Allowed, Excluded, Held, Untrusted, Unassessed }

public sealed record PolicyDecision(PolicyVerdict Verdict, LocText Reason)
{
    public static readonly PolicyDecision Allow = new(PolicyVerdict.Allowed, "");
    public bool Allowed => Verdict == PolicyVerdict.Allowed;
}

/// <summary>
/// Zasady aktualizacji: lista wykluczonych programów, wstrzymane wersje oraz wymagany poziom zaufania źródeł.
/// Obowiązują w oknie programu i w harmonogramie cichych aktualizacji. Zasady komputera
/// (%ProgramData%\BezpiecznyAktualizator\policies.json, zapisywane przez administratora) są dołączane
/// do zasad użytkownika i mają pierwszeństwo.
/// </summary>
public sealed class UpdatePolicies
{
    public static string MachineFilePath { get; set; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "BezpiecznyAktualizator", "policies.json");

    public static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase, PropertyNameCaseInsensitive = true, WriteIndented = true,
    };

    /// <summary>Automatycznie (harmonogram) instalowane są tylko aktualizacje ze źródeł o tym poziomie zaufania.</summary>
    public AutoTrustLevel AutoTrust { get; set; } = AutoTrustLevel.High;

    /// <summary>Także ręczne aktualizacje w oknie programu wymagają zaufanego źródła (niskie i nieocenione są pomijane).</summary>
    public bool ManualRequireTrusted { get; set; }

    public List<ExclusionRule> Excluded { get; set; } = [];
    public List<VersionHold> Holds { get; set; } = [];

    /// <summary>Zasady komputera zostały wczytane i dołączone.</summary>
    [JsonIgnore] public bool HasMachinePolicy { get; private set; }

    /// <summary>Plik zasad komputera jawnie określa poziom zaufania (tylko wtedy jest on wymuszany).</summary>
    [JsonIgnore] public bool SetsAutoTrust { get; set; }

    /// <summary>Poziom zaufania został narzucony przez zasady komputera.</summary>
    [JsonIgnore] public bool AutoTrustManaged { get; private set; }

    /// <summary>Wymóg zaufanego źródła dla ręcznych aktualizacji narzucony przez zasady komputera.</summary>
    [JsonIgnore] public bool ManualTrustManaged { get; private set; }

    public UpdatePolicies Normalize()
    {
        Excluded = (Excluded ?? []).Where(e => e is not null).Select(e =>
        {
            e.WingetId = (e.WingetId ?? "").Trim(); e.Name = (e.Name ?? "").Trim(); e.Reason = (e.Reason ?? "").Trim();
            return e;
        }).Where(e => e.WingetId.Length > 0).DistinctBy(e => e.WingetId, StringComparer.OrdinalIgnoreCase).ToList();
        Holds = (Holds ?? []).Where(h => h is not null).Select(h =>
        {
            h.WingetId = (h.WingetId ?? "").Trim(); h.Name = (h.Name ?? "").Trim();
            h.Version = (h.Version ?? "").Trim(); h.Reason = (h.Reason ?? "").Trim();
            return h;
        }).Where(h => h.WingetId.Length > 0).DistinctBy(h => h.WingetId, StringComparer.OrdinalIgnoreCase).ToList();
        if (!Enum.IsDefined(AutoTrust)) AutoTrust = AutoTrustLevel.High;
        return this;
    }

    public ExclusionRule? ExclusionFor(string? wingetId) =>
        string.IsNullOrEmpty(wingetId) ? null
        : Excluded.FirstOrDefault(e => e.WingetId.Equals(wingetId, StringComparison.OrdinalIgnoreCase));

    public VersionHold? HoldFor(string? wingetId, DateTimeOffset now) =>
        string.IsNullOrEmpty(wingetId) ? null
        : Holds.FirstOrDefault(h => h.WingetId.Equals(wingetId, StringComparison.OrdinalIgnoreCase) && h.IsActive(now));

    public bool IsExcluded(string? wingetId) => ExclusionFor(wingetId) is not null;

    /// <summary>Wykluczenie i wstrzymanie wersji (bez oceny zaufania).</summary>
    public PolicyDecision CheckRules(Software s, DateTimeOffset now)
    {
        if (ExclusionFor(s.WingetId) is { } ex)
            return new(PolicyVerdict.Excluded, ex.Reason.Length > 0
                ? L.Txt("Program jest na liście wykluczonych: {0}", ex.Reason) : L.Txt("Program jest na liście wykluczonych."));
        if (s.HasUpdate && HoldFor(s.WingetId, now) is { } hold && !hold.Allows(s.AvailableVersion))
            return new(PolicyVerdict.Held, hold.Version.Length == 0
                ? L.Txt("Wersja wstrzymana na {0}{1}.", s.Version, hold.Reason.Length > 0 ? " - " + hold.Reason : "")
                : L.Txt("Wersja wstrzymana ({0}) - dostępna wersja {1} nie jest dozwolona{2}.", hold.Version, s.AvailableVersion,
                        hold.Reason.Length > 0 ? " - " + hold.Reason : ""));
        return PolicyDecision.Allow;
    }

    public bool TrustAccepted(string level) =>
        level == Levels.High || AutoTrust == AutoTrustLevel.HighOrMedium && level == Levels.Medium;

    /// <summary>Czy dla tego trybu (automatyczny / ręczny) wymagany jest zaufany poziom źródła.</summary>
    public bool RequiresTrust(bool automatic) => automatic || ManualRequireTrusted;

    /// <summary>Pełna ocena: reguły, a następnie poziom zaufania źródła (gdy jest wymagany).</summary>
    public PolicyDecision Evaluate(Software s, bool automatic, DateTimeOffset now)
    {
        var rules = CheckRules(s, now);
        if (!rules.Allowed || !RequiresTrust(automatic)) return rules;
        if (s.SecurityLevel.Length == 0 || s.SecurityLevel == "?")
            return new(PolicyVerdict.Unassessed, L.Txt("Źródło aktualizacji nie zostało ocenione."));
        return TrustAccepted(s.SecurityLevel) ? PolicyDecision.Allow
            : new(PolicyVerdict.Untrusted, L.Txt("Poziom zaufania źródła ({0}) jest niższy niż wymagany przez zasady.", L.Txt(s.SecurityLevel)));
    }

    /// <summary>Krótki opis dla kolumny „Zasada”.</summary>
    public string Describe(Software s, DateTimeOffset now)
    {
        static string Lock(bool managed) => managed ? " [" + L.T("administrator") + "]" : "";
        if (ExclusionFor(s.WingetId) is { } ex) return L.T("Wykluczony") + Lock(ex.Managed);
        if (HoldFor(s.WingetId, now) is { } hold) return L.F("Wstrzymany: {0}", hold.Display) + Lock(hold.Managed);
        return "";
    }

    /// <summary>Dołącza zasady komputera: ich reguły mają pierwszeństwo, a ustawienia - zawsze ostrzejsze z obu.</summary>
    public UpdatePolicies MergeMachine(UpdatePolicies? machine)
    {
        if (machine is null) return this;
        machine.Normalize();
        foreach (var e in machine.Excluded) e.Managed = true;
        foreach (var h in machine.Holds) h.Managed = true;
        var merged = new UpdatePolicies
        {
            AutoTrust = machine.SetsAutoTrust && machine.AutoTrust == AutoTrustLevel.High ? AutoTrustLevel.High : AutoTrust,
            ManualRequireTrusted = ManualRequireTrusted || machine.ManualRequireTrusted,
            Excluded = machine.Excluded.Concat(Excluded.Where(e => !e.Managed)).ToList(),
            Holds = machine.Holds.Concat(Holds.Where(h => !h.Managed)).ToList(),
            HasMachinePolicy = true,
            AutoTrustManaged = machine.SetsAutoTrust && machine.AutoTrust == AutoTrustLevel.High,
            ManualTrustManaged = machine.ManualRequireTrusted,
        };
        return merged.Normalize();
    }

    /// <summary>Zasady użytkownika bez reguł komputera (do zapisu w ustawieniach).</summary>
    public UpdatePolicies UserPart() => new UpdatePolicies
    {
        AutoTrust = AutoTrust, ManualRequireTrusted = ManualRequireTrusted,
        Excluded = Excluded.Where(e => !e.Managed).ToList(), Holds = Holds.Where(h => !h.Managed).ToList(),
    }.Normalize();

    /// <summary>Zasady komputera; null, gdy pliku nie ma lub jest nieczytelny (wtedy <paramref name="error"/> opisuje problem).</summary>
    public static UpdatePolicies? LoadMachine(out string? error)
    {
        error = null;
        try
        {
            return File.Exists(MachineFilePath) ? MachineFromJson(File.ReadAllText(MachineFilePath)) : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            error = $"{MachineFilePath}: {ex.Message}";
            return null;
        }
    }

    /// <summary>Zasady komputera z JSON; poziom zaufania jest wymuszany tylko wtedy, gdy plik go określa.</summary>
    public static UpdatePolicies? MachineFromJson(string json)
    {
        var p = JsonSerializer.Deserialize<UpdatePolicies>(json, Json);
        if (p is null) return null;
        using var doc = JsonDocument.Parse(json);
        p.SetsAutoTrust = doc.RootElement.ValueKind == JsonValueKind.Object && doc.RootElement.EnumerateObject()
            .Any(x => x.Name.Equals(nameof(AutoTrust), StringComparison.OrdinalIgnoreCase));
        return p.Normalize();
    }

    public string ToJson() => JsonSerializer.Serialize(UserPart(), Json);

    public static UpdatePolicies FromJson(string json) =>
        (JsonSerializer.Deserialize<UpdatePolicies>(json, Json) ?? new UpdatePolicies()).Normalize();
}
