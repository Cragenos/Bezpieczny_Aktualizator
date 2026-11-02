using System.Text.RegularExpressions;
using BezpiecznyAktualizator.Core.Localization;
using BezpiecznyAktualizator.Core.Risk;
using BezpiecznyAktualizator.Core.Security;

namespace BezpiecznyAktualizator.Core.Models;

public sealed partial class Software
{
    public string Name { get; set; } = "";
    public string Version { get; set; } = "";
    public string Publisher { get; set; } = "";
    public string InstallLocation { get; set; } = "";
    public string InstallDate { get; set; } = "";
    /// <summary>Pochodzenie wpisu, np. "HKLM", "HKLM (32-bit)", "HKCU", "winget".</summary>
    public string Origin { get; set; } = "";
    public string RegKey { get; set; } = "";
    public string UrlInfo { get; set; } = "";
    public string UrlUpdate { get; set; } = "";
    public string HelpLink { get; set; } = "";

    public string? WingetId { get; set; }
    public string WingetSource { get; set; } = "";
    public string AvailableVersion { get; set; } = "";
    public bool WingetDetected { get; set; }
    /// <summary>Wewnętrzna wartość poziomu (<see cref="Security.Levels"/>); do wyświetlenia <see cref="SecurityLevelDisplay"/>.</summary>
    public string SecurityLevel { get; set; } = "";
    public string SecurityLevelDisplay => L.T(SecurityLevel);

    /// <summary>Ostatnia ocena źródła - raport jest generowany w bieżącym języku.</summary>
    public Assessment? Assessment { get; set; }
    private string _securityReport = "";
    public string SecurityReport
    {
        get => Assessment?.Report() ?? _securityReport;
        set { _securityReport = value; Assessment = null; }
    }

    public string Homepage { get; set; } = "";
    public LocText SearchHint { get; set; } = "";
    public string CatalogId { get; set; } = "";
    public string CatalogSource { get; set; } = "";
    public string CatalogUrl { get; set; } = "";

    public bool HasUpdate => AvailableVersion.Length > 0 && AvailableVersion != Version;

    public bool CanUpgrade => WingetDetected && !string.IsNullOrEmpty(WingetId) && HasUpdate;

    public bool IsRegistryEntry => Origin.StartsWith("HKLM", StringComparison.Ordinal) ||
                                   Origin.StartsWith("HKCU", StringComparison.Ordinal);

    /// <summary>Opis zasady aktualizacji (wykluczenie / wstrzymanie) dla kolumny „Zasada”.</summary>
    public string PolicyDisplay { get; set; } = "";

    /// <summary>Zasady aktualizacji blokują dostępną aktualizację.</summary>
    public bool PolicyBlocked { get; set; }

    public string Status =>
        HasUpdate && PolicyBlocked ? L.T("Aktualizacja wstrzymana")
        : HasUpdate ? L.T("Aktualizacja dostępna")
        : !string.IsNullOrEmpty(WingetId) && WingetSource.Length > 0 ? L.T("Aktualne")
        : WingetDetected ? L.T("Brak w repozytorium")
        : "";

    public string AvailableDisplay => HasUpdate ? AvailableVersion : "";

    public string SourceDisplay =>
        WingetSource.Length > 0 ? WingetSource
        : CatalogSource.Length > 0 ? CatalogSource
        : VendorUrls().Count > 0 ? L.T("strona producenta") : "";

    public string IdDisplay => WingetId ?? CatalogId;

    /// <summary>Wynik sprawdzenia znanych podatności (NVD); null - nie sprawdzano.</summary>
    public VulnerabilityReport? Vulnerabilities { get; set; }

    /// <summary>Stan wsparcia (EOL / porzucony); null - nie sprawdzano lub brak danych.</summary>
    public LifecycleInfo? Lifecycle { get; set; }

    /// <summary>Zainstalowana wersja ma znane podatności - aktualizacja jest pilna.</summary>
    public bool IsUrgent => Vulnerabilities?.IsUrgent == true;

    public bool IsUnsupported => Lifecycle?.State is LifecycleState.Eol or LifecycleState.Abandoned;

    /// <summary>Wartość dla wyróżnienia wiersza: „urgent”, „unsupported” albo "".</summary>
    public string RiskState => IsUrgent ? "urgent" : IsUnsupported ? "unsupported" : "";

    public string RiskDisplay
    {
        get
        {
            var parts = new List<string>();
            if (IsUrgent)
            {
                var v = Vulnerabilities!;
                if (v.Items.Count > 0)
                    parts.Add(L.F("PILNE: {0} CVE (CVSS {1:0.0})", v.Items.Count, v.MaxScore) + (v.Exploited ? " KEV" : ""));
                if (v.OsvItems.Count > 0) parts.Add(L.F("OSV: {0} podatności", v.OsvItems.Count));
            }
            if (Lifecycle?.State == LifecycleState.Eol) parts.Add(L.T("EOL"));
            else if (Lifecycle?.State == LifecycleState.Abandoned) parts.Add(L.T("porzucony"));
            if (parts.Count > 0) return string.Join(" | ", parts);
            if (Vulnerabilities is { Checked: true }) return L.T("Brak znanych luk");
            return Vulnerabilities is not null || Lifecycle is not null ? L.T("Brak danych") : "";
        }
    }

    public List<string> VendorUrls()
    {
        var urls = new List<string>();
        foreach (var raw in new[] { UrlUpdate, UrlInfo, HelpLink })
        {
            var u = (raw ?? "").Trim();
            if (u.Length > 0 && !urls.Contains(u)) urls.Add(u);
        }
        return urls;
    }

    public static string NormalizeName(string name) => NonAlnum().Replace(name.ToLowerInvariant(), "");

    [GeneratedRegex("[^0-9a-z]+")]
    private static partial Regex NonAlnum();
}
