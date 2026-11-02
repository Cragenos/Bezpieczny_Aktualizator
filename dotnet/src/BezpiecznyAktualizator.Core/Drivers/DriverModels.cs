using System.Text.RegularExpressions;
using BezpiecznyAktualizator.Core.Localization;
using BezpiecznyAktualizator.Core.Security;
using BezpiecznyAktualizator.Core.Updates;

namespace BezpiecznyAktualizator.Core.Drivers;

public sealed class DriverException(string message, Exception? inner = null) : Exception(message, inner);

public sealed partial class DriverUpdate
{
    public string UpdateId { get; init; } = "";
    public string Title { get; init; } = "";
    public string Model { get; init; } = "";
    public string Manufacturer { get; init; } = "";
    public string Provider { get; init; } = "";
    public string DriverClass { get; init; } = "";
    public string HardwareId { get; init; } = "";
    public string Date { get; init; } = "";
    public long Size { get; init; }
    public bool EulaAccepted { get; init; } = true;
    public string SupportUrl { get; init; } = "";
    public string Description { get; init; } = "";

    /// <summary>Tytuły Windows Update mają postać „Dostawca - Klasa - 1.2.3.4”.</summary>
    public string Version => TrailingVersion().Match(Title) is { Success: true } m ? m.Groups[1].Value : "";

    public string SizeText => $"{Size / 1048576.0:0.0} MB";

    [GeneratedRegex(@"(\d+(?:\.\d+){1,3})\s*$")]
    private static partial Regex TrailingVersion();
}

public sealed class Driver
{
    public const string CatalogSearchUrl = MicrosoftUpdateCatalog.SearchUrl;
    public const int ErrorNoDriver = 28;

    private static readonly HashSet<string> WhqlSigners = new(StringComparer.OrdinalIgnoreCase)
    {
        "Microsoft Windows Hardware Compatibility Publisher", "Microsoft Windows",
    };

    public string DeviceName { get; set; } = "";
    public string DeviceId { get; set; } = "";
    public string Version { get; set; } = "";
    public string Date { get; set; } = "";
    public string Provider { get; set; } = "";
    public string Manufacturer { get; set; } = "";
    public string InfName { get; set; } = "";
    public string DeviceClass { get; set; } = "";
    public bool? IsSigned { get; set; }
    public string Signer { get; set; } = "";
    public List<string> HardwareIds { get; set; } = [];
    public List<string> CompatibleIds { get; set; } = [];
    public int ErrorCode { get; set; }
    public DriverUpdate? Update { get; set; }
    /// <summary>Wewnętrzna wartość poziomu (<see cref="Levels"/>); do wyświetlenia <see cref="SecurityLevelDisplay"/>.</summary>
    public string SecurityLevel { get; set; } = "";
    public string SecurityLevelDisplay => L.T(SecurityLevel);

    /// <summary>Ostatnia ocena - raport jest generowany w bieżącym języku.</summary>
    public Assessment? Assessment { get; set; }
    private string _securityReport = "";
    public string SecurityReport
    {
        get => Assessment?.Report() ?? _securityReport;
        set { _securityReport = value; Assessment = null; }
    }

    public bool MissingDriver => ErrorCode == ErrorNoDriver;
    public bool HasUpdate => Update is not null;
    public bool IsWhql => IsSigned == true && WhqlSigners.Contains(Signer);
    public bool HasProblem => ErrorCode != 0 || IsSigned == false;
    public string ProviderDisplay => Provider.Length > 0 ? Provider : Manufacturer;
    public string AvailableDisplay => Update is null ? "" : Update.Version.Length > 0 ? Update.Version : Update.Date;

    public string SignatureText => IsSigned switch
    {
        null => MissingDriver ? L.T("brak sterownika") : "?",
        false => L.T("NIEPODPISANY"),
        _ when IsWhql => "Microsoft (WHQL)",
        _ => Signer.Length > 0 ? Signer : L.T("podpisany"),
    };

    public string Status
    {
        get
        {
            if (Update is not null)
                return MissingDriver ? L.T("Sterownik dostępny")
                    : DriverMatcher.IsNewer(Update, this) ? L.T("Aktualizacja dostępna") : L.T("Alternatywna wersja");
            if (MissingDriver) return L.T("Brak sterownika");
            return ErrorCode != 0 ? L.F("Problem (kod {0})", ErrorCode) : "OK";
        }
    }

    public string CatalogUrl() =>
        MicrosoftUpdateCatalog.Search(HardwareIds.Count > 0 ? HardwareIds[0] : DeviceName);
}

public static class DriverMatcher
{
    public static int[] VersionTuple(string? version) =>
        Regex.Matches(version ?? "", @"\d+").Select(m => int.TryParse(m.Value, out var n) ? n : int.MaxValue).ToArray();

    public static int CompareVersions(string? a, string? b)
    {
        var x = VersionTuple(a);
        var y = VersionTuple(b);
        for (var i = 0; i < Math.Min(x.Length, y.Length); i++)
            if (x[i] != y[i]) return x[i].CompareTo(y[i]);
        return x.Length.CompareTo(y.Length);
    }

    public static bool IsNewer(DriverUpdate update, Driver driver)
    {
        if (update.Version.Length > 0 && driver.Version.Length > 0)
            return CompareVersions(update.Version, driver.Version) > 0;
        if (update.Date.Length > 0 && driver.Date.Length > 0)
            return string.CompareOrdinal(update.Date, driver.Date) > 0;
        return true;
    }

    private static bool Contains(IEnumerable<string> ids, string hwid) =>
        ids.Any(h => string.Equals(h, hwid, StringComparison.OrdinalIgnoreCase));

    /// <summary>Przypisuje aktualizacje do urządzeń po identyfikatorze sprzętu. Niedopasowane trafiają jako nowe wiersze.</summary>
    public static List<Driver> MatchUpdates(IEnumerable<Driver> drivers, IEnumerable<DriverUpdate> updates)
    {
        var result = drivers.ToList();
        foreach (var d in result) d.Update = null;
        foreach (var upd in updates)
        {
            var hwid = upd.HardwareId;
            List<Driver> targets = hwid.Length == 0 ? [] : result.Where(d => Contains(d.HardwareIds, hwid)).ToList();
            if (targets.Count == 0 && hwid.Length > 0)
                targets = result.Where(d => Contains(d.CompatibleIds, hwid)).ToList();
            if (targets.Count == 0)
            {
                var extra = new Driver
                {
                    DeviceName = upd.Model.Length > 0 ? upd.Model : upd.Title, Provider = upd.Provider,
                    Manufacturer = upd.Manufacturer, DeviceClass = upd.DriverClass,
                    HardwareIds = hwid.Length > 0 ? [hwid] : [],
                };
                result.Add(extra);
                targets = [extra];
            }
            foreach (var target in targets)
            {
                if (target.Update is null ||
                    IsNewer(upd, new Driver { Version = target.Update.Version, Date = target.Update.Date }))
                    target.Update = upd;
            }
        }
        return result;
    }
}
