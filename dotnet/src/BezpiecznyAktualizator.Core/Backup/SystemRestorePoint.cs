using System.Management;
using System.Runtime.InteropServices;
using BezpiecznyAktualizator.Core.Localization;

namespace BezpiecznyAktualizator.Core.Backup;

public enum RestorePointOutcome { Created, Recent, Failed }

public enum RestorePointPurpose { Software, Drivers, WindowsUpdate, Store, Scheduled }

public sealed record RestorePointResult(RestorePointOutcome Outcome, DateTime? PointTime, string Detail)
{
    public bool Succeeded => Outcome != RestorePointOutcome.Failed;
}

/// <summary>
/// Punkt przywracania systemu tworzony przed instalacją (WMI root\default:SystemRestore, wymaga administratora).
/// Windows domyślnie tworzy najwyżej jeden punkt na 24 godziny - wtedy za kopię uznawany jest najnowszy istniejący punkt.
/// </summary>
public static class SystemRestorePoint
{
    public const string CreateArgument = "--create-restore-point";
    public static readonly TimeSpan ReuseWindow = TimeSpan.FromHours(24);
    private static readonly TimeSpan ClockSkew = TimeSpan.FromMinutes(5);

    public static string Description(RestorePointPurpose purpose) => purpose switch
    {
        RestorePointPurpose.Drivers => "Bezpieczny Aktualizator - sterowniki",
        RestorePointPurpose.WindowsUpdate => "Bezpieczny Aktualizator - Windows Update",
        RestorePointPurpose.Store => "Bezpieczny Aktualizator - Microsoft Store",
        RestorePointPurpose.Scheduled => "Bezpieczny Aktualizator - ciche aktualizacje",
        _ => "Bezpieczny Aktualizator - programy",
    };

    public static bool TryParsePurpose(string? value, out RestorePointPurpose purpose)
    {
        purpose = default;
        return value is { Length: > 0 } && char.IsLetter(value[0]) &&
               Enum.TryParse(value, ignoreCase: true, out purpose) && Enum.IsDefined(purpose);
    }

    /// <summary>Kod wyjścia procesu pomocniczego uruchomionego z <see cref="CreateArgument"/>.</summary>
    public static int ToExitCode(RestorePointOutcome outcome) => outcome switch
    {
        RestorePointOutcome.Created => 0,
        RestorePointOutcome.Recent => 10,
        _ => 20,
    };

    public static RestorePointResult FromExitCode(int code) => code switch
    {
        0 => new(RestorePointOutcome.Created, null, L.T("Punkt przywracania utworzony.")),
        10 => new(RestorePointOutcome.Recent, null,
            L.T("Windows nie utworzył nowego punktu przywracania - użyto punktu utworzonego w ciągu ostatnich 24 godzin.")),
        _ => new(RestorePointOutcome.Failed, null,
            L.F("Nie utworzono punktu przywracania (kod {0}). Sprawdź, czy ochrona systemu jest włączona.", code)),
    };

    /// <summary>Tworzy punkt przywracania w bieżącym procesie (musi mieć uprawnienia administratora).</summary>
    public static RestorePointResult Create(RestorePointPurpose purpose)
    {
        try
        {
            var before = LatestPointTime();
            uint code;
            using (var restore = new ManagementClass(new ManagementPath(@"\\.\root\default:SystemRestore")))
            using (var input = restore.GetMethodParameters("CreateRestorePoint"))
            {
                input["Description"] = Description(purpose);
                input["RestorePointType"] = 12u; // MODIFY_SETTINGS
                input["EventType"] = 100u;       // BEGIN_SYSTEM_CHANGE
                using var output = restore.InvokeMethod("CreateRestorePoint", input, null);
                code = Convert.ToUInt32(output?["ReturnValue"] ?? 0u);
            }
            return Evaluate(code, before, LatestPointTime(), DateTime.Now);
        }
        catch (Exception ex) when (ex is ManagementException or COMException or UnauthorizedAccessException or
                                       PlatformNotSupportedException)
        {
            return new(RestorePointOutcome.Failed, null, L.F("Nie utworzono punktu przywracania: {0}", ex.Message));
        }
    }

    internal static RestorePointResult Evaluate(uint returnCode, DateTime? before, DateTime? after, DateTime now)
    {
        if (after is { } latest && (before is null || latest > before.Value))
            return new(RestorePointOutcome.Created, latest, L.T("Punkt przywracania utworzony."));
        if (after is { } recent && recent <= now + ClockSkew && now - recent <= ReuseWindow)
            return new(RestorePointOutcome.Recent, recent,
                L.F("Windows nie utworzył nowego punktu przywracania - użyto punktu z {0:yyyy-MM-dd HH:mm}.", recent));
        return new(RestorePointOutcome.Failed, after, returnCode == 0
            ? L.T("Windows nie utworzył punktu przywracania. Sprawdź, czy ochrona systemu jest włączona.")
            : L.F("Nie utworzono punktu przywracania (kod {0}). Sprawdź, czy ochrona systemu jest włączona.", returnCode));
    }

    private static DateTime? LatestPointTime()
    {
        using var searcher = new ManagementObjectSearcher(@"root\default", "SELECT CreationTime FROM SystemRestore");
        DateTime? latest = null;
        foreach (var point in searcher.Get())
        {
            using (point)
            {
                if (point["CreationTime"] is not string value || value.Length == 0) continue;
                var time = ManagementDateTimeConverter.ToDateTime(value);
                if (latest is null || time > latest) latest = time;
            }
        }
        return latest;
    }
}

/// <summary>Tworzy kopię co najwyżej raz na serię instalacji i zapamiętuje wynik (także niepowodzenie).</summary>
public sealed class RestorePointGate(Func<RestorePointResult> create)
{
    private RestorePointResult? _result;

    public bool Attempted => _result is not null;

    public RestorePointResult Ensure() => _result ??= create();
}
