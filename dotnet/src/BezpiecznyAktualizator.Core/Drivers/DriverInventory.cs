using System.Management;

using BezpiecznyAktualizator.Core.Localization;

namespace BezpiecznyAktualizator.Core.Drivers;

/// <summary>Inwentarz sterowników z WMI (Win32_PnPSignedDriver + Win32_PnPEntity).</summary>
public static class DriverInventory
{
    public static List<Driver> Scan()
    {
        try
        {
            var entities = new Dictionary<string, ManagementBaseObject>(StringComparer.OrdinalIgnoreCase);
            using (var searcher = new ManagementObjectSearcher(
                       "SELECT PNPDeviceID, Name, Manufacturer, PNPClass, HardwareID, CompatibleID, ConfigManagerErrorCode FROM Win32_PnPEntity"))
            {
                foreach (var e in searcher.Get())
                    if (e["PNPDeviceID"] is string id) entities[id] = e;
            }

            var records = new List<Dictionary<string, object?>>();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            using (var searcher = new ManagementObjectSearcher(
                       "SELECT DeviceName, DeviceID, DriverVersion, DriverDate, DriverProviderName, Manufacturer, InfName, " +
                       "DeviceClass, IsSigned, Signer, HardWareID FROM Win32_PnPSignedDriver"))
            {
                foreach (var d in searcher.Get())
                {
                    if (d["DeviceName"] is not string name || d["DeviceID"] is not string id) continue;
                    seen.Add(id);
                    entities.TryGetValue(id, out var e);
                    records.Add(new Dictionary<string, object?>
                    {
                        ["DeviceName"] = name, ["DeviceID"] = id, ["DriverVersion"] = d["DriverVersion"],
                        ["DriverDate"] = FormatCimDate(d["DriverDate"] as string),
                        ["DriverProviderName"] = d["DriverProviderName"], ["Manufacturer"] = d["Manufacturer"],
                        ["InfName"] = d["InfName"], ["DeviceClass"] = d["DeviceClass"], ["IsSigned"] = d["IsSigned"],
                        ["Signer"] = d["Signer"],
                        ["HardwareID"] = e?["HardwareID"] ?? d["HardWareID"],
                        ["CompatibleID"] = e?["CompatibleID"],
                        ["ErrorCode"] = e?["ConfigManagerErrorCode"] ?? 0u,
                    });
                }
            }
            // Urządzenia z problemem (np. kod 28 - brak sterownika) nie występują w Win32_PnPSignedDriver.
            foreach (var (id, e) in entities)
            {
                if (seen.Contains(id) || e["Name"] is not string name) continue;
                if (Convert.ToInt32(e["ConfigManagerErrorCode"] ?? 0u) == 0) continue;
                records.Add(new Dictionary<string, object?>
                {
                    ["DeviceName"] = name, ["DeviceID"] = id, ["Manufacturer"] = e["Manufacturer"],
                    ["DeviceClass"] = e["PNPClass"], ["HardwareID"] = e["HardwareID"],
                    ["CompatibleID"] = e["CompatibleID"], ["ErrorCode"] = e["ConfigManagerErrorCode"],
                });
            }
            return FromRecords(records);
        }
        catch (Exception ex) when (ex is ManagementException or System.Runtime.InteropServices.COMException or UnauthorizedAccessException)
        {
            throw new DriverException(L.F("Nie udało się odczytać sterowników z WMI: {0}", ex.Message), ex);
        }
    }

    private static string FormatCimDate(string? cim)
    {
        if (string.IsNullOrEmpty(cim)) return "";
        try
        {
            return ManagementDateTimeConverter.ToDateTime(cim).ToString("yyyy-MM-dd");
        }
        catch (ArgumentOutOfRangeException)
        {
            return cim.Length >= 8 ? $"{cim[..4]}-{cim[4..6]}-{cim[6..8]}" : "";
        }
    }

    private static string Str(IReadOnlyDictionary<string, object?> r, string key) =>
        (r.GetValueOrDefault(key)?.ToString() ?? "").Trim();

    private static List<string> AsList(object? value) => value switch
    {
        null => [],
        string s => s.Length > 0 ? [s] : [],
        System.Collections.IEnumerable items => items.Cast<object?>().Select(i => i?.ToString() ?? "")
                                                     .Where(i => i.Length > 0).ToList(),
        _ => [value.ToString() ?? ""],
    };

    public static List<Driver> FromRecords(IEnumerable<IReadOnlyDictionary<string, object?>> records) =>
        records.Select(r => new Driver
        {
            DeviceName = Str(r, "DeviceName"),
            DeviceId = Str(r, "DeviceID"),
            Version = Str(r, "DriverVersion"),
            Date = Str(r, "DriverDate"),
            Provider = Str(r, "DriverProviderName"),
            Manufacturer = Str(r, "Manufacturer"),
            InfName = Str(r, "InfName"),
            DeviceClass = Str(r, "DeviceClass"),
            IsSigned = r.GetValueOrDefault("IsSigned") as bool?,
            Signer = Str(r, "Signer"),
            HardwareIds = AsList(r.GetValueOrDefault("HardwareID")),
            CompatibleIds = AsList(r.GetValueOrDefault("CompatibleID")),
            ErrorCode = r.GetValueOrDefault("ErrorCode") is { } code ? Convert.ToInt32(code) : 0,
        })
        .OrderBy(d => d.DeviceClass, StringComparer.CurrentCultureIgnoreCase)
        .ThenBy(d => d.DeviceName, StringComparer.CurrentCultureIgnoreCase)
        .ToList();
}
