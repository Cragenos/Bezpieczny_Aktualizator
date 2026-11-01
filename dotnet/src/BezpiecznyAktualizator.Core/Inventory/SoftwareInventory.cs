using BezpiecznyAktualizator.Core.Models;
using Microsoft.Win32;

namespace BezpiecznyAktualizator.Core.Inventory;

/// <summary>Inwentaryzacja oprogramowania na podstawie kluczy Uninstall w rejestrze Windows.</summary>
public static class SoftwareInventory
{
    private const string UninstallPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";

    private static readonly HashSet<string> SkippedReleaseTypes =
        new(StringComparer.OrdinalIgnoreCase) { "update", "hotfix", "security update", "service pack" };

    public static List<Software> ScanInstalled()
    {
        var result = new Dictionary<(string, string), Software>();
        var views = new (RegistryHive Hive, RegistryView View, string Label)[]
        {
            (RegistryHive.LocalMachine, RegistryView.Registry64, "HKLM"),
            (RegistryHive.LocalMachine, RegistryView.Registry32, "HKLM (32-bit)"),
            (RegistryHive.CurrentUser, RegistryView.Default, "HKCU"),
        };
        foreach (var (hive, view, label) in views)
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, view);
            using var root = baseKey.OpenSubKey(UninstallPath);
            if (root is null) continue;
            foreach (var subName in root.GetSubKeyNames())
            {
                RegistryKey? key;
                try { key = root.OpenSubKey(subName); }
                catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException) { continue; }
                if (key is null) continue;
                using (key)
                {
                    var sw = ReadEntry(key, subName, label);
                    if (sw is null) continue;
                    result.TryAdd((Software.NormalizeName(sw.Name), sw.Version), sw);
                }
            }
        }
        return [.. result.Values.OrderBy(s => s.Name, StringComparer.CurrentCultureIgnoreCase)];
    }

    private static Software? ReadEntry(RegistryKey key, string subName, string origin)
    {
        if (key.GetValue("DisplayName") is not string name || string.IsNullOrWhiteSpace(name)) return null;
        if (key.GetValue("SystemComponent") is int sc && sc == 1) return null;
        if (key.GetValue("ParentKeyName") is string parent && parent.Length > 0) return null;
        if (SkippedReleaseTypes.Contains(Str(key, "ReleaseType"))) return null;
        return new Software
        {
            Name = name.Trim(),
            Version = Str(key, "DisplayVersion"),
            Publisher = Str(key, "Publisher"),
            InstallLocation = Str(key, "InstallLocation"),
            InstallDate = Str(key, "InstallDate"),
            Origin = origin,
            RegKey = subName,
            UrlInfo = Str(key, "URLInfoAbout"),
            UrlUpdate = Str(key, "URLUpdateInfo"),
            HelpLink = Str(key, "HelpLink"),
        };
    }

    private static string Str(RegistryKey key, string name) => (key.GetValue(name)?.ToString() ?? "").Trim();
}
