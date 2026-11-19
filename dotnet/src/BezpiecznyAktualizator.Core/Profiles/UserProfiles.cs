using System.Security.Principal;
using BezpiecznyAktualizator.Core.Localization;
using Microsoft.Win32;

namespace BezpiecznyAktualizator.Core.Profiles;

/// <summary>Profil lokalnego lub domenowego użytkownika Windows (z rejestru ProfileList).</summary>
public sealed record UserProfileInfo(string Sid, string UserName, string ProfilePath, bool IsCurrent)
{
    public string Display => IsCurrent
        ? L.F("{0} (bieżący użytkownik) – {1}", UserName, ProfilePath)
        : $"{UserName} – {ProfilePath}";
}

/// <summary>Folder profilu, który można umieścić w paczce (klucz jest stały i zapisywany w manifeście).</summary>
public sealed record ProfileFolder(string Key, Func<string> LocalizedName, string RelativePath, Environment.SpecialFolder? CurrentUserFolder)
{
    public string Name => LocalizedName();
}

public static class UserProfiles
{
    public static IReadOnlyList<ProfileFolder> Folders { get; } =
    [
        new("Desktop", () => L.T("Pulpit"), "Desktop", Environment.SpecialFolder.DesktopDirectory),
        new("Documents", () => L.T("Dokumenty"), "Documents", Environment.SpecialFolder.MyDocuments),
        new("Pictures", () => L.T("Obrazy"), "Pictures", Environment.SpecialFolder.MyPictures),
        new("Music", () => L.T("Muzyka"), "Music", Environment.SpecialFolder.MyMusic),
        new("Videos", () => L.T("Wideo"), "Videos", Environment.SpecialFolder.MyVideos),
        new("Downloads", () => L.T("Pobrane"), "Downloads", null),
        new("Favorites", () => L.T("Ulubione"), "Favorites", Environment.SpecialFolder.Favorites),
        new("AppDataRoaming", () => L.T("Ustawienia programów (AppData\\Roaming)"), @"AppData\Roaming", Environment.SpecialFolder.ApplicationData),
    ];

    /// <summary>Foldery zaznaczone domyślnie (AppData\Roaming bywa duże i zależne od wersji programów).</summary>
    public static bool IsDefault(ProfileFolder folder) => folder.Key != "AppDataRoaming";

    public static ProfileFolder? Find(string key) =>
        Folders.FirstOrDefault(f => string.Equals(f.Key, key, StringComparison.Ordinal));

    /// <summary>Konta zwykłych użytkowników (SID S-1-5-21-… lub Microsoft Entra S-1-12-1-…) z istniejącym folderem profilu.</summary>
    public static List<UserProfileInfo> List()
    {
        var current = CurrentSid();
        var result = new List<UserProfileInfo>();
        using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList");
        if (key is null) return result;
        foreach (var sid in key.GetSubKeyNames())
        {
            if (!IsUserSid(sid)) continue;
            using var profile = key.OpenSubKey(sid);
            if (profile?.GetValue("ProfileImagePath") is not string rawPath || rawPath.Length == 0) continue;
            var path = Environment.ExpandEnvironmentVariables(rawPath);
            if (!Directory.Exists(path)) continue;
            result.Add(new UserProfileInfo(sid, ResolveName(sid, path), path, string.Equals(sid, current, StringComparison.OrdinalIgnoreCase)));
        }
        return result.OrderByDescending(p => p.IsCurrent).ThenBy(p => p.UserName, StringComparer.CurrentCultureIgnoreCase).ToList();
    }

    internal static bool IsUserSid(string sid) =>
        (sid.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase) || sid.StartsWith("S-1-12-1-", StringComparison.OrdinalIgnoreCase)) &&
        !sid.EndsWith(".bak", StringComparison.OrdinalIgnoreCase);

    /// <summary>Ścieżka folderu w profilu; dla bieżącego użytkownika uwzględnia przekierowanie (np. do OneDrive).</summary>
    public static string ResolveFolder(UserProfileInfo profile, ProfileFolder folder)
    {
        if (profile.IsCurrent && folder.CurrentUserFolder is { } special &&
            Environment.GetFolderPath(special, Environment.SpecialFolderOption.DoNotVerify) is { Length: > 0 } redirected)
            return redirected;
        return Path.Combine(profile.ProfilePath, folder.RelativePath);
    }

    public static bool IsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static string? CurrentSid()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return identity.User?.Value;
    }

    private static string ResolveName(string sid, string path)
    {
        try
        {
            return new SecurityIdentifier(sid).Translate(typeof(NTAccount)).Value;
        }
        catch (SystemException)
        {
            return Path.GetFileName(path.TrimEnd(Path.DirectorySeparatorChar));
        }
    }
}
