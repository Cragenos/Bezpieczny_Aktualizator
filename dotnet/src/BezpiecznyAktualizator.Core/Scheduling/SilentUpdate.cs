using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using BezpiecznyAktualizator.Core.Localization;
using BezpiecznyAktualizator.Core.Models;
using BezpiecznyAktualizator.Core.Policies;
using BezpiecznyAktualizator.Core.Security;

namespace BezpiecznyAktualizator.Core.Scheduling;

[JsonConverter(typeof(JsonStringEnumConverter<ScheduleMode>))]
public enum ScheduleMode { CheckOnly, InstallTrusted }

/// <summary>Ustawienia cichego sprawdzania i aktualizacji uruchamianego przez Harmonogram zadań Windows.</summary>
public sealed class ScheduleOptions
{
    public static readonly int[] IdleChoices = [5, 10, 15, 30, 60];
    public static readonly int[] IntervalChoices = [4, 8, 12, 24, 72, 168];

    public bool Enabled { get; set; }
    public ScheduleMode Mode { get; set; } = ScheduleMode.InstallTrusted;
    /// <summary>Ile minut bez aktywności użytkownika jest wymagane przed rozpoczęciem.</summary>
    public int IdleMinutes { get; set; } = 10;
    /// <summary>Minimalny odstęp między kolejnymi uruchomieniami (bezczynność występuje wiele razy dziennie).</summary>
    public int MinIntervalHours { get; set; } = 24;
    /// <summary>Ustawienie z wcześniejszych wersji - przenoszone do <see cref="UpdatePolicies.AutoTrust"/>.</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? AllowMediumTrust { get; set; }
    /// <summary>
    /// Wyraźna zgoda użytkownika na instalację, gdy Microsoft Defender jest niedostępny (np. wyłączony przez inny antywirus).
    /// Domyślnie takie pakiety są pomijane.
    /// </summary>
    public bool AllowWithoutDefenderScan { get; set; }
    public bool CheckDrivers { get; set; } = true;
    public bool InstallDrivers { get; set; }
    /// <summary>Ustawienie z wcześniejszych wersji - przenoszone do <see cref="UpdatePolicies.Excluded"/>.</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public List<string>? Excluded { get; set; }

    /// <summary>Sprowadza wartości (np. ręcznie zmienione w settings.json) do bezpiecznych zakresów.</summary>
    public ScheduleOptions Normalize()
    {
        IdleMinutes = Math.Clamp(IdleMinutes, 1, 240);
        MinIntervalHours = Math.Clamp(MinIntervalHours, 1, 24 * 30);
        if (!Enum.IsDefined(Mode)) Mode = ScheduleMode.CheckOnly;
        return this;
    }

    /// <summary>Przenosi wykluczenia i poziom zaufania z dawnych ustawień harmonogramu do zasad; zwraca true, jeśli coś przeniesiono.</summary>
    public bool MigrateTo(UpdatePolicies policies)
    {
        if (Excluded is null && AllowMediumTrust is null) return false;
        foreach (var id in Excluded ?? [])
            if (id.Trim().Length > 0 && !policies.IsExcluded(id.Trim()))
                policies.Excluded.Add(new ExclusionRule { WingetId = id.Trim() });
        if (AllowMediumTrust == true) policies.AutoTrust = AutoTrustLevel.HighOrMedium;
        Excluded = null;
        AllowMediumTrust = null;
        policies.Normalize();
        return true;
    }
}

/// <summary>Reguły wyboru programów do instalacji bez udziału użytkownika.</summary>
public static class SilentUpdatePolicy
{
    /// <summary>Program ma aktualizację w repozytorium, nie jest wykluczony, a jego wersja nie jest wstrzymana.</summary>
    public static bool IsCandidate(Software s, UpdatePolicies p, DateTimeOffset now) => s.CanUpgrade && p.CheckRules(s, now).Allowed;

    /// <summary>
    /// Instalator musi przejść wszystkie kontrole i skanowanie Defender; bez skanowania tylko wtedy,
    /// gdy użytkownik wyraźnie na to zezwolił w ustawieniach harmonogramu.
    /// </summary>
    public static bool MayInstall(InstallerVerification v, ScheduleOptions o) =>
        v.Passed || o.AllowWithoutDefenderScan && v.PassedWithoutScan;
}

/// <summary>Wynik ostatniego cichego uruchomienia (%LOCALAPPDATA%\BezpiecznyAktualizator\schedule-state.json).</summary>
public sealed class ScheduleState
{
    public static string FilePath { get; set; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "BezpiecznyAktualizator", "schedule-state.json");

    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase, PropertyNameCaseInsensitive = true, WriteIndented = true,
    };

    public DateTimeOffset? LastRun { get; set; }
    public bool Installed { get; set; }
    public int Updates { get; set; }
    public List<string> Updated { get; set; } = [];
    public List<string> Skipped { get; set; } = [];
    public List<string> Failed { get; set; } = [];
    public int DriverUpdates { get; set; } = -1;
    public int DriversInstalled { get; set; }
    public bool Interrupted { get; set; }
    public string Error { get; set; } = "";

    /// <summary>Czy od ostatniego uruchomienia minął wymagany odstęp.</summary>
    public bool IsDue(DateTimeOffset now, int minIntervalHours) =>
        LastRun is not { } last || now - last >= TimeSpan.FromHours(minIntervalHours) || last > now;

    public static ScheduleState Load()
    {
        try
        {
            return File.Exists(FilePath) ? JsonSerializer.Deserialize<ScheduleState>(File.ReadAllText(FilePath), Json) ?? new() : new();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            return new();
        }
    }

    public void Save()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
        File.WriteAllText(FilePath, JsonSerializer.Serialize(this, Json));
    }

    public string Summary()
    {
        if (LastRun is not { } run) return L.T("Ciche sprawdzanie jeszcze się nie odbyło.");
        var text = L.F("Ostatnie ciche sprawdzanie: {0}.", run.LocalDateTime.ToString("g")) + " " +
                   (Installed
                       ? L.F("Dostępne aktualizacje: {0}, zainstalowano: {1}, pominięto: {2}, niepowodzenia: {3}.",
                             Updates, Updated.Count, Skipped.Count, Failed.Count)
                       : L.F("Dostępne aktualizacje: {0} (bez instalacji).", Updates));
        if (DriverUpdates >= 0) text += " " + L.F("Nowsze sterowniki: {0}, zainstalowano: {1}.", DriverUpdates, DriversInstalled);
        if (Interrupted) text += " " + L.T("Przerwano, ponieważ użytkownik wrócił do komputera.");
        if (Error.Length > 0) text += " " + L.F("Błąd: {0}", Error);
        return text;
    }
}

/// <summary>Czas bezczynności użytkownika w bieżącej sesji (GetLastInputInfo).</summary>
public static class IdleTime
{
    [StructLayout(LayoutKind.Sequential)]
    private struct LastInputInfo
    {
        public uint Size;
        public uint Time;
    }

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetLastInputInfo(ref LastInputInfo info);

    public static TimeSpan Current
    {
        get
        {
            var info = new LastInputInfo { Size = (uint)Marshal.SizeOf<LastInputInfo>() };
            if (!GetLastInputInfo(ref info)) return TimeSpan.Zero;
            return TimeSpan.FromMilliseconds(unchecked((uint)Environment.TickCount - info.Time));
        }
    }
}

/// <summary>Rejestracja zadania w Harmonogramie zadań Windows (schtasks.exe + definicja XML).</summary>
public static class ScheduledTask
{
    /// <summary>Nazwa zadania (osobne dla każdego użytkownika komputera, bo działa w jego sesji).</summary>
    public static string TaskName { get; } = TaskFolder + "SilentUpdate-" +
        string.Concat(Environment.UserName.Select(c => char.IsLetterOrDigit(c) || c is '-' or '_' or '.' ? c : '_'));
    public const string TaskFolder = @"\BezpiecznyAktualizator\";
    public const string RunArgument = "--scheduled";
    public const string NowArgument = "--now";

    /// <summary>
    /// Zadanie uruchamiane przy bezczynności komputera, tylko gdy użytkownik jest zalogowany (bez zapisywania hasła),
    /// z najwyższymi dostępnymi uprawnieniami - instalatory nie wyświetlają wtedy monitów UAC.
    /// </summary>
    public static string BuildXml(string executable, string userSid, ScheduleOptions options)
    {
        static string X(string value) => SecurityElement.Escape(value);
        var idle = $"PT{Math.Clamp(options.IdleMinutes, 1, 240)}M";
        return $"""
            <?xml version="1.0" encoding="UTF-16"?>
            <Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
              <RegistrationInfo>
                <Author>Bezpieczny Aktualizator</Author>
                <Description>{X(L.T("Ciche sprawdzanie i instalacja aktualizacji z zaufanych źródeł podczas bezczynności komputera."))}</Description>
                <URI>{X(TaskName)}</URI>
              </RegistrationInfo>
              <Triggers>
                <IdleTrigger>
                  <Enabled>true</Enabled>
                </IdleTrigger>
              </Triggers>
              <Principals>
                <Principal id="Author">
                  <UserId>{X(userSid)}</UserId>
                  <LogonType>InteractiveToken</LogonType>
                  <RunLevel>HighestAvailable</RunLevel>
                </Principal>
              </Principals>
              <Settings>
                <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
                <DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries>
                <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
                <AllowHardTerminate>true</AllowHardTerminate>
                <StartWhenAvailable>false</StartWhenAvailable>
                <RunOnlyIfNetworkAvailable>true</RunOnlyIfNetworkAvailable>
                <IdleSettings>
                  <Duration>{idle}</Duration>
                  <WaitTimeout>PT1H</WaitTimeout>
                  <StopOnIdleEnd>false</StopOnIdleEnd>
                  <RestartOnIdle>false</RestartOnIdle>
                </IdleSettings>
                <AllowStartOnDemand>true</AllowStartOnDemand>
                <Enabled>true</Enabled>
                <Hidden>false</Hidden>
                <RunOnlyIfIdle>false</RunOnlyIfIdle>
                <WakeToRun>false</WakeToRun>
                <ExecutionTimeLimit>PT3H</ExecutionTimeLimit>
                <Priority>7</Priority>
              </Settings>
              <Actions Context="Author">
                <Exec>
                  <Command>"{X(executable)}"</Command>
                  <Arguments>{RunArgument}</Arguments>
                </Exec>
              </Actions>
            </Task>
            """;
    }

    /// <summary>Tworzy lub zastępuje zadanie (wymaga jednorazowego potwierdzenia UAC).</summary>
    public static async Task RegisterAsync(string executable, string userSid, ScheduleOptions options)
    {
        var file = Path.Combine(Path.GetTempPath(), $"bezpieczny_aktualizator_task_{Guid.NewGuid():N}.xml");
        await File.WriteAllTextAsync(file, BuildXml(executable, userSid, options), Encoding.Unicode);
        try
        {
            await RunSchtasksElevatedAsync(["/Create", "/TN", TaskName, "/XML", file, "/F"]);
        }
        finally
        {
            try { File.Delete(file); } catch (IOException) { }
        }
    }

    public static Task UnregisterAsync() => RunSchtasksElevatedAsync(["/Delete", "/TN", TaskName, "/F"]);

    /// <summary>Sprawdza, czy zadanie istnieje (bez podnoszenia uprawnień). null = nie można ustalić.</summary>
    public static async Task<bool?> ExistsAsync()
    {
        try
        {
            var psi = new ProcessStartInfo(SchtasksPath)
            {
                UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true,
            };
            foreach (var a in new[] { "/Query", "/TN", TaskName }) psi.ArgumentList.Add(a);
            using var proc = Process.Start(psi)!;
            var output = proc.StandardOutput.ReadToEndAsync();
            var error = proc.StandardError.ReadToEndAsync();
            await proc.WaitForExitAsync();
            await Task.WhenAll(output, error);
            return proc.ExitCode == 0;
        }
        catch (Win32Exception)
        {
            return null;
        }
    }

    private static string SchtasksPath => Path.Combine(Environment.SystemDirectory, "schtasks.exe");

    private static async Task RunSchtasksElevatedAsync(IEnumerable<string> args)
    {
        var psi = new ProcessStartInfo(SchtasksPath)
        {
            UseShellExecute = true, Verb = "runas", WindowStyle = ProcessWindowStyle.Hidden,
        };
        foreach (var a in args) psi.ArgumentList.Add(a);
        Process proc;
        try
        {
            proc = Process.Start(psi) ?? throw new InvalidOperationException(L.T("Nie udało się uruchomić schtasks.exe."));
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            throw new OperationCanceledException(L.T("Anulowano monit kontroli konta użytkownika (UAC)."), ex);
        }
        using (proc)
        {
            await proc.WaitForExitAsync();
            if (proc.ExitCode != 0)
                throw new InvalidOperationException(L.F("Harmonogram zadań zwrócił kod {0}.", proc.ExitCode));
        }
    }
}
