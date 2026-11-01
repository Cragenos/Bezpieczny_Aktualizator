using System.ComponentModel;
using System.Diagnostics;
using System.Management;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using BezpiecznyAktualizator.Core.Localization;

namespace BezpiecznyAktualizator.Core.Drivers;

public sealed record DriverInstallResult(string UpdateId, string Title, int ResultCode, long HResult,
                                         bool RebootRequired, string Error = "")
{
    public static readonly IReadOnlyDictionary<int, string> Codes = new Dictionary<int, string>
    {
        [0] = L.N("Nie rozpoczęto"), [1] = L.N("W toku"), [2] = L.N("Zainstalowano"),
        [3] = L.N("Zainstalowano z błędami"), [4] = L.N("Błąd"), [5] = L.N("Przerwano"),
    };

    public bool Succeeded => ResultCode is 2 or 3;
    public string ResultText => Codes.TryGetValue(ResultCode, out var text) ? L.T(text) : L.F("kod {0}", ResultCode);
}

/// <summary>
/// Wyszukiwanie i instalacja sterowników przez Windows Update Agent API (COM: Microsoft.Update.Session).
/// Windows Update dostarcza wyłącznie sterowniki podpisane przez Microsoft (WHQL / attestation),
/// a agent weryfikuje podpis i skrót pobranych pakietów przed instalacją.
/// </summary>
public static partial class WindowsUpdateDrivers
{
    public const string InstallArgument = "--install-drivers";
    private const string Criteria = "IsInstalled=0 and Type='Driver' and IsHidden=0";
    private const string ClientId = "BezpiecznyAktualizator";

    private static dynamic CreateCom(string progId)
    {
        var type = Type.GetTypeFromProgID(progId) ?? throw new DriverException(L.F("Brak komponentu COM {0}.", progId));
        return Activator.CreateInstance(type) ?? throw new DriverException(L.F("Nie można utworzyć {0}.", progId));
    }

    private static dynamic CreateSession()
    {
        var session = CreateCom("Microsoft.Update.Session");
        session.ClientApplicationID = ClientId;
        return session;
    }

    private static List<dynamic> SearchRaw(dynamic session)
    {
        var searcher = session.CreateUpdateSearcher();
        searcher.Online = true;
        var result = searcher.Search(Criteria);
        var updates = result.Updates;
        var list = new List<dynamic>();
        int count = updates.Count;
        for (var i = 0; i < count; i++) list.Add(updates.Item[i]);
        return list;
    }

    private static string S(object? value) => value?.ToString() ?? "";

    private static DriverUpdate ToModel(dynamic u)
    {
        string date = "";
        object? verDate = u.DriverVerDate;
        if (verDate is DateTime dt) date = dt.ToString("yyyy-MM-dd");
        return new DriverUpdate
        {
            UpdateId = S(u.Identity.UpdateID), Title = S(u.Title), Model = S(u.DriverModel),
            Manufacturer = S(u.DriverManufacturer), Provider = S(u.DriverProvider), DriverClass = S(u.DriverClass),
            HardwareId = S(u.DriverHardwareID), Date = date, Size = Convert.ToInt64((object)u.MaxDownloadSize),
            EulaAccepted = (bool)u.EulaAccepted, SupportUrl = S(u.SupportUrl), Description = S(u.Description),
        };
    }

    /// <summary>Wyszukuje sterowniki oferowane dla tego komputera (może potrwać kilka minut, nie wymaga administratora).</summary>
    public static List<DriverUpdate> Search()
    {
        try
        {
            List<dynamic> raw = SearchRaw((object)CreateSession());
            return raw.Select(u => (DriverUpdate)ToModel(u)).Where(u => u.UpdateId.Length > 0).ToList();
        }
        catch (COMException ex)
        {
            throw new DriverException(L.F("Windows Update zwrócił błąd 0x{0:X8}: {1}", ex.HResult, ex.Message), ex);
        }
    }

    public static bool IsValidUpdateId(string id) => UpdateIdPattern().IsMatch(id);

    // --------------------------------------------------------------- instalacja (proces nieuprzywilejowany)
    /// <summary>
    /// Uruchamia wskazany plik wykonywalny z argumentem <see cref="InstallArgument"/> z podniesionymi
    /// uprawnieniami (UAC), śledzi dziennik postępu i zwraca wyniki instalacji.
    /// </summary>
    public static async Task<List<DriverInstallResult>> InstallElevatedAsync(
        string executable, IReadOnlyCollection<string> updateIds, bool restorePoint, Action<string> onLog,
        CancellationToken ct = default)
    {
        if (updateIds.Count == 0) return [];
        foreach (var id in updateIds)
            if (!IsValidUpdateId(id)) throw new DriverException(L.F("Nieprawidłowy identyfikator aktualizacji: {0}", id));

        var jobDir = Directory.CreateTempSubdirectory("bezpieczny_aktualizator_").FullName;
        try
        {
            var job = new InstallJob(jobDir);
            await File.WriteAllLinesAsync(job.IdsFile, updateIds, ct);
            await File.WriteAllTextAsync(job.OptionsFile, restorePoint ? "restore-point" : "", ct);
            await File.WriteAllTextAsync(job.LogFile, "", ct);

            var psi = new ProcessStartInfo(executable) { UseShellExecute = true, Verb = "runas", WindowStyle = ProcessWindowStyle.Hidden };
            psi.ArgumentList.Add(InstallArgument);
            psi.ArgumentList.Add(jobDir);
            Process proc;
            try
            {
                proc = Process.Start(psi) ?? throw new DriverException(L.T("Nie udało się uruchomić instalatora."));
            }
            catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
            {
                throw new DriverException(L.T("Anulowano monit kontroli konta użytkownika (UAC)."), ex);
            }

            using (proc)
            {
                long position = 0;
                void Pump(bool final)
                {
                    byte[] chunk;
                    try
                    {
                        using var fs = new FileStream(job.LogFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        fs.Seek(position, SeekOrigin.Begin);
                        using var ms = new MemoryStream();
                        fs.CopyTo(ms);
                        chunk = ms.ToArray();
                    }
                    catch (IOException) { return; }
                    var end = final ? chunk.Length : Array.LastIndexOf(chunk, (byte)'\n') + 1;
                    if (end <= 0) return;
                    position += end;
                    foreach (var line in Encoding.UTF8.GetString(chunk, 0, end).Split('\n'))
                        if (line.Trim().Length > 0) onLog(line.Trim());
                }

                while (!proc.HasExited)
                {
                    Pump(false);
                    await Task.Delay(500, ct);
                }
                Pump(true);
                if (!File.Exists(job.ResultFile))
                    throw new DriverException(L.F("Instalacja nie została wykonana (kod procesu {0}).", proc.ExitCode));
                return JsonSerializer.Deserialize<List<DriverInstallResult>>(await File.ReadAllTextAsync(job.ResultFile, ct)) ?? [];
            }
        }
        finally
        {
            try { Directory.Delete(jobDir, true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
        }
    }

    // ------------------------------------------------------------ instalacja (proces z uprawnieniami admina)
    /// <summary>Instalacja w bieżącym procesie, który ma już uprawnienia administratora (np. zadanie harmonogramu).</summary>
    public static List<DriverInstallResult> InstallInProcess(IReadOnlyCollection<string> updateIds, bool restorePoint,
                                                             Action<string> onLog)
    {
        var ids = updateIds.Where(IsValidUpdateId).ToList();
        if (ids.Count == 0) return [];
        var job = new InstallJob(Directory.CreateTempSubdirectory("bezpieczny_aktualizator_").FullName);
        try
        {
            File.WriteAllLines(job.IdsFile, ids);
            File.WriteAllText(job.OptionsFile, restorePoint ? "restore-point" : "");
            RunInstallJob(job.Dir);
            if (File.Exists(job.LogFile))
                foreach (var line in File.ReadAllLines(job.LogFile, Encoding.UTF8).Where(l => l.Trim().Length > 0))
                    onLog(line.Trim());
            return File.Exists(job.ResultFile)
                ? JsonSerializer.Deserialize<List<DriverInstallResult>>(File.ReadAllText(job.ResultFile)) ?? []
                : [];
        }
        finally
        {
            try { Directory.Delete(job.Dir, true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
        }
    }

    private sealed record InstallJob(string Dir)
    {
        public string IdsFile => Path.Combine(Dir, "ids.txt");
        public string OptionsFile => Path.Combine(Dir, "options.txt");
        public string LogFile => Path.Combine(Dir, "install.log");
        public string ResultFile => Path.Combine(Dir, "result.json");
    }

    /// <summary>Wykonywane w procesie z podniesionymi uprawnieniami. Zwraca kod wyjścia procesu.</summary>
    public static int RunInstallJob(string jobDir)
    {
        var job = new InstallJob(Path.GetFullPath(jobDir));
        if (!File.Exists(job.IdsFile)) return 2;
        void Log(string message) => File.AppendAllText(job.LogFile, message + Environment.NewLine, Encoding.UTF8);

        var results = new List<DriverInstallResult>();
        try
        {
            // Identyfikatory są ponownie walidowane - plik zadania leży w katalogu tymczasowym użytkownika.
            var ids = File.ReadAllLines(job.IdsFile).Select(l => l.Trim()).Where(IsValidUpdateId)
                          .ToHashSet(StringComparer.OrdinalIgnoreCase);
            if (File.Exists(job.OptionsFile) && File.ReadAllText(job.OptionsFile).Contains("restore-point"))
                CreateRestorePoint(Log);

            var session = CreateSession();
            Log(L.T("Wyszukiwanie wybranych sterowników w Windows Update..."));
            var coll = CreateCom("Microsoft.Update.UpdateColl");
            foreach (var u in SearchRaw(session))
            {
                if (!ids.Contains(S(u.Identity.UpdateID))) continue;
                if (!(bool)u.EulaAccepted) u.AcceptEula();
                coll.Add(u);
                Log(L.F("Wybrano: {0}", S(u.Title)));
            }
            if ((int)coll.Count == 0) throw new DriverException(L.T("Wybrane sterowniki nie są już dostępne w Windows Update."));

            Log(L.T("Pobieranie (Windows Update weryfikuje podpis i skrót pakietów)..."));
            var downloader = session.CreateUpdateDownloader();
            downloader.Updates = coll;
            var dl = downloader.Download();
            Log(L.F("Pobieranie zakończone, kod: {0}", (int)dl.ResultCode));

            var toInstall = CreateCom("Microsoft.Update.UpdateColl");
            for (var i = 0; i < (int)coll.Count; i++)
            {
                var u = coll.Item[i];
                if ((bool)u.IsDownloaded)
                {
                    toInstall.Add(u);
                }
                else
                {
                    results.Add(new DriverInstallResult(S(u.Identity.UpdateID), S(u.Title), 4,
                        (long)(int)dl.GetUpdateResult(i).HResult, false, L.T("Nie pobrano pakietu.")));
                    Log(L.F("Nie pobrano: {0}", S(u.Title)));
                }
            }
            if ((int)toInstall.Count > 0)
            {
                Log(L.T("Instalowanie..."));
                var installer = session.CreateUpdateInstaller();
                installer.Updates = toInstall;
                var ir = installer.Install();
                for (var i = 0; i < (int)toInstall.Count; i++)
                {
                    var u = toInstall.Item[i];
                    var r = ir.GetUpdateResult(i);
                    results.Add(new DriverInstallResult(S(u.Identity.UpdateID), S(u.Title), (int)r.ResultCode,
                        (long)(int)r.HResult, (bool)r.RebootRequired));
                    Log($"{S(u.Title)}: {L.T(DriverInstallResult.Codes.GetValueOrDefault((int)r.ResultCode, ""))}");
                }
            }
        }
        catch (Exception ex)
        {
            Log(L.F("BŁĄD: {0}", ex.Message));
            results.Add(new DriverInstallResult("", L.T("Błąd"), 4, ex.HResult, false, ex.Message));
        }
        File.WriteAllText(job.ResultFile, JsonSerializer.Serialize(results), Encoding.UTF8);
        return 0;
    }

    private static void CreateRestorePoint(Action<string> log)
    {
        log(L.T("Tworzenie punktu przywracania systemu..."));
        try
        {
            using var cls = new ManagementClass(new ManagementPath(@"\\.\root\default:SystemRestore"));
            using var input = cls.GetMethodParameters("CreateRestorePoint");
            input["Description"] = "Bezpieczny Aktualizator - sterowniki";
            input["RestorePointType"] = 12u; // MODIFY_SETTINGS
            input["EventType"] = 100u;       // BEGIN_SYSTEM_CHANGE
            using var output = cls.InvokeMethod("CreateRestorePoint", input, null);
            var code = Convert.ToUInt32(output?["ReturnValue"] ?? 0u);
            log(code == 0 ? L.T("Punkt przywracania utworzony.")
                          : L.F("Ostrzeżenie: nie utworzono punktu przywracania (kod {0}). Sprawdź, czy ochrona systemu jest włączona.", code));
        }
        catch (Exception ex) when (ex is ManagementException or COMException or UnauthorizedAccessException)
        {
            log(L.F("Ostrzeżenie: nie utworzono punktu przywracania: {0}", ex.Message));
        }
    }

    [GeneratedRegex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")]
    private static partial Regex UpdateIdPattern();
}
