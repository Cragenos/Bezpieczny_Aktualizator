using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using BezpiecznyAktualizator.Core.Localization;
using Microsoft.CSharp.RuntimeBinder;

namespace BezpiecznyAktualizator.Core.Updates;

public sealed class WindowsUpdateException(string message, Exception? inner = null) : Exception(message, inner);

public readonly record struct WindowsUpdateIdentity(Guid UpdateId, int Revision)
{
    public override string ToString() => $"{UpdateId:D}:{Revision.ToString(CultureInfo.InvariantCulture)}";
}

public sealed class WindowsUpdateItem
{
    public WindowsUpdateIdentity Identity { get; init; }
    public string Title { get; init; } = "";
    public string Description { get; init; } = "";
    public string SupportUrl { get; init; } = "";
    public string Severity { get; init; } = "";
    public string EulaText { get; init; } = "";
    public bool EulaAccepted { get; init; }
    public bool IsDownloaded { get; init; }
    public bool IsMandatory { get; init; }
    public long Size { get; init; }
    public DateTimeOffset? LastDeploymentChangeTime { get; init; }
    public bool IsOfflineScan { get; set; }
    public IReadOnlyList<string> KbIds { get; init; } = [];
    public IReadOnlyList<string> CveIds { get; init; } = [];
    public List<string> MsrcCveIds { get; } = [];
    public string MsrcError { get; set; } = "";
    public string CveError { get; init; } = "";

    public string KbText => string.Join(", ", KbIds.Select(KbLabel));
    public string CveText
    {
        get
        {
            var ids = CveIds.Concat(MsrcCveIds).Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.OrdinalIgnoreCase).ToList();
            return ids.Count == 0 ? L.T("Brak danych CVE") : string.Join(", ", ids);
        }
    }
    public string DownloadText => IsDownloaded ? L.T("Pobrano") : L.T("Do pobrania");
    public string SizeText => Size > 0 ? $"{Size / 1048576.0:0.0} MB" : L.T("Nieznany");
    public string CatalogUrl => MicrosoftUpdateCatalog.Search(KbIds.Count > 0 ? KbLabel(KbIds[0]) : Title);

    private static string KbLabel(string value) =>
        value.StartsWith("KB", StringComparison.OrdinalIgnoreCase) ? value : "KB" + value;
}

public sealed record WindowsUpdateSearchResult(IReadOnlyList<WindowsUpdateItem> Updates, IReadOnlyList<string> Warnings);
public enum WindowsUpdateAction { Download, Install }
public enum StandaloneUpdateStatus { Succeeded, RestartRequired, AlreadyInstalled, NotApplicable, Failed }

public static class WindowsUpdateStandalone
{
    public static StandaloneUpdateStatus ClassifyExitCode(int code) => unchecked((uint)code) switch
    {
        0 => StandaloneUpdateStatus.Succeeded,
        1641 or 3010 or 0x00240005 => StandaloneUpdateStatus.RestartRequired,
        0x00240006 => StandaloneUpdateStatus.AlreadyInstalled,
        0x80240017 => StandaloneUpdateStatus.NotApplicable,
        _ => StandaloneUpdateStatus.Failed,
    };
}

public sealed record WindowsUpdateOutcome(WindowsUpdateIdentity Identity, string Title, int ResultCode, int HResult,
                                          bool RebootRequired, string Message = "")
{
    public bool Succeeded => ResultCode == 2;
}

public sealed record WindowsUpdateOperationReport(IReadOnlyList<WindowsUpdateOutcome> Outcomes,
                                                   IReadOnlyList<string> Warnings, bool RebootRequired)
{
    public bool Succeeded => Outcomes.Count > 0 && Outcomes.All(o => o.Succeeded);
}

/// <summary>Wyszukiwanie i ręczne operacje na aktualizacjach oprogramowania przez Windows Update Agent.</summary>
public static class WindowsUpdateAgent
{
    public const string OperationArgument = "--windows-update-operation";
    public const int MaxSelection = 200;
    private const string Criteria = "IsInstalled=0 and Type='Software' and IsHidden=0";

    public static string SerializeSelection(IReadOnlyCollection<WindowsUpdateIdentity> identities)
    {
        ValidateSelection(identities);
        return string.Join(",", identities);
    }

    public static IReadOnlyList<WindowsUpdateIdentity> ParseSelection(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > MaxSelection * 48)
            throw new WindowsUpdateException(L.T("Nieprawidłowa lista aktualizacji Windows Update."));
        var result = new List<WindowsUpdateIdentity>();
        foreach (var item in value.Split(','))
        {
            var parts = item.Split(':');
            if (parts.Length != 2 || !Guid.TryParseExact(parts[0], "D", out var id) ||
                !int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var revision))
                throw new WindowsUpdateException(L.T("Nieprawidłowy identyfikator lub wersja aktualizacji Windows Update."));
            result.Add(new WindowsUpdateIdentity(id, revision));
        }
        ValidateSelection(result);
        return result;
    }

    private static void ValidateSelection(IReadOnlyCollection<WindowsUpdateIdentity> identities)
    {
        if (identities.Count is 0 or > MaxSelection || identities.Any(i => i.UpdateId == Guid.Empty || i.Revision < 0) ||
            identities.Distinct().Count() != identities.Count)
            throw new WindowsUpdateException(L.T("Nieprawidłowa lista aktualizacji Windows Update."));
    }

    private static dynamic SearchRaw(dynamic session)
    {
        var searcher = session.CreateUpdateSearcher();
        searcher.Online = true;
        var result = searcher.Search(Criteria);
        var code = (int)result.ResultCode;
        if (code is not (2 or 3))
            throw new WindowsUpdateException(L.F("Windows Update nie zakończył wyszukiwania (kod {0}).", code));
        return result;
    }

    private static List<string> SearchWarnings(dynamic result)
    {
        var warnings = new List<string>();
        if ((int)result.ResultCode == 3)
            warnings.Add(L.T("Wyszukiwanie Windows Update zakończyło się z ostrzeżeniami; lista może być niepełna."));
        var items = result.Warnings;
        for (var i = 0; i < (int)items.Count; i++)
        {
            var warning = items.Item[i];
            warnings.Add($"{WindowsUpdateInterop.Text((object?)warning.Message)} (0x{unchecked((uint)(int)warning.HResult):X8})");
        }
        return warnings;
    }

    private static List<string> Strings(dynamic collection)
    {
        var result = new List<string>();
        for (var i = 0; i < (int)collection.Count; i++)
        {
            var value = WindowsUpdateInterop.Text((object?)collection.Item[i]);
            if (value.Length > 0) result.Add(value);
        }
        return result;
    }

    internal static WindowsUpdateItem ToItem(dynamic update)
    {
        var id = WindowsUpdateInterop.Text((object?)update.Identity.UpdateID);
        if (!Guid.TryParseExact(id, "D", out var guid) || guid == Guid.Empty)
            throw new WindowsUpdateException(L.F("Windows Update zwrócił nieprawidłowy identyfikator: {0}", id));
        var revision = (int)update.Identity.RevisionNumber;
        if (revision < 0) throw new WindowsUpdateException(L.T("Windows Update zwrócił nieprawidłową wersję aktualizacji."));

        var cves = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var errors = new List<string>();
        var visited = 0;
        void ReadCves(object value, int depth)
        {
            if (++visited > 2000 || depth > 8)
            {
                if (errors.Count == 0) errors.Add(L.T("Lista składników aktualizacji jest zbyt złożona."));
                return;
            }
            dynamic current = value;
            try
            {
                foreach (var cve in Strings((object)current.CveIDs)) cves.Add(cve);
            }
            catch (Exception ex) when (ex is COMException or RuntimeBinderException)
            {
                errors.Add(ex.Message);
            }
            var bundled = current.BundledUpdates;
            for (var i = 0; i < (int)bundled.Count; i++) ReadCves((object)bundled.Item[i], depth + 1);
        }
        ReadCves((object)update, 0);

        return new WindowsUpdateItem
        {
            Identity = new WindowsUpdateIdentity(guid, revision),
            Title = WindowsUpdateInterop.Text((object?)update.Title),
            Description = WindowsUpdateInterop.Text((object?)update.Description),
            SupportUrl = WindowsUpdateInterop.Text((object?)update.SupportUrl),
            Severity = WindowsUpdateInterop.Text((object?)update.MsrcSeverity),
            EulaText = WindowsUpdateInterop.Text((object?)update.EulaText),
            EulaAccepted = (bool)update.EulaAccepted,
            IsDownloaded = (bool)update.IsDownloaded,
            IsMandatory = (bool)update.IsMandatory,
            Size = Convert.ToInt64((object)update.MaxDownloadSize, CultureInfo.InvariantCulture),
            LastDeploymentChangeTime = DeploymentChangeTime(update),
            KbIds = Strings((object)update.KBArticleIDs).Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
            CveIds = cves.Order(StringComparer.OrdinalIgnoreCase).ToList(),
            CveError = string.Join("; ", errors.Distinct(StringComparer.Ordinal)),
        };
    }

    private static DateTimeOffset? DeploymentChangeTime(dynamic update)
    {
        try
        {
            var value = (DateTime)update.LastDeploymentChangeTime;
            if (value == DateTime.MinValue) return null;
            return new DateTimeOffset(DateTime.SpecifyKind(value, DateTimeKind.Utc));
        }
        catch (Exception ex) when (ex is COMException or RuntimeBinderException or InvalidCastException)
        {
            return null;
        }
    }

    public static WindowsUpdateSearchResult Search()
    {
        try
        {
            var result = SearchRaw((object)WindowsUpdateInterop.CreateSession());
            var updates = result.Updates;
            var list = new List<WindowsUpdateItem>();
            for (var i = 0; i < (int)updates.Count; i++) list.Add(ToItem((object)updates.Item[i]));
            return new WindowsUpdateSearchResult(list, SearchWarnings((object)result));
        }
        catch (COMException ex)
        {
            throw new WindowsUpdateException(L.F("Windows Update zwrócił błąd 0x{0:X8}: {1}", ex.HResult, ex.Message), ex);
        }
    }

    public static WindowsUpdateSearchResult SearchOffline(string cabinetPath)
    {
        var path = Path.GetFullPath(cabinetPath);
        if (!Path.GetExtension(path).Equals(".cab", StringComparison.OrdinalIgnoreCase) ||
            !File.Exists(path) || (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new WindowsUpdateException(L.T("Wybierz istniejący, lokalny plik katalogu skanowania Windows Update (.cab)."));
        try
        {
            dynamic manager = WindowsUpdateInterop.CreateServiceManager();
            dynamic session = WindowsUpdateInterop.CreateSession();
            return SearchOfflineCore(path, (object)manager, (object)session);
        }
        catch (COMException ex)
        {
            throw new WindowsUpdateException(L.F("Skanowanie offline Windows Update nie powiodło się (0x{0:X8}): {1}", ex.HResult, ex.Message), ex);
        }
    }

        internal static WindowsUpdateSearchResult SearchOfflineCore(string cabinetPath, object managerObject, object sessionObject)
        {
            dynamic manager = managerObject;
            dynamic session = sessionObject;
            dynamic service = manager.AddScanPackageService("Bezpieczny Aktualizator " + Guid.NewGuid().ToString("N"),
                cabinetPath, 0);
            var warnings = new List<string>();
            WindowsUpdateSearchResult? result = null;
            Exception? failure = null;
            try
            {
                dynamic searcher = session.CreateUpdateSearcher();
                searcher.Online = false;
                searcher.ServerSelection = 3;
                searcher.ServiceID = WindowsUpdateInterop.Text((object?)service.ServiceID);
                dynamic searchResult = searcher.Search("IsInstalled=0");
                var resultCode = (int)searchResult.ResultCode;
                if (resultCode is not (2 or 3))
                    throw new WindowsUpdateException(L.F("Skanowanie offline Windows Update nie zakończyło się (kod {0}).", resultCode));
                var updates = searchResult.Updates;
                var items = new List<WindowsUpdateItem>();
                for (var i = 0; i < (int)updates.Count; i++)
                {
                    var item = ToItem((object)updates.Item[i]);
                    item.IsOfflineScan = true;
                    items.Add(item);
                }
                warnings.AddRange(SearchWarnings((object)searchResult));
                result = new WindowsUpdateSearchResult(items, warnings);
            }
            catch (COMException ex)
            {
                failure = new WindowsUpdateException(L.F("Skanowanie offline Windows Update zwróciło błąd 0x{0:X8}: {1}", ex.HResult, ex.Message), ex);
            }
            finally
            {
                try { manager.RemoveService(WindowsUpdateInterop.Text((object?)service.ServiceID)); }
                catch (COMException ex)
                {
                    if (failure is null)
                        warnings.Add(L.F("Nie udało się usunąć tymczasowej usługi skanowania Windows Update (0x{0:X8}): {1}", ex.HResult, ex.Message));
                }
            }
            if (failure is not null) throw failure;
            return result ?? throw new InvalidOperationException("Offline Windows Update scan returned no result.");
    }

    public static WindowsUpdateOperationReport Execute(WindowsUpdateAction action,
                                                       IReadOnlyList<WindowsUpdateIdentity> identities)
    {
        ValidateOperation(action, identities);
        try
        {
            return ExecuteCore(action, identities, (object)WindowsUpdateInterop.CreateSession(),
                () => (object)WindowsUpdateInterop.CreateCom("Microsoft.Update.UpdateColl"));
        }
        catch (COMException ex)
        {
            throw new WindowsUpdateException(L.F("Windows Update zwrócił błąd 0x{0:X8}: {1}", ex.HResult, ex.Message), ex);
        }
    }

    internal static WindowsUpdateOperationReport ExecuteCore(WindowsUpdateAction action,
        IReadOnlyList<WindowsUpdateIdentity> identities, object sessionObject, Func<object> createCollection)
    {
        ValidateOperation(action, identities);
        dynamic session = sessionObject;
        var search = SearchRaw((object)session);
        var warnings = SearchWarnings((object)search);
        var available = new Dictionary<WindowsUpdateIdentity, object>();
        var updates = search.Updates;
        for (var i = 0; i < (int)updates.Count; i++)
        {
            var update = updates.Item[i];
            if (Guid.TryParseExact(WindowsUpdateInterop.Text((object?)update.Identity.UpdateID), "D", out var id))
                available[new WindowsUpdateIdentity(id, (int)update.Identity.RevisionNumber)] = (object)update;
        }

        var outcomes = new WindowsUpdateOutcome?[identities.Count];
        dynamic collection = createCollection();
        var queued = new List<(int Index, object Update)>();
        for (var i = 0; i < identities.Count; i++)
        {
            var identity = identities[i];
            if (!available.TryGetValue(identity, out var value))
            {
                outcomes[i] = new(identity, identity.ToString(), 4, 0, false,
                    L.T("Wybrana wersja aktualizacji nie jest już dostępna dla tego komputera."));
                continue;
            }
            dynamic update = value;
            var title = WindowsUpdateInterop.Text((object?)update.Title);
            var downloaded = (bool)update.IsDownloaded;
            if (action == WindowsUpdateAction.Download && downloaded)
            {
                outcomes[i] = new(identity, title, 2, 0, false, L.T("Aktualizacja była już pobrana."));
                continue;
            }
            if (action == WindowsUpdateAction.Install && !downloaded)
            {
                outcomes[i] = new(identity, title, 4, 0, false, L.T("Najpierw pobierz tę aktualizację."));
                continue;
            }
            if (!(bool)update.EulaAccepted)
            {
                if (string.IsNullOrWhiteSpace(WindowsUpdateInterop.Text((object?)update.EulaText)))
                {
                    outcomes[i] = new(identity, title, 4, 0, false,
                        L.T("Nie można odczytać wymaganych warunków licencji. Aktualizacja nie zostanie wykonana."));
                    continue;
                }
                update.AcceptEula();
            }
            collection.Add(update);
            queued.Add((i, value));
        }

        var reboot = false;
        if (queued.Count > 0)
        {
            dynamic operation;
            if (action == WindowsUpdateAction.Download)
            {
                var downloader = session.CreateUpdateDownloader();
                downloader.Updates = collection;
                operation = downloader.Download();
            }
            else
            {
                var installer = session.CreateUpdateInstaller();
                installer.Updates = collection;
                operation = installer.Install();
                reboot = (bool)operation.RebootRequired;
            }
            for (var i = 0; i < queued.Count; i++)
            {
                var (index, value) = queued[i];
                dynamic update = value;
                var itemResult = operation.GetUpdateResult(i);
                var code = (int)itemResult.ResultCode;
                var itemReboot = action == WindowsUpdateAction.Install && (bool)itemResult.RebootRequired;
                var message = "";
                if (action == WindowsUpdateAction.Download && !(bool)update.IsDownloaded)
                {
                    if (code == 2) code = 4;
                    message = L.T("Windows Update nie potwierdził pobrania pakietu.");
                }
                outcomes[index] = new(identities[index], WindowsUpdateInterop.Text((object?)update.Title),
                    code, (int)itemResult.HResult, itemReboot, message);
                reboot |= itemReboot;
            }
        }
        return new WindowsUpdateOperationReport(
            outcomes.Select(o => o ?? throw new InvalidOperationException("Missing Windows Update result.")).ToList(),
            warnings, reboot);
    }

    private static void ValidateOperation(WindowsUpdateAction action, IReadOnlyCollection<WindowsUpdateIdentity> identities)
    {
        ValidateSelection(identities);
        if (action is not (WindowsUpdateAction.Download or WindowsUpdateAction.Install))
            throw new WindowsUpdateException(L.T("Nieprawidłowa operacja Windows Update."));
    }
}
