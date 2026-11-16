using System.Runtime.InteropServices;
using BezpiecznyAktualizator.Core.Logging;
using BezpiecznyAktualizator.Core.Localization;

namespace BezpiecznyAktualizator.Core.Updates;

internal static class WindowsUpdateInterop
{
    [ComVisible(true)]
    [Guid("88aee058-d4b0-4725-a2f1-814a67ae964c")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface ISearchCompletedCallback
    {
        void Invoke(
            [In, MarshalAs(UnmanagedType.Interface)] object searchJob,
            [In, MarshalAs(UnmanagedType.Interface)] object callbackArgs);
    }

    [ComVisible(true)]
    [ClassInterface(ClassInterfaceType.None)]
    private sealed class SearchCompletedCallback(Action completed) : ISearchCompletedCallback
    {
        public void Invoke(object searchJob, object callbackArgs) => completed();
    }

    internal static dynamic CreateCom(string progId)
    {
        var type = Type.GetTypeFromProgID(progId) ??
                   throw new COMException(L.F("Brak komponentu COM {0}.", progId));
        return Activator.CreateInstance(type) ??
               throw new COMException(L.F("Nie można utworzyć {0}.", progId));
    }

    internal static dynamic CreateSession()
    {
        var session = CreateCom("Microsoft.Update.Session");
        session.ClientApplicationID = "BezpiecznyAktualizator";
        return session;
    }

    internal static async Task<object> SearchAsync(object searcherObject, string criteria, CancellationToken ct)
    {
        dynamic searcher = searcherObject;
        object? job = null;
        SearchCompletedCallback? callback = null;
        try
        {
            return await SearchAsyncCore(
                completed =>
                {
                    callback = new SearchCompletedCallback(completed);
                    job = searcher.BeginSearch(criteria, callback, Type.Missing);
                },
                () => ((dynamic)job!).RequestAbort(),
                () => (object)searcher.EndSearch(job!),
                () => ((dynamic)job!).CleanUp(),
                ct).ConfigureAwait(false);
        }
        finally
        {
            GC.KeepAlive(callback);
        }
    }

    internal static async Task<T> SearchAsyncCore<T>(
        Action<Action> beginSearch, Action requestAbort, Func<T> endSearch, Action cleanup, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        beginSearch(() => completion.TrySetResult());
        using var registration = ct.Register(() =>
        {
            if (completion.Task.IsCompleted) return;
            try
            {
                requestAbort();
            }
            catch (COMException ex)
            {
                Syslog.Warning(LogEvent.WindowsUpdate, L.F("Windows Update zwrócił błąd 0x{0:X8}: {1}", ex.HResult, ex.Message));
            }
        });

        await completion.Task.ConfigureAwait(false);
        try
        {
            var result = endSearch();
            ct.ThrowIfCancellationRequested();
            return result;
        }
        catch (COMException) when (ct.IsCancellationRequested)
        {
            throw new OperationCanceledException(ct);
        }
        finally
        {
            try
            {
                cleanup();
            }
            catch (COMException ex) when (ct.IsCancellationRequested)
            {
                Syslog.Warning(LogEvent.WindowsUpdate, L.F("Windows Update zwrócił błąd 0x{0:X8}: {1}", ex.HResult, ex.Message));
            }
        }
    }

    internal static dynamic CreateServiceManager() => CreateCom("Microsoft.Update.ServiceManager");

    internal static string Text(object? value) => value?.ToString() ?? "";
}

public static class MicrosoftUpdateCatalog
{
    public const string SearchUrl = "https://www.catalog.update.microsoft.com/Search.aspx?q=";

    public static string Search(string query) => SearchUrl + Uri.EscapeDataString(query);
}
