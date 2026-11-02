using System.Runtime.InteropServices;
using BezpiecznyAktualizator.Core.Localization;

namespace BezpiecznyAktualizator.Core.Updates;

internal static class WindowsUpdateInterop
{
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

    internal static dynamic CreateServiceManager() => CreateCom("Microsoft.Update.ServiceManager");

    internal static string Text(object? value) => value?.ToString() ?? "";
}

public static class MicrosoftUpdateCatalog
{
    public const string SearchUrl = "https://www.catalog.update.microsoft.com/Search.aspx?q=";

    public static string Search(string query) => SearchUrl + Uri.EscapeDataString(query);
}
