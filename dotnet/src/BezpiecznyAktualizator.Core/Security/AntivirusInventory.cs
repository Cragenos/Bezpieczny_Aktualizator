using System.Reflection;
using System.Runtime.InteropServices;
using BezpiecznyAktualizator.Core.Localization;

namespace BezpiecznyAktualizator.Core.Security;

public enum AntivirusProtectionState { Unknown, On, Off, Snoozed, Expired }
public enum AntivirusSignatureStatus { Unknown, OutOfDate, UpToDate }

public sealed record AntivirusProduct(string Name, AntivirusProtectionState Protection, AntivirusSignatureStatus Signatures);

public sealed class AntivirusInventoryException(string message, Exception? inner = null) : Exception(message, inner);

/// <summary>Odczytuje programy antywirusowe zgłoszone do Centrum zabezpieczeń Windows.</summary>
public static class AntivirusInventory
{
    private const uint AntivirusProvider = 0x4;
    private static readonly Guid ProductListClass = new("17072F7B-9ABE-4A74-A261-1EB76B55107A");

    [ComImport, Guid("722A338C-6E8E-4E72-AC27-1417FB0C81C2"), InterfaceType(ComInterfaceType.InterfaceIsDual)]
    [Obfuscation(Exclude = true)]
    private interface IWscProductList
    {
        [PreserveSig] int Initialize(uint provider);
        [PreserveSig] int GetCount(out int count);
        [PreserveSig] int GetItem(uint index, [MarshalAs(UnmanagedType.Interface)] out IWscProduct? product);
    }

    [ComImport, Guid("8C38232E-3A45-4A27-92B0-1A16A975F669"), InterfaceType(ComInterfaceType.InterfaceIsDual)]
    [Obfuscation(Exclude = true)]
    private interface IWscProduct
    {
        [PreserveSig] int GetName([MarshalAs(UnmanagedType.BStr)] out string? name);
        [PreserveSig] int GetState(out int state);
        [PreserveSig] int GetSignatureStatus(out int status);
    }

    [DllImport("wscapi.dll", ExactSpelling = true)]
    private static extern int WscGetSecurityProviderHealth(uint providers, out int health);

    public static IReadOnlyList<AntivirusProduct> GetRegisteredProducts()
    {
        if (!OperatingSystem.IsWindowsVersionAtLeast(6, 2))
            throw new AntivirusInventoryException(L.T("Wykrywanie antywirusów wymaga systemu Windows 8 lub nowszego."));

        object? instance = null;
        try
        {
            EnsureServiceAvailable(WscGetSecurityProviderHealth(AntivirusProvider, out _));
            var type = Type.GetTypeFromCLSID(ProductListClass, throwOnError: true)
                       ?? throw new AntivirusInventoryException(L.T("Zabezpieczenia Windows zwróciły nieprawidłowe dane o antywirusach."));
            instance = Activator.CreateInstance(type);
            if (instance is not IWscProductList list)
                throw new AntivirusInventoryException(L.T("Zabezpieczenia Windows zwróciły nieprawidłowe dane o antywirusach."));
            EnsureSuccess(list.Initialize(AntivirusProvider));
            EnsureSuccess(list.GetCount(out var count));
            if (count < 0)
                throw new AntivirusInventoryException(L.T("Zabezpieczenia Windows zwróciły nieprawidłowe dane o antywirusach."));

            var products = new List<AntivirusProduct>();
            for (var i = 0; i < count; i++)
            {
                IWscProduct? product = null;
                try
                {
                    EnsureSuccess(list.GetItem((uint)i, out product));
                    if (product is null)
                        throw new AntivirusInventoryException(L.T("Zabezpieczenia Windows zwróciły nieprawidłowe dane o antywirusach."));
                    EnsureSuccess(product.GetName(out var name));
                    EnsureSuccess(product.GetState(out var state));
                    EnsureSuccess(product.GetSignatureStatus(out var signatures));
                    if (string.IsNullOrWhiteSpace(name))
                        throw new AntivirusInventoryException(L.T("Zabezpieczenia Windows zwróciły nieprawidłowe dane o antywirusach."));
                    products.Add(new AntivirusProduct(name.Trim(), MapProtectionState(state), MapSignatureStatus(signatures)));
                }
                finally
                {
                    if (product is not null && Marshal.IsComObject(product)) Marshal.ReleaseComObject(product);
                }
            }
            return products;
        }
        catch (Exception ex) when (ex is COMException or InvalidComObjectException or InvalidCastException or
                                       TypeLoadException or MissingMethodException or TargetInvocationException or
                                       DllNotFoundException or EntryPointNotFoundException or UnauthorizedAccessException)
        {
            throw new AntivirusInventoryException(L.F("Nie można odczytać antywirusów z Zabezpieczeń Windows: {0}", ex.Message), ex);
        }
        finally
        {
            if (instance is not null && Marshal.IsComObject(instance)) Marshal.ReleaseComObject(instance);
        }
    }

    internal static void EnsureServiceAvailable(int result)
    {
        if (result == 1)
            throw new AntivirusInventoryException(L.T("Usługa Centrum zabezpieczeń Windows nie działa."));
        EnsureSuccess(result);
    }

    private static void EnsureSuccess(int result)
    {
        if (result != 0)
            throw new COMException(L.F("Centrum zabezpieczeń Windows zwróciło kod 0x{0:X8}.", unchecked((uint)result)), result);
    }

    internal static AntivirusProtectionState MapProtectionState(int state) => state switch
    {
        0 => AntivirusProtectionState.On,
        1 => AntivirusProtectionState.Off,
        2 => AntivirusProtectionState.Snoozed,
        3 => AntivirusProtectionState.Expired,
        _ => AntivirusProtectionState.Unknown,
    };

    internal static AntivirusSignatureStatus MapSignatureStatus(int status) => status switch
    {
        0 => AntivirusSignatureStatus.OutOfDate,
        1 => AntivirusSignatureStatus.UpToDate,
        _ => AntivirusSignatureStatus.Unknown,
    };

    public static LocText Describe(IReadOnlyList<AntivirusProduct> products)
    {
        var description = products.Count == 0
            ? L.Txt("Zabezpieczenia Windows nie zgłaszają antywirusów; niezarejestrowane programy mogą nie być widoczne.")
            : L.Txt("Programy antywirusowe zgłoszone przez Zabezpieczenia Windows:");
        foreach (var product in products)
        {
            var protection = product.Protection switch
            {
                AntivirusProtectionState.On => L.Txt("włączona"),
                AntivirusProtectionState.Off => L.Txt("wyłączona"),
                AntivirusProtectionState.Snoozed => L.Txt("tymczasowo wstrzymana"),
                AntivirusProtectionState.Expired => L.Txt("wygasła"),
                _ => L.Txt("stan nieznany"),
            };
            var signatures = product.Signatures switch
            {
                AntivirusSignatureStatus.OutOfDate => L.Txt("Nieaktualne"),
                AntivirusSignatureStatus.UpToDate => L.Txt("Aktualne"),
                _ => L.Txt("nieznane"),
            };
            description += LocText.Raw("\n  • ") + L.Txt("{0}: ochrona {1}, sygnatury {2}", product.Name, protection, signatures);
        }
        return description + LocText.Raw("\n\n") + L.Txt("Wykrycie programu nie oznacza, że instalator został przeskanowany.");
    }
}
