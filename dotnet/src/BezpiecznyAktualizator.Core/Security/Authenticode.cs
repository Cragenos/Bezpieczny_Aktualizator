using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using BezpiecznyAktualizator.Core.Localization;

namespace BezpiecznyAktualizator.Core.Security;

public enum SignatureState { Valid, Unsigned, Invalid, Unknown }

public sealed record SignatureInfo(SignatureState State, int Code, string Signer);

/// <summary>Weryfikacja podpisu Authenticode (WinVerifyTrust, z kontrolą unieważnienia certyfikatów).</summary>
public static class Authenticode
{
    private const int TrustENoSignature = unchecked((int)0x800B0100);
    private const int TrustESubjectFormUnknown = unchecked((int)0x800B0003);
    private const int TrustEProviderUnknown = unchecked((int)0x800B0001);
    private const int TrustEBadDigest = unchecked((int)0x80096010);
    private const int TrustECertSignature = unchecked((int)0x80096004);
    private const int TrustEExplicitDistrust = unchecked((int)0x800B0111);
    private const int CertERevoked = unchecked((int)0x800B010C);

    private static Guid GenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustFileInfo
    {
        public uint cbStruct;
        public IntPtr pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustData
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid action, ref WinTrustData data);

    internal static SignatureState Classify(int code) => code switch
    {
        0 => SignatureState.Valid,
        TrustENoSignature or TrustESubjectFormUnknown or TrustEProviderUnknown => SignatureState.Unsigned,
        // Plik zmieniony po podpisaniu, podpis sfałszowany lub certyfikat unieważniony/zablokowany.
        TrustEBadDigest or TrustECertSignature or TrustEExplicitDistrust or CertERevoked => SignatureState.Invalid,
        _ => SignatureState.Unknown,
    };

    /// <param name="checkRevocation">false - bez sprawdzania unieważnienia (bez ruchu sieciowego), np. przy kontroli własnego pliku.</param>
    public static SignatureInfo Verify(string path, bool checkRevocation = true)
    {
        var pathPtr = Marshal.StringToHGlobalUni(path);
        var fileInfo = new WinTrustFileInfo { cbStruct = (uint)Marshal.SizeOf<WinTrustFileInfo>(), pcwszFilePath = pathPtr };
        var filePtr = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustFileInfo>());
        int code;
        try
        {
            Marshal.StructureToPtr(fileInfo, filePtr, false);
            var data = new WinTrustData
            {
                cbStruct = (uint)Marshal.SizeOf<WinTrustData>(),
                dwUIChoice = 2,               // WTD_UI_NONE
                fdwRevocationChecks = checkRevocation ? 1u : 0u,  // WTD_REVOKE_WHOLECHAIN / WTD_REVOKE_NONE
                dwUnionChoice = 1,            // WTD_CHOICE_FILE
                pFile = filePtr,
                dwStateAction = 1,            // WTD_STATEACTION_VERIFY
                // WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT / WTD_CACHE_ONLY_URL_RETRIEVAL
                dwProvFlags = checkRevocation ? 0x80u : 0x1000u,
            };
            code = WinVerifyTrust(new IntPtr(-1), ref GenericVerifyV2, ref data);
            data.dwStateAction = 2;           // WTD_STATEACTION_CLOSE
            WinVerifyTrust(new IntPtr(-1), ref GenericVerifyV2, ref data);
        }
        finally
        {
            Marshal.FreeHGlobal(filePtr);
            Marshal.FreeHGlobal(pathPtr);
        }
        return new SignatureInfo(Classify(code), code, SignerName(path));
    }

    private static string SignerName(string path)
    {
        using var cert = Signer(path);
        return cert?.GetNameInfo(X509NameType.SimpleName, false) ?? "";
    }

    /// <summary>Odcisk SHA-1 certyfikatu, którym podpisano plik (pusty, gdy brak podpisu).</summary>
    public static string SignerThumbprint(string path)
    {
        using var cert = Signer(path);
        return cert?.Thumbprint ?? "";
    }

    private static X509Certificate2? Signer(string path)
    {
        try
        {
            // X509CertificateLoader nie obsługuje odczytu podpisującego z pliku Authenticode.
#pragma warning disable SYSLIB0057
            return new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
#pragma warning restore SYSLIB0057
        }
        catch (CryptographicException)
        {
            return null;
        }
    }
}

/// <summary>Kontrola integralności pliku programu na podstawie jego podpisu Authenticode.</summary>
public static class IntegrityCheck
{
    /// <summary>Opis problemu albo null, gdy plik jest nienaruszony i podpisany oczekiwanym certyfikatem.</summary>
    /// <remarks>Certyfikat własny (niezaufany w systemie) jest akceptowany, jeśli skrót pliku się zgadza i odcisk jest oczekiwany.</remarks>
    public static string? Problem(SignatureInfo signature, string actualThumbprint, string expectedThumbprint) => signature.State switch
    {
        SignatureState.Unsigned => L.T("Plik programu nie ma podpisu cyfrowego."),
        SignatureState.Invalid => L.T("Podpis cyfrowy pliku programu jest nieprawidłowy - plik został zmieniony po podpisaniu."),
        _ when expectedThumbprint.Length > 0 &&
               !string.Equals(actualThumbprint, expectedThumbprint, StringComparison.OrdinalIgnoreCase)
            => L.T("Plik programu podpisano innym certyfikatem niż certyfikat wydawcy."),
        _ => null,
    };
}
