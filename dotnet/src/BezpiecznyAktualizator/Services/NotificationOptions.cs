using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;

namespace BezpiecznyAktualizator.Services;

[System.Reflection.Obfuscation(Exclude = true)]
public sealed class NotificationOptions
{
    private const uint UiForbidden = 0x1;
    private const string EntropyText = "BezpiecznyAktualizator notification secrets v1";

    public bool Enabled { get; set; }
    public bool TeamsEnabled { get; set; }
    public string TeamsWebhookProtected { get; set; } = "";
    public bool EmailEnabled { get; set; }
    public string SmtpHost { get; set; } = "";
    public int SmtpPort { get; set; } = 587;
    public string SmtpUser { get; set; } = "";
    public string SmtpFrom { get; set; } = "";
    public string SmtpTo { get; set; } = "";
    public string SmtpPasswordProtected { get; set; } = "";
    public bool SmtpUseTls { get; set; } = true;

    [JsonIgnore] public bool HasTeamsWebhook => TeamsWebhookProtected.Length > 0;
    [JsonIgnore] public bool HasSmtpPassword => SmtpPasswordProtected.Length > 0;

    public void SetTeamsWebhook(string? value) =>
        TeamsWebhookProtected = ProtectOrEmpty(value);

    public void SetSmtpPassword(string? value) =>
        SmtpPasswordProtected = ProtectOrEmpty(value);

    public string? GetTeamsWebhook() => UnprotectOrNull(TeamsWebhookProtected);
    public string? GetSmtpPassword() => UnprotectOrNull(SmtpPasswordProtected);

    public NotificationOptions Normalize()
    {
        SmtpHost = SmtpHost.Trim();
        SmtpPort = Math.Clamp(SmtpPort, 1, 65535);
        SmtpUser = SmtpUser.Trim();
        SmtpFrom = SmtpFrom.Trim();
        SmtpTo = SmtpTo.Trim();
        return this;
    }

    private static string ProtectOrEmpty(string? value) =>
        string.IsNullOrEmpty(value) ? "" : Convert.ToBase64String(Transform(Encoding.UTF8.GetBytes(value), protect: true));

    private static string? UnprotectOrNull(string encoded) =>
        encoded.Length == 0 ? null : new UTF8Encoding(false, true).GetString(Transform(Convert.FromBase64String(encoded), protect: false));

    private static byte[] Transform(byte[] inputBytes, bool protect)
    {
        var entropyBytes = SHA256.HashData(Encoding.UTF8.GetBytes(EntropyText));
        var inputHandle = GCHandle.Alloc(inputBytes, GCHandleType.Pinned);
        var entropyHandle = GCHandle.Alloc(entropyBytes, GCHandleType.Pinned);
        var input = new DataBlob(inputBytes.Length, inputHandle.AddrOfPinnedObject());
        var entropy = new DataBlob(entropyBytes.Length, entropyHandle.AddrOfPinnedObject());
        DataBlob output = default;
        IntPtr description = IntPtr.Zero;
        try
        {
            var succeeded = protect
                ? CryptProtectData(ref input, null, ref entropy, IntPtr.Zero, IntPtr.Zero, UiForbidden, out output)
                : CryptUnprotectData(ref input, out description, ref entropy, IntPtr.Zero, IntPtr.Zero, UiForbidden, out output);
            if (!succeeded) throw new Win32Exception(Marshal.GetLastWin32Error());
            var result = new byte[output.Size];
            Marshal.Copy(output.Data, result, 0, output.Size);
            return result;
        }
        finally
        {
            if (output.Data != IntPtr.Zero) LocalFree(output.Data);
            if (description != IntPtr.Zero) LocalFree(description);
            entropyHandle.Free();
            inputHandle.Free();
            CryptographicOperations.ZeroMemory(inputBytes);
            CryptographicOperations.ZeroMemory(entropyBytes);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct DataBlob(int size, IntPtr data)
    {
        public int Size = size;
        public IntPtr Data = data;
    }

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptProtectData(ref DataBlob input, string? description, ref DataBlob entropy,
        IntPtr reserved, IntPtr prompt, uint flags, out DataBlob output);

    [DllImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptUnprotectData(ref DataBlob input, out IntPtr description, ref DataBlob entropy,
        IntPtr reserved, IntPtr prompt, uint flags, out DataBlob output);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);
}
