using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace BezpiecznyAktualizator.Tests;

internal sealed class OfflinePackageTestSigner : IDisposable
{
    private readonly string _thumbprint;

    private OfflinePackageTestSigner(X509Certificate2 certificate)
    {
        Certificate = certificate;
        Sha256 = Convert.ToHexString(SHA256.HashData(certificate.RawData));
        _thumbprint = certificate.Thumbprint;
    }

    public X509Certificate2 Certificate { get; }
    public string Sha256 { get; }

    public static OfflinePackageTestSigner Create()
    {
        var executable = Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe");
        var start = new ProcessStartInfo(executable)
        {
            UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true,
        };
        start.Environment["PSModulePath"] = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            @"System32\WindowsPowerShell\v1.0\Modules");
        foreach (var argument in new[]
                 {
                     "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
                     "$ErrorActionPreference='Stop';" +
                     "$cert=New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=Offline package test signer' " +
                     "-CertStoreLocation 'Cert:\\CurrentUser\\My' -KeyAlgorithm RSA -KeyLength 2048 " +
                     "-HashAlgorithm SHA256 -KeyExportPolicy NonExportable -NotAfter (Get-Date).AddDays(2);" +
                     "$cert.Thumbprint",
                 })
            start.ArgumentList.Add(argument);
        using var process = Process.Start(start) ?? throw new InvalidOperationException("PowerShell did not start.");
        var stdout = process.StandardOutput.ReadToEnd();
        var stderr = process.StandardError.ReadToEnd();
        process.WaitForExit();
        if (process.ExitCode != 0)
            throw new InvalidOperationException($"Could not create test code-signing certificate: {stderr}{stdout}");
        var thumbprint = stdout.Trim().Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries).LastOrDefault()
            ?? throw new InvalidOperationException("PowerShell did not return a certificate thumbprint.");
        using var personal = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        personal.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
        var matches = personal.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);
        var certificate = matches.Cast<X509Certificate2>().FirstOrDefault()
            ?? throw new InvalidOperationException("The generated test certificate was not found in the personal store.");
        using var roots = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
        using var publishers = new X509Store(StoreName.TrustedPublisher, StoreLocation.CurrentUser);
        roots.Open(OpenFlags.ReadWrite);
        publishers.Open(OpenFlags.ReadWrite);
        using var publicCertificate = X509CertificateLoader.LoadCertificate(certificate.RawData);
        roots.Add(publicCertificate);
        publishers.Add(publicCertificate);
        return new OfflinePackageTestSigner(certificate);
    }

    public void Dispose()
    {
        using var personal = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        using var roots = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
        using var publishers = new X509Store(StoreName.TrustedPublisher, StoreLocation.CurrentUser);
        personal.Open(OpenFlags.ReadWrite);
        roots.Open(OpenFlags.ReadWrite);
        publishers.Open(OpenFlags.ReadWrite);
        foreach (var store in new[] { personal, roots, publishers })
        {
            var matches = store.Certificates.Find(X509FindType.FindByThumbprint, _thumbprint, false);
            foreach (var match in matches) store.Remove(match);
        }
        Certificate.Dispose();
    }
}
