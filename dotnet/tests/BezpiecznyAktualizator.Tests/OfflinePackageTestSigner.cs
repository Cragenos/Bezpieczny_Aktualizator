using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace BezpiecznyAktualizator.Tests;

internal sealed class OfflinePackageTestSigner : IDisposable
{
    private readonly string _thumbprint;
    private readonly StoreLocation _rootStoreLocation;
    private bool _rootAdded;
    private bool _publisherAdded;

    private OfflinePackageTestSigner(X509Certificate2 certificate, StoreLocation rootStoreLocation)
    {
        Certificate = certificate;
        Sha256 = Convert.ToHexString(SHA256.HashData(certificate.RawData));
        _thumbprint = certificate.Thumbprint;
        _rootStoreLocation = rootStoreLocation;
    }

    public X509Certificate2 Certificate { get; }
    public string Sha256 { get; }

    public static OfflinePackageTestSigner Create()
    {
        var rootStoreLocation = SelectRootStore(
            Environment.GetEnvironmentVariable("BA_OFFLINE_TEST_MACHINE_ROOT"),
            Environment.GetEnvironmentVariable("RUNNER_ENVIRONMENT"));
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
        var stdoutTask = process.StandardOutput.ReadToEndAsync();
        var stderrTask = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(60_000))
        {
            process.Kill(entireProcessTree: true);
            process.WaitForExit();
            throw new TimeoutException("Timed out creating the offline package test certificate.");
        }
        var stdout = stdoutTask.GetAwaiter().GetResult();
        var stderr = stderrTask.GetAwaiter().GetResult();
        if (process.ExitCode != 0)
            throw new InvalidOperationException($"Could not create test code-signing certificate: {stderr}{stdout}");
        var thumbprint = stdout.Trim().Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries).LastOrDefault()
            ?? throw new InvalidOperationException("PowerShell did not return a certificate thumbprint.");
        using var personal = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        personal.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
        var matches = personal.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);
        var certificate = matches.Cast<X509Certificate2>().FirstOrDefault()
            ?? throw new InvalidOperationException("The generated test certificate was not found in the personal store.");
        var signer = new OfflinePackageTestSigner(certificate, rootStoreLocation);
        var created = false;
        try
        {
            using var roots = new X509Store(StoreName.Root, rootStoreLocation);
            using var publishers = new X509Store(StoreName.TrustedPublisher, StoreLocation.CurrentUser);
            roots.Open(OpenFlags.ReadWrite);
            publishers.Open(OpenFlags.ReadWrite);
            using var publicCertificate = X509CertificateLoader.LoadCertificate(certificate.RawData);
            roots.Add(publicCertificate);
            signer._rootAdded = true;
            publishers.Add(publicCertificate);
            signer._publisherAdded = true;
            created = true;
            return signer;
        }
        finally
        {
            if (!created) signer.Dispose();
        }
    }

    internal static StoreLocation SelectRootStore(string? machineRoot, string? runnerEnvironment)
    {
        if (string.IsNullOrEmpty(machineRoot)) return StoreLocation.CurrentUser;
        if (machineRoot != "1" || runnerEnvironment != "github-hosted")
            throw new InvalidOperationException("Machine root test certificates require an explicitly configured GitHub-hosted runner.");
        return StoreLocation.LocalMachine;
    }

    public void Dispose()
    {
        try
        {
            if (_rootAdded) RemoveCertificate(StoreName.Root, _rootStoreLocation);
        }
        finally
        {
            try
            {
                if (_publisherAdded) RemoveCertificate(StoreName.TrustedPublisher, StoreLocation.CurrentUser);
            }
            finally
            {
                try { RemoveCertificate(StoreName.My, StoreLocation.CurrentUser); }
                finally { Certificate.Dispose(); }
            }
        }
    }

    private void RemoveCertificate(StoreName name, StoreLocation location)
    {
        using var store = new X509Store(name, location);
        store.Open(OpenFlags.ReadWrite);
        var matches = store.Certificates.Find(X509FindType.FindByThumbprint, _thumbprint, false);
        foreach (var match in matches)
        {
            using (match) store.Remove(match);
        }
    }
}
