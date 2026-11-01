using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography;
using System.Windows;
using BezpiecznyAktualizator.Core.Security;
using BezpiecznyAktualizator.Core.Updates;
using Microsoft.Win32;
using Application = System.Windows.Application;

namespace BezpiecznyAktualizator.Services;

internal static class ApplicationUpdateService
{
    private const string MsiRegistryKey = @"SOFTWARE\Cragenos\BezpiecznyAktualizator";
    private const long MaximumInstallerSize = 512L * 1024 * 1024;
    private static readonly HttpClient DownloadClient = new() { Timeout = TimeSpan.FromMinutes(3) };

    public static string Repository => typeof(App).Assembly.GetCustomAttributes<AssemblyMetadataAttribute>()
        .FirstOrDefault(a => a.Key == "UpdateRepository")?.Value ?? "";

    public static Version CurrentVersion => typeof(App).Assembly.GetName().Version ?? new Version(0, 0);

    public static bool IsMsiInstallation()
    {
        var executable = Environment.ProcessPath;
        if (string.IsNullOrEmpty(executable)) return false;
        using var key = Registry.LocalMachine.OpenSubKey(MsiRegistryKey, writable: false);
        var installPath = key?.GetValue("InstallLocation") as string;
        var channel = key?.GetValue("UpdateChannel") as string;
        return string.Equals(channel, "msi", StringComparison.OrdinalIgnoreCase) &&
               !string.IsNullOrEmpty(installPath) &&
               string.Equals(Path.GetFullPath(executable),
                   Path.GetFullPath(Path.Combine(installPath, "BezpiecznyAktualizator.exe")),
                   StringComparison.OrdinalIgnoreCase);
    }

    public static async Task<ApplicationRelease?> CheckAsync(CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(Repository))
            throw new InvalidOperationException("The update repository is not configured.");
        return await GitHubReleaseClient.GetLatestAsync(Repository, CurrentVersion, cancellationToken).ConfigureAwait(false);
    }

    public static async Task<string> DownloadAndVerifyAsync(ApplicationRelease release, string expectedSigner,
        CancellationToken cancellationToken = default)
    {
        if (expectedSigner.Length != 40 || expectedSigner.Any(c => !Uri.IsHexDigit(c)))
            throw new InvalidOperationException("The trusted publisher certificate is not configured in this build.");
        if (release.Size <= 0 || release.Size > MaximumInstallerSize)
            throw new InvalidDataException("The update installer exceeds the permitted size.");

        var updateDirectory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "BezpiecznyAktualizator", "Updates");
        Directory.CreateDirectory(updateDirectory);
        var finalPath = Path.Combine(updateDirectory, $"BezpiecznyAktualizator-{release.Version}.msi");
        var partialPath = finalPath + "." + Guid.NewGuid().ToString("N") + ".download";
        try
        {
            using var response = await DownloadClient.GetAsync(release.InstallerUrl,
                HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
            response.EnsureSuccessStatusCode();
            if (response.Content.Headers.ContentLength is { } length &&
                (length != release.Size || length > MaximumInstallerSize))
                throw new InvalidDataException("The update installer size does not match the release metadata.");

            await using (var output = new FileStream(partialPath, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                             81920, FileOptions.Asynchronous | FileOptions.SequentialScan))
            await using (var input = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false))
            {
                var buffer = new byte[81920];
                long total = 0;
                int read;
                while ((read = await input.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) > 0)
                {
                    total += read;
                    if (total > release.Size || total > MaximumInstallerSize)
                        throw new InvalidDataException("The update installer exceeded the announced size.");
                    await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
                }
                if (total != release.Size) throw new InvalidDataException("The update installer is incomplete.");
            }

            await using var downloaded = File.OpenRead(partialPath);
            var actualHash = await SHA256.HashDataAsync(downloaded, cancellationToken).ConfigureAwait(false);
            var expectedHash = Convert.FromHexString(release.Sha256);
            if (!CryptographicOperations.FixedTimeEquals(actualHash, expectedHash))
                throw new InvalidDataException("The update installer SHA-256 digest does not match the release.");

            var signature = Authenticode.Verify(partialPath, checkRevocation: false);
            var signer = Authenticode.SignerThumbprint(partialPath);
            if (signature.State is SignatureState.Invalid or SignatureState.Unsigned ||
                !string.Equals(signer, expectedSigner, StringComparison.OrdinalIgnoreCase))
                throw new CryptographicException("The update installer signature or publisher certificate is invalid.");

            if (File.Exists(finalPath)) File.Delete(finalPath);
            File.Move(partialPath, finalPath);
            return finalPath;
        }
        finally
        {
            if (File.Exists(partialPath)) File.Delete(partialPath);
        }
    }

    public static void StartMsiUpgrade(string installerPath)
    {
        var process = Process.Start(new ProcessStartInfo
        {
            FileName = "msiexec.exe",
            Arguments = $"/i \"{installerPath}\" /passive /norestart",
            UseShellExecute = true,
            Verb = "runas",
        });
        if (process is null) throw new InvalidOperationException("Windows Installer did not start.");
        process.Dispose();
        Application.Current.Shutdown();
    }
}
