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

    public static Task<ReleaseCheckResult> CheckLatestAsync(CancellationToken cancellationToken = default) =>
        CheckLatestAsync(includePrereleases: false, cancellationToken);

    public static async Task<ReleaseCheckResult> CheckLatestAsync(bool includePrereleases,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(Repository))
            throw new InvalidOperationException("The update repository is not configured.");
        return await GitHubReleaseClient.CheckLatestAsync(Repository, CurrentVersion, includePrereleases, cancellationToken)
            .ConfigureAwait(false);
    }

    public static async Task<string> DownloadAndVerifyAsync(ApplicationRelease release, IReadOnlyCollection<string> expectedSigners,
        CancellationToken cancellationToken = default)
    {
        var updateDirectory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "BezpiecznyAktualizator", "Updates");
        return await DownloadAndVerifyCoreAsync(release, expectedSigners, DownloadClient, updateDirectory, cancellationToken)
            .ConfigureAwait(false);
    }

    internal static async Task<string> DownloadAndVerifyCoreAsync(ApplicationRelease release,
        IReadOnlyCollection<string> expectedSigners, HttpClient client, string updateDirectory,
        CancellationToken cancellationToken = default)
    {
        if (expectedSigners.Count == 0 || expectedSigners.Any(t => !IntegrityCheck.IsThumbprint(t)))
            throw new InvalidOperationException("The trusted publisher certificate is not configured in this build.");
        if (release.Size <= 0 || release.Size > MaximumInstallerSize)
            throw new InvalidDataException("The update installer exceeds the permitted size.");

        Directory.CreateDirectory(updateDirectory);
        var finalPath = Path.Combine(updateDirectory, $"BezpiecznyAktualizator-{release.Version}.msi");
        var partialPath = finalPath + "." + Guid.NewGuid().ToString("N") + ".download";
        try
        {
            using var response = await client.GetAsync(release.InstallerUrl,
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

            var actualHash = await HashFileAsync(partialPath, cancellationToken).ConfigureAwait(false);
            var expectedHash = Convert.FromHexString(release.Sha256);
            if (!CryptographicOperations.FixedTimeEquals(actualHash, expectedHash))
                throw new InvalidDataException("The update installer SHA-256 digest does not match the release.");

            var signature = Authenticode.Verify(partialPath, checkRevocation: false);
            var signer = Authenticode.SignerThumbprint(partialPath);
            if (signature.State is SignatureState.Invalid or SignatureState.Unsigned ||
                !expectedSigners.Contains(signer, StringComparer.OrdinalIgnoreCase))
                throw new CryptographicException("The update installer signature or publisher certificate is invalid.");

            File.Move(partialPath, finalPath, overwrite: true);
            return finalPath;
        }
        finally
        {
            if (File.Exists(partialPath)) File.Delete(partialPath);
        }
    }

    internal static async Task<byte[]> HashFileAsync(string path, CancellationToken cancellationToken = default)
    {
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read,
            81920, FileOptions.Asynchronous | FileOptions.SequentialScan);
        return await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false);
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
