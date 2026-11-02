using System.Diagnostics;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using BezpiecznyAktualizator.Core.Localization;
using BezpiecznyAktualizator.Core.Logging;

namespace BezpiecznyAktualizator.Core.Updates;

public sealed record OfflinePackageEntry(string File, string OriginalName, long Size, string Sha256);

public sealed record OfflinePackageSigner(X509Certificate2 Certificate, string Label, string Sha256);

/// <summary>Creates signed, portable archives from user-selected MSU/CAB packages.</summary>
public static class OfflineUpdatePackage
{
    private const int MaxFiles = 9999;
    private const string PowerShellScript = "Install-OfflineUpdates.ps1";
    private const string SignatureFile = "manifest.sig";
    private const string CertificateFile = "signer.cer";

    public static IReadOnlyList<OfflinePackageSigner> GetAvailableSigners()
    {
        using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
        return store.Certificates.Cast<X509Certificate2>()
            .Where(IsCodeSigningCertificate)
            .Select(certificate => new OfflinePackageSigner(
                new X509Certificate2(certificate), certificate.GetNameInfo(X509NameType.SimpleName, false),
                CertificateSha256(certificate)))
            .OrderBy(signer => signer.Label, StringComparer.CurrentCultureIgnoreCase)
            .ThenBy(signer => signer.Sha256, StringComparer.Ordinal)
            .ToList();
    }

    public static string CertificateSha256(X509Certificate2 certificate) =>
        Convert.ToHexString(SHA256.HashData(certificate.RawData));

    public static bool IsCodeSigningCertificate(X509Certificate2 certificate)
    {
        var now = DateTime.UtcNow;
        if (!certificate.HasPrivateKey || now < certificate.NotBefore.ToUniversalTime() ||
            now > certificate.NotAfter.ToUniversalTime())
            return false;
        var usage = certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().FirstOrDefault();
        if (usage is null || !usage.EnhancedKeyUsages.Cast<Oid>()
                .Any(oid => oid.Value == "1.3.6.1.5.5.7.3.3"))
            return false;
        using var privateKey = certificate.GetRSAPrivateKey();
        return privateKey is not null && privateKey.KeySize >= 2048;
    }

    public static async Task CreateAsync(string destination, IReadOnlyList<string> files,
                                         IReadOnlyList<WindowsUpdateItem> references,
                                         X509Certificate2 signer, bool overwrite = false,
                                         CancellationToken ct = default, IProgress<string>? progress = null)
    {
        if (files.Count is 0 or > MaxFiles)
            throw new WindowsUpdateException(L.T("Wybierz co najmniej jeden plik MSU lub CAB."));
        if (references.Count > WindowsUpdateAgent.MaxSelection)
            throw new WindowsUpdateException(L.T("Wybrano zbyt wiele aktualizacji do opisu paczki."));
        if (!IsCodeSigningCertificate(signer))
            throw new WindowsUpdateException(L.T("Wybierz ważny certyfikat podpisywania kodu z kluczem prywatnym RSA o długości co najmniej 2048 bitów."));

        var target = Path.GetFullPath(destination);
        if (!target.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
            throw new WindowsUpdateException(L.T("Paczka offline musi mieć rozszerzenie .zip."));
        var directory = Path.GetDirectoryName(target) ?? throw new InvalidDataException("Missing destination directory.");
        if (!Directory.Exists(directory)) throw new DirectoryNotFoundException(directory);

        var sources = new List<(string Path, string Name)>();
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var file in files)
        {
            var path = Path.GetFullPath(file);
            var name = Path.GetFileName(path);
            var extension = Path.GetExtension(name);
            if (!extension.Equals(".msu", StringComparison.OrdinalIgnoreCase) &&
                !extension.Equals(".cab", StringComparison.OrdinalIgnoreCase))
                throw new WindowsUpdateException(L.F("Nieobsługiwany plik aktualizacji: {0}", name));
            if (!File.Exists(path)) throw new FileNotFoundException(L.T("Nie znaleziono pliku aktualizacji."), path);
            if (!names.Add(name) || !paths.Add(path))
                throw new WindowsUpdateException(L.F("Pliki w paczce muszą mieć różne nazwy: {0}", name));
            sources.Add((path, name));
        }

        var temporary = Path.Combine(directory, "." + Path.GetFileName(target) + "." + Guid.NewGuid().ToString("N") + ".tmp");
        var workingDirectory = Path.Combine(directory, "." + Path.GetFileName(target) + "." + Guid.NewGuid().ToString("N"));
        try
        {
            var packageDirectory = Path.Combine(workingDirectory, "packages");
            Directory.CreateDirectory(packageDirectory);
            var entries = new List<OfflinePackageEntry>();
            for (var index = 0; index < sources.Count; index++)
            {
                ct.ThrowIfCancellationRequested();
                var source = sources[index];
                progress?.Report(L.F("Kopiowanie pliku {0} z {1}: {2}", index + 1, sources.Count, source.Name));
                var path = Path.Combine(packageDirectory, source.Name);
                var (size, hash) = await CopyAndHashAsync(source.Path, path, ct);
                if (size == 0) throw new WindowsUpdateException(L.F("Plik aktualizacji jest pusty: {0}", source.Name));
                entries.Add(new OfflinePackageEntry("packages/" + source.Name, source.Name, size, hash));
            }

            progress?.Report(L.T("Dodawanie skryptów i dokumentacji..."));
            await AddResourceAsync(workingDirectory, PowerShellScript, "OfflineUpdate.Install.ps1", ct);
            await AddResourceAsync(workingDirectory, "Install-OfflineUpdates.cmd", "OfflineUpdate.Install.cmd", ct);
            await AddResourceAsync(workingDirectory, "Verify-OfflineUpdates.cmd", "OfflineUpdate.Verify.cmd", ct);
            await AddResourceAsync(workingDirectory, "README.txt", "OfflineUpdate.README.txt", ct);
            progress?.Report(L.T("Podpisywanie instalatora..."));
            await SignPowerShellFileAsync(Path.Combine(workingDirectory, PowerShellScript), signer, ct);
            progress?.Report(L.T("Tworzenie i podpisywanie manifestu..."));
            var manifestFiles = new List<Dictionary<string, object?>>();
            foreach (var file in Directory.EnumerateFiles(workingDirectory, "*", SearchOption.AllDirectories)
                         .OrderBy(path => Path.GetRelativePath(workingDirectory, path), StringComparer.Ordinal))
            {
                ct.ThrowIfCancellationRequested();
                var name = Path.GetRelativePath(workingDirectory, file).Replace('\\', '/');
                var (size, hash) = await HashFileAsync(file, ct);
                manifestFiles.Add(new Dictionary<string, object?> { ["file"] = name, ["size"] = size, ["sha256"] = hash });
            }

            var packageId = Guid.NewGuid().ToString("D");
            var manifest = new Dictionary<string, object?>
            {
                ["version"] = 2,
                ["packageId"] = packageId,
                ["createdUtc"] = DateTimeOffset.UtcNow,
                ["signingCertificateSha256"] = CertificateSha256(signer),
                ["files"] = manifestFiles,
                ["packages"] = entries.Select(entry => new Dictionary<string, object?>
                {
                    ["file"] = entry.File, ["originalName"] = entry.OriginalName,
                    ["size"] = entry.Size, ["sha256"] = entry.Sha256,
                }).ToList(),
                ["references"] = references.Select(update => new Dictionary<string, object?>
                {
                    ["updateId"] = update.Identity.UpdateId.ToString("D"), ["revision"] = update.Identity.Revision,
                    ["title"] = update.Title, ["kbIds"] = update.KbIds, ["cveIds"] = update.CveIds,
                }).ToList(),
            };
            var manifestBytes = JsonSerializer.SerializeToUtf8Bytes(manifest, new JsonSerializerOptions { WriteIndented = true });
            await File.WriteAllBytesAsync(Path.Combine(workingDirectory, "manifest.json"), manifestBytes, ct);
            await File.WriteAllTextAsync(Path.Combine(workingDirectory, SignatureFile),
                Convert.ToBase64String(SignManifest(manifestBytes, signer)), Encoding.ASCII, ct);
            await File.WriteAllBytesAsync(Path.Combine(workingDirectory, CertificateFile), signer.Export(X509ContentType.Cert), ct);

            using (var output = new FileStream(temporary, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None,
                                               131072, FileOptions.Asynchronous | FileOptions.SequentialScan))
            using (var zip = new ZipArchive(output, ZipArchiveMode.Create, leaveOpen: false, Encoding.UTF8))
            {
                progress?.Report(L.T("Pakowanie plików do archiwum ZIP..."));
                foreach (var file in Directory.EnumerateFiles(workingDirectory, "*", SearchOption.AllDirectories)
                             .OrderBy(path => Path.GetRelativePath(workingDirectory, path), StringComparer.Ordinal))
                {
                    ct.ThrowIfCancellationRequested();
                    var archiveName = Path.GetRelativePath(workingDirectory, file).Replace('\\', '/');
                    var entry = zip.CreateEntry(archiveName, archiveName.StartsWith("packages/", StringComparison.Ordinal)
                        ? CompressionLevel.NoCompression : CompressionLevel.Optimal);
                    await using var input = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.Read,
                                                           131072, FileOptions.Asynchronous | FileOptions.SequentialScan);
                    await using var entryStream = entry.Open();
                    await input.CopyToAsync(entryStream, ct);
                }
            }

            progress?.Report(L.T("Weryfikowanie zawartości i podpisu..."));
            await VerifyAsync(temporary, entries, manifestBytes, signer, ct);
            progress?.Report(L.T("Zapisywanie zweryfikowanej paczki..."));
            File.Move(temporary, target, overwrite);
        }
        finally
        {
            TryDeleteFile(temporary);
            TryDeleteDirectory(workingDirectory);
        }
    }

    internal static byte[] SignManifest(ReadOnlySpan<byte> manifest, X509Certificate2 signer)
    {
        using var key = signer.GetRSAPrivateKey() ?? throw new CryptographicException("Signing certificate has no RSA private key.");
        return key.SignData(manifest, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }

    internal static bool VerifyManifest(ReadOnlySpan<byte> manifest, ReadOnlySpan<byte> signature,
                                        X509Certificate2 signer)
    {
        using var key = signer.GetRSAPublicKey() ?? throw new CryptographicException("Signing certificate has no RSA public key.");
        return key.VerifyData(manifest, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }

    private static async Task<(long Size, string Sha256)> CopyAndHashAsync(string source, string destination,
                                                                            CancellationToken ct)
    {
        await using var input = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.Read, 131072,
                                               FileOptions.Asynchronous | FileOptions.SequentialScan);
        await using var output = new FileStream(destination, FileMode.CreateNew, FileAccess.Write, FileShare.None, 131072,
                                                FileOptions.Asynchronous | FileOptions.SequentialScan);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[131072];
        long size = 0;
        int count;
        while ((count = await input.ReadAsync(buffer, ct)) > 0)
        {
            await output.WriteAsync(buffer.AsMemory(0, count), ct);
            hash.AppendData(buffer, 0, count);
            size = checked(size + count);
        }
        return (size, Convert.ToHexString(hash.GetHashAndReset()));
    }

    private static async Task AddResourceAsync(string directory, string fileName, string resourceName,
                                               CancellationToken ct)
    {
        await using var input = typeof(OfflineUpdatePackage).Assembly.GetManifestResourceStream(resourceName) ??
                                throw new InvalidDataException($"Missing embedded resource: {resourceName}");
        await using var output = new FileStream(Path.Combine(directory, fileName), FileMode.CreateNew,
            FileAccess.Write, FileShare.None, 81920, FileOptions.Asynchronous | FileOptions.SequentialScan);
        await input.CopyToAsync(output, ct);
    }

    private static async Task<(long Size, string Sha256)> HashFileAsync(string path, CancellationToken ct)
    {
        await using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 131072,
                                               FileOptions.Asynchronous | FileOptions.SequentialScan);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[131072];
        long size = 0;
        int count;
        while ((count = await input.ReadAsync(buffer, ct)) > 0)
        {
            hash.AppendData(buffer, 0, count);
            size = checked(size + count);
        }
        return (size, Convert.ToHexString(hash.GetHashAndReset()));
    }

    private static async Task SignPowerShellFileAsync(string scriptPath, X509Certificate2 signer, CancellationToken ct)
    {
        var executable = Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe");
        if (!File.Exists(executable)) throw new FileNotFoundException(L.T("Nie znaleziono Windows PowerShell do podpisania instalatora."), executable);
        var thumbprint = signer.Thumbprint?.Replace(" ", "", StringComparison.Ordinal) ??
                         throw new CryptographicException("Signing certificate has no thumbprint.");
        var command = "$ErrorActionPreference='Stop';Import-Module Microsoft.PowerShell.Security -ErrorAction Stop;" +
                      "$certificate=Get-Item -LiteralPath 'Cert:\\CurrentUser\\My\\" + thumbprint + "';" +
                      "$result=Set-AuthenticodeSignature -FilePath '" + EscapePowerShellLiteral(scriptPath) +
                      "' -Certificate $certificate -HashAlgorithm SHA256;" +
                      "if($result.Status -ne 'Valid'){throw ('PowerShell Authenticode signing failed: '+$result.Status)}";
        var start = new ProcessStartInfo(executable)
        {
            UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true,
            CreateNoWindow = true,
        };
        start.Environment["PSModulePath"] = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            @"System32\WindowsPowerShell\v1.0\Modules");
        foreach (var argument in new[] { "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", command })
            start.ArgumentList.Add(argument);
        using var process = Process.Start(start) ?? throw new InvalidOperationException("Windows PowerShell did not start.");
        var stdout = process.StandardOutput.ReadToEndAsync(ct);
        var stderr = process.StandardError.ReadToEndAsync(ct);
        try { await process.WaitForExitAsync(ct); }
        catch (OperationCanceledException)
        {
            process.Kill(entireProcessTree: true);
            throw;
        }
        var output = (await stdout) + (await stderr);
        if (process.ExitCode != 0)
            throw new CryptographicException(L.F("Nie udało się podpisać skryptu instalatora: {0}", output.Trim()));
    }

    private static string EscapePowerShellLiteral(string value) => value.Replace("'", "''", StringComparison.Ordinal);

    private static async Task VerifyAsync(string path, IReadOnlyList<OfflinePackageEntry> entries,
                                          byte[] manifestBytes, X509Certificate2 signer, CancellationToken ct)
    {
        using var zip = ZipFile.OpenRead(path);
        var manifestEntry = zip.GetEntry("manifest.json") ?? throw new InvalidDataException("Missing signed manifest.");
        await using var manifestStream = manifestEntry.Open();
        var archivedManifest = await ReadAllBytesAsync(manifestStream, ct);
        if (!archivedManifest.AsSpan().SequenceEqual(manifestBytes)) throw new InvalidDataException("Manifest changed while packaging.");
        var signatureEntry = zip.GetEntry(SignatureFile) ?? throw new InvalidDataException("Missing manifest signature.");
        await using var signatureStream = signatureEntry.Open();
        var signature = Convert.FromBase64String(Encoding.ASCII.GetString(await ReadAllBytesAsync(signatureStream, ct)));
        if (!VerifyManifest(manifestBytes, signature, signer)) throw new CryptographicException("Manifest signature verification failed.");

        foreach (var expected in entries)
        {
            var entry = zip.GetEntry(expected.File) ?? throw new InvalidDataException("Missing archived package.");
            if (entry.Length != expected.Size) throw new InvalidDataException("Archived package size mismatch.");
            await using var stream = entry.Open();
            var digest = await SHA256.HashDataAsync(stream, ct);
            if (!Convert.ToHexString(digest).Equals(expected.Sha256, StringComparison.Ordinal))
                throw new InvalidDataException("Archived package checksum mismatch.");
        }
        foreach (var name in new[] { PowerShellScript, "Install-OfflineUpdates.cmd", "Verify-OfflineUpdates.cmd",
                                     "README.txt", CertificateFile })
            if (zip.GetEntry(name) is null) throw new InvalidDataException($"Missing archive entry: {name}");
    }

    private static async Task<byte[]> ReadAllBytesAsync(Stream stream, CancellationToken ct)
    {
        using var output = new MemoryStream();
        await stream.CopyToAsync(output, ct);
        return output.ToArray();
    }

    private static void TryDeleteFile(string path)
    {
        if (!File.Exists(path)) return;
        try { File.Delete(path); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Syslog.Warning(LogEvent.WindowsUpdate, L.F("Nie usunięto pliku tymczasowego paczki: {0}", ex.Message));
        }
    }

    private static void TryDeleteDirectory(string path)
    {
        if (!Directory.Exists(path)) return;
        try { Directory.Delete(path, recursive: true); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Syslog.Warning(LogEvent.WindowsUpdate, L.F("Nie usunięto katalogu tymczasowej paczki: {0}", ex.Message));
        }
    }
}
