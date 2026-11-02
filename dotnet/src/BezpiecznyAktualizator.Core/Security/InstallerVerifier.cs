using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Security.Cryptography;
using BezpiecznyAktualizator.Core.Localization;
using BezpiecznyAktualizator.Core.Winget;

namespace BezpiecznyAktualizator.Core.Security;

public sealed class InstallerVerification
{
    public List<Check> Checks { get; } = [];

    /// <summary>Instalator został pobrany i sprawdzony (nawet jeśli wynik jest negatywny).</summary>
    public bool Completed { get; set; }

    /// <summary>Powód, dla którego weryfikacji nie dało się przeprowadzić.</summary>
    public LocText? Error { get; set; }

    public string Version { get; set; } = "";
    public string InstallerUrl { get; set; } = "";
    public string Sha256 { get; set; } = "";

    /// <summary>Skanowanie programem Microsoft Defender było wymagane, ale nie mogło zostać wykonane.</summary>
    public bool DefenderUnavailable { get; set; }

    /// <summary>Aktualizacja jest zarządzana przez Microsoft Store, który nie udostępnia instalatora do niezależnego skanu.</summary>
    public bool StoreManaged { get; set; }

    public VerifiedInstaller? VerifiedInstaller { get; set; }

    public bool Blocked => Checks.Any(c => c.Status == CheckStatus.Fail);

    /// <summary>Instalator przeszedł wszystkie kontrole, łącznie z czystym wynikiem skanowania antywirusowego.</summary>
    public bool Passed => Completed && !Blocked && !DefenderUnavailable && !StoreManaged;

    /// <summary>Kontrole przeszły, ale skanowanie Defender nie zostało wykonane – instalacja tylko za wyraźną zgodą użytkownika.</summary>
    public bool PassedWithoutScan => Completed && !Blocked && DefenderUnavailable && !StoreManaged;
}

public sealed record WingetInstallerManifest(string PackageId, string Version, string InstallerUrl, string Sha256);

public sealed class VerifiedInstaller : IDisposable
{
    private readonly string _directory;
    private bool _disposed;

    internal VerifiedInstaller(string directory, string manifestPath, string packageId, string version,
                               string sha256, string manifestSha256)
    {
        _directory = directory;
        ManifestPath = manifestPath;
        PackageId = packageId;
        Version = version;
        Sha256 = sha256;
        ManifestSha256 = manifestSha256;
    }

    public string ManifestPath { get; }
    public string PackageId { get; }
    public string Version { get; }
    public string Sha256 { get; }
    public string ManifestSha256 { get; }

    internal void Validate()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!File.Exists(ManifestPath))
            throw new WingetException(L.T("Brakuje zweryfikowanego manifestu aktualizacji."));
        var manifestBytes = File.ReadAllBytes(ManifestPath);
        if (manifestBytes.Length > 5 * 1024 * 1024)
            throw new WingetException(L.T("Zweryfikowany manifest aktualizacji przekracza dozwolony rozmiar."));
        var digest = SHA256.HashData(manifestBytes);
        var manifest = InstallerVerifier.ParseManifest(File.ReadAllText(ManifestPath));
        if (!CryptographicOperations.FixedTimeEquals(digest, Convert.FromHexString(ManifestSha256)) ||
            !manifest.PackageId.Equals(PackageId, StringComparison.OrdinalIgnoreCase) ||
            !manifest.Version.Equals(Version, StringComparison.OrdinalIgnoreCase) ||
            !manifest.Sha256.Equals(Sha256, StringComparison.OrdinalIgnoreCase))
            throw new WingetException(L.T("Zweryfikowany manifest aktualizacji zmienił się przed instalacją."));
    }

    public void Dispose()
    {
        if (_disposed) return;
        if (Directory.Exists(_directory)) Directory.Delete(_directory, recursive: true);
        _disposed = true;
    }
}

/// <summary>
/// Sprawdza instalator przed instalacją: pobiera go przez winget do katalogu tymczasowego i porównuje
/// jego sumę z manifestem, z plikami kontrolnymi publikowanymi przez wydawcę (jeśli są dostępne)
/// oraz weryfikuje podpis Authenticode.
/// </summary>
public static partial class InstallerVerifier
{
    private static readonly TimeSpan ProbeTimeout = TimeSpan.FromSeconds(15);

    public static WingetInstallerManifest ParseManifest(string yaml)
    {
        static string Value(Match m) => m.Success ? m.Groups["v"].Value.Trim().Trim('\'', '"') : "";
        return new(Value(ManifestPackageId().Match(yaml)), Value(ManifestVersion().Match(yaml)),
            Value(ManifestUrl().Match(yaml)), Value(ManifestSha256().Match(yaml)).ToLowerInvariant());
    }

    public static async Task<InstallerVerification> VerifyAsync(string packageId, string source, Action<string>? progress = null,
                                                                CancellationToken ct = default, string version = "",
                                                                bool scanWithDefender = true)
    {
        var result = new InstallerVerification();
        if (string.Equals(source, "msstore", StringComparison.OrdinalIgnoreCase))
        {
            result.StoreManaged = true;
            result.Checks.Add(new Check(L.Txt("Pakiet Microsoft Store"), CheckStatus.Warn,
                L.Txt("Nie można niezależnie przeskanować instalatora Microsoft Store; aktualizacje Store nie są instalowane automatycznie.")));
            result.Completed = true;
            return result;
        }

        var dir = Path.Combine(Path.GetTempPath(), "BezpiecznyAktualizator", "verify-" + Guid.NewGuid().ToString("N"));
        var retainDirectory = false;
        try
        {
            Directory.CreateDirectory(dir);
            progress?.Invoke(L.T("Pobieranie instalatora do weryfikacji..."));
            var (code, output) = await WingetClient.DownloadAsync(packageId, dir, source, version, ct);
            if (code == WingetClient.HashMismatchCode)
            {
                result.Checks.Add(new Check(L.Txt("Suma SHA256 zgodna z manifestem winget"), CheckStatus.Fail,
                    L.Txt("winget odrzucił pobrany plik - suma SHA256 nie zgadza się z manifestem.")));
                result.Completed = true;
                return result;
            }
            if (code != 0)
            {
                var last = WingetClient.SplitLines(output).LastOrDefault(l => l.Trim().Length > 0)?.Trim() ?? "";
                result.Error = L.Txt("winget download zakończył się kodem 0x{0:X8}: {1}", code, last);
                return result;
            }

            var files = Directory.Exists(dir) ? Directory.GetFiles(dir) : [];
            var manifests = files.Where(f => f.EndsWith(".yaml", StringComparison.OrdinalIgnoreCase)).ToArray();
            var installers = files.Except(manifests, StringComparer.OrdinalIgnoreCase).ToArray();
            if (manifests.Length != 1 || installers.Length != 1)
            {
                result.Error = L.Txt("Nie znaleziono dokładnie jednego pobranego instalatora i manifestu.");
                return result;
            }
            var yamlPath = manifests[0];
            var installer = installers[0];

            var manifestInfo = new FileInfo(yamlPath);
            if (manifestInfo.Length > 5 * 1024 * 1024)
            {
                result.Error = L.T("Pobrany manifest przekracza dozwolony rozmiar.");
                return result;
            }
            var manifest = ParseManifest(await File.ReadAllTextAsync(yamlPath, ct));
            if (manifest.PackageId.Length == 0 || !manifest.PackageId.Equals(packageId, StringComparison.OrdinalIgnoreCase) ||
                version.Length > 0 && !manifest.Version.Equals(version, StringComparison.OrdinalIgnoreCase))
            {
                result.Error = L.Txt("Pobrany manifest nie odpowiada wybranemu pakietowi lub wersji.");
                return result;
            }
            result.Version = manifest.Version;
            result.InstallerUrl = manifest.InstallerUrl;
            progress?.Invoke(L.T("Obliczanie sum kontrolnych SHA256/SHA512..."));
            var digests = await Task.Run(() => FileDigests.Compute(installer), ct);
            result.Sha256 = digests.Sha256;

            result.Checks.Add(ManifestCheck(manifest, digests));
            progress?.Invoke(L.T("Wyszukiwanie plików kontrolnych wydawcy..."));
            result.Checks.Add(await PublisherCheckAsync(manifest.InstallerUrl, digests, ct));
            result.Checks.Add(SignatureCheck(Authenticode.Verify(installer)));
            if (scanWithDefender)
            {
                progress?.Invoke(L.T("Skanowanie instalatora programem Microsoft Defender..."));
                var scan = await DefenderScanner.ScanFileAsync(installer, ct);
                result.DefenderUnavailable = scan.Verdict == DefenderVerdict.Unavailable;
                result.Checks.Add(DefenderCheck(scan));
            }
            result.Completed = true;
            if (!result.Blocked)
            {
                var manifestSha256 = Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(yamlPath, ct)));
                result.VerifiedInstaller = new VerifiedInstaller(dir, yamlPath, manifest.PackageId, manifest.Version,
                    digests.Sha256, manifestSha256);
                retainDirectory = true;
            }
            return result;
        }
        catch (Exception ex) when (ex is WingetException or IOException or UnauthorizedAccessException)
        {
            result.Error = ex.Message;
            return result;
        }
        finally
        {
            if (!retainDirectory && Directory.Exists(dir)) Directory.Delete(dir, true);
        }
    }

    internal static Check ManifestCheck(WingetInstallerManifest manifest, FileDigests digests)
    {
        var label = L.Txt("Suma SHA256 zgodna z manifestem winget");
        if (!SecurityRules.IsSha256(manifest.Sha256))
            return new Check(label, CheckStatus.Fail, L.Txt("Manifest nie zawiera sumy SHA256."));
        return string.Equals(manifest.Sha256, digests.Sha256, StringComparison.OrdinalIgnoreCase)
            ? new Check(label, CheckStatus.Ok, digests.Sha256)
            : new Check(label, CheckStatus.Fail, L.Txt("Oczekiwano {0}, obliczono {1}.", manifest.Sha256, digests.Sha256));
    }

    /// <summary>Ocena zebranych wpisów z plików kontrolnych wydawcy.</summary>
    internal static Check EvaluatePublisher(IReadOnlyList<(string Source, ChecksumEntry Entry)> found, FileDigests digests)
    {
        var label = L.Txt("Plik kontrolny wydawcy");
        var bad = found.Where(f => !ChecksumFiles.Matches(f.Entry, digests)).ToList();
        if (bad.Count > 0)
            return new Check(label, CheckStatus.Fail, L.Txt("Suma {0} niezgodna z {1}: oczekiwano {2}, obliczono {3}.",
                bad[0].Entry.Algorithm, bad[0].Source, bad[0].Entry.Hash, digests.For(bad[0].Entry.Algorithm)));
        if (found.Count > 0)
            return new Check(label, CheckStatus.Ok, L.Txt("Suma zgodna ({0}): {1}",
                string.Join(", ", found.Select(f => f.Entry.Algorithm).Distinct()), string.Join(", ", found.Select(f => f.Source).Distinct())));
        return new Check(label, CheckStatus.Warn, L.Txt("Wydawca nie publikuje pliku kontrolnego dla tego instalatora (sprawdzono typowe lokalizacje)."));
    }

    internal static Check SignatureCheck(SignatureInfo sig)
    {
        var label = L.Txt("Podpis cyfrowy Authenticode");
        return sig.State switch
        {
            SignatureState.Valid => new Check(label, CheckStatus.Ok,
                sig.Signer.Length > 0 ? L.Txt("Prawidłowy, podpisany przez: {0}", sig.Signer) : L.Txt("Prawidłowy.")),
            SignatureState.Unsigned => new Check(label, CheckStatus.Warn,
                L.Txt("Instalator nie jest podpisany - integralność potwierdzają tylko sumy kontrolne.")),
            SignatureState.Invalid => new Check(label, CheckStatus.Fail,
                L.Txt("Podpis nieprawidłowy lub certyfikat unieważniony (0x{0:X8}).", sig.Code)),
            _ => new Check(label, CheckStatus.Warn, L.Txt("Nie udało się potwierdzić podpisu (0x{0:X8}).", sig.Code)),
        };
    }

    internal static Check DefenderCheck(DefenderScan scan)
    {
        var label = L.Txt("Skanowanie Microsoft Defender");
        return scan.Verdict switch
        {
            DefenderVerdict.Clean => new Check(label, CheckStatus.Ok, L.Txt("Nie wykryto zagrożeń.")),
            DefenderVerdict.Threat => new Check(label, CheckStatus.Fail, L.Txt("Wykryto zagrożenie: {0}",
                scan.Threats.Count > 0 ? string.Join(", ", scan.Threats) : scan.Detail)),
            _ => new Check(label, CheckStatus.Warn,
                L.Txt("Microsoft Defender jest niedostępny (np. wyłączony przez inny program antywirusowy): {0}", scan.Detail)),
        };
    }

    private static async Task<Check> PublisherCheckAsync(string installerUrl, FileDigests digests, CancellationToken ct)
    {
        var fileName = ChecksumFiles.FileNameFromUrl(installerUrl);
        var found = new List<(string, ChecksumEntry)>();
        var release = ChecksumFiles.ParseGitHubRelease(installerUrl);
        var gitHubOk = release is not null && await GitHubAsync(release, digests, found, ct);
        if (!gitHubOk)
        {
            var probes = ChecksumFiles.Candidates(installerUrl).Select(async c =>
            {
                var text = await FetchTextAsync(c.Url, ct);
                if (text is null) return ((string, ChecksumEntry)?)null;
                var entry = ChecksumFiles.Find(ChecksumFiles.Parse(text), fileName, c.Sidecar);
                return entry is null ? null : (c.Url.ToString(), entry);
            });
            found.AddRange((await Task.WhenAll(probes)).OfType<(string, ChecksumEntry)>());
        }
        return EvaluatePublisher(found, digests);
    }

    /// <summary>GitHub Releases: suma "digest" zasobu z API oraz pliki kontrolne dołączone do wydania.</summary>
    private static async Task<bool> GitHubAsync(ChecksumFiles.GitHubRelease release, FileDigests digests,
                                                List<(string, ChecksumEntry)> found, CancellationToken ct)
    {
        var api = new Uri($"https://api.github.com/repos/{release.Owner}/{release.Repo}/releases/tags/{Uri.EscapeDataString(release.Tag)}");
        var json = await FetchTextAsync(api, ct, "application/vnd.github+json");
        if (json is null) return false;
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (!doc.RootElement.TryGetProperty("assets", out var assets) || assets.ValueKind != JsonValueKind.Array) return false;
            var checksumAssets = new List<(string Name, Uri Url)>();
            foreach (var asset in assets.EnumerateArray())
            {
                var name = asset.TryGetProperty("name", out var n) ? n.GetString() ?? "" : "";
                if (string.Equals(name, release.File, StringComparison.OrdinalIgnoreCase) &&
                    asset.TryGetProperty("digest", out var d) && d.GetString() is { } digest)
                {
                    var parts = digest.Split(':', 2);
                    var alg = parts[0].Replace("-", "").ToUpperInvariant();
                    if (parts.Length == 2 && alg is ChecksumFiles.Sha256 or ChecksumFiles.Sha512)
                        found.Add(($"GitHub Releases ({release.Owner}/{release.Repo})",
                                   new ChecksumEntry(alg, parts[1].ToLowerInvariant(), release.File)));
                }
                else if (ChecksumFiles.IsChecksumAsset(name, release.File) &&
                         asset.TryGetProperty("size", out var size) && size.GetInt64() <= ChecksumFiles.MaxSize &&
                         asset.TryGetProperty("browser_download_url", out var u) &&
                         Uri.TryCreate(u.GetString(), UriKind.Absolute, out var url))
                {
                    checksumAssets.Add((name, url));
                }
            }
            foreach (var (name, url) in checksumAssets.Take(5))
            {
                var text = await FetchTextAsync(url, ct);
                if (text is null) continue;
                var sidecar = !string.Equals(name, release.File, StringComparison.OrdinalIgnoreCase) &&
                              name.StartsWith(release.File, StringComparison.OrdinalIgnoreCase);
                var entry = ChecksumFiles.Find(ChecksumFiles.Parse(text), release.File, sidecar);
                if (entry is not null) found.Add((name, entry));
            }
            return true;
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or FormatException)
        {
            return false;
        }
    }

    /// <summary>Pobiera mały plik tekstowy wyłącznie przez HTTPS (także po przekierowaniach), z limitem rozmiaru.</summary>
    internal static async Task<string?> FetchTextAsync(Uri url, CancellationToken ct, string? accept = null)
    {
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(ProbeTimeout);
            var current = url;
            for (var hop = 0; hop < 8; hop++)
            {
                if (current.Scheme != Uri.UriSchemeHttps) return null;
                using var request = new HttpRequestMessage(HttpMethod.Get, current);
                if (accept is not null) request.Headers.Accept.ParseAdd(accept);
                using var response = await SecurityRules.Http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
                var code = (int)response.StatusCode;
                if (code is >= 300 and < 400 && response.Headers.Location is { } location)
                {
                    current = location.IsAbsoluteUri ? location : new Uri(current, location);
                    continue;
                }
                if (!response.IsSuccessStatusCode || response.Content.Headers.ContentLength > ChecksumFiles.MaxSize) return null;
                await using var stream = await response.Content.ReadAsStreamAsync(timeout.Token);
                var buffer = new byte[ChecksumFiles.MaxSize + 1];
                var total = 0;
                int read;
                while (total < buffer.Length && (read = await stream.ReadAsync(buffer.AsMemory(total), timeout.Token)) > 0) total += read;
                if (total > ChecksumFiles.MaxSize) return null;
                var text = Encoding.UTF8.GetString(buffer, 0, total);
                return text.TrimStart().StartsWith('<') ? null : text;
            }
            return null;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return null;
        }
        catch (Exception ex) when (ex is HttpRequestException or UriFormatException or IOException)
        {
            return null;
        }
    }

    [GeneratedRegex(@"^PackageIdentifier:\s*(?<v>.+?)\s*$", RegexOptions.Multiline)]
    private static partial Regex ManifestPackageId();

    [GeneratedRegex(@"^PackageVersion:\s*(?<v>.+?)\s*$", RegexOptions.Multiline)]
    private static partial Regex ManifestVersion();

    [GeneratedRegex(@"^\s*InstallerUrl:\s*(?<v>\S+)\s*$", RegexOptions.Multiline)]
    private static partial Regex ManifestUrl();

    [GeneratedRegex(@"^\s*InstallerSha256:\s*(?<v>\S+)\s*$", RegexOptions.Multiline)]
    private static partial Regex ManifestSha256();

}
