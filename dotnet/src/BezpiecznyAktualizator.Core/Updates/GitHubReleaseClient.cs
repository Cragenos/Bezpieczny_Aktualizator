using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace BezpiecznyAktualizator.Core.Updates;

public sealed record ApplicationRelease(Version Version, string Tag, Uri InstallerUrl, string Sha256, long Size,
    string ReleaseUrl, string Notes)
{
    public bool IsPrerelease { get; init; }
}

public enum ReleaseCheckStatus { UpdateAvailable, UpToDate, NoRelease, RepositoryUnavailable, MissingInstaller }

public sealed record ReleaseCheckResult(ReleaseCheckStatus Status, ApplicationRelease? Release = null);

/// <summary>Reads the latest stable MSI release and its SHA-256 digest from a public GitHub repository.</summary>
public static partial class GitHubReleaseClient
{
    private const long MaximumInstallerSize = 512L * 1024 * 1024;
    private static readonly HttpClient Client = CreateClient();

    public static async Task<ApplicationRelease?> GetLatestAsync(string repository, Version currentVersion,
        CancellationToken cancellationToken = default) =>
        (await CheckLatestAsync(repository, currentVersion, cancellationToken).ConfigureAwait(false)).Release;

    public static async Task<ReleaseCheckResult> CheckLatestAsync(string repository, Version currentVersion,
        CancellationToken cancellationToken = default) =>
        await CheckLatestAsync(repository, currentVersion, includePrereleases: false, cancellationToken).ConfigureAwait(false);

    public static async Task<ReleaseCheckResult> CheckLatestAsync(string repository, Version currentVersion,
        bool includePrereleases, CancellationToken cancellationToken = default)
    {
        var (owner, name) = ParseRepository(repository);
        var repoApi = new Uri($"https://api.github.com/repos/{owner}/{name}");
        var api = new Uri(includePrereleases ? $"{repoApi}/releases?per_page=20" : $"{repoApi}/releases/latest");
        using var request = new HttpRequestMessage(HttpMethod.Get, api);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
        using var response = await Client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken)
            .ConfigureAwait(false);
        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            using var repositoryResponse = await Client.GetAsync(repoApi, cancellationToken).ConfigureAwait(false);
            if (repositoryResponse.StatusCode == HttpStatusCode.NotFound)
                return new ReleaseCheckResult(ReleaseCheckStatus.RepositoryUnavailable);
            repositoryResponse.EnsureSuccessStatusCode();
            return new ReleaseCheckResult(ReleaseCheckStatus.NoRelease);
        }
        response.EnsureSuccessStatusCode();
        if (includePrereleases)
        {
            if (response.Content.Headers.ContentLength is > 2 * 1024 * 1024)
                throw new InvalidDataException("The GitHub release list is too large.");
            var text = await ReadLimitedAsync(response.Content, 2 * 1024 * 1024, cancellationToken).ConfigureAwait(false);
            using var releases = JsonDocument.Parse(text);
            if (releases.RootElement.ValueKind != JsonValueKind.Array)
                throw new InvalidDataException("GitHub returned an invalid release list.");
            return await ParseReleaseListAsync(releases.RootElement, owner, name, currentVersion, cancellationToken)
                .ConfigureAwait(false);
        }
        using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using var json = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken).ConfigureAwait(false);
        var root = json.RootElement;
        var status = Classify(root, currentVersion, $"{owner}/{name}");
        if (status != ReleaseCheckStatus.UpdateAvailable) return new ReleaseCheckResult(status);
        var release = await ParseReleaseAsync(root, $"{owner}/{name}", currentVersion, cancellationToken).ConfigureAwait(false);
        return release is null
            ? new ReleaseCheckResult(ReleaseCheckStatus.MissingInstaller)
            : new ReleaseCheckResult(ReleaseCheckStatus.UpdateAvailable, release);
    }

    public static ReleaseCheckStatus ParseLatestStatus(string json, Version currentVersion)
    {
        using var document = JsonDocument.Parse(json);
        return Classify(document.RootElement, currentVersion, null);
    }

    internal static ReleaseCheckResult ParseReleaseList(string json, Version currentVersion)
    {
        using var document = JsonDocument.Parse(json);
        if (document.RootElement.ValueKind != JsonValueKind.Array)
            throw new InvalidDataException("GitHub returned an invalid release list.");
        var candidate = SelectRelease(document.RootElement, currentVersion, out var hasReleases);
        if (candidate is null)
            return new ReleaseCheckResult(hasReleases ? ReleaseCheckStatus.UpToDate : ReleaseCheckStatus.NoRelease);
        var metadata = ParseMetadata(candidate.Value, currentVersion, null, allowPrerelease: true);
        if (metadata is null || metadata.Sha256 is null && metadata.ChecksumUrl is null)
            return new ReleaseCheckResult(ReleaseCheckStatus.MissingInstaller);
        return new ReleaseCheckResult(ReleaseCheckStatus.UpdateAvailable,
            new ApplicationRelease(metadata.Version, metadata.Tag, metadata.InstallerUrl, metadata.Sha256 ?? "",
                metadata.Size, metadata.ReleaseUrl, metadata.Notes) { IsPrerelease = metadata.IsPrerelease });
    }

    private static async Task<ReleaseCheckResult> ParseReleaseListAsync(JsonElement releases, string owner, string name,
        Version currentVersion, CancellationToken cancellationToken)
    {
        var candidate = SelectRelease(releases, currentVersion, out var hasReleases);
        if (candidate is null)
            return new ReleaseCheckResult(hasReleases ? ReleaseCheckStatus.UpToDate : ReleaseCheckStatus.NoRelease);
        var repository = $"{owner}/{name}";
        var metadata = ParseMetadata(candidate.Value, currentVersion, repository, allowPrerelease: true);
        if (metadata is null || metadata.Sha256 is null && metadata.ChecksumUrl is null)
            return new ReleaseCheckResult(ReleaseCheckStatus.MissingInstaller);
        var release = await ParseReleaseAsync(candidate.Value, repository, currentVersion, cancellationToken,
            allowPrerelease: true).ConfigureAwait(false);
        return release is null
            ? new ReleaseCheckResult(ReleaseCheckStatus.MissingInstaller)
            : new ReleaseCheckResult(ReleaseCheckStatus.UpdateAvailable, release);
    }

    private static JsonElement? SelectRelease(JsonElement releases, Version currentVersion, out bool hasReleases)
    {
        hasReleases = false;
        JsonElement? selected = null;
        Version? selectedVersion = null;
        var selectedIsPrerelease = true;
        foreach (var release in releases.EnumerateArray())
        {
            if (release.GetProperty("draft").GetBoolean()) continue;
            hasReleases = true;
            var tag = release.GetProperty("tag_name").GetString() ?? "";
            if (!TryParseReleaseVersion(tag, out var version, out _, out var taggedPrerelease) ||
                version <= currentVersion) continue;
            var isPrerelease = release.GetProperty("prerelease").GetBoolean() || taggedPrerelease;
            if (selectedVersion is null || version > selectedVersion ||
                version == selectedVersion && selectedIsPrerelease && !isPrerelease)
            {
                selected = release.Clone();
                selectedVersion = version;
                selectedIsPrerelease = isPrerelease;
            }
        }
        return selected;
    }

    private static ReleaseCheckStatus Classify(JsonElement root, Version currentVersion, string? repository)
    {
        if (root.GetProperty("draft").GetBoolean() || root.GetProperty("prerelease").GetBoolean())
            return ReleaseCheckStatus.NoRelease;
        var tag = root.GetProperty("tag_name").GetString() ?? "";
        if (!TryParseReleaseVersion(tag, out var latest, out _, out var taggedPrerelease))
            throw new InvalidDataException("The latest release has an invalid version tag.");
        if (taggedPrerelease) return ReleaseCheckStatus.NoRelease;
        if (latest <= currentVersion) return ReleaseCheckStatus.UpToDate;
        var metadata = ParseMetadata(root, currentVersion, repository);
        return metadata is null || metadata.Sha256 is null && metadata.ChecksumUrl is null
            ? ReleaseCheckStatus.MissingInstaller
            : ReleaseCheckStatus.UpdateAvailable;
    }

    private static async Task<string> ReadLimitedAsync(HttpContent content, int maximumBytes, CancellationToken cancellationToken)
    {
        await using var stream = await content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using var buffer = new MemoryStream();
        var chunk = new byte[1024];
        int read;
        while ((read = await stream.ReadAsync(chunk, cancellationToken).ConfigureAwait(false)) > 0)
        {
            if (buffer.Length + read > maximumBytes) throw new InvalidDataException("The release checksum file is too large.");
            await buffer.WriteAsync(chunk.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
        }
        return System.Text.Encoding.UTF8.GetString(buffer.ToArray());
    }

    private static async Task<ApplicationRelease?> ParseReleaseAsync(JsonElement root, string repository,
        Version currentVersion, CancellationToken cancellationToken, bool allowPrerelease = false)
    {
        var metadata = ParseMetadata(root, currentVersion, repository, allowPrerelease);
        if (metadata is null) return null;
        var digest = metadata.Sha256;
        if (digest is null)
        {
            if (metadata.ChecksumUrl is null) return null;
            using var checksumResponse = await Client.GetAsync(metadata.ChecksumUrl, cancellationToken).ConfigureAwait(false);
            checksumResponse.EnsureSuccessStatusCode();
            if (checksumResponse.Content.Headers.ContentLength is > 4096)
                throw new InvalidDataException("The release checksum file is too large.");
            var text = await ReadLimitedAsync(checksumResponse.Content, 4096, cancellationToken).ConfigureAwait(false);
            digest = ParseChecksum(text, metadata.InstallerName);
        }

        return new ApplicationRelease(metadata.Version, metadata.Tag, metadata.InstallerUrl, digest, metadata.Size,
            metadata.ReleaseUrl, metadata.Notes) { IsPrerelease = metadata.IsPrerelease };
    }

    public static ApplicationRelease? ParseLatestRelease(string json, Version currentVersion)
    {
        using var document = JsonDocument.Parse(json);
        var metadata = ParseMetadata(document.RootElement, currentVersion, null);
        if (metadata?.Sha256 is not { } digest) return null;
        return new ApplicationRelease(metadata.Version, metadata.Tag, metadata.InstallerUrl, digest, metadata.Size,
            metadata.ReleaseUrl, metadata.Notes) { IsPrerelease = metadata.IsPrerelease };
    }

    private static ReleaseMetadata? ParseMetadata(JsonElement root, Version currentVersion, string? repository,
        bool allowPrerelease = false)
    {
        var isPrerelease = root.GetProperty("prerelease").GetBoolean();
        if (root.GetProperty("draft").GetBoolean()) return null;
        var tag = root.GetProperty("tag_name").GetString() ?? "";
        if (!TryParseReleaseVersion(tag, out var version, out var installerVersion, out var taggedPrerelease) ||
            version <= currentVersion) return null;
        isPrerelease |= taggedPrerelease;
        if (isPrerelease && !allowPrerelease) return null;

        var releaseUrl = root.GetProperty("html_url").GetString() ?? "";
        if (!IsGitHubUrl(releaseUrl, "github.com") || repository is not null &&
            !new Uri(releaseUrl).AbsolutePath.StartsWith($"/{repository}/releases/tag/", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Release URL does not match the configured GitHub repository.");
        var installerName = $"BezpiecznyAktualizator-{installerVersion}-win-x64.msi";
        JsonElement? installer = null;
        JsonElement? checksumAsset = null;
        foreach (var asset in root.GetProperty("assets").EnumerateArray())
        {
            var name = asset.GetProperty("name").GetString();
            if (string.Equals(name, installerName, StringComparison.Ordinal)) installer = asset;
            if (string.Equals(name, installerName + ".sha256", StringComparison.Ordinal)) checksumAsset = asset;
        }
        if (installer is not { } msi) return null;

        var size = msi.GetProperty("size").GetInt64();
        if (size <= 0 || size > MaximumInstallerSize)
            throw new InvalidDataException("The update installer has an invalid or excessive size.");
        var download = msi.GetProperty("browser_download_url").GetString() ?? "";
        if (!IsGitHubUrl(download, "github.com") || repository is not null &&
            !new Uri(download).AbsolutePath.StartsWith($"/{repository}/releases/download/", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Installer URL does not match the configured GitHub repository.");
        Uri? checksumUrl = null;
        if (checksumAsset is { } checksum)
        {
            if (checksum.GetProperty("size").GetInt64() is < 1 or > 4096)
                throw new InvalidDataException("The release checksum file has an invalid size.");
            var value = checksum.GetProperty("browser_download_url").GetString() ?? "";
            if (!IsGitHubUrl(value, "github.com") || repository is not null &&
                !new Uri(value).AbsolutePath.StartsWith($"/{repository}/releases/download/", StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Checksum URL does not match the configured GitHub repository.");
            checksumUrl = new Uri(value);
        }
        var notes = root.TryGetProperty("body", out var body) ? body.GetString() ?? "" : "";
        if (notes.Length > 10_000) notes = notes[..10_000];
        return new ReleaseMetadata(version, tag, installerName, new Uri(download), ReadDigest(msi), checksumUrl, size,
            releaseUrl, notes, isPrerelease);
    }

    private static bool TryParseReleaseVersion(string tag, out Version version, out string installerVersion,
        out bool isPrerelease)
    {
        version = new Version(0, 0);
        var value = tag.StartsWith('v') ? tag[1..] : tag;
        var metadataIndex = value.IndexOf('+');
        if (metadataIndex >= 0) value = value[..metadataIndex];
        var prereleaseIndex = value.IndexOf('-');
        isPrerelease = prereleaseIndex >= 0;
        installerVersion = prereleaseIndex >= 0 ? value[..prereleaseIndex] : value;
        return ReleaseTagPattern().IsMatch(value) &&
               Version.TryParse(installerVersion, out version!);
    }

    private static string? ReadDigest(JsonElement asset)
    {
        if (!asset.TryGetProperty("digest", out var digestValue) || digestValue.ValueKind != JsonValueKind.String)
            return null;
        var digest = digestValue.GetString() ?? "";
        if (!digest.StartsWith("sha256:", StringComparison.OrdinalIgnoreCase)) return null;
        var hex = digest[7..];
        return Sha256Pattern().IsMatch(hex) ? hex.ToLowerInvariant() : null;
    }

    private static string ParseChecksum(string text, string expectedFileName)
    {
        var line = text.Trim();
        var match = ChecksumPattern().Match(line);
        if (!match.Success || (match.Groups[2].Success &&
            !string.Equals(match.Groups[2].Value.TrimStart('*'), expectedFileName, StringComparison.Ordinal)))
            throw new InvalidDataException("The release checksum file is invalid.");
        return match.Groups[1].Value.ToLowerInvariant();
    }

    private static bool IsGitHubUrl(string value, string host)
    {
        return Uri.TryCreate(value, UriKind.Absolute, out var uri) &&
               uri.Scheme == Uri.UriSchemeHttps &&
               string.Equals(uri.Host, host, StringComparison.OrdinalIgnoreCase) &&
               uri.UserInfo.Length == 0;
    }

    private static (string Owner, string Repository) ParseRepository(string value)
    {
        var parts = value.Split('/');
        if (parts.Length != 2 || !RepositoryPartPattern().IsMatch(parts[0]) || !RepositoryPartPattern().IsMatch(parts[1]))
            throw new ArgumentException("Expected a GitHub repository in owner/name form.", nameof(value));
        return (parts[0], parts[1]);
    }

    private static HttpClient CreateClient()
    {
        var client = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("BezpiecznyAktualizator/2.1");
        return client;
    }

    private sealed record ReleaseMetadata(Version Version, string Tag, string InstallerName, Uri InstallerUrl,
        string? Sha256, Uri? ChecksumUrl, long Size, string ReleaseUrl, string Notes, bool IsPrerelease);

    [GeneratedRegex(@"^\d+\.\d+\.\d+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?(?:\+[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$", RegexOptions.CultureInvariant)]
    private static partial Regex ReleaseTagPattern();

    [GeneratedRegex(@"^[0-9a-fA-F]{64}$", RegexOptions.CultureInvariant)]
    private static partial Regex Sha256Pattern();

    [GeneratedRegex(@"^\s*([0-9a-fA-F]{64})(?:\s+[* ]?(.+))?\s*$", RegexOptions.CultureInvariant)]
    private static partial Regex ChecksumPattern();

    [GeneratedRegex(@"^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$", RegexOptions.CultureInvariant)]
    private static partial Regex RepositoryPartPattern();
}
