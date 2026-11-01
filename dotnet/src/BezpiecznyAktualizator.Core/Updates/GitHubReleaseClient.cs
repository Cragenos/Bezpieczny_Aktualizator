using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace BezpiecznyAktualizator.Core.Updates;

public sealed record ApplicationRelease(Version Version, string Tag, Uri InstallerUrl, string Sha256, long Size,
    string ReleaseUrl, string Notes);

/// <summary>Reads the latest stable MSI release and its SHA-256 digest from a public GitHub repository.</summary>
public static partial class GitHubReleaseClient
{
    private const long MaximumInstallerSize = 512L * 1024 * 1024;
    private static readonly HttpClient Client = CreateClient();

    public static async Task<ApplicationRelease?> GetLatestAsync(string repository, Version currentVersion,
        CancellationToken cancellationToken = default)
    {
        var (owner, name) = ParseRepository(repository);
        var api = new Uri($"https://api.github.com/repos/{owner}/{name}/releases/latest");
        using var request = new HttpRequestMessage(HttpMethod.Get, api);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
        using var response = await Client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken)
            .ConfigureAwait(false);
        if (response.StatusCode == HttpStatusCode.NotFound) return null;
        response.EnsureSuccessStatusCode();
        using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using var json = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken).ConfigureAwait(false);
        return await ParseReleaseAsync(json.RootElement, $"{owner}/{name}", currentVersion, cancellationToken).ConfigureAwait(false);
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
        Version currentVersion, CancellationToken cancellationToken)
    {
        var metadata = ParseMetadata(root, currentVersion, repository);
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
            metadata.ReleaseUrl, metadata.Notes);
    }

    public static ApplicationRelease? ParseLatestRelease(string json, Version currentVersion)
    {
        using var document = JsonDocument.Parse(json);
        var metadata = ParseMetadata(document.RootElement, currentVersion, null);
        if (metadata?.Sha256 is not { } digest) return null;
        return new ApplicationRelease(metadata.Version, metadata.Tag, metadata.InstallerUrl, digest, metadata.Size,
            metadata.ReleaseUrl, metadata.Notes);
    }

    private static ReleaseMetadata? ParseMetadata(JsonElement root, Version currentVersion, string? repository)
    {
        if (root.GetProperty("draft").GetBoolean() || root.GetProperty("prerelease").GetBoolean()) return null;
        var tag = root.GetProperty("tag_name").GetString() ?? "";
        var versionText = tag.StartsWith('v') ? tag[1..] : tag;
        if (!Version.TryParse(versionText, out var version) || version <= currentVersion) return null;

        var releaseUrl = root.GetProperty("html_url").GetString() ?? "";
        if (!IsGitHubUrl(releaseUrl, "github.com") || repository is not null &&
            !new Uri(releaseUrl).AbsolutePath.StartsWith($"/{repository}/releases/tag/", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Release URL does not match the configured GitHub repository.");
        var installerName = $"BezpiecznyAktualizator-{version}-win-x64.msi";
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
        return new ReleaseMetadata(version, tag, installerName, new Uri(download), ReadDigest(msi), checksumUrl, size,
            releaseUrl, notes);
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
        string? Sha256, Uri? ChecksumUrl, long Size, string ReleaseUrl, string Notes);

    [GeneratedRegex(@"^[0-9a-fA-F]{64}$", RegexOptions.CultureInvariant)]
    private static partial Regex Sha256Pattern();

    [GeneratedRegex(@"^\s*([0-9a-fA-F]{64})(?:\s+[* ]?(.+))?\s*$", RegexOptions.CultureInvariant)]
    private static partial Regex ChecksumPattern();

    [GeneratedRegex(@"^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$", RegexOptions.CultureInvariant)]
    private static partial Regex RepositoryPartPattern();
}
