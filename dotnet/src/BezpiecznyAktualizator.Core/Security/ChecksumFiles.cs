using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace BezpiecznyAktualizator.Core.Security;

/// <summary>Pojedynczy wpis pliku kontrolnego; FileName == null dla plików zawierających samą sumę.</summary>
public sealed record ChecksumEntry(string Algorithm, string Hash, string? FileName);

public sealed record FileDigests(string Sha256, string Sha512)
{
    public string For(string algorithm) => algorithm == ChecksumFiles.Sha512 ? Sha512 : Sha256;

    public static FileDigests Compute(string path)
    {
        using var sha256 = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        using var sha512 = IncrementalHash.CreateHash(HashAlgorithmName.SHA512);
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 16, FileOptions.SequentialScan);
        var buffer = new byte[1 << 16];
        int read;
        while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
        {
            sha256.AppendData(buffer, 0, read);
            sha512.AppendData(buffer, 0, read);
        }
        return new FileDigests(Convert.ToHexStringLower(sha256.GetHashAndReset()),
                               Convert.ToHexStringLower(sha512.GetHashAndReset()));
    }
}

/// <summary>Parsowanie i dopasowywanie plików kontrolnych (SHA256SUMS, *.sha256, BSD "SHA256 (plik) = ...").</summary>
public static partial class ChecksumFiles
{
    public const string Sha256 = "SHA256";
    public const string Sha512 = "SHA512";
    public const int MaxSize = 1 << 20;

    internal static readonly string[] SidecarExtensions = [".sha256", ".sha256sum", ".sha256.txt", ".sha512", ".sha512sum"];
    internal static readonly string[] DirectoryFiles = ["SHA256SUMS", "SHA256SUMS.txt", "sha256sums.txt", "checksums.txt", "SHA512SUMS"];

    private static string? AlgorithmFor(string hex) => hex.Length switch { 64 => Sha256, 128 => Sha512, _ => null };

    public static List<ChecksumEntry> Parse(string text)
    {
        var entries = new List<ChecksumEntry>();
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.Trim().TrimStart('\uFEFF');
            if (line.Length == 0 || line.StartsWith('#')) continue;
            Match m;
            if ((m = Bsd().Match(line)).Success)
            {
                var alg = m.Groups["alg"].Value.Replace("-", "").ToUpperInvariant();
                var hex = m.Groups["hex"].Value;
                if (AlgorithmFor(hex) == alg) entries.Add(new(alg, hex.ToLowerInvariant(), m.Groups["name"].Value.Trim()));
            }
            else if ((m = Gnu().Match(line)).Success)
            {
                var hex = m.Groups["hex"].Value;
                var name = m.Groups["name"].Success ? m.Groups["name"].Value.Trim() : null;
                entries.Add(new(AlgorithmFor(hex)!, hex.ToLowerInvariant(), string.IsNullOrEmpty(name) ? null : name));
            }
            else if ((m = Reversed().Match(line)).Success)
            {
                var hex = m.Groups["hex"].Value;
                entries.Add(new(AlgorithmFor(hex)!, hex.ToLowerInvariant(), m.Groups["name"].Value.Trim()));
            }
        }
        return entries;
    }

    private static string BaseName(string name)
    {
        var n = name.Trim().TrimStart('*').Replace('\\', '/');
        return n[(n.LastIndexOf('/') + 1)..];
    }

    /// <summary>Szuka wpisu dla pliku; wpisy bez nazwy są brane pod uwagę tylko dla plików "obok" instalatora.</summary>
    public static ChecksumEntry? Find(IEnumerable<ChecksumEntry> entries, string fileName, bool allowUnnamed)
    {
        var list = entries.ToList();
        var named = list.FirstOrDefault(e => e.FileName is not null &&
                                             string.Equals(BaseName(e.FileName), fileName, StringComparison.OrdinalIgnoreCase));
        if (named is not null) return named;
        return allowUnnamed && list.Count == 1 && list[0].FileName is null ? list[0] : null;
    }

    public static bool Matches(ChecksumEntry entry, FileDigests digests) =>
        string.Equals(entry.Hash, digests.For(entry.Algorithm), StringComparison.OrdinalIgnoreCase);

    /// <summary>Nazwa pliku z adresu URL (winget zmienia nazwę pobranego pliku, więc porównujemy z oryginałem).</summary>
    public static string FileNameFromUrl(string url) =>
        Uri.TryCreate(url, UriKind.Absolute, out var uri)
            ? Uri.UnescapeDataString(uri.AbsolutePath[(uri.AbsolutePath.LastIndexOf('/') + 1)..])
            : "";

    /// <summary>Adresy, pod którymi wydawcy zwykle publikują pliki kontrolne (tylko HTTPS).</summary>
    public static List<(Uri Url, bool Sidecar)> Candidates(string installerUrl)
    {
        var list = new List<(Uri, bool)>();
        if (!Uri.TryCreate(installerUrl, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps) return list;
        var path = uri.GetLeftPart(UriPartial.Path);
        if (FileNameFromUrl(installerUrl).Length > 0)
            list.AddRange(SidecarExtensions.Select(ext => (new Uri(path + ext), true)));
        list.AddRange(DirectoryFiles.Select(name => (new Uri(uri, name), false)));
        return list;
    }

    public sealed record GitHubRelease(string Owner, string Repo, string Tag, string File);

    public static GitHubRelease? ParseGitHubRelease(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)) return null;
        var m = GitHubDownload().Match(uri.GetLeftPart(UriPartial.Path));
        return m.Success
            ? new(m.Groups["owner"].Value, m.Groups["repo"].Value, m.Groups["tag"].Value, Uri.UnescapeDataString(m.Groups["file"].Value))
            : null;
    }

    /// <summary>Czy zasób wydania wygląda na plik kontrolny dla podanego instalatora.</summary>
    public static bool IsChecksumAsset(string assetName, string installerFile)
    {
        var n = assetName.ToLowerInvariant();
        if (SidecarExtensions.Any(ext => string.Equals(assetName, installerFile + ext, StringComparison.OrdinalIgnoreCase)))
            return true;
        if (n.EndsWith(".sig") || n.EndsWith(".asc") || n.EndsWith(".exe") || n.EndsWith(".msi") || n.EndsWith(".zip")) return false;
        return n.Contains("sha256") || n.Contains("sha512") || n.Contains("checksum") || n.Contains("sums");
    }

    [GeneratedRegex(@"^(?<alg>SHA-?(?:256|512))\s*\((?<name>.+)\)\s*=\s*(?<hex>[0-9A-Fa-f]+)$", RegexOptions.IgnoreCase)]
    private static partial Regex Bsd();

    [GeneratedRegex(@"^(?<hex>[0-9A-Fa-f]{128}|[0-9A-Fa-f]{64})(?:\s+\*?(?<name>.+))?$")]
    private static partial Regex Gnu();

    [GeneratedRegex(@"^(?<name>\S.*?)[\s:=]+(?<hex>[0-9A-Fa-f]{128}|[0-9A-Fa-f]{64})$")]
    private static partial Regex Reversed();

    [GeneratedRegex(@"^https://github\.com/(?<owner>[^/]+)/(?<repo>[^/]+)/releases/download/(?<tag>[^/]+)/(?<file>[^/]+)$",
                    RegexOptions.IgnoreCase)]
    private static partial Regex GitHubDownload();
}
