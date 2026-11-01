using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;
using BezpiecznyAktualizator.Core.Localization;
using BezpiecznyAktualizator.Core.Security;

namespace BezpiecznyAktualizator.Core.Catalogs;

public sealed class CatalogException(string message, Exception? inner = null) : Exception(message, inner);

public sealed record CatalogPackage(string Manager, string Name, string Id, string Version, string Source,
                                    string DetailsUrl = "", string Homepage = "", JsonObject? Manifest = null);

/// <summary>Dodatkowe katalogi: Scoop Main i Chocolatey Community.</summary>
public static partial class CatalogClient
{
    private const string ScoopTreeUrl = "https://api.github.com/repos/ScoopInstaller/Main/git/trees/master?recursive=1";
    private const string ScoopRawUrl = "https://raw.githubusercontent.com/ScoopInstaller/Main/master/bucket/";
    private const string ChocoSearchUrl = "https://community.chocolatey.org/api/v2/Search()";

    private static readonly HttpClient Http = CreateClient();
    private static IReadOnlyList<string>? _scoopTree;
    private static readonly SemaphoreSlim TreeLock = new(1, 1);

    private static HttpClient CreateClient()
    {
        var client = new HttpClient(new SocketsHttpHandler { AutomaticDecompression = System.Net.DecompressionMethods.All })
        {
            Timeout = TimeSpan.FromSeconds(45),
        };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("BezpiecznyAktualizator/2.0");
        return client;
    }

    private static async Task<string> ReadUrlAsync(string url, CancellationToken ct)
    {
        try
        {
            using var response = await Http.GetAsync(url, ct);
            response.EnsureSuccessStatusCode();
            if (response.RequestMessage?.RequestUri?.Scheme != Uri.UriSchemeHttps)
                throw new CatalogException(L.F("Odpowiedź z {0} nie pochodzi z połączenia HTTPS.", url));
            return await response.Content.ReadAsStringAsync(ct);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            throw new CatalogException(L.F("Nie udało się pobrać danych z {0}: {1}", url, ex.Message), ex);
        }
    }

    private static string Quote(string s) => Uri.EscapeDataString(s);

    // ------------------------------------------------------------------ Scoop
    internal static List<string> ScoopSlugs(string query, IEnumerable<string> paths, int limit = 8)
    {
        var lowered = query.ToLowerInvariant();
        var tokens = AlnumTokens().Matches(lowered).Select(m => m.Value).Where(t => t.Length > 1).ToList();
        if (tokens.Count == 0) return [];
        var files = paths.Where(p => p.StartsWith("bucket/", StringComparison.Ordinal) && p.EndsWith(".json", StringComparison.Ordinal))
                         .Select(p => p["bucket/".Length..^".json".Length]).ToList();
        var normalizedQuery = NonAlnum().Replace(lowered, "");
        var exact = files.Where(s => NonAlnum().Replace(s.ToLowerInvariant(), "") == normalizedQuery);
        var matching = files.Where(s => tokens.Any(t =>
            Regex.IsMatch(s.ToLowerInvariant(), $"(?<![a-z0-9]){Regex.Escape(t)}(?![a-z0-9])")));
        return exact.Concat(matching).Distinct().Take(limit).ToList();
    }

    private static async Task<IReadOnlyList<string>> ScoopTreeAsync(CancellationToken ct)
    {
        if (_scoopTree is not null) return _scoopTree;
        await TreeLock.WaitAsync(ct);
        try
        {
            if (_scoopTree is not null) return _scoopTree;
            var data = JsonNode.Parse(await ReadUrlAsync(ScoopTreeUrl, ct)) as JsonObject
                       ?? throw new CatalogException(L.T("Nieprawidłowa odpowiedź GitHub API dla Scoop Main."));
            if (data["truncated"]?.GetValue<bool>() == true || data["tree"] is not JsonArray tree)
                throw new CatalogException(L.T("Lista manifestów Scoop Main jest niekompletna."));
            return _scoopTree = tree.OfType<JsonObject>().Select(e => e["path"]?.GetValue<string>())
                                    .OfType<string>().ToList();
        }
        catch (JsonException ex)
        {
            throw new CatalogException(L.F("Nieprawidłowa odpowiedź GitHub API dla Scoop Main: {0}", ex.Message), ex);
        }
        finally
        {
            TreeLock.Release();
        }
    }

    /// <summary>Wyszukuje wyłącznie w oficjalnym Scoop Main; nie korzysta z dodatkowych bucketów.</summary>
    public static async Task<List<CatalogPackage>> SearchScoopAsync(string query, CancellationToken ct = default)
    {
        var packages = new List<CatalogPackage>();
        foreach (var slug in ScoopSlugs(query, await ScoopTreeAsync(ct)))
        {
            JsonObject manifest;
            try
            {
                manifest = JsonNode.Parse(await ReadUrlAsync(ScoopRawUrl + Quote(slug) + ".json", ct)) as JsonObject
                           ?? throw new CatalogException(L.F("Nieprawidłowy manifest Scoop Main: {0}", slug));
            }
            catch (JsonException ex)
            {
                throw new CatalogException(L.F("Nieprawidłowy manifest Scoop Main: {0}", slug), ex);
            }
            packages.Add(new CatalogPackage(
                "scoop", slug, slug, JsonString(manifest["version"]), "Scoop Main",
                "https://github.com/ScoopInstaller/Main/blob/master/bucket/" + Quote(slug) + ".json",
                JsonString(manifest["homepage"]), manifest));
        }
        return packages;
    }

    private static string JsonString(JsonNode? node) =>
        node is JsonValue v && v.TryGetValue<string>(out var s) ? s : node?.ToString() ?? "";

    // ------------------------------------------------------------- Chocolatey
    /// <summary>Wyszukuje pakiety w oficjalnym, moderowanym kanale Chocolatey Community.</summary>
    public static async Task<List<CatalogPackage>> SearchChocolateyAsync(string query, CancellationToken ct = default)
    {
        var escaped = query.Replace("'", "''");
        var url = $"{ChocoSearchUrl}?searchTerm={Quote($"'{escaped}'")}&targetFramework={Quote("''")}&includePrerelease=false";
        return ParseChocolateyFeed(await ReadUrlAsync(url, ct));
    }

    internal static List<CatalogPackage> ParseChocolateyFeed(string xml)
    {
        XDocument doc;
        try
        {
            doc = XDocument.Parse(xml, LoadOptions.None);
        }
        catch (XmlException ex)
        {
            throw new CatalogException(L.F("Chocolatey zwróciło nieprawidłową odpowiedź XML: {0}", ex.Message), ex);
        }

        string ChildText(XElement e, string name) =>
            e.Descendants().FirstOrDefault(d => d.Name.LocalName == name && d.Value.Trim().Length > 0)?.Value.Trim() ?? "";

        var packages = new List<CatalogPackage>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in doc.Descendants().Where(e => e.Name.LocalName == "entry"))
        {
            var idElement = entry.Elements().FirstOrDefault(c => c.Name.LocalName == "id");
            var m = idElement is null ? Match.Empty : ChocoId().Match(idElement.Value);
            if (!m.Success) continue;
            var id = m.Groups[1].Value;
            if (!seen.Add(id)) continue;
            var title = ChildText(entry, "Title") is { Length: > 0 } t ? t : ChildText(entry, "title") is { Length: > 0 } t2 ? t2 : id;
            var version = ChildText(entry, "Version") is { Length: > 0 } v ? v : m.Groups[2].Value;
            packages.Add(new CatalogPackage(
                "chocolatey", title, id, version, "Chocolatey Community",
                "https://community.chocolatey.org/packages/" + Quote(id) + (version.Length > 0 ? "/" + Quote(version) : ""),
                ChildText(entry, "ProjectUrl")));
            if (packages.Count >= 30) break;
        }
        return packages;
    }

    // ------------------------------------------------------------- Assessment
    internal static List<(string Url, string Hash)> InstallerPairs(JsonObject manifest)
    {
        var pairs = new List<(string, string)>();

        static List<string?> AsList(JsonNode? node) => node switch
        {
            JsonArray a => a.Select(x => x is JsonValue v && v.TryGetValue<string>(out var s) ? s : null).ToList(),
            JsonValue v when v.TryGetValue<string>(out var s) => [s],
            _ => [],
        };

        void Collect(JsonNode? node)
        {
            if (node is not JsonObject obj) return;
            var urls = AsList(obj["url"]);
            var hashes = AsList(obj["hash"]);
            for (var i = 0; i < urls.Count; i++)
                if (urls[i] is { } u) pairs.Add((u, i < hashes.Count ? hashes[i] ?? "" : ""));
        }

        Collect(manifest);
        if (manifest["architecture"] is JsonObject arch)
            foreach (var (_, node) in arch) Collect(node);
        return pairs;
    }

    private static bool UninstallerIsScript(JsonNode? node) =>
        node is JsonObject or JsonArray ||
        (node is JsonValue v && v.TryGetValue<string>(out var s) && PsScript().IsMatch(s));

    internal static bool ManifestHasScripts(JsonObject manifest)
    {
        string[] scriptKeys = ["pre_install", "installer", "post_install"];
        if (scriptKeys.Any(manifest.ContainsKey)) return true;
        if (manifest["architecture"] is JsonObject arch)
        {
            foreach (var (_, node) in arch)
            {
                if (node is not JsonObject details) continue;
                if (scriptKeys.Any(details.ContainsKey) || UninstallerIsScript(details["uninstaller"])) return true;
            }
        }
        return UninstallerIsScript(manifest["uninstaller"]);
    }

    public static async Task<Assessment> AssessScoopAsync(CatalogPackage package, bool verifyTls = true,
                                                          CancellationToken ct = default)
    {
        var manifest = package.Manifest ?? [];
        var checks = new List<Check>
        {
            new(L.Txt("Źródło: oficjalny Scoop Main"), CheckStatus.Ok,
                L.Txt("Wynik pochodzi z repozytorium ScoopInstaller/Main, a nie z dodatkowego bucketu.")),
            new(L.Txt("Manifest nie jest podpisany kryptograficznie"), CheckStatus.Warn,
                L.Txt("Zaufanie opiera się na oficjalnym repozytorium i HTTPS; sprawdź źródło przed instalacją.")),
            new(L.Txt("Manifest pobrany przez HTTPS z GitHub"), CheckStatus.Ok,
                L.Txt("Aplikacja pobiera manifest z oficjalnego repozytorium ScoopInstaller/Main.")),
        };
        var pairs = InstallerPairs(manifest);
        if (pairs.Count == 0)
            checks.Add(new Check(L.Txt("Adres instalatora"), CheckStatus.Fail, L.Txt("Manifest nie zawiera adresu URL instalatora.")));
        foreach (var (url, digest) in pairs.Take(5))
        {
            var https = url.StartsWith("https://", StringComparison.OrdinalIgnoreCase);
            checks.Add(https
                ? new Check(L.Txt("Instalator przez HTTPS"), CheckStatus.Ok, url)
                : new Check(L.Txt("Instalator bez HTTPS lub z adresem dynamicznym"), CheckStatus.Fail, url));
            checks.Add(SecurityRules.IsSha256(digest)
                ? new Check(L.Txt("Suma SHA256 w manifeście"), CheckStatus.Ok, digest)
                : new Check(L.Txt("Brak weryfikowalnej sumy SHA256"), CheckStatus.Fail,
                    L.Txt("Scoop nie może zweryfikować integralności tego instalatora.")));
            if (verifyTls && https) checks.Add(await SecurityRules.CheckTlsAsync(url, ct));
        }

        var hasScript = ManifestHasScripts(manifest);
        if (hasScript)
            checks.Add(new Check(L.Txt("Manifest zawiera skrypt instalacyjny"), CheckStatus.Warn,
                L.Txt("Scoop może wykonać skrypt dostarczony przez manifest; przejrzyj go w repozytorium.")));

        // Oficjalny bucket i SHA256 są dobrym sygnałem, ale manifesty nie są podpisywane.
        var level = checks.Any(c => c.Status == CheckStatus.Fail) || hasScript ? Levels.Low : Levels.Medium;
        return new Assessment(level, checks, L.Txt("Pakiet {0} w wersji {1} z oficjalnego Scoop Main.", package.Id, package.Version));
    }

    public static Assessment AssessChocolatey(CatalogPackage package) => new(Levels.Low,
    [
        new(L.Txt("Źródło: Chocolatey Community"), CheckStatus.Ok,
            L.Txt("Oficjalny kanał społecznościowy z moderacją publikowanych wersji pakietów.")),
        new(L.Txt("Metadane pobrane przez HTTPS"), CheckStatus.Ok,
            L.Txt("Odpowiedź pochodzi z community.chocolatey.org po weryfikacji certyfikatu TLS.")),
        new(L.Txt("Pakiet może uruchamiać skrypty PowerShell"), CheckStatus.Fail,
            L.Txt("Moderacja nie oznacza skanowania instalowanego programu; skrypty pakietów mogą wykonywać dowolne działania.")),
        new(L.Txt("Źródło binariów i sumy kontrolne nie są tu zweryfikowane"), CheckStatus.Warn,
            L.Txt("Przed instalacją sprawdź stronę pakietu i zgodność wydawcy z witryną producenta.")),
    ], L.Txt("Pakiet {0} w wersji {1}; ręcznie moderowany kanał publiczny.", package.Id, package.Version));

    [GeneratedRegex("[a-z0-9]+")]
    private static partial Regex AlnumTokens();

    [GeneratedRegex("[^a-z0-9]")]
    private static partial Regex NonAlnum();

    [GeneratedRegex(@"Packages\(Id='([^']+)',Version='([^']+)'\)")]
    private static partial Regex ChocoId();

    [GeneratedRegex(@"\.ps1\b|powershell", RegexOptions.IgnoreCase)]
    private static partial Regex PsScript();
}
