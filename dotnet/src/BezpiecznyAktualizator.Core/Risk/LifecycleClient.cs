using System.Globalization;
using System.Net;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using BezpiecznyAktualizator.Core.Localization;
using BezpiecznyAktualizator.Core.Models;

namespace BezpiecznyAktualizator.Core.Risk;

/// <param name="IsMaintained">Czy wersja nadal dostaje poprawki, także w ramach wsparcia rozszerzonego (null = brak danych).</param>
/// <param name="EoesFrom">Koniec wsparcia rozszerzonego.</param>
public sealed record EolRelease(string Name, string Label, bool IsEol, DateOnly? EolFrom, string Latest, DateOnly? LatestDate,
                                bool? IsMaintained = null, DateOnly? EoesFrom = null);

public sealed record EolProduct(string Name, string Label, IReadOnlyList<string> Aliases, string Category, string Cpe,
                                string Link, IReadOnlyList<EolRelease> Releases);

/// <summary>
/// Wykrywanie programów nieobsługiwanych (EOL) na podstawie otwartej bazy endoflife.date
/// oraz programów porzuconych (zarchiwizowane repozytorium GitHub, brak nowych wydań od lat).
/// </summary>
public static partial class LifecycleClient
{
    private const string ProductsUrl = "https://endoflife.date/api/v1/products/full";
    private const string ProductsCacheFile = "endoflife.json";
    private const string GitHubCacheFile = "github-repos.json";
    public static readonly TimeSpan ProductsCacheTtl = TimeSpan.FromHours(24);
    public static readonly TimeSpan GitHubCacheTtl = TimeSpan.FromDays(7);

    /// <summary>Brak nowych wydań / zmian przez tyle dni oznacza program prawdopodobnie porzucony.</summary>
    public const int AbandonedAfterDays = 3 * 365;

    /// <summary>Tyle dni po końcu wsparcia wersji, dla której jest już wspierana następczyni, nie oznaczamy jej jako EOL.</summary>
    public const int EolGraceDays = 60;

    private static readonly HashSet<string> SkippedCategories = new(StringComparer.OrdinalIgnoreCase) { "os", "device", "service" };

    /// <summary>Nazwy programów Windows, których nie da się dopasować po etykiecie produktu.</summary>
    internal static readonly (Regex Name, string Product)[] Aliases =
    [
        (new(@"^Microsoft (\.NET|Windows Desktop|ASP\.NET Core)( Core)? (Runtime|Shared Framework|Host)\b", RegexOptions.IgnoreCase), "dotnet"),
        (new(@"^Java(\(TM\))? (SE )?(Development Kit )?\d+", RegexOptions.IgnoreCase), "oracle-jdk"),
        (new(@"^Microsoft Visual Studio (Community|Professional|Enterprise|Build Tools) \d{4}", RegexOptions.IgnoreCase), "visual-studio"),
        (new(@"^Microsoft Office\b", RegexOptions.IgnoreCase), "office"),
    ];

    private static readonly HashSet<string> TrailingNoise = new(StringComparer.OrdinalIgnoreCase)
    {
        "x64", "x86", "amd64", "arm64", "64", "32", "bit", "win64", "win32", "version", "for", "windows", "esr", "update", "lts", "stable",
    };

    // ------------------------------------------------------------- endoflife.date
    internal static List<EolProduct> ParseProducts(JsonNode root)
    {
        var list = new List<EolProduct>();
        foreach (var p in root["result"]?.AsArray().OfType<JsonObject>() ?? [])
        {
            var name = p["name"]?.GetValue<string>() ?? "";
            if (name.Length == 0) continue;
            var cpe = (p["identifiers"]?.AsArray().OfType<JsonObject>() ?? [])
                .Where(i => i["type"]?.GetValue<string>() == "cpe")
                .Select(i => i["id"]?.GetValue<string>() ?? "")
                .Select(id => CpeProduct().Match(id))
                .Where(m => m.Success).Select(m => $"{m.Groups["v"].Value}:{m.Groups["p"].Value}")
                .Distinct().FirstOrDefault() ?? "";
            var releases = (p["releases"]?.AsArray().OfType<JsonObject>() ?? []).Select(r => new EolRelease(
                r["name"]?.GetValue<string>() ?? "",
                r["label"]?.GetValue<string>() ?? r["name"]?.GetValue<string>() ?? "",
                r["isEol"]?.GetValue<bool>() ?? false,
                Date(r["eolFrom"]),
                r["latest"]?["name"]?.GetValue<string>() ?? "",
                Date(r["latest"]?["date"]),
                r["isMaintained"] is JsonValue m && m.TryGetValue<bool>(out var maintained) ? maintained : null,
                Date(r["eoesFrom"]))).Where(r => r.Name.Length > 0).ToList();
            list.Add(new EolProduct(name, p["label"]?.GetValue<string>() ?? name,
                (p["aliases"]?.AsArray() ?? []).Select(a => a?.GetValue<string>() ?? "").Where(a => a.Length > 0).ToList(),
                p["category"]?.GetValue<string>() ?? "", cpe,
                p["links"]?["html"]?.GetValue<string>() ?? $"https://endoflife.date/{name}", releases));
        }
        return list;
    }

    private static DateOnly? Date(JsonNode? node) =>
        node is JsonValue v && v.TryGetValue<string>(out var s) &&
        DateOnly.TryParseExact(s, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var d) ? d : null;

    private static List<string> Tokens(string s) => AlnumTokens().Matches(s.ToLowerInvariant()).Select(m => m.Value).ToList();

    /// <summary>Dopasowuje program do produktu endoflife.date (po etykiecie, nazwie, aliasach lub wbudowanych wzorcach).</summary>
    internal static EolProduct? MatchProduct(Software s, IReadOnlyList<EolProduct> products)
    {
        var name = s.Name.Trim();
        foreach (var (pattern, product) in Aliases)
            if (pattern.IsMatch(name)) return products.FirstOrDefault(p => p.Name == product);

        var tokens = Tokens(name);
        if (tokens.Count == 0) return null;
        // Nazwa wydawcy na początku (np. „Mozilla Firefox”) nie jest częścią nazwy produktu.
        var publisher = Software.NormalizeName(s.Publisher);
        var variants = new List<List<string>> { tokens };
        if (tokens.Count > 1 && publisher.Length > 0 && publisher.Contains(tokens[0])) variants.Add(tokens.Skip(1).ToList());

        EolProduct? best = null;
        var bestLength = 0;
        foreach (var p in products)
        {
            if (SkippedCategories.Contains(p.Category)) continue;
            var keys = new[] { p.Label, p.Name.Replace('-', ' ') }.Concat(p.Aliases.Select(a => a.Replace('-', ' ')))
                .Select(Tokens).Where(k => k.Count > 0 && string.Concat(k).Length >= 3);
            foreach (var key in keys)
            foreach (var v in variants)
            {
                if (key.Count > v.Count || !key.SequenceEqual(v.Take(key.Count))) continue;
                var next = v.Count > key.Count ? v[key.Count] : null;
                if (next is not null && !char.IsDigit(next[0]) && !TrailingNoise.Contains(next)) continue;
                var length = string.Concat(key).Length;
                if (length > bestLength)
                {
                    best = p;
                    bestLength = length;
                }
            }
        }
        return best;
    }

    /// <summary>Wybiera cykl wydań odpowiadający zainstalowanej wersji (najdłuższy pasujący prefiks lub rok w nazwie).</summary>
    internal static EolRelease? MatchRelease(EolProduct product, string name, string version)
    {
        var parts = NvdClient.CpeVersion(version).Split('.', StringSplitOptions.RemoveEmptyEntries);
        EolRelease? best = null;
        var bestDepth = 0;
        foreach (var r in product.Releases)
        {
            var cycle = r.Name.Split('.');
            if (!cycle.All(c => c.Length > 0 && c.All(char.IsDigit)) || cycle.Length > parts.Length) continue;
            var matches = cycle.Select((c, i) => int.Parse(c, CultureInfo.InvariantCulture) == ParseInt(parts[i])).All(b => b);
            if (matches && cycle.Length > bestDepth)
            {
                best = r;
                bestDepth = cycle.Length;
            }
        }
        if (best is not null) return best;
        var nameTokens = Tokens(name);
        return product.Releases.FirstOrDefault(r => r.Name.Length >= 4 && r.Name.All(char.IsDigit) && nameTokens.Contains(r.Name));
    }

    private static int ParseInt(string s) => int.TryParse(s, NumberStyles.None, CultureInfo.InvariantCulture, out var v) ? v : -1;

    /// <summary>Ocena cyklu życia na podstawie dopasowanego produktu i cyklu.</summary>
    internal static LifecycleInfo Evaluate(EolProduct product, EolRelease release, DateOnly today)
    {
        var info = new LifecycleInfo
        {
            Origin = "endoflife.date", Product = product.Label, Cycle = release.Label, Latest = release.Latest,
            EolFrom = release.EolFrom, Link = product.Link,
        };
        var newer = product.Releases.FirstOrDefault(r => r.Name != release.Name && !IsEnded(r, today));
        var eol = IsEnded(release, today);
        // Przy szybkich cyklach wydań (np. Firefox, Chrome) wersja traci wsparcie w dniu wydania następnej -
        // to zwykła zaległa aktualizacja, a nie program bez wsparcia.
        if (eol && newer is not null && release.EolFrom is { } ended && today.DayNumber - ended.DayNumber <= EolGraceDays)
        {
            info.State = LifecycleState.Supported;
            info.Reason = L.Txt("Wersja {0} przestała otrzymywać poprawki {1:yyyy-MM-dd} po wydaniu nowszej - zaktualizuj do wersji {2}.",
                                release.Label, ended, newer.Label);
            return info;
        }
        if (eol)
        {
            var newest = newer;
            info.State = newest is null ? LifecycleState.Abandoned : LifecycleState.Eol;
            info.Reason = newest is null
                ? L.Txt("Produkt {0} nie jest już rozwijany - żadna wersja nie otrzymuje poprawek bezpieczeństwa.", product.Label)
                : release.EolFrom is { } from
                    ? L.Txt("Wersja {0} nie otrzymuje poprawek bezpieczeństwa od {1:yyyy-MM-dd}. Wspierana jest m.in. wersja {2}.", release.Label, from, newest.Label)
                    : L.Txt("Wersja {0} nie otrzymuje już poprawek bezpieczeństwa. Wspierana jest m.in. wersja {1}.", release.Label, newest.Label);
            return info;
        }
        info.State = LifecycleState.Supported;
        // Po końcu wsparcia standardowego wersja może być nadal łatana w ramach wsparcia rozszerzonego (np. Java 8).
        var supportedUntil = release.EolFrom is { } std && std <= today ? release.EoesFrom : release.EolFrom;
        info.EolFrom = supportedUntil;
        info.Reason = supportedUntil is { } until
            ? L.Txt("Wersja {0} jest wspierana do {1:yyyy-MM-dd}.", release.Label, until)
            : L.Txt("Wersja {0} jest wspierana.", release.Label);
        return info;
    }

    private static bool IsEnded(EolRelease r, DateOnly today) =>
        r.IsMaintained is { } maintained ? !maintained : r.IsEol || (r.EolFrom is { } d && d <= today);

    private static readonly SemaphoreSlim ProductsLock = new(1, 1);
    private static List<EolProduct>? _products;

    // Zapisywana w JSON: nazwy właściwości nie mogą być zmieniane przez zaciemnianie kodu.
    [System.Reflection.Obfuscation(Exclude = true)]
    private sealed class ProductsCache
    {
        public DateTimeOffset Time { get; set; }
        public string Json { get; set; } = "";
    }

    public static async Task<IReadOnlyList<EolProduct>> ProductsAsync(CancellationToken ct = default)
    {
        await ProductsLock.WaitAsync(ct);
        try
        {
            if (_products is not null) return _products;
            var cached = RiskHttp.LoadCache<ProductsCache>(ProductsCacheFile);
            if (cached is not null && DateTimeOffset.UtcNow - cached.Time < ProductsCacheTtl && cached.Json.Length > 0)
            {
                try
                {
                    return _products = ParseProducts(RiskHttp.ParseJson(cached.Json, ProductsUrl));
                }
                catch (RiskException) { }
            }
            try
            {
                var (status, body) = await RiskHttp.GetAsync(ProductsUrl, null, ct);
                if (status != HttpStatusCode.OK) throw new RiskException(L.F("Serwis endoflife.date zwrócił kod HTTP {0}.", (int)status));
                _products = ParseProducts(RiskHttp.ParseJson(body, ProductsUrl));
                RiskHttp.SaveCache(ProductsCacheFile, new ProductsCache { Time = DateTimeOffset.UtcNow, Json = body });
                return _products;
            }
            catch (RiskException) when (cached is not null && cached.Json.Length > 0)
            {
                // Bez sieci korzystamy z nieaktualnej kopii - dane o cyklach życia zmieniają się powoli.
                return _products = ParseProducts(RiskHttp.ParseJson(cached.Json, ProductsUrl));
            }
        }
        finally
        {
            ProductsLock.Release();
        }
    }

    // ------------------------------------------------------------- porzucone projekty
    [System.Reflection.Obfuscation(Exclude = true)]
    private sealed class RepoEntry
    {
        public bool Found { get; set; }
        public bool Archived { get; set; }
        public DateTimeOffset? PushedAt { get; set; }
        public DateTimeOffset Time { get; set; }
    }

    private static readonly object RepoLock = new();
    private static Dictionary<string, RepoEntry>? _repos;

    /// <summary>Repozytorium GitHub (owner/repo) wskazane w adresach programu.</summary>
    internal static string? GitHubRepo(Software s)
    {
        foreach (var url in new[] { s.Homepage }.Concat(s.VendorUrls()))
        {
            var m = GitHubUrl().Match(url ?? "");
            if (!m.Success) continue;
            var repo = m.Groups["repo"].Value;
            if (repo.EndsWith(".git", StringComparison.OrdinalIgnoreCase)) repo = repo[..^4];
            return $"{m.Groups["owner"].Value}/{repo}";
        }
        return null;
    }

    private static async Task<RepoEntry?> RepoAsync(string repo, CancellationToken ct)
    {
        lock (RepoLock)
        {
            _repos ??= RiskHttp.LoadCache<Dictionary<string, RepoEntry>>(GitHubCacheFile) ?? [];
            if (_repos.TryGetValue(repo, out var c) && DateTimeOffset.UtcNow - c.Time < GitHubCacheTtl) return c;
        }
        var url = "https://api.github.com/repos/" + repo;
        var (status, body) = await RiskHttp.GetAsync(url, new Dictionary<string, string> { ["Accept"] = "application/vnd.github+json" }, ct);
        RepoEntry entry;
        if (status == HttpStatusCode.NotFound) entry = new RepoEntry { Found = false };
        else if (status != HttpStatusCode.OK) return null; // np. limit zapytań - spróbujemy następnym razem
        else
        {
            var root = RiskHttp.ParseJson(body, url);
            entry = new RepoEntry
            {
                Found = true,
                Archived = root["archived"]?.GetValue<bool>() ?? false,
                PushedAt = DateTimeOffset.TryParse(root["pushed_at"]?.GetValue<string>(), CultureInfo.InvariantCulture,
                                                   DateTimeStyles.AssumeUniversal, out var p) ? p : null,
            };
        }
        entry.Time = DateTimeOffset.UtcNow;
        lock (RepoLock)
        {
            _repos![repo] = entry;
            RiskHttp.SaveCache(GitHubCacheFile, _repos);
        }
        return entry;
    }

    /// <summary>Data ostatniego wydania z manifestu winget (pole Release Date), jeśli jest dostępna.</summary>
    public static DateOnly? WingetReleaseDate(IReadOnlyDictionary<string, string> showInfo)
    {
        foreach (var (key, value) in showInfo)
        {
            var k = key.ToLowerInvariant();
            if (!(k.Contains("release") || k.Contains("date") || k.Contains("data"))) continue;
            if (DateOnly.TryParseExact(value.Trim(), "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var d)) return d;
        }
        return null;
    }

    internal static LifecycleInfo? FromActivity(string origin, DateOnly? last, bool archived, string link, DateOnly today)
    {
        if (archived)
            return new LifecycleInfo
            {
                State = LifecycleState.Abandoned, Origin = origin, LastActivity = last, Link = link,
                Reason = L.Txt("Repozytorium projektu zostało zarchiwizowane przez autorów - program nie jest już rozwijany."),
            };
        if (last is not { } d) return null;
        if (today.DayNumber - d.DayNumber > AbandonedAfterDays)
            return new LifecycleInfo
            {
                State = LifecycleState.Abandoned, Origin = origin, LastActivity = d, Link = link,
                Reason = origin == "GitHub"
                    ? L.Txt("Brak zmian w repozytorium projektu od {0:yyyy-MM-dd} - program jest prawdopodobnie porzucony.", d)
                    : L.Txt("Najnowsze wydanie w repozytorium winget pochodzi z {0:yyyy-MM-dd} - program jest prawdopodobnie porzucony.", d),
            };
        return new LifecycleInfo
        {
            State = LifecycleState.Supported, Origin = origin, LastActivity = d, Link = link,
            Reason = L.Txt("Ostatnia aktywność projektu: {0:yyyy-MM-dd}.", d),
        };
    }

    /// <summary>
    /// Ustala stan wsparcia programu: najpierw endoflife.date, potem aktywność repozytorium GitHub,
    /// na końcu data najnowszego wydania z manifestu winget (<paramref name="wingetShow"/>).
    /// </summary>
    public static async Task<(LifecycleInfo? Info, EolProduct? Product)> CheckAsync(
        Software s, Func<Task<IReadOnlyDictionary<string, string>?>>? wingetShow = null, CancellationToken ct = default)
    {
        var today = DateOnly.FromDateTime(DateTime.Today);
        var products = await ProductsAsync(ct);
        var product = MatchProduct(s, products);
        if (product is not null && MatchRelease(product, s.Name, s.Version) is { } release)
            return (Evaluate(product, release, today), product);

        if (GitHubRepo(s) is { } repo && await RepoAsync(repo, ct) is { Found: true } r &&
            FromActivity("GitHub", r.PushedAt is { } p ? DateOnly.FromDateTime(p.UtcDateTime) : null, r.Archived,
                         "https://github.com/" + repo, today) is { } gh)
            return (gh, product);

        if (wingetShow is not null && !string.IsNullOrEmpty(s.WingetId) && await wingetShow() is { } show &&
            FromActivity("winget", WingetReleaseDate(show), false, "", today) is { } wg)
            return (wg, product);

        return (null, product);
    }

    [GeneratedRegex(@"^cpe:2\.3:a:(?<v>[^:]+):(?<p>[^:]+)")]
    private static partial Regex CpeProduct();

    [GeneratedRegex("[0-9a-z]+")]
    private static partial Regex AlnumTokens();

    [GeneratedRegex(@"^https?://(www\.)?github\.com/(?<owner>[\w.-]+)/(?<repo>[\w.-]+)", RegexOptions.IgnoreCase)]
    private static partial Regex GitHubUrl();
}
