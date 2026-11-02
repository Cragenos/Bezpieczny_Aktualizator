using System.Net;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using BezpiecznyAktualizator.Core.Localization;
using BezpiecznyAktualizator.Core.Models;

namespace BezpiecznyAktualizator.Core.Risk;

/// <summary>
/// Sprawdzanie znanych podatności (CVE) w bazie NVD (NIST National Vulnerability Database, API 2.0).
/// Program jest dopasowywany do produktu CPE (wbudowana mapa popularnych programów, identyfikator z endoflife.date
/// albo wyszukiwanie w słowniku CPE), a następnie NVD zwraca CVE, których konfiguracje obejmują zainstalowaną wersję.
/// Bez klucza API NVD pozwala na 5 zapytań w 30 s, z kluczem na 50 - wyniki są zapisywane w pamięci podręcznej.
/// </summary>
public static partial class NvdClient
{
    private const string CveUrl = "https://services.nvd.nist.gov/rest/json/cves/2.0";
    private const string CpeUrl = "https://services.nvd.nist.gov/rest/json/cpes/2.0";
    private const string CveCacheFile = "nvd-cve.json";
    private const string CpeCacheFile = "nvd-cpe.json";
    public static readonly TimeSpan CveCacheTtl = TimeSpan.FromHours(24);
    public static readonly TimeSpan CpeCacheTtl = TimeSpan.FromDays(30);

    /// <summary>Opcjonalny klucz API NVD (https://nvd.nist.gov/developers/request-an-api-key).</summary>
    public static string? ApiKey { get; set; } = Environment.GetEnvironmentVariable("NVD_API_KEY");

    /// <summary>
    /// Mapa popularnych programów Windows na produkty CPE (vendor:product; kilka rozdzielonych „|”).
    /// Wzorce są dopasowywane do nazwy programu z rejestru.
    /// </summary>
    internal static readonly (Regex Name, string Cpe)[] KnownProducts =
    [
        (new(@"^7-Zip\b", RegexOptions.IgnoreCase), "7-zip:7-zip"),
        (new(@"^Mozilla Firefox\b", RegexOptions.IgnoreCase), "mozilla:firefox"),
        (new(@"^Mozilla Thunderbird\b", RegexOptions.IgnoreCase), "mozilla:thunderbird"),
        (new(@"^Google Chrome\b", RegexOptions.IgnoreCase), "google:chrome"),
        (new(@"^Microsoft Edge$", RegexOptions.IgnoreCase), "microsoft:edge_chromium"),
        (new(@"^Notepad\+\+", RegexOptions.IgnoreCase), @"notepad-plus-plus:notepad\+\+|don_ho:notepad\+\+"),
        (new(@"^VLC media player\b", RegexOptions.IgnoreCase), "videolan:vlc_media_player"),
        (new(@"^Adobe Acrobat( Reader)?( DC)?\b", RegexOptions.IgnoreCase), "adobe:acrobat_reader_dc|adobe:acrobat_dc"),
        (new(@"^WinRAR\b", RegexOptions.IgnoreCase), "rarlab:winrar"),
        (new(@"^PuTTY\b", RegexOptions.IgnoreCase), "putty:putty|simon_tatham:putty"),
        (new(@"^WinSCP\b", RegexOptions.IgnoreCase), "winscp:winscp"),
        (new(@"^FileZilla( Client)?\b", RegexOptions.IgnoreCase), "filezilla-project:filezilla_client"),
        (new(@"^Wireshark\b", RegexOptions.IgnoreCase), "wireshark:wireshark"),
        (new(@"^KeePass Password Safe\b", RegexOptions.IgnoreCase), "keepass:keepass"),
        (new(@"^LibreOffice\b", RegexOptions.IgnoreCase), "libreoffice:libreoffice"),
        (new(@"^Git( version [\d.]+)?$", RegexOptions.IgnoreCase), "git-scm:git"),
        (new(@"^Python \d+\.\d+\.\d+ \(", RegexOptions.IgnoreCase), "python:python"),
        (new(@"^Node\.js$", RegexOptions.IgnoreCase), "nodejs:node.js"),
        (new(@"^TeamViewer\b", RegexOptions.IgnoreCase), "teamviewer:teamviewer"),
        (new(@"^AnyDesk\b", RegexOptions.IgnoreCase), "anydesk:anydesk"),
        (new(@"^Microsoft Visual Studio Code\b", RegexOptions.IgnoreCase), "microsoft:visual_studio_code"),
        (new(@"^OpenVPN \d", RegexOptions.IgnoreCase), "openvpn:openvpn"),
        (new(@"^VeraCrypt\b", RegexOptions.IgnoreCase), "idrix:veracrypt"),
        (new(@"^Audacity\b", RegexOptions.IgnoreCase), "audacityteam:audacity"),
        (new(@"^GIMP\b", RegexOptions.IgnoreCase), "gimp:gimp"),
        (new(@"^Inkscape\b", RegexOptions.IgnoreCase), "inkscape:inkscape"),
        (new(@"^Docker Desktop\b", RegexOptions.IgnoreCase), "docker:desktop"),
        (new(@"^Oracle (VM )?VirtualBox\b", RegexOptions.IgnoreCase), "oracle:vm_virtualbox"),
        (new(@"^Foxit (PDF )?Reader\b", RegexOptions.IgnoreCase), "foxit:pdf_reader"),
        (new(@"^Opera( Stable)?( \d|$)", RegexOptions.IgnoreCase), "opera:opera_browser"),
        (new(@"^PowerShell \d", RegexOptions.IgnoreCase), "microsoft:powershell"),
        (new(@"^IrfanView\b", RegexOptions.IgnoreCase), "irfanview:irfanview"),
        (new(@"^TightVNC\b", RegexOptions.IgnoreCase), "tightvnc:tightvnc"),
        (new(@"^Zoom( Workplace)?\b", RegexOptions.IgnoreCase), "zoom:workplace_desktop|zoom:meetings"),
        (new(@"^Blender\b", RegexOptions.IgnoreCase), "blender:blender"),
        (new(@"^Nmap\b", RegexOptions.IgnoreCase), "nmap:nmap"),
        (new(@"^iTunes\b", RegexOptions.IgnoreCase), "apple:itunes"),
    ];

    /// <summary>Produkt CPE z wbudowanej mapy (null, gdy brak wpisu).</summary>
    public static string? KnownCpe(string name) =>
        KnownProducts.FirstOrDefault(p => p.Name.IsMatch(name.Trim())).Cpe;

    /// <summary>Nazwa bez numeru wersji, architektury i dopisków w nawiasach - do wyszukiwania w słowniku CPE.</summary>
    public static string BaseName(string name)
    {
        var s = Regex.Replace(name, @"\(.*?\)|\[.*?\]", " ");
        s = Regex.Replace(s, @"\s+-\s+.*$", " ");
        s = Regex.Replace(s, @"\bv?\d+(?:\.\d+)+[\w.\-+]*|\b(x64|x86|amd64|arm64|64-bit|32-bit|win64|win32)\b", " ", RegexOptions.IgnoreCase);
        return Regex.Replace(s, @"\s+", " ").Trim();
    }

    /// <summary>Wersja w postaci akceptowanej w CPE (same cyfry i kropki), np. „23.01” z „23.01 (x64)”.</summary>
    public static string CpeVersion(string version)
    {
        var m = Regex.Match(version ?? "", @"\d+(?:\.\d+)*");
        return m.Success ? m.Value : "";
    }

    /// <summary>
    /// Wersja porównywana z NVD. Zwykle jest to DisplayVersion z rejestru, ale wersja z nazwy ma pierwszeństwo, gdy:
    /// <list type="bullet">
    /// <item>jest dokładniejsza (Python: „3.14-64” w rejestrze, „Python 3.14.3” w nazwie);</item>
    /// <item>jest wersją „roczną”, a rejestr zawiera numer kompilacji (JetBrains: „262.10968.63” i „IntelliJ IDEA 2026.2.3”).</item>
    /// </list>
    /// </summary>
    public static string ProductVersion(string name, string displayVersion)
    {
        var display = CpeVersion(displayVersion);
        var m = Regex.Match(name ?? "", @"(?<![\w.])v?(\d+(?:\.\d+)+)(?![\w.])");
        if (!m.Success) return display;
        var fromName = m.Groups[1].Value;
        if (display.Length == 0 || fromName.StartsWith(display + ".", StringComparison.Ordinal)) return fromName;
        var nameMajor = fromName.Split('.')[0];
        return nameMajor.Length == 4 && nameMajor[..2] is "19" or "20" && nameMajor != display.Split('.')[0] ? fromName : display;
    }

    /// <summary>Programy, których wersja w rejestrze dotyczy instalatora, a nie samego programu.</summary>
    private static readonly Regex UnreliableVersion = new(@"^Epic Games Launcher$", RegexOptions.IgnoreCase);

    /// <summary>Dzieli nazwę CPE 2.3 na składniki, z uwzględnieniem znaków ucieczki („\:”).</summary>
    internal static string[] SplitCpe(string cpeName) => Regex.Split(cpeName, @"(?<!\\):");

    private static string Unescape(string s) => s.Replace("\\", "");

    /// <summary>
    /// Wybiera produkt CPE (vendor:product) z wyników wyszukiwania słownika CPE.
    /// Zwraca null, gdy nie ma jednoznacznego dopasowania - lepiej nie sprawdzić niż zgłosić cudze luki.
    /// </summary>
    internal static string? PickCpe(string baseName, string publisher, IEnumerable<string> cpeNames)
    {
        var query = baseName.Trim().ToLowerInvariant();
        if (query.Length < 2) return null;
        var underscored = Regex.Replace(query, @"\s+", "_");
        var normalized = Software.NormalizeName(query);
        var candidates = cpeNames.Select(SplitCpe).Where(p => p.Length > 5 && p[2] == "a")
            .GroupBy(p => $"{p[3]}:{p[4]}")
            .Select(g =>
            {
                var vendor = Unescape(g.First()[3]).ToLowerInvariant();
                var product = Unescape(g.First()[4]).ToLowerInvariant();
                var tier = product == underscored ? 1
                    : $"{vendor}_{product}" == underscored || Software.NormalizeName(vendor + product) == normalized ? 2
                    : Software.NormalizeName(product) == normalized ? 3 : 0;
                return (Cpe: g.Key, Vendor: vendor, Tier: tier, Count: g.Count());
            })
            .Where(c => c.Tier > 0).ToList();
        if (candidates.Count == 0) return null;
        var best = candidates.Where(c => c.Tier == candidates.Min(x => x.Tier)).ToList();
        if (best.Count == 1) return best[0].Cpe;
        var pub = Software.NormalizeName(publisher);
        var byPublisher = best.Where(c =>
        {
            var v = Software.NormalizeName(c.Vendor);
            return pub.Length > 0 && v.Length > 2 && (pub.Contains(v) || v.Contains(pub));
        }).ToList();
        return byPublisher.Count >= 1 ? byPublisher.OrderByDescending(c => c.Count).First().Cpe : null;
    }

    // --------------------------------------------------------------- limit zapytań
    private static readonly SemaphoreSlim Gate = new(1, 1);
    private static readonly Queue<DateTime> Recent = new();

    private static async Task ThrottleAsync(CancellationToken ct)
    {
        var limit = string.IsNullOrWhiteSpace(ApiKey) ? 5 : 50;
        var window = TimeSpan.FromSeconds(31);
        while (true)
        {
            var now = DateTime.UtcNow;
            while (Recent.Count > 0 && now - Recent.Peek() > window) Recent.Dequeue();
            if (Recent.Count < limit) break;
            await Task.Delay(window - (now - Recent.Peek()) + TimeSpan.FromMilliseconds(200), ct);
        }
        Recent.Enqueue(DateTime.UtcNow);
    }

    private static async Task<JsonNode> QueryAsync(string url, CancellationToken ct)
    {
        await Gate.WaitAsync(ct);
        try
        {
            var headers = string.IsNullOrWhiteSpace(ApiKey) ? null : new Dictionary<string, string> { ["apiKey"] = ApiKey.Trim() };
            for (var attempt = 1; ; attempt++)
            {
                await ThrottleAsync(ct);
                var (status, body) = await RiskHttp.GetAsync(url, headers, ct);
                if (status == HttpStatusCode.OK) return RiskHttp.ParseJson(body, url);
                var retry = status is HttpStatusCode.Forbidden or HttpStatusCode.TooManyRequests or HttpStatusCode.ServiceUnavailable
                            or HttpStatusCode.GatewayTimeout or HttpStatusCode.BadGateway;
                if (!retry || attempt >= 4)
                    throw new RiskException(L.F("Baza NVD zwróciła kod HTTP {0}.", (int)status));
                await Task.Delay(TimeSpan.FromSeconds(10 * attempt), ct);
            }
        }
        finally
        {
            Gate.Release();
        }
    }

    // --------------------------------------------------------------- parsowanie
    /// <param name="products">Produkty CPE („vendor:product”) i wersja - gdy podane, odrzucane są luki, których
    /// konfiguracje dotyczą tej wersji wyłącznie na innym systemie (np. macOS).</param>
    internal static List<CveItem> ParseCves(JsonNode root, IReadOnlyCollection<string>? products = null, string version = "")
    {
        var list = new List<CveItem>();
        foreach (var v in root["vulnerabilities"]?.AsArray() ?? [])
        {
            if (v?["cve"] is not JsonObject cve) continue;
            var id = cve["id"]?.GetValue<string>() ?? "";
            if (id.Length == 0 || (cve["vulnStatus"]?.GetValue<string>() ?? "").Equals("Rejected", StringComparison.OrdinalIgnoreCase))
                continue;
            if (products is { Count: > 0 } && version.Length > 0 && !AppliesToWindows(cve, products, version)) continue;
            var description = cve["descriptions"]?.AsArray().OfType<JsonObject>()
                .FirstOrDefault(d => d["lang"]?.GetValue<string>() == "en")?["value"]?.GetValue<string>() ?? "";
            var (score, severity) = Score(cve["metrics"] as JsonObject);
            DateTimeOffset? published = DateTimeOffset.TryParse(cve["published"]?.GetValue<string>(),
                System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.AssumeUniversal, out var p) ? p : null;
            list.Add(new CveItem(id, score, severity, description, published, cve["cisaExploitAdd"] is not null));
        }
        return list.OrderByDescending(c => c.Exploited).ThenByDescending(c => c.Score).ThenByDescending(c => c.Published).ToList();
    }

    /// <summary>
    /// Wyszukiwanie NVD (virtualMatchString) nie uwzględnia wszystkich warunków konfiguracji CVE. Luka jest odrzucana, gdy:
    /// <list type="bullet">
    /// <item>produkt występuje w konfiguracjach tylko jako platforma (vulnerable=false, np. Node.js dla Next.js);</item>
    /// <item>wersja jest objęta wyłącznie wpisami dla innych systemów - target_sw (np. Office dla Androida)
    /// albo warunek AND z innym systemem (np. „BlueStacks ≥ 2.0 na macOS”).</item>
    /// </list>
    /// W razie wątpliwości (brak konfiguracji, nietypowy zapis wersji) luka jest zachowywana - wynik serwera ma pierwszeństwo.
    /// </summary>
    internal static bool AppliesToWindows(JsonObject cve, IReadOnlyCollection<string> products, string version)
    {
        bool mentioned = false, vulnerable = false;
        var covered = new List<bool>();
        foreach (var config in cve["configurations"]?.AsArray().OfType<JsonObject>() ?? [])
        {
            var nodes = config["nodes"]?.AsArray().OfType<JsonObject>().ToList() ?? [];
            var productNodes = new HashSet<JsonObject>();
            var windows = false;
            foreach (var node in nodes)
            foreach (var m in Matches(node))
            {
                var c = SplitCpe(m["criteria"]?.GetValue<string>() ?? "");
                if (c.Length < 11 || !products.Contains($"{c[3]}:{c[4]}")) continue;
                mentioned = true;
                if (m["vulnerable"]?.GetValue<bool>() != true) continue;
                vulnerable = true;
                if (!CoversVersion(m, c, version)) continue;
                productNodes.Add(node);
                windows |= c[10] is "*" or "-" || c[10].Contains("windows", StringComparison.OrdinalIgnoreCase);
            }
            if (productNodes.Count == 0) continue;
            if (windows && (config["operator"]?.GetValue<string>() ?? "").Equals("AND", StringComparison.OrdinalIgnoreCase))
            {
                var platforms = nodes.Where(n => !productNodes.Contains(n)).SelectMany(Matches)
                    .Select(m => SplitCpe(m["criteria"]?.GetValue<string>() ?? "")).Where(c => c.Length > 4 && c[2] == "o").ToList();
                windows = platforms.Count == 0 || platforms.Any(c => c[3] == "microsoft");
            }
            covered.Add(windows);
        }
        if (mentioned && !vulnerable) return false;
        return covered.Count == 0 || covered.Contains(true);

        static IEnumerable<JsonObject> Matches(JsonObject node) => node["cpeMatch"]?.AsArray().OfType<JsonObject>() ?? [];
    }
    private static bool CoversVersion(JsonObject match, string[] c, string version)
    {
        string? Bound(string name) => match[name]?.GetValue<string>();
        if (c[5] is not ("*" or "-")) return CompareVersions(version, Unescape(c[5])) == 0;
        if (Bound("versionStartIncluding") is { } si && CompareVersions(version, si) < 0) return false;
        if (Bound("versionStartExcluding") is { } se && CompareVersions(version, se) <= 0) return false;
        if (Bound("versionEndIncluding") is { } ei && CompareVersions(version, ei) > 0) return false;
        if (Bound("versionEndExcluding") is { } ee && CompareVersions(version, ee) >= 0) return false;
        return true;
    }

    internal static int CompareVersions(string a, string b)
    {
        var x = a.Split('.', '-', '_');
        var y = b.Split('.', '-', '_');
        for (var i = 0; i < Math.Max(x.Length, y.Length); i++)
        {
            var p = i < x.Length ? x[i] : "0";
            var q = i < y.Length ? y[i] : "0";
            var r = long.TryParse(p, out var pn) && long.TryParse(q, out var qn)
                ? pn.CompareTo(qn) : string.Compare(p, q, StringComparison.OrdinalIgnoreCase);
            if (r != 0) return r;
        }
        return 0;
    }

    private static (double Score, string Severity) Score(JsonObject? metrics)
    {
        if (metrics is null) return (0, "");
        foreach (var key in new[] { "cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2" })
        {
            if (metrics[key] is not JsonArray arr || arr.Count == 0) continue;
            var entry = arr.OfType<JsonObject>().FirstOrDefault(m => m["type"]?.GetValue<string>() == "Primary")
                        ?? arr.OfType<JsonObject>().First();
            var data = entry["cvssData"] as JsonObject;
            var score = data?["baseScore"]?.GetValue<double>() ?? 0;
            var severity = data?["baseSeverity"]?.GetValue<string>() ?? entry["baseSeverity"]?.GetValue<string>() ?? "";
            return (score, severity.ToUpperInvariant());
        }
        return (0, "");
    }

    // --------------------------------------------------------------- pamięć podręczna
    [System.Reflection.Obfuscation(Exclude = true)]
    private sealed class CpeEntry
    {
        public string Cpe { get; set; } = "";
        public DateTimeOffset Time { get; set; }
    }

    private static readonly object CacheLock = new();
    private static Dictionary<string, CpeEntry>? _cpeCache;
    private static Dictionary<string, VulnerabilityReport>? _cveCache;

    private static Dictionary<string, CpeEntry> CpeCache =>
        _cpeCache ??= RiskHttp.LoadCache<Dictionary<string, CpeEntry>>(CpeCacheFile) ?? [];

    private static Dictionary<string, VulnerabilityReport> CveCache =>
        _cveCache ??= RiskHttp.LoadCache<Dictionary<string, VulnerabilityReport>>(CveCacheFile) ?? [];

    /// <summary>Usuwa zapamiętane wyniki (np. przed wymuszonym ponownym sprawdzeniem).</summary>
    public static void ClearCache()
    {
        lock (CacheLock)
        {
            _cpeCache = [];
            _cveCache = [];
            RiskHttp.SaveCache(CpeCacheFile, _cpeCache);
            RiskHttp.SaveCache(CveCacheFile, _cveCache);
        }
    }

    // --------------------------------------------------------------- API
    /// <summary>Ustala produkt CPE programu. Zwraca (cpe, pochodzenie) lub ("", "") gdy brak dopasowania.</summary>
    public static async Task<(string Cpe, string Origin)> ResolveCpeAsync(Software s, string? lifecycleCpe, CancellationToken ct = default)
    {
        if (KnownCpe(s.Name) is { } known) return (known, "map");
        if (!string.IsNullOrEmpty(lifecycleCpe)) return (lifecycleCpe, "endoflife.date");
        var baseName = BaseName(s.Name);
        var key = Software.NormalizeName(baseName);
        if (key.Length < 2) return ("", "");
        lock (CacheLock)
        {
            if (CpeCache.TryGetValue(key, out var cached) && DateTimeOffset.UtcNow - cached.Time < CpeCacheTtl)
                return cached.Cpe.Length > 0 ? (cached.Cpe, "nvd") : ("", "");
        }
        var url = $"{CpeUrl}?resultsPerPage=500&keywordSearch={Uri.EscapeDataString(baseName)}";
        var root = await QueryAsync(url, ct);
        var names = (root["products"]?.AsArray() ?? []).Select(p => p?["cpe"]?["cpeName"]?.GetValue<string>())
                                                       .OfType<string>().ToList();
        var cpe = PickCpe(baseName, s.Publisher, names) ?? "";
        lock (CacheLock)
        {
            CpeCache[key] = new CpeEntry { Cpe = cpe, Time = DateTimeOffset.UtcNow };
            RiskHttp.SaveCache(CpeCacheFile, CpeCache);
        }
        return cpe.Length > 0 ? (cpe, "nvd") : ("", "");
    }

    /// <summary>Sprawdza znane podatności zainstalowanej wersji programu.</summary>
    public static async Task<VulnerabilityReport> CheckAsync(Software s, string? lifecycleCpe = null, CancellationToken ct = default)
    {
        var version = ProductVersion(s.Name, s.Version);
        var report = new VulnerabilityReport { Version = version, CheckedAt = DateTimeOffset.UtcNow };
        if (version.Length == 0)
        {
            report.Error = L.Txt("Brak numeru wersji - nie można sprawdzić podatności.");
            return report;
        }
        if (UnreliableVersion.IsMatch(s.Name.Trim()))
        {
            report.Error = L.Txt("Numer wersji w rejestrze dotyczy instalatora, a nie programu - nie można wiarygodnie sprawdzić podatności.");
            return report;
        }
        if (s.Origin.Contains("MSIX", StringComparison.OrdinalIgnoreCase))
        {
            report.Error = L.Txt("Pakiet MSIX/Microsoft Store - numer wersji pakietu nie odpowiada wersji programu, więc nie można wiarygodnie sprawdzić podatności. Takie pakiety aktualizuje Microsoft Store.");
            return report;
        }
        var (cpe, origin) = await ResolveCpeAsync(s, lifecycleCpe, ct);
        if (cpe.Length == 0)
        {
            report.Error = L.Txt("Nie znaleziono programu w słowniku CPE bazy NVD.");
            return report;
        }
        report.Cpe = cpe;
        report.CpeOrigin = origin;
        var cacheKey = $"v2|{cpe}|{version}";
        VulnerabilityReport? cachedReport = null;
        lock (CacheLock)
        {
            if (CveCache.TryGetValue(cacheKey, out var cached) && DateTimeOffset.UtcNow - cached.CheckedAt < CveCacheTtl)
            {
                cached.CpeOrigin = origin;
                if (cached.EpssCheckedAt is { } epssChecked && DateTimeOffset.UtcNow - epssChecked < CveCacheTtl) return cached;
                cachedReport = cached;
            }
        }
        if (cachedReport is not null)
        {
            cachedReport.EpssError = await EpssClient.EnrichAsync(cachedReport.Items, ct);
            if (cachedReport.EpssError is null) cachedReport.EpssCheckedAt = DateTimeOffset.UtcNow;
            return cachedReport;
        }
        var items = new Dictionary<string, CveItem>();
        var products = cpe.Split('|');
        foreach (var product in products)
        {
            var match = $"cpe:2.3:a:{product}:{version}";
            var url = $"{CveUrl}?noRejected&resultsPerPage=2000&virtualMatchString={Uri.EscapeDataString(match)}";
            foreach (var item in ParseCves(await QueryAsync(url, ct), products, version)) items.TryAdd(item.Id, item);
        }
        report.Items = items.Values.OrderByDescending(c => c.Exploited).ThenByDescending(c => c.Score).ToList();
        report.EpssError = await EpssClient.EnrichAsync(report.Items, ct);
        if (report.EpssError is null) report.EpssCheckedAt = DateTimeOffset.UtcNow;
        lock (CacheLock)
        {
            CveCache[cacheKey] = report;
            var stale = CveCache.Where(kv => DateTimeOffset.UtcNow - kv.Value.CheckedAt > CveCacheTtl).Select(kv => kv.Key).ToList();
            foreach (var k in stale) CveCache.Remove(k);
            RiskHttp.SaveCache(CveCacheFile, CveCache);
        }
        return report;
    }

    /// <summary>Szacowany czas (w sekundach) sprawdzenia podanej liczby programów bez pamięci podręcznej.</summary>
    public static int EstimateSeconds(int programs) =>
        string.IsNullOrWhiteSpace(ApiKey) ? programs * 2 * 6 : Math.Max(1, programs * 2 * 6 / 10);
}
