using System.Globalization;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using BezpiecznyAktualizator.Core.Risk;

namespace BezpiecznyAktualizator.Core.Updates;

public static partial class MsrcWindowsUpdateClient
{
    private const string ApiRoot = "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/";
    private static readonly TimeSpan CacheLifetime = TimeSpan.FromHours(12);
    private static readonly HttpClient Client = new(new SocketsHttpHandler
    {
        AllowAutoRedirect = false,
        AutomaticDecompression = DecompressionMethods.All,
    }) { Timeout = TimeSpan.FromSeconds(30) };

    static MsrcWindowsUpdateClient() =>
        Client.DefaultRequestHeaders.UserAgent.ParseAdd("BezpiecznyAktualizator/2.1");

    public static async Task<IReadOnlyList<string>> EnrichAsync(IReadOnlyList<WindowsUpdateItem> updates,
                                                                 CancellationToken ct = default)
    {
        var warnings = new List<string>();
        var byRelease = updates.Where(update => update.KbIds.Count > 0 && update.LastDeploymentChangeTime.HasValue)
            .GroupBy(update => update.LastDeploymentChangeTime!.Value.ToString("yyyy-MMM", CultureInfo.InvariantCulture),
                StringComparer.OrdinalIgnoreCase);
        foreach (var group in byRelease)
        {
            try
            {
                var releases = new[] { group.Key, PreviousRelease(group.First().LastDeploymentChangeTime!.Value) }
                    .Distinct(StringComparer.OrdinalIgnoreCase);
                var maps = new List<IReadOnlyDictionary<string, List<string>>>();
                foreach (var release in releases)
                    maps.Add((await GetReleaseMapAsync(release, ct)).CvesByKb);

                foreach (var update in group)
                {
                    var cves = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    foreach (var kb in update.KbIds)
                    {
                        var normalized = NormalizeKb(kb);
                        foreach (var map in maps)
                            if (map.TryGetValue(normalized, out var matches))
                                cves.UnionWith(matches);
                    }
                    update.MsrcCveIds.Clear();
                    update.MsrcCveIds.AddRange(cves.Order(StringComparer.OrdinalIgnoreCase));
                }
            }
            catch (RiskException ex)
            {
                foreach (var update in group) update.MsrcError = ex.Message;
                warnings.Add(ex.Message);
            }
        }

        foreach (var update in updates.Where(update => update.KbIds.Count > 0 && !update.LastDeploymentChangeTime.HasValue))
        {
            update.MsrcError = "Windows Update did not provide a release date for exact MSRC correlation.";
            warnings.Add($"{update.Title}: {update.MsrcError}");
        }
        return warnings;
    }

    internal static IReadOnlyDictionary<string, IReadOnlyList<string>> ParseReleaseMap(string json)
    {
        JsonNode document;
        try { document = JsonNode.Parse(json) ?? throw new JsonException("Empty response."); }
        catch (JsonException ex) { throw new RiskException("MSRC returned invalid CVRF JSON.", ex); }

        if (document is not JsonObject root || root["Vulnerability"] is not JsonArray vulnerabilities)
            throw new RiskException("MSRC CVRF response does not contain a vulnerability list.");

        var map = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var vulnerability in vulnerabilities)
        {
            if (vulnerability is not JsonObject item) continue;
            var cve = item["CVE"]?.ToString() ?? "";
            if (!CveIdPattern().IsMatch(cve) || item["Remediations"] is not JsonArray remediations)
                continue;
            foreach (var remediation in remediations)
            {
                if (remediation is not JsonObject entry) continue;
                var description = entry["Description"] is JsonObject descriptionObject
                    ? descriptionObject["Value"]?.ToString() ?? ""
                    : "";
                foreach (var kb in FindKbIds(
                             description, entry["URL"]?.ToString() ?? ""))
                {
                    if (!map.TryGetValue(kb, out var cves)) map[kb] = cves = new(StringComparer.OrdinalIgnoreCase);
                    cves.Add(cve.ToUpperInvariant());
                }
            }
        }
        return map.ToDictionary(entry => entry.Key,
            entry => (IReadOnlyList<string>)entry.Value.Order(StringComparer.OrdinalIgnoreCase).ToList(),
            StringComparer.OrdinalIgnoreCase);
    }

    internal static IReadOnlyList<string> FindKbIds(string description, string url)
    {
        var result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var numeric = BareKbPattern().Match(description);
        if (numeric.Success) result.Add(numeric.Groups[1].Value);
        foreach (Match match in KbPattern().Matches(description + " " + url))
            for (var group = 1; group < match.Groups.Count; group++)
                if (match.Groups[group].Success) result.Add(match.Groups[group].Value);
        return result.Order(StringComparer.OrdinalIgnoreCase).ToList();
    }

    internal static string NormalizeKb(string value)
    {
        var digits = value.StartsWith("KB", StringComparison.OrdinalIgnoreCase) ? value[2..] : value;
        return digits.Trim();
    }

    private static async Task<MsrcReleaseCache> GetReleaseMapAsync(string release, CancellationToken ct)
    {
        var fileName = "msrc-" + release + ".json";
        var cached = RiskHttp.LoadCache<MsrcReleaseCache>(fileName);
        if (cached is not null && cached.FetchedAtUtc > DateTimeOffset.UtcNow - CacheLifetime &&
            cached.CvesByKb is not null)
            return cached;

        using var request = new HttpRequestMessage(HttpMethod.Get, ApiRoot + Uri.EscapeDataString(release));
        request.Headers.Accept.ParseAdd("application/json");
        try
        {
            using var response = await Client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
            if (response.RequestMessage?.RequestUri is not { Scheme: "https", Host: "api.msrc.microsoft.com" })
                throw new RiskException("MSRC response did not come from the official HTTPS API.");
            if (response.StatusCode != HttpStatusCode.OK)
                throw new RiskException($"MSRC CVRF release {release} returned HTTP {(int)response.StatusCode}.");
            var json = await response.Content.ReadAsStringAsync(ct);
            var parsed = ParseReleaseMap(json);
            var cache = new MsrcReleaseCache
            {
                FetchedAtUtc = DateTimeOffset.UtcNow,
                CvesByKb = parsed.ToDictionary(entry => entry.Key, entry => entry.Value.ToList(),
                    StringComparer.OrdinalIgnoreCase),
            };
            RiskHttp.SaveCache(fileName, cache);
            return cache;
        }
        catch (Exception ex) when ((ex is HttpRequestException or TaskCanceledException) && !ct.IsCancellationRequested)
        {
            throw new RiskException($"Could not retrieve MSRC CVRF release {release}: {ex.Message}", ex);
        }
    }

    private static string PreviousRelease(DateTimeOffset date) =>
        new DateTimeOffset(date.Year, date.Month, 1, 0, 0, 0, TimeSpan.Zero)
            .AddMonths(-1).ToString("yyyy-MMM", CultureInfo.InvariantCulture);

    [System.Reflection.Obfuscation(Exclude = true)]
    internal sealed class MsrcReleaseCache
    {
        public DateTimeOffset FetchedAtUtc { get; set; }
        public Dictionary<string, List<string>> CvesByKb { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    }

    [GeneratedRegex(@"(?i)\bCVE-\d{4}-\d{4,}\b", RegexOptions.CultureInvariant)]
    private static partial Regex CveIdPattern();

    [GeneratedRegex(@"(?i)\bKB\s*(\d{5,8})\b|/help/(\d{5,8})\b|[?&]q=KB?(\d{5,8})\b", RegexOptions.CultureInvariant)]
    private static partial Regex KbPattern();

    [GeneratedRegex(@"^\s*(\d{5,8})\s*$", RegexOptions.CultureInvariant)]
    private static partial Regex BareKbPattern();
}
