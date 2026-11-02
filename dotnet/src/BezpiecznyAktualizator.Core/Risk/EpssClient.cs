using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Text.Json.Nodes;
using BezpiecznyAktualizator.Core.Localization;

namespace BezpiecznyAktualizator.Core.Risk;

/// <summary>Uzupełnia rekordy CVE o ocenę prawdopodobieństwa wykorzystania z FIRST EPSS.</summary>
public static class EpssClient
{
    private const string Endpoint = "https://api.first.org/data/v1/epss";
    private static readonly TimeSpan CacheTtl = TimeSpan.FromHours(24);
    private static readonly ConcurrentDictionary<string, (DateTimeOffset Time, double Score, double Percentile)> Cache =
        new(StringComparer.OrdinalIgnoreCase);
    private static readonly SemaphoreSlim Gate = new(1, 1);

    public static async Task<string?> EnrichAsync(IList<CveItem> items, CancellationToken ct = default)
    {
        var ids = items.Select(item => item.Id).Where(IsCveId).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (ids.Count == 0) return null;

        try
        {
            foreach (var batch in ids.Chunk(100))
            {
                var missing = batch.Where(id => !HasFresh(id)).ToArray();
                if (missing.Length == 0) continue;

                await Gate.WaitAsync(ct);
                try
                {
                    missing = missing.Where(id => !HasFresh(id)).ToArray();
                    if (missing.Length == 0) continue;
                    var url = Endpoint + "?cve=" + Uri.EscapeDataString(string.Join(',', missing));
                    var (status, body) = await RiskHttp.GetAsync(url, null, ct);
                    if (status != HttpStatusCode.OK)
                        throw new RiskException(L.F("FIRST EPSS zwrócił kod HTTP {0}.", (int)status));
                    foreach (var (id, score, percentile) in Parse(RiskHttp.ParseJson(body, url)))
                        Cache[id] = (DateTimeOffset.UtcNow, score, percentile);
                }
                finally
                {
                    Gate.Release();
                }
            }

            for (var i = 0; i < items.Count; i++)
                if (Cache.TryGetValue(items[i].Id, out var value) && DateTimeOffset.UtcNow - value.Time < CacheTtl)
                    items[i] = items[i] with { EpssScore = value.Score, EpssPercentile = value.Percentile };
            return null;
        }
        catch (RiskException ex)
        {
            return ex.Message;
        }
    }

    internal static IReadOnlyList<(string Id, double Score, double Percentile)> Parse(JsonNode root)
    {
        var values = new List<(string, double, double)>();
        foreach (var row in root["data"]?.AsArray().OfType<JsonObject>() ?? [])
        {
            var id = row["cve"]?.GetValue<string>() ?? "";
            if (!IsCveId(id) ||
                !double.TryParse(row["epss"]?.GetValue<string>(), CultureInfo.InvariantCulture, out var score) ||
                !double.TryParse(row["percentile"]?.GetValue<string>(), CultureInfo.InvariantCulture, out var percentile) ||
                score is < 0 or > 1 || percentile is < 0 or > 1)
                continue;
            values.Add((id, score, percentile));
        }
        return values;
    }

    private static bool HasFresh(string id) =>
        Cache.TryGetValue(id, out var value) && DateTimeOffset.UtcNow - value.Time < CacheTtl;

    private static bool IsCveId(string id) =>
        id.StartsWith("CVE-", StringComparison.OrdinalIgnoreCase) && id.Length <= 32 &&
        id.AsSpan(4).IndexOfAnyExcept("0123456789-") < 0;
}
