using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using BezpiecznyAktualizator.Core.Localization;

namespace BezpiecznyAktualizator.Core.Risk;

/// <summary>Sprawdza OSV wyłącznie dla dokładnego repozytorium GitHub z metadanych pakietu.</summary>
public static class OsvClient
{
    private const string Endpoint = "https://api.osv.dev/v1/query";
    private static readonly TimeSpan CacheTtl = TimeSpan.FromHours(24);
    private static readonly ConcurrentDictionary<string, (DateTimeOffset Time, IReadOnlyList<OsvItem> Items)> Cache = new();
    private static readonly System.Text.Json.JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase,
    };

    public static string? GitHubRepository(string? homepage)
    {
        if (!Uri.TryCreate(homepage, UriKind.Absolute, out var uri) ||
            uri.Scheme != Uri.UriSchemeHttps ||
            !uri.Host.Equals("github.com", StringComparison.OrdinalIgnoreCase) ||
            uri.UserInfo.Length > 0 || uri.Query.Length > 0 || uri.Fragment.Length > 0)
            return null;

        var parts = uri.AbsolutePath.Trim('/').Split('/');
        if (parts.Length != 2 || !IsSafePart(parts[0]) || !IsSafePart(parts[1])) return null;
        var repository = parts[1].EndsWith(".git", StringComparison.OrdinalIgnoreCase) ? parts[1][..^4] : parts[1];
        if (!IsSafePart(repository)) return null;
        return $"{parts[0]}/{repository}";
    }

    public static async Task<IReadOnlyList<OsvItem>> CheckGitHubRepositoryAsync(string owner, string repository,
        string version, CancellationToken ct = default)
    {
        if (!IsSafePart(owner) || !IsSafePart(repository) || version.Length is 0 or > 128 ||
            version.Any(char.IsControl))
            throw new ArgumentException("A valid GitHub owner, repository, and installed version are required.");

        var key = $"{owner}/{repository}@{version}";
        if (Cache.TryGetValue(key, out var cached) && DateTimeOffset.UtcNow - cached.Time < CacheTtl)
            return cached.Items;

        var requestBody = new
        {
            version,
            package = new { name = $"https://github.com/{owner}/{repository}", ecosystem = "GIT" },
        };
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, Endpoint)
            {
                Content = JsonContent.Create(requestBody, options: JsonOptions),
            };
            using var response = await RiskHttp.Client.SendAsync(request, ct);
            if (response.RequestMessage?.RequestUri?.Scheme != Uri.UriSchemeHttps)
                throw new RiskException(L.F("Odpowiedź z {0} nie pochodzi z połączenia HTTPS.", Endpoint));
            if (response.StatusCode != HttpStatusCode.OK)
                throw new RiskException(L.F("OSV zwrócił kod HTTP {0}.", (int)response.StatusCode));

            var root = RiskHttp.ParseJson(await response.Content.ReadAsStringAsync(ct), Endpoint);
            var items = Parse(root);
            Cache[key] = (DateTimeOffset.UtcNow, items);
            return items;
        }
        catch (RiskException)
        {
            throw;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or System.Text.Json.JsonException)
        {
            throw new RiskException(L.F("Nie udało się sprawdzić repozytorium {0} w OSV: {1}", key, ex.Message), ex);
        }
    }

    internal static IReadOnlyList<OsvItem> Parse(JsonNode root) =>
        (root["vulns"]?.AsArray().OfType<JsonObject>() ?? [])
        .Select(item => new OsvItem(
            item["id"]?.GetValue<string>() ?? "",
            item["summary"]?.GetValue<string>() ?? item["details"]?.GetValue<string>() ?? "",
            item["aliases"]?.AsArray().Select(alias => alias?.GetValue<string>() ?? "")
                .Where(alias => alias.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).ToArray() ?? []))
        .Where(item => item.Id.Length > 0)
        .DistinctBy(item => item.Id, StringComparer.OrdinalIgnoreCase)
        .OrderBy(item => item.Id, StringComparer.OrdinalIgnoreCase)
        .ToArray();

    private static bool IsSafePart(string value) =>
        value.Length is > 0 and <= 100 && value != "." && value != ".." &&
        value.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.');
}
