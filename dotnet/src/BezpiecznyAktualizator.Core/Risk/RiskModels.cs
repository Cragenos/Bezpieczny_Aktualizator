using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using BezpiecznyAktualizator.Core.Localization;

namespace BezpiecznyAktualizator.Core.Risk;

public sealed class RiskException(string message, Exception? inner = null) : Exception(message, inner);

/// <summary>Pojedyncza podatność z bazy NVD.</summary>
public sealed record CveItem(string Id, double Score, string Severity, string Description, DateTimeOffset? Published, bool Exploited)
{
    [JsonIgnore]
    public string Url => "https://nvd.nist.gov/vuln/detail/" + Id;
}

/// <summary>Wynik sprawdzenia podatności zainstalowanej wersji programu.</summary>
public sealed class VulnerabilityReport
{
    /// <summary>Dopasowany produkt CPE w postaci „vendor:product” (pusty, gdy nie znaleziono).</summary>
    public string Cpe { get; set; } = "";
    /// <summary>Skąd pochodzi dopasowanie CPE: „map”, „endoflife.date”, „nvd”.</summary>
    public string CpeOrigin { get; set; } = "";
    public string Version { get; set; } = "";
    public List<CveItem> Items { get; set; } = [];
    public DateTimeOffset CheckedAt { get; set; }

    [JsonIgnore] public LocText? Error { get; set; }
    [JsonIgnore] public bool Checked => Error is null && Cpe.Length > 0;
    [JsonIgnore] public double MaxScore => Items.Count == 0 ? 0 : Items.Max(i => i.Score);
    [JsonIgnore] public bool Exploited => Items.Any(i => i.Exploited);
    [JsonIgnore] public bool IsUrgent => Items.Count > 0;
}

public enum LifecycleState { Unknown, Supported, Eol, Abandoned }

/// <summary>Informacje o cyklu życia (wsparciu) zainstalowanej wersji programu.</summary>
public sealed class LifecycleInfo
{
    public LifecycleState State { get; set; }
    /// <summary>„endoflife.date”, „GitHub” albo „winget”.</summary>
    public string Origin { get; set; } = "";
    public string Product { get; set; } = "";
    public string Cycle { get; set; } = "";
    public string Latest { get; set; } = "";
    public DateOnly? EolFrom { get; set; }
    public DateOnly? LastActivity { get; set; }
    public string Link { get; set; } = "";
    public LocText Reason { get; set; } = "";
}

/// <summary>Wspólny klient HTTPS dla zewnętrznych baz (NVD, endoflife.date, GitHub).</summary>
internal static class RiskHttp
{
    public static readonly HttpClient Client = Create();

    private static HttpClient Create()
    {
        var client = new HttpClient(new SocketsHttpHandler { AutomaticDecompression = DecompressionMethods.All })
        {
            Timeout = TimeSpan.FromSeconds(60),
        };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("BezpiecznyAktualizator/2.0");
        return client;
    }

    public static async Task<(HttpStatusCode Status, string Body)> GetAsync(string url, IDictionary<string, string>? headers,
                                                                            CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        foreach (var (k, v) in headers ?? new Dictionary<string, string>()) request.Headers.TryAddWithoutValidation(k, v);
        try
        {
            using var response = await Client.SendAsync(request, ct);
            if (response.RequestMessage?.RequestUri?.Scheme != Uri.UriSchemeHttps)
                throw new RiskException(L.F("Odpowiedź z {0} nie pochodzi z połączenia HTTPS.", url));
            return (response.StatusCode, await response.Content.ReadAsStringAsync(ct));
        }
        catch (Exception ex) when ((ex is HttpRequestException or TaskCanceledException) && !ct.IsCancellationRequested)
        {
            throw new RiskException(L.F("Nie udało się pobrać danych z {0}: {1}", url, ex.Message), ex);
        }
    }

    public static JsonNode ParseJson(string body, string url)
    {
        try
        {
            return JsonNode.Parse(body) ?? throw new RiskException(L.F("Nieprawidłowa odpowiedź z {0}.", url));
        }
        catch (JsonException ex)
        {
            throw new RiskException(L.F("Nieprawidłowa odpowiedź z {0}.", url), ex);
        }
    }

    public static string CacheDirectory { get; set; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "BezpiecznyAktualizator", "Cache");

    public static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase, PropertyNameCaseInsensitive = true,
    };

    /// <summary>Prosta pamięć podręczna JSON w pliku (błędy odczytu/zapisu są ignorowane).</summary>
    public static T? LoadCache<T>(string fileName) where T : class
    {
        try
        {
            var path = Path.Combine(CacheDirectory, fileName);
            return File.Exists(path) ? JsonSerializer.Deserialize<T>(File.ReadAllText(path), JsonOptions) : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            return null;
        }
    }

    public static void SaveCache<T>(string fileName, T value)
    {
        try
        {
            Directory.CreateDirectory(CacheDirectory);
            var path = Path.Combine(CacheDirectory, fileName);
            var temp = path + ".tmp";
            File.WriteAllText(temp, JsonSerializer.Serialize(value, JsonOptions));
            File.Move(temp, path, true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
        }
    }
}
