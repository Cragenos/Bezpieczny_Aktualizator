using System.Net;
using System.Security.Authentication;
using System.Text;
using System.Text.RegularExpressions;
using BezpiecznyAktualizator.Core.Localization;

namespace BezpiecznyAktualizator.Core.Security;

public enum CheckStatus { Ok, Warn, Fail }

/// <summary>Wynik pojedynczego sprawdzenia; teksty są tłumaczone przy wyświetleniu raportu.</summary>
public sealed record Check(LocText Label, CheckStatus Status, LocText? Detail = null);

/// <summary>Poziomy zaufania (wartości wewnętrzne po polsku; do wyświetlenia przez L.T).</summary>
public static class Levels
{
    public static readonly string High = L.N("Wysoki");
    public static readonly string Medium = L.N("Średni");
    public static readonly string Low = L.N("Niski");
    public static readonly string None = L.N("Brak źródła");
}

public sealed class Assessment(string level, List<Check> checks, LocText? summary = null)
{
    public string Level { get; set; } = level;
    public List<Check> Checks { get; } = checks;
    public LocText Summary { get; set; } = summary ?? "";

    public string Report()
    {
        var sb = new StringBuilder();
        sb.AppendLine(L.F("Poziom zaufania: {0}", L.T(Level)));
        sb.AppendLine(Summary.ToString());
        sb.AppendLine();
        foreach (var c in Checks)
        {
            var icon = c.Status switch { CheckStatus.Ok => "[OK]  ", CheckStatus.Warn => "[!]   ", _ => "[" + L.T("BŁĄD") + "]" };
            sb.AppendLine($"{icon} {c.Label}");
            var detail = c.Detail?.ToString() ?? "";
            if (detail.Length > 0) sb.AppendLine($"        {detail}");
        }
        return sb.ToString().Trim();
    }
}

public static partial class SecurityRules
{
    /// <summary>Znane, zaufane serwery dystrybucji wydań open source / producentów.</summary>
    public static readonly HashSet<string> TrustedHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com",
        "gitlab.com", "sourceforge.net", "downloads.sourceforge.net",
        "download.microsoft.com", "aka.ms", "go.microsoft.com", "dl.google.com",
        "download.mozilla.org", "ftp.mozilla.org", "cdn.jsdelivr.net",
    };

    private static readonly HashSet<string> SecondLevel = ["co", "com", "org", "net", "gov", "ac", "edu"];

    private static readonly HashSet<string> PublisherStopwords =
    [
        "inc", "llc", "ltd", "gmbh", "corp", "corporation", "co", "the", "foundation", "project",
        "software", "sp", "zoo", "sa", "ag", "bv", "limited", "company", "technologies",
    ];

    internal static readonly HttpClient Http = CreateClient();

    private static HttpClient CreateClient()
    {
        // Domyślna walidacja certyfikatów; przekierowania obsługujemy ręcznie, aby wykryć przejście na HTTP.
        var handler = new SocketsHttpHandler { AllowAutoRedirect = false, AutomaticDecompression = DecompressionMethods.All };
        var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(45) };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("BezpiecznyAktualizator/2.0");
        return client;
    }

    public static string RegistrableDomain(string urlOrHost)
    {
        string host = urlOrHost;
        if (urlOrHost.Contains("://"))
            host = Uri.TryCreate(urlOrHost, UriKind.Absolute, out var uri) ? uri.Host : "";
        host = host.ToLowerInvariant().Trim('.');
        var parts = host.Split('.');
        if (parts.Length >= 3 && parts[^1].Length == 2 && SecondLevel.Contains(parts[^2]))
            return string.Join('.', parts[^3..]);
        return string.Join('.', parts.Length >= 2 ? parts[^2..] : parts);
    }

    public static string HostOf(string url) =>
        Uri.TryCreate(url, UriKind.Absolute, out var uri) ? uri.Host.ToLowerInvariant() : "";

    private static HashSet<string> PublisherTokens(string text) =>
        Tokens().Matches(text.ToLowerInvariant()).Select(m => m.Value)
            .Where(t => t.Length > 1 && !PublisherStopwords.Contains(t)).ToHashSet();

    public static bool PublishersMatch(string a, string b)
    {
        var ta = PublisherTokens(a);
        var tb = PublisherTokens(b);
        if (ta.Count == 0 || tb.Count == 0) return false;
        if (ta.Overlaps(tb)) return true;
        var ja = string.Concat(ta.Order(StringComparer.Ordinal));
        var jb = string.Concat(tb.Order(StringComparer.Ordinal));
        return ja.Contains(jb) || jb.Contains(ja);
    }

    public static string Level(IEnumerable<Check> checks)
    {
        var list = checks.ToList();
        if (list.Any(c => c.Status == CheckStatus.Fail)) return Levels.Low;
        var warns = list.Count(c => c.Status == CheckStatus.Warn);
        return warns <= 1 ? Levels.High : warns <= 3 ? Levels.Medium : Levels.Low;
    }

    public static bool IsSha256(string? value) => value is not null && Sha256().IsMatch(value);

    /// <summary>Łączy się z serwerem z pełną weryfikacją certyfikatu (zapytanie HEAD, bez pobierania pliku).</summary>
    public static async Task<Check> CheckTlsAsync(string url, CancellationToken ct = default)
    {
        var label = L.Txt("Certyfikat TLS serwera {0}", HostOf(url));
        try
        {
            var current = new Uri(url);
            for (var hop = 0; hop < 8; hop++)
            {
                using var request = new HttpRequestMessage(HttpMethod.Head, current);
                using var response = await Http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
                var code = (int)response.StatusCode;
                if (code is >= 300 and < 400 && response.Headers.Location is { } location)
                {
                    current = location.IsAbsoluteUri ? location : new Uri(current, location);
                    if (current.Scheme != Uri.UriSchemeHttps)
                        return new Check(label, CheckStatus.Fail, L.Txt("Przekierowanie na niezaszyfrowany adres: {0}", current));
                    continue;
                }
                // Serwer odpowiedział - uzgadnianie TLS z weryfikacją certyfikatu zakończyło się sukcesem.
                return response.IsSuccessStatusCode
                    ? new Check(label, CheckStatus.Ok, L.Txt("Połączenie zweryfikowane (HTTP {0}).", code))
                    : new Check(label, CheckStatus.Ok, L.Txt("Certyfikat poprawny (serwer zwrócił HTTP {0} na zapytanie HEAD).", code));
            }
            return new Check(label, CheckStatus.Warn, L.Txt("Zbyt wiele przekierowań."));
        }
        catch (HttpRequestException ex) when (ex.InnerException is AuthenticationException auth)
        {
            return new Check(label, CheckStatus.Fail, L.Txt("Nieprawidłowy certyfikat lub błąd TLS: {0}", auth.Message));
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or UriFormatException)
        {
            return new Check(label, CheckStatus.Warn, L.Txt("Nie udało się połączyć: {0}", ex.Message));
        }
    }

    [GeneratedRegex("[0-9a-z]+")]
    private static partial Regex Tokens();

    [GeneratedRegex("^[0-9A-Fa-f]{64}$")]
    private static partial Regex Sha256();
}
