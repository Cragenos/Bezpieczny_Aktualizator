using System.Text.RegularExpressions;
using BezpiecznyAktualizator.Core.Localization;
using BezpiecznyAktualizator.Core.Models;
using BezpiecznyAktualizator.Core.Winget;

namespace BezpiecznyAktualizator.Core.Security;

/// <summary>Ocena wiarygodności źródła aktualizacji oprogramowania.</summary>
public static class SoftwareAssessor
{
    public static async Task<Assessment> AssessWingetAsync(Dictionary<string, string> info, string source,
                                                           string localPublisher = "", bool verifyTls = true,
                                                           CancellationToken ct = default)
    {
        var checks = new List<Check>();
        source = (source ?? "").ToLowerInvariant();
        var itype = WingetClient.InstallerType(info).ToLowerInvariant();
        var isStore = source == "msstore" || itype == "msstore";

        if (source == "winget")
            checks.Add(new Check(L.Txt("Źródło: oficjalne repozytorium winget-pkgs (Microsoft)"), CheckStatus.Ok,
                L.Txt("Manifesty przechodzą automatyczną walidację, skan antywirusowy i przegląd przed publikacją.")));
        else if (isStore)
            checks.Add(new Check(L.Txt("Źródło: Microsoft Store"), CheckStatus.Warn,
                L.Txt("Sklep zarządza dostarczaniem, ale aplikacje mogą pochodzić od zewnętrznych wydawców i nie są tu skanowane osobno.")));
        else
            checks.Add(new Check(L.Txt("Źródło: {0}", source.Length > 0 ? source : L.Txt("nieznane")), CheckStatus.Warn,
                L.Txt("Niestandardowe źródło winget - sprawdź, kto nim zarządza.")));

        if (isStore)
            return new Assessment(SecurityRules.Level(checks), checks, L.Txt("Aktualizacja dostarczana przez Microsoft Store."));

        var url = WingetClient.InstallerUrl(info);
        if (url.Length == 0)
            checks.Add(new Check(L.Txt("Adres instalatora"), CheckStatus.Fail, L.Txt("Manifest nie zawiera adresu instalatora.")));
        else if (url.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            checks.Add(new Check(L.Txt("Instalator pobierany przez HTTPS"), CheckStatus.Ok, url));
        else
            checks.Add(new Check(L.Txt("Instalator pobierany bez szyfrowania (HTTP)"), CheckStatus.Fail, url));

        var sha = WingetClient.InstallerSha256(info);
        checks.Add(SecurityRules.IsSha256(sha)
            ? new Check(L.Txt("Suma kontrolna SHA256 w manifeście"), CheckStatus.Ok, L.Txt("{0} - winget odrzuci plik, jeśli suma się nie zgadza.", sha))
            : new Check(L.Txt("Brak sumy kontrolnej SHA256"), CheckStatus.Fail, L.Txt("Nie można zweryfikować integralności pliku.")));

        var homepage = info.GetValueOrDefault("Homepage") ?? info.GetValueOrDefault("Publisher Url") ?? "";
        if (url.Length > 0)
        {
            var installerDomain = SecurityRules.RegistrableDomain(url);
            var host = SecurityRules.HostOf(url);
            var homeDomains = new[] { info.GetValueOrDefault("Homepage"), info.GetValueOrDefault("Publisher Url") }
                .Where(u => !string.IsNullOrEmpty(u)).Select(u => SecurityRules.RegistrableDomain(u!)).ToHashSet();
            var trustedDomains = SecurityRules.TrustedHosts.Select(SecurityRules.RegistrableDomain).ToHashSet();
            if (homeDomains.Contains(installerDomain))
                checks.Add(new Check(L.Txt("Domena instalatora zgodna ze stroną producenta"), CheckStatus.Ok, installerDomain));
            else if (SecurityRules.TrustedHosts.Contains(host) || trustedDomains.Contains(installerDomain))
                checks.Add(new Check(L.Txt("Instalator hostowany w zaufanym serwisie"), CheckStatus.Ok, host));
            else
                checks.Add(new Check(L.Txt("Domena instalatora inna niż strona producenta"), CheckStatus.Warn,
                    L.Txt("Instalator: {0}; strona producenta: {1}", installerDomain, homeDomains.Count > 0 ? string.Join(", ", homeDomains.Order()) : L.Txt("brak"))));
        }

        var manifestPublisher = info.GetValueOrDefault("Publisher") ?? "";
        if (localPublisher.Length > 0 && manifestPublisher.Length > 0)
        {
            checks.Add(SecurityRules.PublishersMatch(localPublisher, manifestPublisher)
                ? new Check(L.Txt("Wydawca zgodny z zainstalowanym programem"), CheckStatus.Ok, manifestPublisher)
                : new Check(L.Txt("Wydawca różni się od zainstalowanego programu"), CheckStatus.Warn,
                    L.Txt("Zainstalowany: {0}; w repozytorium: {1}", localPublisher, manifestPublisher)));
        }

        if (verifyTls && url.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            checks.Add(await SecurityRules.CheckTlsAsync(url, ct));

        var summary = L.Txt("Pakiet {0} w wersji {1}", info.GetValueOrDefault("id"), info.GetValueOrDefault("Version") ?? "?") +
                      (homepage.Length > 0 ? L.Txt(", strona: {0}", homepage) : "");
        return new Assessment(SecurityRules.Level(checks), checks, summary);
    }

    /// <summary>Ocena programów spoza repozytoriów - tylko adresy zapisane przez instalator.</summary>
    public static async Task<Assessment> AssessVendorAsync(Software sw, bool verifyTls = true, CancellationToken ct = default)
    {
        var urls = sw.VendorUrls();
        var checks = new List<Check>
        {
            new(L.Txt("Program nie jest śledzony przez zaufane repozytorium"), CheckStatus.Warn,
                L.Txt("Brak sum kontrolnych - aktualizację należy pobrać ręcznie ze strony producenta.")),
        };
        if (urls.Count == 0)
            return new Assessment(Levels.None, checks, L.Txt("Instalator nie zapisał adresu strony producenta."));

        var anyHttps = false;
        foreach (var url in urls)
        {
            if (!Regex.IsMatch(url, "^https?://", RegexOptions.IgnoreCase))
            {
                checks.Add(new Check(L.Txt("Nieprawidłowy adres"), CheckStatus.Warn, url));
            }
            else if (url.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            {
                anyHttps = true;
                checks.Add(new Check(L.Txt("Strona producenta (HTTPS)"), CheckStatus.Ok, url));
                if (verifyTls) checks.Add(await SecurityRules.CheckTlsAsync(url, ct));
            }
            else
            {
                var httpsUrl = "https://" + url["http://".Length..];
                var tls = verifyTls ? await SecurityRules.CheckTlsAsync(httpsUrl, ct) : null;
                if (tls?.Status == CheckStatus.Ok)
                {
                    anyHttps = true;
                    checks.Add(new Check(L.Txt("Adres zapisany jako HTTP, ale strona działa poprawnie przez HTTPS"),
                        CheckStatus.Warn, L.Txt("Używaj: {0}", httpsUrl)));
                    checks.Add(tls);
                }
                else
                {
                    checks.Add(new Check(L.Txt("Strona producenta bez szyfrowania (HTTP)"), CheckStatus.Fail, url));
                }
            }
        }
        var level = !anyHttps || checks.Any(c => c.Status == CheckStatus.Fail) ? Levels.Low : Levels.Medium;
        return new Assessment(level, checks, L.Txt("Ocena na podstawie adresów zapisanych w rejestrze przez instalator."));
    }

    /// <summary>Ocenia program (winget lub strona producenta) i zapisuje wynik w obiekcie.</summary>
    public static async Task AssessSoftwareAsync(Software s, bool verifyTls, CancellationToken ct = default)
    {
        Assessment result;
        if (!string.IsNullOrEmpty(s.WingetId) && s.WingetSource.Length > 0)
        {
            var info = await WingetClient.ShowAsync(s.WingetId, s.WingetSource, ct);
            result = await AssessWingetAsync(info, s.WingetSource, s.Publisher, verifyTls, ct);
            if (s.HasUpdate && !s.WingetDetected)
                result.Summary += "\n" + L.Txt("Uwaga: winget nie powiązał tej instalacji z pakietem - aktualizację można zainstalować poleceniem: {0}", $"winget install --id {s.WingetId} --exact");
            s.Homepage = info.GetValueOrDefault("Homepage") ?? info.GetValueOrDefault("Publisher Url") ?? "";
        }
        else
        {
            result = await AssessVendorAsync(s, verifyTls, ct);
        }
        s.SecurityLevel = result.Level;
        s.Assessment = result;
    }
}
