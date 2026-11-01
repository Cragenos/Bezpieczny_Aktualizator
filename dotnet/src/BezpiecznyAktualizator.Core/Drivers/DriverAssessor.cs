using BezpiecznyAktualizator.Core.Localization;
using BezpiecznyAktualizator.Core.Security;

namespace BezpiecznyAktualizator.Core.Drivers;

/// <summary>Ocena bezpieczeństwa zainstalowanego sterownika i aktualizacji z Windows Update.</summary>
public static class DriverAssessor
{
    public static List<Check> AssessInstalled(Driver driver)
    {
        var checks = new List<Check>();
        if (driver.IsSigned is null)
        {
            if (driver.MissingDriver)
                checks.Add(new Check(L.Txt("Urządzenie nie ma zainstalowanego sterownika"), CheckStatus.Warn));
        }
        else if (driver.IsSigned == false)
        {
            checks.Add(new Check(L.Txt("Zainstalowany sterownik NIE jest podpisany cyfrowo"), CheckStatus.Fail,
                L.Txt("Rozważ wymianę na wersję z Windows Update lub od producenta.")));
        }
        else if (driver.IsWhql)
        {
            checks.Add(new Check(L.Txt("Zainstalowany sterownik podpisany przez Microsoft (WHQL)"), CheckStatus.Ok, driver.Signer));
        }
        else
        {
            checks.Add(new Check(L.Txt("Zainstalowany sterownik podpisany przez producenta"), CheckStatus.Ok,
                driver.Signer.Length > 0 ? driver.Signer : L.Txt("podpis obecny")));
        }
        return checks;
    }

    public static Assessment Assess(Driver driver)
    {
        var checks = AssessInstalled(driver);
        var upd = driver.Update;
        if (upd is null)
        {
            checks.Add(new Check(L.Txt("Brak nowszego sterownika w Windows Update"), CheckStatus.Warn,
                L.Txt("Wyszukaj ręcznie w Katalogu Microsoft Update (HTTPS): {0}", driver.CatalogUrl())));
            var level = checks.Any(c => c.Status == CheckStatus.Fail) ? Levels.Low : Levels.None;
            return new Assessment(level, checks, L.Txt("Ocena zainstalowanego sterownika."));
        }

        checks.Add(new Check(L.Txt("Źródło: Windows Update (Microsoft)"), CheckStatus.Ok,
            L.Txt("Sterowniki w Windows Update muszą być podpisane przez Microsoft (WHQL lub attestation).")));
        checks.Add(new Check(L.Txt("Pobieranie i weryfikacja przez Windows Update Agent"), CheckStatus.Ok,
            L.Txt("Agent sprawdza podpis cyfrowy i skrót pakietu przed instalacją.")));

        var hw = upd.HardwareId;
        if (hw.Length > 0 && driver.HardwareIds.Contains(hw, StringComparer.OrdinalIgnoreCase))
            checks.Add(new Check(L.Txt("Identyfikator sprzętu zgodny z urządzeniem"), CheckStatus.Ok, hw));
        else if (hw.Length > 0 && driver.CompatibleIds.Contains(hw, StringComparer.OrdinalIgnoreCase))
            checks.Add(new Check(L.Txt("Dopasowanie po identyfikatorze zgodności (ogólne)"), CheckStatus.Warn, hw));
        else
            checks.Add(new Check(L.Txt("Nie znaleziono urządzenia o tym identyfikatorze"), CheckStatus.Warn,
                hw.Length > 0 ? hw : L.Txt("brak identyfikatora")));

        var newVersion = upd.Version.Length > 0 ? upd.Version : upd.Date;
        if (driver.Version.Length > 0)
        {
            checks.Add(DriverMatcher.IsNewer(upd, driver)
                ? new Check(L.Txt("Nowsza wersja niż zainstalowana"), CheckStatus.Ok, $"{driver.Version} → {newVersion}")
                : new Check(L.Txt("Wersja nie jest nowsza od zainstalowanej"), CheckStatus.Warn,
                    L.Txt("zainstalowana {0}, w WU {1}", driver.Version, newVersion)));
        }
        if (driver.Provider.Length > 0 && upd.Provider.Length > 0 &&
            !SecurityRules.PublishersMatch(driver.Provider, upd.Provider))
            checks.Add(new Check(L.Txt("Inny dostawca niż obecny sterownik"), CheckStatus.Warn,
                L.Txt("obecnie: {0}; w WU: {1}", driver.Provider, upd.Provider)));
        if (!upd.EulaAccepted)
            checks.Add(new Check(L.Txt("Wymaga akceptacji licencji producenta"), CheckStatus.Warn));

        var summary = upd.Title + (upd.Size > 0 ? $" ({upd.SizeText})" : "");
        return new Assessment(SecurityRules.Level(checks), checks, summary);
    }

    /// <summary>Ocenia sterownik i zapisuje wynik. Poziom pokazujemy tylko przy aktualizacji lub problemie.</summary>
    public static void Apply(Driver driver)
    {
        var a = Assess(driver);
        driver.SecurityLevel = driver.Update is not null || a.Level == Levels.Low ? a.Level : "";
        driver.Assessment = a;
    }
}
