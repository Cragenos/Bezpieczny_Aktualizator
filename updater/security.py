"""Ocena wiarygodności źródła aktualizacji."""
from __future__ import annotations

import re
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from urllib.parse import urlparse

from . import winget
from .models import Software

OK, WARN, FAIL = "ok", "warn", "fail"
LEVEL_HIGH, LEVEL_MEDIUM, LEVEL_LOW, LEVEL_NONE = "Wysoki", "Średni", "Niski", "Brak źródła"

# Znane, zaufane serwery dystrybucji wydań open source / producentów.
TRUSTED_HOSTS = {
    "github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com",
    "gitlab.com", "sourceforge.net", "downloads.sourceforge.net",
    "download.microsoft.com", "aka.ms", "go.microsoft.com", "dl.google.com",
    "download.mozilla.org", "ftp.mozilla.org", "cdn.jsdelivr.net",
}
_SECOND_LEVEL = {"co", "com", "org", "net", "gov", "ac", "edu"}
_PUBLISHER_STOPWORDS = {
    "inc", "llc", "ltd", "gmbh", "corp", "corporation", "co", "the", "foundation", "project",
    "software", "sp", "zoo", "sa", "ag", "bv", "limited", "company", "technologies",
}


@dataclass
class Check:
    label: str
    status: str
    detail: str = ""


@dataclass
class Assessment:
    level: str
    checks: list[Check] = field(default_factory=list)
    summary: str = ""

    def report(self) -> str:
        icons = {OK: "[OK]  ", WARN: "[!]   ", FAIL: "[BŁĄD]"}
        lines = [f"Poziom zaufania: {self.level}", self.summary, ""]
        for c in self.checks:
            lines.append(f"{icons[c.status]} {c.label}")
            if c.detail:
                lines.append(f"        {c.detail}")
        return "\n".join(lines).strip()


def registrable_domain(url_or_host: str) -> str:
    host = urlparse(url_or_host).hostname if "://" in url_or_host else url_or_host
    host = (host or "").lower().strip(".")
    parts = host.split(".")
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in _SECOND_LEVEL:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _publisher_tokens(text: str) -> set[str]:
    tokens = set(re.findall(r"[0-9a-z]+", text.casefold()))
    return {t for t in tokens if len(t) > 1 and t not in _PUBLISHER_STOPWORDS}


def publishers_match(a: str, b: str) -> bool:
    ta, tb = _publisher_tokens(a), _publisher_tokens(b)
    if not ta or not tb:
        return False
    if ta & tb:
        return True
    ja, jb = "".join(sorted(ta)), "".join(sorted(tb))
    return ja in jb or jb in ja


def check_tls(url: str, timeout: float = 10.0) -> Check:
    """Łączy się z serwerem z pełną weryfikacją certyfikatu (bez pobierania pliku)."""
    label = f"Certyfikat TLS serwera {urlparse(url).hostname}"
    context = ssl.create_default_context()
    request = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "BezpiecznyAktualizator/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as resp:
            final = resp.geturl()
            if not final.lower().startswith("https://"):
                return Check(label, FAIL, f"Przekierowanie na niezaszyfrowany adres: {final}")
            return Check(label, OK, f"Połączenie zweryfikowane (HTTP {resp.status}).")
    except urllib.error.HTTPError as exc:
        # Serwer odpowiedział - uzgadnianie TLS (z weryfikacją certyfikatu) zakończyło się sukcesem.
        return Check(label, OK, f"Certyfikat poprawny (serwer zwrócił HTTP {exc.code} na zapytanie HEAD).")
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, ssl.SSLCertVerificationError):
            return Check(label, FAIL, f"Nieprawidłowy certyfikat: {exc.reason.verify_message}")
        if isinstance(exc.reason, ssl.SSLError):
            return Check(label, FAIL, f"Błąd TLS: {exc.reason}")
        return Check(label, WARN, f"Nie udało się połączyć: {exc.reason}")
    except Exception as exc:  # noqa: BLE001 - sieć może zgłosić wiele różnych wyjątków
        return Check(label, WARN, f"Nie udało się połączyć: {exc}")


def _level(checks: list[Check]) -> str:
    if any(c.status == FAIL for c in checks):
        return LEVEL_LOW
    warns = sum(c.status == WARN for c in checks)
    if warns <= 1:
        return LEVEL_HIGH
    if warns <= 3:
        return LEVEL_MEDIUM
    return LEVEL_LOW


def assess_winget(info: dict, source: str, local_publisher: str = "", verify_tls: bool = True) -> Assessment:
    checks: list[Check] = []
    source = (source or "").casefold()
    itype = winget.installer_type(info).casefold()

    if source == "winget":
        checks.append(Check(
            "Źródło: oficjalne repozytorium winget-pkgs (Microsoft)", OK,
            "Manifesty przechodzą automatyczną walidację, skan antywirusowy i przegląd przed publikacją.",
        ))
    elif source == "msstore" or itype == "msstore":
        checks.append(Check(
            "Źródło: Microsoft Store", OK,
            "Pakiety są certyfikowane i podpisane przez Microsoft.",
        ))
    else:
        checks.append(Check(f"Źródło: {source or 'nieznane'}", WARN, "Niestandardowe źródło winget - sprawdź, kto nim zarządza."))

    if source == "msstore" or itype == "msstore":
        assessment = Assessment(_level(checks), checks)
        assessment.summary = "Aktualizacja dostarczana przez Microsoft Store."
        return assessment

    url = winget.installer_url(info)
    if not url:
        checks.append(Check("Adres instalatora", FAIL, "Manifest nie zawiera adresu instalatora."))
    elif url.lower().startswith("https://"):
        checks.append(Check("Instalator pobierany przez HTTPS", OK, url))
    else:
        checks.append(Check("Instalator pobierany bez szyfrowania (HTTP)", FAIL, url))

    sha = winget.installer_sha256(info)
    if re.fullmatch(r"[0-9A-Fa-f]{64}", sha or ""):
        checks.append(Check(
            "Suma kontrolna SHA256 w manifeście", OK,
            f"{sha} - winget odrzuci plik, jeśli suma się nie zgadza.",
        ))
    else:
        checks.append(Check("Brak sumy kontrolnej SHA256", FAIL, "Nie można zweryfikować integralności pliku."))

    homepage = info.get("Homepage") or info.get("Publisher Url") or ""
    if url:
        inst_dom = registrable_domain(url)
        host = (urlparse(url).hostname or "").lower()
        home_doms = {registrable_domain(u) for u in (info.get("Homepage", ""), info.get("Publisher Url", "")) if u}
        if inst_dom in home_doms:
            checks.append(Check("Domena instalatora zgodna ze stroną producenta", OK, inst_dom))
        elif host in TRUSTED_HOSTS or inst_dom in {registrable_domain(h) for h in TRUSTED_HOSTS}:
            checks.append(Check("Instalator hostowany w zaufanym serwisie", OK, host))
        else:
            checks.append(Check(
                "Domena instalatora inna niż strona producenta", WARN,
                f"Instalator: {inst_dom}; strona producenta: {', '.join(sorted(home_doms)) or 'brak'}",
            ))

    manifest_publisher = info.get("Publisher", "")
    if local_publisher and manifest_publisher:
        if publishers_match(local_publisher, manifest_publisher):
            checks.append(Check("Wydawca zgodny z zainstalowanym programem", OK, manifest_publisher))
        else:
            checks.append(Check(
                "Wydawca różni się od zainstalowanego programu", WARN,
                f"Zainstalowany: {local_publisher}; w repozytorium: {manifest_publisher}",
            ))

    if verify_tls and url.lower().startswith("https://"):
        checks.append(check_tls(url))

    assessment = Assessment(_level(checks), checks)
    assessment.summary = (
        f"Pakiet {info.get('id', '')} w wersji {info.get('Version', '?')}"
        + (f", strona: {homepage}" if homepage else "")
    )
    return assessment


def assess_vendor(sw: Software, verify_tls: bool = True) -> Assessment:
    """Ocena dla programów nieobecnych w repozytoriach - tylko adresy zapisane przez instalator."""
    urls = sw.vendor_urls()
    checks: list[Check] = [Check(
        "Program nie jest śledzony przez zaufane repozytorium", WARN,
        "Brak sum kontrolnych - aktualizację należy pobrać ręcznie ze strony producenta.",
    )]
    if not urls:
        return Assessment(LEVEL_NONE, checks, "Instalator nie zapisał adresu strony producenta.")
    any_https = False
    for url in urls:
        if not re.match(r"^https?://", url, re.I):
            checks.append(Check("Nieprawidłowy adres", WARN, url))
        elif url.lower().startswith("https://"):
            any_https = True
            checks.append(Check("Strona producenta (HTTPS)", OK, url))
            if verify_tls:
                checks.append(check_tls(url))
        else:
            https_url = "https://" + url[len("http://"):]
            tls = check_tls(https_url) if verify_tls else None
            if tls is not None and tls.status == OK:
                any_https = True
                checks.append(Check(
                    "Adres zapisany jako HTTP, ale strona działa poprawnie przez HTTPS", WARN,
                    f"Używaj: {https_url}",
                ))
                checks.append(tls)
            else:
                checks.append(Check("Strona producenta bez szyfrowania (HTTP)", FAIL, url))
    if not any_https:
        level = LEVEL_LOW
    elif any(c.status == FAIL for c in checks):
        level = LEVEL_LOW
    else:
        level = LEVEL_MEDIUM
    return Assessment(level, checks, "Ocena na podstawie adresów zapisanych w rejestrze przez instalator.")
