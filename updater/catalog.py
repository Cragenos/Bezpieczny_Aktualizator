"""Dodatkowe katalogi: Scoop Main i Chocolatey Community."""
from __future__ import annotations

import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from functools import lru_cache
from typing import Optional

from . import security

SCOOP_TREE_URL = "https://api.github.com/repos/ScoopInstaller/Main/git/trees/master?recursive=1"
SCOOP_RAW_URL = "https://raw.githubusercontent.com/ScoopInstaller/Main/master/bucket/"
CHOCO_SEARCH_URL = "https://community.chocolatey.org/api/v2/Search()"
USER_AGENT = "BezpiecznyAktualizator/1.0"


class CatalogError(RuntimeError):
    pass


@dataclass
class CatalogPackage:
    manager: str
    name: str
    id: str
    version: str
    source: str
    details_url: str = ""
    homepage: str = ""
    manifest: Optional[dict] = None


def _read_url(url: str, timeout: int = 20) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=ssl.create_default_context()) as response:
            return response.read()
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise CatalogError(f"Nie udało się pobrać danych z {url}: {exc}") from exc


def _scoop_slugs(query: str, paths: list[str], limit: int = 8) -> list[str]:
    tokens = [re.escape(t) for t in re.findall(r"[a-z0-9]+", query.casefold()) if len(t) > 1]
    if not tokens:
        return []
    files = [
        path[len("bucket/"):-len(".json")]
        for path in paths
        if path.startswith("bucket/") and path.endswith(".json")
    ]
    normalized_query = re.sub(r"[^a-z0-9]", "", query.casefold())
    exact = [
        slug for slug in files
        if normalized_query == re.sub(r"[^a-z0-9]", "", slug.casefold())
    ]
    matching = [
        slug for slug in files
        if any(re.search(rf"(?<![a-z0-9]){token}(?![a-z0-9])", slug.casefold()) for token in tokens)
    ]
    return list(dict.fromkeys(exact + matching))[:limit]


@lru_cache(maxsize=1)
def _scoop_tree() -> tuple[str, ...]:
    try:
        data = json.loads(_read_url(SCOOP_TREE_URL, timeout=45))
        paths = data.get("tree", [])
        if data.get("truncated") or not isinstance(paths, list):
            raise CatalogError("Lista manifestów Scoop Main jest niekompletna.")
        return tuple(entry["path"] for entry in paths if isinstance(entry, dict) and "path" in entry)
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise CatalogError(f"Nieprawidłowa odpowiedź GitHub API dla Scoop Main: {exc}") from exc


def search_scoop(query: str) -> list[CatalogPackage]:
    """Wyszukuje wyłącznie w oficjalnym Scoop Main; nie korzysta z dodatkowych bucketów."""
    packages = []
    for slug in _scoop_slugs(query, list(_scoop_tree())):
        url = SCOOP_RAW_URL + urllib.parse.quote(slug, safe="._+-") + ".json"
        try:
            manifest = json.loads(_read_url(url))
        except json.JSONDecodeError as exc:
            raise CatalogError(f"Nieprawidłowy manifest Scoop Main: {slug}") from exc
        packages.append(CatalogPackage(
            manager="scoop",
            name=slug,
            id=slug,
            version=str(manifest.get("version", "")),
            source="Scoop Main",
            details_url="https://github.com/ScoopInstaller/Main/blob/master/bucket/"
            + urllib.parse.quote(slug, safe="._+-") + ".json",
            homepage=str(manifest.get("homepage", "")),
            manifest=manifest,
        ))
    return packages


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _child_text(element: ET.Element, name: str) -> str:
    for child in element.iter():
        if _local_name(child.tag) == name and child.text:
            return child.text.strip()
    return ""


def search_chocolatey(query: str) -> list[CatalogPackage]:
    """Wyszukuje pakiety w oficjalnym, moderowanym kanale Chocolatey Community."""
    escaped = query.replace("'", "''")
    params = urllib.parse.urlencode({
        "searchTerm": f"'{escaped}'",
        "targetFramework": "''",
        "includePrerelease": "false",
    })
    url = f"{CHOCO_SEARCH_URL}?{params}"
    try:
        root = ET.fromstring(_read_url(url))
    except ET.ParseError as exc:
        raise CatalogError(f"Chocolatey zwróciło nieprawidłową odpowiedź XML: {exc}") from exc

    packages = []
    seen_ids = set()
    for entry in root.iter():
        if _local_name(entry.tag) != "entry":
            continue
        package_id = ""
        package_version = ""
        for child in entry:
            if _local_name(child.tag) == "id" and child.text:
                match = re.search(r"Packages\(Id='([^']+)',Version='([^']+)'\)", child.text)
                if match:
                    package_id, package_version = match.groups()
                    break
        if not package_id:
            continue
        if package_id.casefold() in seen_ids:
            continue
        seen_ids.add(package_id.casefold())
        title = _child_text(entry, "Title") or _child_text(entry, "title") or package_id
        version = _child_text(entry, "Version") or package_version
        packages.append(CatalogPackage(
            manager="chocolatey",
            name=title,
            id=package_id,
            version=version,
            source="Chocolatey Community",
            details_url=(
                "https://community.chocolatey.org/packages/"
                + urllib.parse.quote(package_id, safe="")
                + ("/" + urllib.parse.quote(version, safe="") if version else "")
            ),
            homepage=_child_text(entry, "ProjectUrl"),
        ))
        if len(packages) >= 30:
            break
    return packages


def _installer_pairs(manifest: dict) -> list[tuple[str, str]]:
    pairs = []

    def collect(node):
        if not isinstance(node, dict):
            return
        urls, hashes = node.get("url"), node.get("hash")
        if isinstance(urls, str):
            urls = [urls]
        if isinstance(hashes, str):
            hashes = [hashes]
        if isinstance(urls, list):
            for index, url in enumerate(urls):
                digest = hashes[index] if isinstance(hashes, list) and index < len(hashes) else ""
                if isinstance(url, str):
                    pairs.append((url, str(digest or "")))

    collect(manifest)
    architectures = manifest.get("architecture", {})
    if isinstance(architectures, dict):
        for node in architectures.values():
            collect(node)
    return pairs


def _manifest_has_scripts(manifest: dict) -> bool:
    script_keys = {"pre_install", "installer", "post_install"}
    if any(key in manifest for key in script_keys):
        return True
    architectures = manifest.get("architecture", {})
    if isinstance(architectures, dict):
        for details in architectures.values():
            if not isinstance(details, dict):
                continue
            if any(key in details for key in script_keys):
                return True
            uninstaller = details.get("uninstaller")
            if isinstance(uninstaller, (dict, list)) or (
                isinstance(uninstaller, str)
                and re.search(r"\.ps1\b|powershell", uninstaller, re.IGNORECASE)
            ):
                return True
    uninstaller = manifest.get("uninstaller")
    return isinstance(uninstaller, (dict, list)) or (
        isinstance(uninstaller, str) and re.search(r"\.ps1\b|powershell", uninstaller, re.IGNORECASE)
    )


def assess_scoop(package: CatalogPackage, verify_tls: bool = True) -> security.Assessment:
    manifest = package.manifest or {}
    checks = [
        security.Check(
            "Źródło: oficjalny Scoop Main", security.OK,
            "Wynik pochodzi z repozytorium ScoopInstaller/Main, a nie z dodatkowego bucketu.",
        ),
        security.Check(
            "Manifest nie jest podpisany kryptograficznie", security.WARN,
            "Zaufanie opiera się na oficjalnym repozytorium i HTTPS; sprawdź źródło przed instalacją.",
        ),
        security.Check(
            "Manifest pobrany przez HTTPS z GitHub", security.OK,
            "Aplikacja pobiera manifest z oficjalnego repozytorium ScoopInstaller/Main.",
        ),
    ]
    pairs = _installer_pairs(manifest)
    if not pairs:
        checks.append(security.Check("Adres instalatora", security.FAIL, "Manifest nie zawiera adresu URL instalatora."))
    for url, digest in pairs[:5]:
        if url.lower().startswith("https://"):
            checks.append(security.Check("Instalator przez HTTPS", security.OK, url))
        else:
            checks.append(security.Check("Instalator bez HTTPS lub z adresem dynamicznym", security.FAIL, url))
        if re.fullmatch(r"[0-9a-fA-F]{64}", digest):
            checks.append(security.Check("Suma SHA256 w manifeście", security.OK, digest))
        else:
            checks.append(security.Check(
                "Brak weryfikowalnej sumy SHA256", security.FAIL,
                "Scoop nie może zweryfikować integralności tego instalatora.",
            ))
        if verify_tls and url.lower().startswith("https://"):
            checks.append(security.check_tls(url))

    has_script = _manifest_has_scripts(manifest)
    if has_script:
        checks.append(security.Check(
            "Manifest zawiera skrypt instalacyjny", security.WARN,
            "Scoop może wykonać skrypt dostarczony przez manifest; przejrzyj go w repozytorium.",
        ))

    if any(check.status == security.FAIL for check in checks):
        level = security.LEVEL_LOW
    elif has_script:
        level = security.LEVEL_LOW
    else:
        # Oficjalny bucket i SHA256 są dobrym sygnałem, ale manifesty nie są podpisywane.
        level = security.LEVEL_MEDIUM
    return security.Assessment(
        level,
        checks,
        f"Pakiet {package.id} w wersji {package.version} z oficjalnego Scoop Main.",
    )


def assess_chocolatey(package: CatalogPackage) -> security.Assessment:
    checks = [
        security.Check(
            "Źródło: Chocolatey Community", security.OK,
            "Oficjalny kanał społecznościowy z moderacją publikowanych wersji pakietów.",
        ),
        security.Check(
            "Metadane pobrane przez HTTPS", security.OK,
            "Odpowiedź pochodzi z community.chocolatey.org po weryfikacji certyfikatu TLS.",
        ),
        security.Check(
            "Pakiet może uruchamiać skrypty PowerShell", security.FAIL,
            "Moderacja nie oznacza skanowania instalowanego programu; skrypty pakietów mogą wykonywać dowolne działania.",
        ),
        security.Check(
            "Źródło binariów i sumy kontrolne nie są tu zweryfikowane", security.WARN,
            "Przed instalacją sprawdź stronę pakietu i zgodność wydawcy z witryną producenta.",
        ),
    ]
    return security.Assessment(
        security.LEVEL_LOW,
        checks,
        f"Pakiet {package.id} w wersji {package.version}; ręcznie moderowany kanał publiczny.",
    )
