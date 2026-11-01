"""Integracja z Windows Package Manager (winget, https://github.com/microsoft/winget-cli, licencja MIT)."""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from typing import Callable, Optional

from .models import Software, normalize_name

COMMON_ARGS = ["--accept-source-agreements", "--disable-interactivity"]
TRUSTED_SOURCES = {"winget", "msstore"}
LOCAL_ID_PREFIXES = ("ARP\\", "MSIX\\")

_CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


class WingetError(RuntimeError):
    pass


@dataclass
class WingetPackage:
    name: str
    id: str
    version: str = ""
    available: str = ""
    source: str = ""

    @property
    def is_local_only(self) -> bool:
        return self.id.startswith(LOCAL_ID_PREFIXES)


def is_available() -> bool:
    return shutil.which("winget") is not None


def _decode(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode(sys.getdefaultencoding(), errors="replace")


def run(args: list[str], timeout: int = 300) -> tuple[int, str]:
    if not is_available():
        raise WingetError("Nie znaleziono programu winget. Zainstaluj „Instalator aplikacji” z Microsoft Store.")
    try:
        proc = subprocess.run(
            ["winget", *args],
            capture_output=True,
            timeout=timeout,
            creationflags=_CREATE_NO_WINDOW,
        )
    except subprocess.TimeoutExpired as exc:
        raise WingetError(f"Przekroczono czas oczekiwania na winget ({timeout} s).") from exc
    return proc.returncode, _decode(proc.stdout) + _decode(proc.stderr)


def _split_lines(text: str) -> list[str]:
    # winget rysuje paski postępu przy użyciu \r - interesuje nas tylko ostatni stan linii.
    lines = []
    for raw in text.split("\n"):
        parts = [p for p in raw.split("\r") if p.strip()]
        lines.append(parts[-1].rstrip() if parts else "")
    return lines


def parse_table(text: str) -> list[list[str]]:
    """Parsuje tabele o stałej szerokości kolumn wypisywane przez winget (list/upgrade/search)."""
    lines = _split_lines(text)
    rows: list[list[str]] = []
    for idx, line in enumerate(lines):
        if not re.fullmatch(r"-{5,}", line.strip()):
            continue
        header_idx = idx - 1
        while header_idx >= 0 and not lines[header_idx].strip():
            header_idx -= 1
        if header_idx < 0:
            continue
        header = lines[header_idx]
        starts = [m.start() for m in re.finditer(r"\S+", header)]
        if len(starts) < 3:
            continue
        for row_line in lines[idx + 1:]:
            if not row_line.strip():
                break
            if len(row_line) <= starts[1] or row_line[starts[1] - 1] != " ":
                break
            cells = []
            for i, start in enumerate(starts):
                end = starts[i + 1] if i + 1 < len(starts) else None
                cells.append(row_line[start:end].strip())
            if not cells[1]:
                break
            rows.append(cells)
    return rows


def _rows_to_packages(rows: list[list[str]]) -> list[WingetPackage]:
    packages = []
    for cells in rows:
        cells = cells + [""] * (5 - len(cells))
        packages.append(
            WingetPackage(name=cells[0], id=cells[1], version=cells[2], available=cells[3], source=cells[4])
        )
    return packages


def list_installed() -> list[WingetPackage]:
    """Wszystkie pakiety rozpoznane przez winget (z dostępną wersją, jeśli jest nowsza)."""
    code, out = run(["list", *COMMON_ARGS])
    packages = _rows_to_packages(parse_table(out))
    if code != 0 and not packages:
        raise WingetError(f"winget list zakończył się kodem {code:#x}:\n{out.strip()}")
    return packages


def list_upgrades() -> list[WingetPackage]:
    code, out = run(["upgrade", "--include-unknown", *COMMON_ARGS])
    packages = _rows_to_packages(parse_table(out))
    if code != 0 and not packages and "No installed package" not in out:
        raise WingetError(f"winget upgrade zakończył się kodem {code:#x}:\n{out.strip()}")
    return packages


def search(query: str) -> list[WingetPackage]:
    code, out = run(["search", "--query", query, *COMMON_ARGS], timeout=120)
    result = []
    for cells in parse_table(out):
        # Kolumny: Name, Id, Version, [Match], Source
        result.append(
            WingetPackage(name=cells[0], id=cells[1], version=cells[2], source=cells[-1] if len(cells) >= 4 else "")
        )
    return result


def parse_show(text: str) -> dict:
    """Parsuje wynik `winget show` do słownika. Klucze sekcji Installer mają prefiks 'Installer.'."""
    info: dict = {}
    section: Optional[str] = None
    for line in _split_lines(text):
        found = re.match(r"^\S.*?\[(?P<id>[^\]]+)\]\s*$", line)
        if found and "name" not in info and ":" not in line.split("[")[0]:
            info["id"] = found.group("id")
            info["name"] = line.split(" ", 1)[1].rsplit("[", 1)[0].strip() if " " in line else ""
            continue
        m = re.match(r"^(?P<indent>\s*)(?P<key>[^\W\d_][\w ]*?):(?:\s+(?P<value>.*))?$", line)
        if not m:
            continue
        indent = len(m.group("indent"))
        key = m.group("key").strip()
        value = (m.group("value") or "").strip()
        if indent == 0:
            if value:
                info[key] = value
                section = None
            else:
                section = key
        elif section and section.casefold().startswith("installer") and indent <= 4 and value:
            info[f"Installer.{key}"] = value
    return info


def installer_url(info: dict) -> str:
    for key, value in info.items():
        if key.startswith("Installer.") and "url" in key.casefold() and str(value).lower().startswith("http"):
            return value
    return ""


def installer_sha256(info: dict) -> str:
    for key, value in info.items():
        if key.startswith("Installer.") and "sha256" in key.casefold():
            return value
    return ""


def installer_type(info: dict) -> str:
    for key, value in info.items():
        if key.startswith("Installer.") and "type" in key.casefold():
            return value
    return ""


def show(package_id: str, source: str = "") -> dict:
    args = ["show", "--id", package_id, "--exact", *COMMON_ARGS]
    if source:
        args += ["--source", source]
    code, out = run(args, timeout=120)
    info = parse_show(out)
    if code != 0 or "id" not in info:
        raise WingetError(f"Nie udało się pobrać manifestu {package_id} (kod {code & 0xFFFFFFFF:#x}):\n{out.strip()}")
    info["_raw"] = out
    return info


def upgrade(package_id: str, on_output: Callable[[str], None], source: str = "") -> int:
    """Uruchamia aktualizację. winget sam weryfikuje sumę SHA256 instalatora przed uruchomieniem."""
    args = [
        "winget", "upgrade", "--id", package_id, "--exact", "--silent",
        "--accept-package-agreements", *COMMON_ARGS,
    ]
    if source:
        args += ["--source", source]
    proc = subprocess.Popen(
        args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, creationflags=_CREATE_NO_WINDOW
    )
    assert proc.stdout is not None
    for raw in proc.stdout:
        text = _decode(raw)
        parts = [p for p in text.replace("\n", "").split("\r") if p.strip()]
        if parts:
            line = parts[-1].strip()
            if not re.fullmatch(r"[-\\|/ ]+", line):
                on_output(line)
    return proc.wait()


def _match_target(pkg: WingetPackage, by_key: dict, by_name: dict, software: list[Software]) -> Optional[Software]:
    if pkg.id.startswith("ARP\\"):
        reg_key = pkg.id.rsplit("\\", 1)[-1]
        if reg_key in by_key:
            return by_key[reg_key]
    name = pkg.name
    if name.endswith("…"):
        prefix = normalize_name(name[:-1])
        candidates = [s for s in software if normalize_name(s.name).startswith(prefix)] if prefix else []
    else:
        candidates = by_name.get(normalize_name(name), [])
    free = [c for c in candidates if not c.winget_detected]
    if free:
        candidates = free
    elif pkg.is_local_only:
        # Nie nadpisuj już powiązanego programu lokalnym wpisem (np. drugi Edge jako MSIX).
        return None
    if not candidates:
        return None
    for c in candidates:
        if c.version == pkg.version:
            return c
    return candidates[0]


def merge(software: list[Software], packages: list[WingetPackage]) -> list[Software]:
    """Łączy inwentarz z rejestru z danymi winget. Zwraca nową listę (wraz z pakietami spoza rejestru)."""
    by_key = {s.reg_key: s for s in software if s.reg_key}
    by_name: dict[str, list[Software]] = {}
    for s in software:
        by_name.setdefault(normalize_name(s.name), []).append(s)

    merged = list(software)
    for pkg in packages:
        target = _match_target(pkg, by_key, by_name, software)
        if target is None:
            target = Software(name=pkg.name, version=pkg.version, origin="winget (MSIX/Store)" if pkg.id.startswith("MSIX\\") else "winget")
            merged.append(target)
        target.winget_detected = True
        if pkg.is_local_only:
            target.winget_id = None
            target.winget_source = ""
        else:
            target.winget_id = pkg.id
            target.winget_source = pkg.source
        if pkg.available:
            target.available_version = pkg.available
        elif not target.available_version:
            target.available_version = ""
    return sorted(merged, key=lambda s: s.name.casefold())
