"""Inwentaryzacja oprogramowania na podstawie kluczy Uninstall w rejestrze Windows."""
from __future__ import annotations

import sys

from .models import Software, normalize_name

UNINSTALL_PATH = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
SKIPPED_RELEASE_TYPES = {"update", "hotfix", "security update", "service pack"}


def _read_value(key, name: str):
    import winreg

    try:
        value, _ = winreg.QueryValueEx(key, name)
        return value
    except OSError:
        return None


def _iter_uninstall_entries():
    import winreg

    views = [
        (winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_64KEY, "HKLM"),
        (winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_32KEY, "HKLM (32-bit)"),
        (winreg.HKEY_CURRENT_USER, 0, "HKCU"),
    ]
    for hive, flag, label in views:
        try:
            root = winreg.OpenKey(hive, UNINSTALL_PATH, 0, winreg.KEY_READ | flag)
        except OSError:
            continue
        with root:
            index = 0
            while True:
                try:
                    sub_name = winreg.EnumKey(root, index)
                except OSError:
                    break
                index += 1
                try:
                    with winreg.OpenKey(root, sub_name, 0, winreg.KEY_READ | flag) as sub:
                        yield label, sub_name, sub
                except OSError:
                    continue


def scan_installed() -> list[Software]:
    """Zwraca listę programów widocznych w „Programy i funkcje”."""
    if sys.platform != "win32":
        return []

    result: dict[tuple[str, str], Software] = {}
    for origin, sub_name, key in _iter_uninstall_entries():
        name = _read_value(key, "DisplayName")
        if not name or not isinstance(name, str):
            continue
        if _read_value(key, "SystemComponent") == 1:
            continue
        if _read_value(key, "ParentKeyName"):
            continue
        release_type = str(_read_value(key, "ReleaseType") or "").casefold()
        if release_type in SKIPPED_RELEASE_TYPES:
            continue

        sw = Software(
            name=name.strip(),
            version=str(_read_value(key, "DisplayVersion") or "").strip(),
            publisher=str(_read_value(key, "Publisher") or "").strip(),
            install_location=str(_read_value(key, "InstallLocation") or "").strip(),
            install_date=str(_read_value(key, "InstallDate") or "").strip(),
            origin=origin,
            reg_key=sub_name,
            url_info=str(_read_value(key, "URLInfoAbout") or "").strip(),
            url_update=str(_read_value(key, "URLUpdateInfo") or "").strip(),
            help_link=str(_read_value(key, "HelpLink") or "").strip(),
        )
        dedupe_key = (normalize_name(sw.name), sw.version)
        if dedupe_key not in result:
            result[dedupe_key] = sw

    return sorted(result.values(), key=lambda s: s.name.casefold())
