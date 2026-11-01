from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional


def normalize_name(name: str) -> str:
    return re.sub(r"[^0-9a-z]+", "", name.casefold())


@dataclass
class Software:
    name: str
    version: str = ""
    publisher: str = ""
    install_location: str = ""
    install_date: str = ""
    origin: str = ""  # np. "HKLM", "HKLM (32-bit)", "HKCU", "winget"
    reg_key: str = ""
    url_info: str = ""
    url_update: str = ""
    help_link: str = ""

    winget_id: Optional[str] = None
    winget_source: str = ""
    available_version: str = ""
    winget_detected: bool = False
    security_level: str = ""
    security_report: str = ""
    extra: dict = field(default_factory=dict)

    @property
    def has_update(self) -> bool:
        return bool(self.available_version) and self.available_version != self.version

    @property
    def can_upgrade(self) -> bool:
        return self.winget_detected and bool(self.winget_id) and self.has_update

    @property
    def status(self) -> str:
        if self.has_update:
            return "Aktualizacja dostępna"
        if self.winget_id and self.winget_source:
            return "Aktualne"
        if self.winget_detected:
            return "Brak w repozytorium"
        return ""

    def vendor_urls(self) -> list[str]:
        urls = []
        for u in (self.url_update, self.url_info, self.help_link):
            u = (u or "").strip()
            if u and u not in urls:
                urls.append(u)
        return urls
