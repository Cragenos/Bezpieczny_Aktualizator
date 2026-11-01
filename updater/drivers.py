"""Sterowniki: inwentarz (WMI), wyszukiwanie aktualizacji i instalacja przez Windows Update Agent.

Windows Update dostarcza wyłącznie sterowniki podpisane przez Microsoft (WHQL / attestation),
a Windows Update Agent weryfikuje podpis i skrót pobranych pakietów przed instalacją.
"""
from __future__ import annotations

import base64
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from typing import Callable, Optional
from urllib.parse import quote

from . import security

_CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
CATALOG_SEARCH_URL = "https://www.catalog.update.microsoft.com/Search.aspx?q="
WHQL_SIGNERS = ("microsoft windows hardware compatibility publisher", "microsoft windows")
RESULT_CODES = {
    0: "Nie rozpoczęto", 1: "W toku", 2: "Zainstalowano", 3: "Zainstalowano z błędami",
    4: "Błąd", 5: "Przerwano",
}


class DriverError(RuntimeError):
    pass


@dataclass
class DriverUpdate:
    update_id: str
    title: str
    model: str = ""
    manufacturer: str = ""
    provider: str = ""
    driver_class: str = ""
    hardware_id: str = ""
    date: str = ""
    size: int = 0
    eula_accepted: bool = True
    support_url: str = ""
    description: str = ""

    @property
    def version(self) -> str:
        # Tytuły WU mają postać „Dostawca - Klasa - 1.2.3.4”.
        m = re.search(r"(\d+(?:\.\d+){1,3})\s*$", self.title)
        return m.group(1) if m else ""


@dataclass
class Driver:
    device_name: str
    device_id: str = ""
    version: str = ""
    date: str = ""
    provider: str = ""
    manufacturer: str = ""
    inf_name: str = ""
    device_class: str = ""
    is_signed: Optional[bool] = None
    signer: str = ""
    hardware_ids: list[str] = field(default_factory=list)
    compatible_ids: list[str] = field(default_factory=list)
    error_code: int = 0
    update: Optional[DriverUpdate] = None
    security_level: str = ""
    security_report: str = ""

    @property
    def missing_driver(self) -> bool:
        return self.error_code == 28

    @property
    def signature_text(self) -> str:
        if self.is_signed is None:
            return "brak sterownika" if self.missing_driver else "?"
        if not self.is_signed:
            return "NIEPODPISANY"
        if self.signer.casefold() in WHQL_SIGNERS:
            return "Microsoft (WHQL)"
        return self.signer or "podpisany"

    @property
    def status(self) -> str:
        if self.update:
            if self.missing_driver:
                return "Sterownik dostępny"
            return "Aktualizacja dostępna" if is_newer(self.update, self) else "Alternatywna wersja"
        if self.missing_driver:
            return "Brak sterownika"
        if self.error_code:
            return f"Problem (kod {self.error_code})"
        return "OK"

    def catalog_url(self) -> str:
        query = self.hardware_ids[0] if self.hardware_ids else self.device_name
        return CATALOG_SEARCH_URL + quote(query)


# --------------------------------------------------------------------- PowerShell
def _powershell_exe() -> str:
    root = os.environ.get("SystemRoot", r"C:\Windows")
    path = os.path.join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
    return path if os.path.exists(path) else "powershell.exe"


def run_powershell(script: str, timeout: int = 600) -> str:
    if sys.platform != "win32":
        raise DriverError("Funkcja dostępna tylko w systemie Windows.")
    prefix = "$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[Text.Encoding]::UTF8;\n"
    encoded = base64.b64encode((prefix + script).encode("utf-16-le")).decode("ascii")
    try:
        proc = subprocess.run(
            [_powershell_exe(), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
             "-EncodedCommand", encoded],
            capture_output=True, timeout=timeout, creationflags=_CREATE_NO_WINDOW,
        )
    except subprocess.TimeoutExpired as exc:
        raise DriverError(f"Przekroczono czas oczekiwania ({timeout} s).") from exc
    out = proc.stdout.decode("utf-8", errors="replace")
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", errors="replace") or out
        raise DriverError(f"PowerShell zakończył się kodem {proc.returncode}:\n{err.strip()}")
    return out


def _json_list(text: str) -> list[dict]:
    text = text.strip().lstrip("\ufeff")
    if not text:
        return []
    data = json.loads(text)
    if isinstance(data, dict):
        return [data]
    return [d for d in data if isinstance(d, dict)]


def _as_list(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value else []
    return [str(v) for v in value if v]


INVENTORY_SCRIPT = r"""
$entities = @{}
foreach ($e in Get-CimInstance Win32_PnPEntity) {
    if ($e.PNPDeviceID) { $entities[$e.PNPDeviceID] = $e }
}
$seen = @{}
$list = New-Object System.Collections.ArrayList
foreach ($d in Get-CimInstance Win32_PnPSignedDriver) {
    if (-not $d.DeviceName -or -not $d.DeviceID) { continue }
    $e = $entities[$d.DeviceID]
    $seen[$d.DeviceID] = $true
    $date = ''
    if ($d.DriverDate) { $date = $d.DriverDate.ToString('yyyy-MM-dd') }
    [void]$list.Add([ordered]@{
        DeviceName = $d.DeviceName; DeviceID = $d.DeviceID; DriverVersion = $d.DriverVersion
        DriverDate = $date; DriverProviderName = $d.DriverProviderName; Manufacturer = $d.Manufacturer
        InfName = $d.InfName; DeviceClass = $d.DeviceClass; IsSigned = $d.IsSigned; Signer = $d.Signer
        HardwareID = @(if ($e) { $e.HardwareID } elseif ($d.HardWareID) { $d.HardWareID })
        CompatibleID = @(if ($e) { $e.CompatibleID })
        ErrorCode = [int]$(if ($e) { $e.ConfigManagerErrorCode } else { 0 })
    })
}
foreach ($e in $entities.Values) {
    if ($seen[$e.PNPDeviceID] -or $e.ConfigManagerErrorCode -eq 0 -or -not $e.Name) { continue }
    [void]$list.Add([ordered]@{
        DeviceName = $e.Name; DeviceID = $e.PNPDeviceID; Manufacturer = $e.Manufacturer
        DeviceClass = $e.PNPClass; HardwareID = @($e.HardwareID); CompatibleID = @($e.CompatibleID)
        ErrorCode = [int]$e.ConfigManagerErrorCode
    })
}
ConvertTo-Json -InputObject @($list) -Depth 4 -Compress
"""

SEARCH_SCRIPT = r"""
$session = New-Object -ComObject Microsoft.Update.Session
$session.ClientApplicationID = 'BezpiecznyAktualizator'
$searcher = $session.CreateUpdateSearcher()
$searcher.Online = $true
$result = $searcher.Search("IsInstalled=0 and Type='Driver' and IsHidden=0")
$list = New-Object System.Collections.ArrayList
foreach ($u in $result.Updates) {
    $date = ''
    if ($u.DriverVerDate) { $date = ([datetime]$u.DriverVerDate).ToString('yyyy-MM-dd') }
    [void]$list.Add([ordered]@{
        UpdateID = $u.Identity.UpdateID; Title = $u.Title; DriverModel = $u.DriverModel
        DriverManufacturer = $u.DriverManufacturer; DriverProvider = $u.DriverProvider
        DriverClass = $u.DriverClass; DriverHardwareID = $u.DriverHardwareID; DriverVerDate = $date
        MaxDownloadSize = [int64]$u.MaxDownloadSize; EulaAccepted = [bool]$u.EulaAccepted
        SupportUrl = $u.SupportUrl; Description = $u.Description
    })
}
ConvertTo-Json -InputObject @($list) -Depth 3 -Compress
"""

INSTALL_SCRIPT = r"""
param([string]$IdsFile, [string]$LogFile, [string]$ResultFile, [int]$RestorePoint)
$ErrorActionPreference = 'Stop'
function Log([string]$m) { Add-Content -LiteralPath $LogFile -Value $m -Encoding UTF8 }
$results = New-Object System.Collections.ArrayList
try {
    $ids = @(Get-Content -LiteralPath $IdsFile -Encoding UTF8 | Where-Object { $_ })
    if ($RestorePoint -eq 1) {
        Log 'Tworzenie punktu przywracania systemu...'
        try {
            Checkpoint-Computer -Description 'Bezpieczny Aktualizator - sterowniki' -RestorePointType MODIFY_SETTINGS
            Log 'Punkt przywracania utworzony.'
        } catch { Log "Ostrzeżenie: nie utworzono punktu przywracania: $($_.Exception.Message)" }
    }
    $session = New-Object -ComObject Microsoft.Update.Session
    $session.ClientApplicationID = 'BezpiecznyAktualizator'
    $searcher = $session.CreateUpdateSearcher()
    $searcher.Online = $true
    Log 'Wyszukiwanie wybranych sterowników w Windows Update...'
    $found = $searcher.Search("IsInstalled=0 and Type='Driver' and IsHidden=0")
    $coll = New-Object -ComObject Microsoft.Update.UpdateColl
    foreach ($u in $found.Updates) {
        if ($ids -contains $u.Identity.UpdateID) {
            if (-not $u.EulaAccepted) { $u.AcceptEula() }
            [void]$coll.Add($u)
            Log "Wybrano: $($u.Title)"
        }
    }
    if ($coll.Count -eq 0) { throw 'Wybrane sterowniki nie są już dostępne w Windows Update.' }
    Log 'Pobieranie (Windows Update weryfikuje podpis i skrót pakietów)...'
    $downloader = $session.CreateUpdateDownloader()
    $downloader.Updates = $coll
    $dl = $downloader.Download()
    Log "Pobieranie zakończone, kod: $($dl.ResultCode)"
    $toInstall = New-Object -ComObject Microsoft.Update.UpdateColl
    for ($i = 0; $i -lt $coll.Count; $i++) {
        if ($coll.Item($i).IsDownloaded) { [void]$toInstall.Add($coll.Item($i)) }
        else {
            [void]$results.Add([ordered]@{ UpdateID = $coll.Item($i).Identity.UpdateID; Title = $coll.Item($i).Title
                ResultCode = 4; HResult = $dl.GetUpdateResult($i).HResult; RebootRequired = $false })
            Log "Nie pobrano: $($coll.Item($i).Title)"
        }
    }
    if ($toInstall.Count -gt 0) {
        Log 'Instalowanie...'
        $installer = $session.CreateUpdateInstaller()
        $installer.Updates = $toInstall
        $ir = $installer.Install()
        for ($i = 0; $i -lt $toInstall.Count; $i++) {
            $r = $ir.GetUpdateResult($i)
            [void]$results.Add([ordered]@{ UpdateID = $toInstall.Item($i).Identity.UpdateID; Title = $toInstall.Item($i).Title
                ResultCode = [int]$r.ResultCode; HResult = [int64]$r.HResult; RebootRequired = [bool]$r.RebootRequired })
            Log "$($toInstall.Item($i).Title): kod wyniku $($r.ResultCode)"
        }
    }
} catch {
    Log "BŁĄD: $($_.Exception.Message)"
    [void]$results.Add([ordered]@{ UpdateID = ''; Title = 'Błąd'; ResultCode = 4; HResult = 0; RebootRequired = $false
        Error = $_.Exception.Message })
}
Set-Content -LiteralPath $ResultFile -Value (ConvertTo-Json -InputObject @($results) -Depth 3) -Encoding UTF8
"""


# ----------------------------------------------------------------------- parsing
def parse_inventory(rows: list[dict]) -> list[Driver]:
    drivers = []
    for r in rows:
        signed = r.get("IsSigned")
        drivers.append(Driver(
            device_name=str(r.get("DeviceName") or "").strip(),
            device_id=str(r.get("DeviceID") or ""),
            version=str(r.get("DriverVersion") or ""),
            date=str(r.get("DriverDate") or ""),
            provider=str(r.get("DriverProviderName") or ""),
            manufacturer=str(r.get("Manufacturer") or ""),
            inf_name=str(r.get("InfName") or ""),
            device_class=str(r.get("DeviceClass") or ""),
            is_signed=signed if isinstance(signed, bool) else None,
            signer=str(r.get("Signer") or ""),
            hardware_ids=_as_list(r.get("HardwareID")),
            compatible_ids=_as_list(r.get("CompatibleID")),
            error_code=int(r.get("ErrorCode") or 0),
        ))
    return sorted(drivers, key=lambda d: (d.device_class.casefold(), d.device_name.casefold()))


def parse_updates(rows: list[dict]) -> list[DriverUpdate]:
    return [
        DriverUpdate(
            update_id=str(r.get("UpdateID") or ""),
            title=str(r.get("Title") or ""),
            model=str(r.get("DriverModel") or ""),
            manufacturer=str(r.get("DriverManufacturer") or ""),
            provider=str(r.get("DriverProvider") or ""),
            driver_class=str(r.get("DriverClass") or ""),
            hardware_id=str(r.get("DriverHardwareID") or ""),
            date=str(r.get("DriverVerDate") or ""),
            size=int(r.get("MaxDownloadSize") or 0),
            eula_accepted=bool(r.get("EulaAccepted", True)),
            support_url=str(r.get("SupportUrl") or ""),
            description=str(r.get("Description") or ""),
        )
        for r in rows if r.get("UpdateID")
    ]


def _version_tuple(v: str) -> tuple[int, ...]:
    return tuple(int(p) for p in re.findall(r"\d+", v or ""))


def is_newer(update: DriverUpdate, driver: Driver) -> bool:
    if update.version and driver.version:
        return _version_tuple(update.version) > _version_tuple(driver.version)
    if update.date and driver.date:
        return update.date > driver.date
    return True


def match_updates(drivers: list[Driver], updates: list[DriverUpdate]) -> list[Driver]:
    """Przypisuje aktualizacje do urządzeń po identyfikatorze sprzętu. Zwraca listę z niedopasowanymi."""
    result = list(drivers)
    for d in result:
        d.update = None
    for upd in updates:
        hwid = upd.hardware_id.casefold()
        targets = [d for d in result if hwid and hwid in (h.casefold() for h in d.hardware_ids)]
        if not targets:
            targets = [d for d in result if hwid and hwid in (c.casefold() for c in d.compatible_ids)]
        if not targets:
            targets = [Driver(device_name=upd.model or upd.title, provider=upd.provider,
                              manufacturer=upd.manufacturer, device_class=upd.driver_class,
                              hardware_ids=[upd.hardware_id] if upd.hardware_id else [])]
            result.append(targets[0])
        for target in targets:
            if target.update is None or is_newer(upd, Driver("", version=target.update.version,
                                                             date=target.update.date)):
                target.update = upd
    return result


# ------------------------------------------------------------------- operations
def list_drivers() -> list[Driver]:
    try:
        return parse_inventory(_json_list(run_powershell(INVENTORY_SCRIPT, timeout=180)))
    except json.JSONDecodeError as exc:
        raise DriverError(f"Nieprawidłowe dane inwentarza sterowników: {exc}") from exc


def search_updates() -> list[DriverUpdate]:
    try:
        return parse_updates(_json_list(run_powershell(SEARCH_SCRIPT, timeout=900)))
    except json.JSONDecodeError as exc:
        raise DriverError(f"Nieprawidłowa odpowiedź Windows Update: {exc}") from exc


def install_updates(update_ids: list[str], on_log: Callable[[str], None],
                    restore_point: bool = True) -> list[dict]:
    """Instaluje sterowniki przez Windows Update Agent w procesie z podniesionymi uprawnieniami (UAC)."""
    if not update_ids:
        return []
    for uid in update_ids:
        if not re.fullmatch(r"[0-9a-fA-F-]{36}", uid):
            raise DriverError(f"Nieprawidłowy identyfikator aktualizacji: {uid}")
    workdir = tempfile.mkdtemp(prefix="bezpieczny_aktualizator_")
    try:
        return _run_install(workdir, update_ids, on_log, restore_point)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def _run_install(workdir: str, update_ids: list[str], on_log: Callable[[str], None],
                 restore_point: bool) -> list[dict]:
    script = os.path.join(workdir, "install_drivers.ps1")
    ids_file = os.path.join(workdir, "ids.txt")
    log_file = os.path.join(workdir, "install.log")
    result_file = os.path.join(workdir, "result.json")
    with open(script, "w", encoding="utf-8-sig") as f:
        f.write(INSTALL_SCRIPT)
    with open(ids_file, "w", encoding="utf-8") as f:
        f.write("\n".join(update_ids))
    open(log_file, "w", encoding="utf-8").close()

    def ps_quote(s: str) -> str:
        return "'" + s.replace("'", "''") + "'"

    inner_args = (
        f"-NoProfile -ExecutionPolicy Bypass -File \"{script}\" -IdsFile \"{ids_file}\" "
        f"-LogFile \"{log_file}\" -ResultFile \"{result_file}\" -RestorePoint {1 if restore_point else 0}"
    )
    launcher = (
        f"$p = Start-Process -FilePath {ps_quote(_powershell_exe())} -Verb RunAs -WindowStyle Hidden "
        f"-Wait -PassThru -ArgumentList {ps_quote(inner_args)}; exit $p.ExitCode"
    )
    encoded = base64.b64encode(launcher.encode("utf-16-le")).decode("ascii")
    proc = subprocess.Popen(
        [_powershell_exe(), "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=_CREATE_NO_WINDOW,
    )
    position = 0

    def pump_log(final: bool = False):
        nonlocal position
        try:
            with open(log_file, "rb") as f:
                f.seek(position)
                chunk = f.read()
        except OSError:
            return
        end = len(chunk) if final else chunk.rfind(b"\n") + 1
        if end <= 0:
            return
        position += end
        text = chunk[:end].decode("utf-8", errors="replace").lstrip("\ufeff")
        for line in text.splitlines():
            if line.strip():
                on_log(line.strip())

    while proc.poll() is None:
        pump_log()
        time.sleep(0.5)
    pump_log(final=True)
    _, err = proc.communicate()
    if not os.path.exists(result_file):
        message = err.decode("utf-8", errors="replace").strip()
        if "canceled by the user" in message or "anulowana przez użytkownika" in message or "1223" in message:
            raise DriverError("Anulowano monit kontroli konta użytkownika (UAC).")
        raise DriverError(f"Instalacja nie została wykonana.\n{message}")
    with open(result_file, "r", encoding="utf-8-sig") as f:
        text = f.read()
    return _json_list(text)


# ---------------------------------------------------------------------- security
def assess_installed(driver: Driver) -> list[security.Check]:
    checks = []
    if driver.is_signed is None:
        if driver.missing_driver:
            checks.append(security.Check("Urządzenie nie ma zainstalowanego sterownika", security.WARN))
    elif not driver.is_signed:
        checks.append(security.Check("Zainstalowany sterownik NIE jest podpisany cyfrowo", security.FAIL,
                                     "Rozważ wymianę na wersję z Windows Update lub od producenta."))
    elif driver.signer.casefold() in WHQL_SIGNERS:
        checks.append(security.Check("Zainstalowany sterownik podpisany przez Microsoft (WHQL)", security.OK,
                                     driver.signer))
    else:
        checks.append(security.Check("Zainstalowany sterownik podpisany przez producenta", security.OK,
                                     driver.signer or "podpis obecny"))
    return checks


def assess(driver: Driver) -> security.Assessment:
    checks = assess_installed(driver)
    upd = driver.update
    if upd is None:
        checks.append(security.Check(
            "Brak nowszego sterownika w Windows Update", security.WARN,
            f"Wyszukaj ręcznie w Katalogu Microsoft Update (HTTPS): {driver.catalog_url()}",
        ))
        level = security.LEVEL_LOW if any(c.status == security.FAIL for c in checks) else security.LEVEL_NONE
        return security.Assessment(level, checks, "Ocena zainstalowanego sterownika.")

    checks.append(security.Check(
        "Źródło: Windows Update (Microsoft)", security.OK,
        "Sterowniki w Windows Update muszą być podpisane przez Microsoft (WHQL lub attestation).",
    ))
    checks.append(security.Check(
        "Pobieranie i weryfikacja przez Windows Update Agent", security.OK,
        "Agent sprawdza podpis cyfrowy i skrót pakietu przed instalacją.",
    ))
    hw = upd.hardware_id.casefold()
    if hw and hw in (h.casefold() for h in driver.hardware_ids):
        checks.append(security.Check("Identyfikator sprzętu zgodny z urządzeniem", security.OK, upd.hardware_id))
    elif hw and hw in (c.casefold() for c in driver.compatible_ids):
        checks.append(security.Check("Dopasowanie po identyfikatorze zgodności (ogólne)", security.WARN,
                                     upd.hardware_id))
    else:
        checks.append(security.Check("Nie znaleziono urządzenia o tym identyfikatorze", security.WARN,
                                     upd.hardware_id or "brak identyfikatora"))
    if driver.version:
        if is_newer(upd, driver):
            checks.append(security.Check("Nowsza wersja niż zainstalowana", security.OK,
                                         f"{driver.version} → {upd.version or upd.date}"))
        else:
            checks.append(security.Check("Wersja nie jest nowsza od zainstalowanej", security.WARN,
                                         f"zainstalowana {driver.version}, w WU {upd.version or upd.date}"))
    if driver.provider and upd.provider and not security.publishers_match(driver.provider, upd.provider):
        checks.append(security.Check("Inny dostawca niż obecny sterownik", security.WARN,
                                     f"obecnie: {driver.provider}; w WU: {upd.provider}"))
    if not upd.eula_accepted:
        checks.append(security.Check("Wymaga akceptacji licencji producenta", security.WARN))
    level = security._level(checks)
    summary = f"{upd.title}" + (f" ({upd.size / 1048576:.1f} MB)" if upd.size else "")
    return security.Assessment(level, checks, summary)
