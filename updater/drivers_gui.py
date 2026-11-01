"""Zakładka „Sterowniki”: inwentarz, aktualizacje z Windows Update i instalacja."""
from __future__ import annotations

import csv
import json
import os
import queue
import threading
import traceback
import webbrowser
from datetime import datetime
from tkinter import filedialog, messagebox, ttk
import tkinter as tk
from typing import Callable, Optional

from . import drivers, security
from .drivers import Driver
from .gui import App

COLUMNS = (
    ("name", "Urządzenie", 280),
    ("class", "Klasa", 110),
    ("version", "Wersja", 120),
    ("date", "Data", 90),
    ("available", "Nowa wersja", 120),
    ("status", "Status", 150),
    ("provider", "Dostawca", 160),
    ("signature", "Podpis", 150),
    ("security", "Zaufanie", 90),
)


class DriversTab(ttk.Frame):
    def __init__(self, parent: tk.Misc, root: tk.Tk):
        super().__init__(parent, padding=6)
        self.root = root
        self.items: list[Driver] = []
        self.by_iid: dict[str, Driver] = {}
        self.updates_checked = False
        self._queue: "queue.Queue[Callable[[], None]]" = queue.Queue()
        self._busy = 0
        self._sort_col = "class"
        self._sort_desc = False

        self.filter_var = tk.StringVar()
        self.only_updates_var = tk.BooleanVar(value=False)
        self.hide_generic_var = tk.BooleanVar(value=False)
        self.restore_point_var = tk.BooleanVar(value=True)
        self.status_var = tk.StringVar(value="Gotowy.")

        self._build_ui()
        self.filter_var.trace_add("write", lambda *_: self.refresh_tree())
        self.after(100, self._poll_queue)
        self.after(300, self.scan)

    # ------------------------------------------------------------------ UI
    def _build_ui(self) -> None:
        toolbar = ttk.Frame(self)
        toolbar.pack(fill="x", pady=(0, 6))
        self.buttons: list[ttk.Button] = []

        def add_button(text: str, cmd: Callable[[], None]) -> None:
            b = ttk.Button(toolbar, text=text, command=cmd)
            b.pack(side="left", padx=(0, 4))
            self.buttons.append(b)

        add_button("Skanuj sterowniki", self.scan)
        add_button("Szukaj aktualizacji (Windows Update)", self.search_updates)
        add_button("Instaluj zaznaczone", self.install_selected)
        add_button("Instaluj wszystkie dostępne", self.install_all)
        add_button("Katalog Microsoft Update", self.open_catalog)
        add_button("Menedżer urządzeń", self.open_device_manager)
        add_button("Eksportuj raport", self.export_report)

        filters = ttk.Frame(self)
        filters.pack(fill="x", pady=(0, 6))
        ttk.Label(filters, text="Filtr:").pack(side="left")
        ttk.Entry(filters, textvariable=self.filter_var, width=40).pack(side="left", padx=(4, 12))
        ttk.Checkbutton(filters, text="Tylko z aktualizacją lub problemem", variable=self.only_updates_var,
                        command=self.refresh_tree).pack(side="left")
        ttk.Checkbutton(filters, text="Ukryj ogólne sterowniki systemu Windows", variable=self.hide_generic_var,
                        command=self.refresh_tree).pack(side="left", padx=(12, 0))
        ttk.Checkbutton(filters, text="Punkt przywracania przed instalacją",
                        variable=self.restore_point_var).pack(side="left", padx=(12, 0))
        self.count_label = ttk.Label(filters, text="")
        self.count_label.pack(side="right")

        paned = ttk.PanedWindow(self, orient="vertical")
        paned.pack(fill="both", expand=True)
        tree_frame = ttk.Frame(paned)
        self.tree = ttk.Treeview(tree_frame, columns=[c[0] for c in COLUMNS], show="headings",
                                 selectmode="extended")
        for key, title, width in COLUMNS:
            self.tree.heading(key, text=title, command=lambda k=key: self._sort_by(k))
            self.tree.column(key, width=width, stretch=key in ("name", "provider"))
        ysb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        xsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=ysb.set, xscrollcommand=xsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        ysb.grid(row=0, column=1, sticky="ns")
        xsb.grid(row=1, column=0, sticky="ew")
        tree_frame.rowconfigure(0, weight=1)
        tree_frame.columnconfigure(0, weight=1)
        self.tree.tag_configure("update", background="#fff4cc")
        self.tree.tag_configure("problem", background="#fde0e0")
        self.tree.tag_configure("low", foreground="#b00020")
        self.tree.tag_configure("high", foreground="#0b6e2e")
        self.tree.bind("<<TreeviewSelect>>", lambda _e: self.show_details())
        paned.add(tree_frame, weight=3)

        notebook = ttk.Notebook(paned)
        self.details = App._make_text(notebook)
        self.log = App._make_text(notebook)
        notebook.add(self.details.master, text="Szczegóły i ocena bezpieczeństwa")
        notebook.add(self.log.master, text="Dziennik")
        self.notebook = notebook
        paned.add(notebook, weight=2)

        statusbar = ttk.Frame(self)
        statusbar.pack(fill="x", pady=(6, 0))
        ttk.Label(statusbar, textvariable=self.status_var).pack(side="left")
        self.progress = ttk.Progressbar(statusbar, mode="indeterminate", length=200)
        self.progress.pack(side="right")

    def log_line(self, line: str) -> None:
        self.log.configure(state="normal")
        self.log.insert("end", f"[{datetime.now():%H:%M:%S}] {line}\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    # --------------------------------------------------------- threading
    def _poll_queue(self) -> None:
        try:
            while True:
                self._queue.get_nowait()()
        except queue.Empty:
            pass
        self.after(100, self._poll_queue)

    def ui(self, fn: Callable[[], None]) -> None:
        self._queue.put(fn)

    def run_background(self, description: str, work: Callable[[], object],
                       on_done: Optional[Callable[[object], None]] = None) -> None:
        self._set_busy(True, description)
        self.log_line(description)

        def runner():
            try:
                result = work()
            except Exception as exc:  # noqa: BLE001
                details = traceback.format_exc()
                self.ui(lambda e=exc, d=details: self._on_error(description, e, d))
            else:
                self.ui(lambda: on_done(result) if on_done else None)
            finally:
                self.ui(lambda: self._set_busy(False))

        threading.Thread(target=runner, daemon=True).start()

    def _on_error(self, description: str, exc: Exception, details: str) -> None:
        self.log_line(f"BŁĄD ({description}): {exc}")
        if not isinstance(exc, drivers.DriverError):
            self.log_line(details.strip())
        messagebox.showerror("Błąd", f"{description}\n\n{exc}", parent=self.root)

    def _set_busy(self, busy: bool, description: str = "") -> None:
        self._busy += 1 if busy else -1
        state = "disabled" if self._busy > 0 else "normal"
        for b in self.buttons:
            b.configure(state=state)
        if self._busy > 0:
            self.progress.start(12)
            if description:
                self.status_var.set(description)
        else:
            self.progress.stop()
            self.status_var.set(self._summary_text())

    def _summary_text(self) -> str:
        updates = sum(1 for d in self.items if d.update)
        problems = sum(1 for d in self.items if d.error_code)
        unsigned = sum(1 for d in self.items if d.is_signed is False)
        wu = "" if self.updates_checked else " (kliknij „Szukaj aktualizacji”)"
        return (f"Urządzeń: {len(self.items)} | z aktualizacją: {updates}{wu} | z problemem: {problems} | "
                f"niepodpisanych sterowników: {unsigned}")

    # -------------------------------------------------------------- tree
    def _row_values(self, d: Driver) -> tuple:
        available = ""
        if d.update:
            available = d.update.version or d.update.date
        return (d.device_name, d.device_class, d.version, d.date, available, d.status,
                d.provider or d.manufacturer, d.signature_text, d.security_level)

    def _sort_by(self, col: str) -> None:
        self._sort_desc = not self._sort_desc if self._sort_col == col else False
        self._sort_col = col
        self.refresh_tree()

    def _sort_key(self, d: Driver):
        idx = [c[0] for c in COLUMNS].index(self._sort_col)
        value = self._row_values(d)[idx]
        if self._sort_col in ("version", "available"):
            return drivers._version_tuple(str(value))
        return (str(value).casefold(), d.device_name.casefold())

    @staticmethod
    def _is_generic(d: Driver) -> bool:
        return (d.provider.casefold() == "microsoft" and d.update is None and not d.error_code)

    def refresh_tree(self) -> None:
        selected = {id(self.by_iid[i]) for i in self.tree.selection() if i in self.by_iid}
        self.tree.delete(*self.tree.get_children())
        self.by_iid.clear()
        needle = self.filter_var.get().casefold().strip()
        shown = 0
        for d in sorted(self.items, key=self._sort_key, reverse=self._sort_desc):
            if self.only_updates_var.get() and not (d.update or d.error_code or d.is_signed is False):
                continue
            if self.hide_generic_var.get() and self._is_generic(d):
                continue
            if needle and not any(needle in str(v).casefold()
                                  for v in self._row_values(d) + tuple(d.hardware_ids)):
                continue
            tags = []
            if d.update:
                tags.append("update")
            elif d.error_code or d.is_signed is False:
                tags.append("problem")
            if d.security_level == security.LEVEL_LOW:
                tags.append("low")
            elif d.security_level == security.LEVEL_HIGH:
                tags.append("high")
            iid = self.tree.insert("", "end", values=self._row_values(d), tags=tags)
            self.by_iid[iid] = d
            shown += 1
            if id(d) in selected:
                self.tree.selection_add(iid)
        self.count_label.configure(text=f"Wyświetlono {shown} z {len(self.items)}")
        if self._busy == 0:
            self.status_var.set(self._summary_text())

    def selected(self) -> list[Driver]:
        return [self.by_iid[i] for i in self.tree.selection() if i in self.by_iid]

    def _assess_all(self) -> None:
        for d in self.items:
            a = drivers.assess(d)
            d.security_level = a.level if (d.update or a.level == security.LEVEL_LOW) else ""
            d.security_report = a.report()

    def show_details(self) -> None:
        sel = self.selected()
        if not sel:
            return
        d = sel[0]
        lines = [
            d.device_name, "",
            f"Klasa urządzenia:     {d.device_class}",
            f"Producent urządzenia: {d.manufacturer}",
            f"Dostawca sterownika:  {d.provider}",
            f"Wersja / data:        {d.version} / {d.date}",
            f"Plik INF:             {d.inf_name}",
            f"Podpis:               {d.signature_text}" + (f" ({d.signer})" if d.signer else ""),
            f"Status:               {d.status}",
            f"Identyfikator:        {d.device_id}",
            "Identyfikatory sprzętu:",
        ]
        lines += [f"    {h}" for h in d.hardware_ids[:6]] or ["    (brak)"]
        if d.update:
            u = d.update
            lines += [
                "", "AKTUALIZACJA Z WINDOWS UPDATE:",
                f"    {u.title}",
                f"    Model: {u.model} | Dostawca: {u.provider} | Klasa: {u.driver_class}",
                f"    Wersja: {u.version or '?'} | Data: {u.date} | Rozmiar: {u.size / 1048576:.1f} MB",
                f"    Identyfikator aktualizacji: {u.update_id}",
            ]
            if u.support_url:
                lines.append(f"    Wsparcie: {u.support_url}")
        lines += ["", f"Katalog Microsoft Update: {d.catalog_url()}", "", "-" * 60,
                  d.security_report or drivers.assess(d).report()]
        App._set_text(self.details, "\n".join(lines))
        self.notebook.select(0)

    # ---------------------------------------------------------- actions
    def scan(self) -> None:
        def done(result):
            self.items = result
            self.updates_checked = False
            self._assess_all()
            self.refresh_tree()
            unsigned = [d.device_name for d in self.items if d.is_signed is False]
            self.log_line(f"Znaleziono {len(self.items)} urządzeń ze sterownikami.")
            if unsigned:
                self.log_line("Niepodpisane sterowniki: " + ", ".join(unsigned))

        self.run_background("Skanowanie sterowników (WMI)...", drivers.list_drivers, done)

    def search_updates(self) -> None:
        def work():
            installed = self.items or drivers.list_drivers()
            return installed, drivers.search_updates()

        def done(result):
            installed, updates = result
            self.items = drivers.match_updates(installed, updates)
            self.updates_checked = True
            self._assess_all()
            self.refresh_tree()
            self.log_line(f"Windows Update: znaleziono {len(updates)} sterowników do zainstalowania.")
            for u in updates:
                self.log_line(f"  • {u.title} [{u.hardware_id}]")
            if not updates:
                messagebox.showinfo(
                    "Sterowniki aktualne",
                    "Windows Update nie oferuje nowszych sterowników dla tego komputera.\n\n"
                    "Najnowsze wersje od producenta możesz sprawdzić w Katalogu Microsoft Update "
                    "(przycisk „Katalog Microsoft Update”) lub na stronie producenta sprzętu.",
                    parent=self.root,
                )

        self.run_background("Wyszukiwanie sterowników w Windows Update (może potrwać kilka minut)...",
                            work, done)

    def install_selected(self) -> None:
        sel = [d for d in self.selected() if d.update]
        if not sel:
            messagebox.showinfo("Brak aktualizacji",
                                "Zaznacz urządzenia z dostępną aktualizacją z Windows Update.\n"
                                "Najpierw kliknij „Szukaj aktualizacji (Windows Update)”.", parent=self.root)
            return
        self._install(sel)

    def install_all(self) -> None:
        sel = [d for d in self.items if d.update]
        if not sel:
            messagebox.showinfo("Brak aktualizacji", "Brak sterowników do zainstalowania.\n"
                                "Najpierw kliknij „Szukaj aktualizacji (Windows Update)”.", parent=self.root)
            return
        self._install(sel)

    def _install(self, selection: list[Driver]) -> None:
        updates = {}
        for d in selection:
            updates.setdefault(d.update.update_id, d.update)
        lines = [f"• {u.title} ({u.size / 1048576:.1f} MB)" for u in updates.values()]
        eula = [u for u in updates.values() if not u.eula_accepted]
        warnings = [d for d in selection if d.security_level == security.LEVEL_LOW]
        text = ("Zostaną pobrane i zainstalowane z Windows Update (pakiety podpisane przez Microsoft):\n\n"
                + "\n".join(lines[:15]) + ("\n…" if len(lines) > 15 else "")
                + "\n\nWymagane są uprawnienia administratora (monit UAC). Instalacja sterownika może "
                  "chwilowo odłączyć urządzenie (np. ekran lub sieć) i wymagać ponownego uruchomienia.")
        if self.restore_point_var.get():
            text += "\nPrzed instalacją zostanie utworzony punkt przywracania systemu."
        if eula:
            text += ("\n\nUWAGA: " + str(len(eula)) + " pakiet(y) wymagają akceptacji licencji producenta. "
                     "Kontynuując, akceptujesz te licencje.")
        if warnings:
            text += "\n\nUWAGA: część pozycji ma niski poziom zaufania - sprawdź szczegóły oceny."
        if not messagebox.askyesno("Instalacja sterowników", text + "\n\nKontynuować?",
                                   icon="warning", parent=self.root):
            return
        ids = list(updates)
        restore = self.restore_point_var.get()

        def work():
            return drivers.install_updates(ids, lambda line: self.ui(lambda l=line: self.log_line(l)), restore)

        def done(results):
            ok = reboot = 0
            for r in results:
                code = int(r.get("ResultCode") or 0)
                ok += code in (2, 3)
                reboot += bool(r.get("RebootRequired"))
                msg = drivers.RESULT_CODES.get(code, f"kod {code}")
                extra = f" (HRESULT 0x{int(r.get('HResult') or 0) & 0xFFFFFFFF:08X})" if code not in (2,) else ""
                self.log_line(f"{r.get('Title')}: {msg}{extra}" + (f" - {r['Error']}" if r.get("Error") else ""))
            summary = f"Zainstalowano {ok} z {len(ids)} sterowników."
            if reboot:
                summary += "\n\nWymagane jest ponowne uruchomienie komputera, aby zakończyć instalację."
            (messagebox.showinfo if ok == len(ids) else messagebox.showwarning)(
                "Instalacja sterowników", summary + "\n\nSzczegóły w zakładce „Dziennik”.", parent=self.root)
            self.notebook.select(1)
            self.scan()

        self.notebook.select(1)
        self.run_background(f"Instalowanie {len(ids)} sterowników przez Windows Update...", work, done)

    def open_catalog(self) -> None:
        sel = self.selected()
        if not sel:
            messagebox.showinfo("Brak zaznaczenia", "Zaznacz urządzenie na liście.", parent=self.root)
            return
        if len(sel) > 5 and not messagebox.askyesno(
                "Katalog Microsoft Update", f"Otworzyć {len(sel)} kart przeglądarki?", parent=self.root):
            return
        for d in sel:
            url = d.catalog_url()
            self.log_line(f"Katalog Microsoft Update: {url}")
            webbrowser.open(url)

    def open_device_manager(self) -> None:
        try:
            os.startfile("devmgmt.msc")  # type: ignore[attr-defined]
        except OSError as exc:
            messagebox.showerror("Błąd", str(exc), parent=self.root)

    def export_report(self) -> None:
        path = filedialog.asksaveasfilename(
            parent=self.root, title="Eksportuj raport sterowników", defaultextension=".csv",
            filetypes=[("CSV", "*.csv"), ("JSON", "*.json")],
            initialfile=f"sterowniki_{datetime.now():%Y%m%d_%H%M}.csv",
        )
        if not path:
            return
        rows = []
        for d in self.items:
            rows.append({
                "urzadzenie": d.device_name, "klasa": d.device_class, "wersja": d.version, "data": d.date,
                "dostawca": d.provider, "producent": d.manufacturer, "inf": d.inf_name,
                "podpis": d.signature_text, "status": d.status, "zaufanie": d.security_level,
                "id_sprzetu": ";".join(d.hardware_ids),
                "aktualizacja": d.update.title if d.update else "",
                "id_aktualizacji": d.update.update_id if d.update else "",
            })
        try:
            if path.lower().endswith(".json"):
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(rows, f, ensure_ascii=False, indent=2)
            else:
                with open(path, "w", encoding="utf-8-sig", newline="") as f:
                    w = csv.DictWriter(f, fieldnames=list(rows[0]) if rows else ["urzadzenie"], delimiter=";")
                    w.writeheader()
                    w.writerows(rows)
        except OSError as exc:
            messagebox.showerror("Błąd zapisu", str(exc), parent=self.root)
            return
        self.log_line(f"Zapisano raport: {path}")
