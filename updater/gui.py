"""Interfejs graficzny (tkinter/ttk)."""
from __future__ import annotations

import csv
import json
import queue
import re
import threading
import traceback
import webbrowser
from dataclasses import asdict
from datetime import datetime
from tkinter import filedialog, messagebox, ttk
import tkinter as tk
from typing import Callable, Optional
from urllib.parse import quote, urlparse

from . import __version__, catalog, inventory, security, winget
from .models import Software

COLUMNS = (
    ("name", "Nazwa", 300),
    ("version", "Wersja", 110),
    ("available", "Dostępna", 110),
    ("status", "Status", 150),
    ("publisher", "Wydawca", 180),
    ("source", "Źródło aktualizacji", 120),
    ("security", "Zaufanie", 90),
    ("id", "Identyfikator pakietu", 220),
)


class App(ttk.Frame):
    def __init__(self, parent: tk.Misc, root: tk.Tk):
        super().__init__(parent, padding=6)
        self.root = root
        self.items: list[Software] = []
        self.by_iid: dict[str, Software] = {}
        self._queue: "queue.Queue[Callable[[], None]]" = queue.Queue()
        self._busy = 0
        self._sort_col = "name"
        self._sort_desc = False

        self.filter_var = tk.StringVar()
        self.only_updates_var = tk.BooleanVar(value=False)
        self.verify_tls_var = tk.BooleanVar(value=True)
        self.status_var = tk.StringVar(value="Gotowy. Kliknij „Skanuj komputer”.")

        self._build_ui()
        self.filter_var.trace_add("write", lambda *_: self.refresh_tree())
        self.after(100, self._poll_queue)
        self.after(200, self.scan)

    # ------------------------------------------------------------------ UI
    def _build_ui(self) -> None:
        toolbar = ttk.Frame(self)
        toolbar.pack(fill="x", pady=(0, 6))
        self.buttons: list[ttk.Button] = []

        def add_button(text: str, cmd: Callable[[], None]) -> ttk.Button:
            b = ttk.Button(toolbar, text=text, command=cmd)
            b.pack(side="left", padx=(0, 4))
            self.buttons.append(b)
            return b

        add_button("Skanuj komputer", self.scan)
        add_button("Sprawdź aktualizacje", self.check_updates)
        add_button("Oceń źródło", self.assess_selected)
        add_button("Oceń wszystkie aktualizacje", self.assess_all_updates)
        add_button("Aktualizuj zaznaczone", self.upgrade_selected)
        add_button("Szukaj w repozytorium", self.search_selected)
        add_button("Strona producenta", self.open_homepage)
        add_button("Eksportuj raport", self.export_report)

        filters = ttk.Frame(self)
        filters.pack(fill="x", pady=(0, 6))
        ttk.Label(filters, text="Filtr:").pack(side="left")
        entry = ttk.Entry(filters, textvariable=self.filter_var, width=40)
        entry.pack(side="left", padx=(4, 12))
        ttk.Checkbutton(
            filters, text="Tylko z dostępną aktualizacją", variable=self.only_updates_var, command=self.refresh_tree
        ).pack(side="left")
        ttk.Checkbutton(
            filters, text="Weryfikuj certyfikaty TLS serwerów", variable=self.verify_tls_var
        ).pack(side="left", padx=(12, 0))
        self.count_label = ttk.Label(filters, text="")
        self.count_label.pack(side="right")

        paned = ttk.PanedWindow(self, orient="vertical")
        paned.pack(fill="both", expand=True)

        tree_frame = ttk.Frame(paned)
        self.tree = ttk.Treeview(
            tree_frame, columns=[c[0] for c in COLUMNS], show="headings", selectmode="extended"
        )
        for key, title, width in COLUMNS:
            self.tree.heading(key, text=title, command=lambda k=key: self._sort_by(k))
            self.tree.column(key, width=width, stretch=key in ("name", "publisher"))
        ysb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        xsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=ysb.set, xscrollcommand=xsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        ysb.grid(row=0, column=1, sticky="ns")
        xsb.grid(row=1, column=0, sticky="ew")
        tree_frame.rowconfigure(0, weight=1)
        tree_frame.columnconfigure(0, weight=1)
        self.tree.tag_configure("update", background="#fff4cc")
        self.tree.tag_configure("low", foreground="#b00020")
        self.tree.tag_configure("high", foreground="#0b6e2e")
        self.tree.bind("<<TreeviewSelect>>", lambda _e: self.show_details())
        self.tree.bind("<Double-1>", lambda _e: self.assess_selected())
        paned.add(tree_frame, weight=3)

        notebook = ttk.Notebook(paned)
        self.details = self._make_text(notebook)
        self.log = self._make_text(notebook)
        notebook.add(self.details.master, text="Szczegóły i ocena źródła")
        notebook.add(self.log.master, text="Dziennik")
        self.notebook = notebook
        paned.add(notebook, weight=2)

        statusbar = ttk.Frame(self)
        statusbar.pack(fill="x", pady=(6, 0))
        ttk.Label(statusbar, textvariable=self.status_var).pack(side="left")
        self.progress = ttk.Progressbar(statusbar, mode="indeterminate", length=200)
        self.progress.pack(side="right")

    @staticmethod
    def _make_text(parent) -> tk.Text:
        frame = ttk.Frame(parent)
        text = tk.Text(frame, wrap="word", height=10, font=("Consolas", 10), state="disabled")
        sb = ttk.Scrollbar(frame, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=sb.set)
        text.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        return text

    @staticmethod
    def _set_text(widget: tk.Text, content: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("end", content)
        widget.configure(state="disabled")

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
        """Wywołuje fn w wątku GUI (bezpieczne z wątków roboczych)."""
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
        self.log_line(details.strip())
        messagebox.showerror("Błąd", f"{description}\n\n{exc}", parent=self.root)

    def _set_busy(self, busy: bool, description: str = "") -> None:
        self._busy += 1 if busy else -1
        state = "disabled" if self._busy > 0 else "normal"
        for b in self.buttons:
            b.configure(state=state)
        if self._busy > 0:
            self.progress.configure(mode="indeterminate")
            self.progress.start(12)
            if description:
                self.status_var.set(description)
        else:
            self.progress.stop()
            self.progress.configure(mode="determinate", value=0)
            self.status_var.set(self._summary_text())

    def _summary_text(self) -> str:
        updates = sum(1 for s in self.items if s.has_update)
        tracked = sum(1 for s in self.items if s.winget_id)
        return f"Programów: {len(self.items)} | śledzonych w repozytoriach: {tracked} | z aktualizacją: {updates}"

    # ---------------------------------------------------------- tree
    def _row_values(self, s: Software) -> tuple:
        return (
            s.name, s.version, s.available_version if s.has_update else "", s.status, s.publisher,
            s.winget_source or s.extra.get("catalog_source", "") or
            ("strona producenta" if s.vendor_urls() else ""), s.security_level,
            s.winget_id or s.extra.get("catalog_id", ""),
        )

    def _sort_key(self, s: Software):
        idx = [c[0] for c in COLUMNS].index(self._sort_col)
        return str(self._row_values(s)[idx]).casefold()

    def _sort_by(self, col: str) -> None:
        self._sort_desc = not self._sort_desc if self._sort_col == col else False
        self._sort_col = col
        self.refresh_tree()

    def refresh_tree(self) -> None:
        selected = {id(self.by_iid[i]) for i in self.tree.selection() if i in self.by_iid}
        self.tree.delete(*self.tree.get_children())
        self.by_iid.clear()
        needle = self.filter_var.get().casefold().strip()
        shown = 0
        for s in sorted(self.items, key=self._sort_key, reverse=self._sort_desc):
            if self.only_updates_var.get() and not s.has_update:
                continue
            if needle and not any(needle in str(v).casefold() for v in self._row_values(s)):
                continue
            tags = []
            if s.has_update:
                tags.append("update")
            if s.security_level in (security.LEVEL_LOW,):
                tags.append("low")
            elif s.security_level == security.LEVEL_HIGH:
                tags.append("high")
            iid = self.tree.insert("", "end", values=self._row_values(s), tags=tags)
            self.by_iid[iid] = s
            shown += 1
            if id(s) in selected:
                self.tree.selection_add(iid)
        self.count_label.configure(text=f"Wyświetlono {shown} z {len(self.items)}")
        if self._busy == 0:
            self.status_var.set(self._summary_text())

    def selected(self) -> list[Software]:
        return [self.by_iid[i] for i in self.tree.selection() if i in self.by_iid]

    def _require_selection(self) -> list[Software]:
        sel = self.selected()
        if not sel:
            messagebox.showinfo("Brak zaznaczenia", "Zaznacz co najmniej jeden program na liście.", parent=self.root)
        return sel

    def show_details(self) -> None:
        sel = self.selected()
        if not sel:
            return
        s = sel[0]
        lines = [
            f"Nazwa:              {s.name}",
            f"Wersja:             {s.version or '-'}",
            f"Wydawca:            {s.publisher or '-'}",
            f"Lokalizacja:        {s.install_location or '-'}",
            f"Data instalacji:    {s.install_date or '-'}",
            f"Pochodzenie wpisu:  {s.origin or '-'}",
            f"Id winget:          {s.winget_id or '-'}  (źródło: {s.winget_source or '-'})",
            f"Dostępna wersja:    {s.available_version or '-'}",
        ]
        for label, url in (("Strona informacji", s.url_info), ("Aktualizacje", s.url_update), ("Pomoc", s.help_link)):
            if url:
                lines.append(f"{label + ':':<20}{url}")
        if s.extra.get("search_hint"):
            lines += ["", s.extra["search_hint"]]
        if s.extra.get("catalog_url"):
            lines += ["", f"Strona pakietu:      {s.extra['catalog_url']}"]
        if s.security_report:
            lines += ["", "=" * 70, "OCENA ŹRÓDŁA AKTUALIZACJI", "=" * 70, s.security_report]
        else:
            lines += ["", "Kliknij dwukrotnie lub użyj „Oceń źródło”, aby zweryfikować źródło aktualizacji."]
        self._set_text(self.details, "\n".join(lines))

    # --------------------------------------------------------- actions
    def scan(self) -> None:
        def done(result):
            self.items = result
            self.log_line(f"Znaleziono {len(result)} programów w rejestrze.")
            self.refresh_tree()
            if winget.is_available():
                self.check_updates()
            else:
                self.log_line("winget nie jest dostępny - sprawdzanie aktualizacji w repozytoriach wyłączone.")

        self.run_background("Skanowanie zainstalowanego oprogramowania...", inventory.scan_installed, done)

    def check_updates(self) -> None:
        if not winget.is_available():
            messagebox.showwarning(
                "Brak winget",
                "Nie znaleziono programu winget (Windows Package Manager).\n"
                "Zainstaluj „Instalator aplikacji” (App Installer) z Microsoft Store.",
                parent=self.root,
            )
            return
        base = [s for s in self.items if s.origin.startswith(("HKLM", "HKCU"))] or inventory.scan_installed()

        def work():
            for s in base:
                s.winget_detected = False
                s.winget_id = None
                s.winget_source = ""
                s.available_version = ""
            packages = winget.list_installed()
            upgrades = winget.list_upgrades()
            available = {p.id: p.available for p in upgrades if p.available}
            for p in packages:
                if p.id in available:
                    p.available = available[p.id]
            known = {p.id for p in packages}
            packages += [p for p in upgrades if p.id not in known]
            return winget.merge(base, packages), len(packages)

        def done(result):
            self.items, count = result
            self.log_line(f"winget rozpoznał {count} pakietów; dostępnych aktualizacji: "
                          f"{sum(1 for s in self.items if s.has_update)}.")
            self.refresh_tree()

        self.run_background("Sprawdzanie aktualizacji w repozytoriach winget / Microsoft Store...", work, done)

    def _assess(self, s: Software, verify_tls: bool) -> None:
        if s.winget_id and s.winget_source:
            info = winget.show(s.winget_id, s.winget_source)
            result = security.assess_winget(info, s.winget_source, s.publisher, verify_tls)
            if s.has_update and not s.winget_detected:
                result.summary += ("\nUwaga: winget nie powiązał tej instalacji z pakietem - aktualizację można "
                                   f"zainstalować poleceniem: winget install --id {s.winget_id} --exact")
            s.extra["homepage"] = info.get("Homepage") or info.get("Publisher Url") or ""
        else:
            result = security.assess_vendor(s, verify_tls)
        s.security_level = result.level
        s.security_report = result.report()

    def assess_selected(self) -> None:
        sel = self._require_selection()
        if not sel:
            return
        verify = self.verify_tls_var.get()

        def work():
            for s in sel:
                self.ui(lambda s=s: self.status_var.set(f"Ocena źródła: {s.name}..."))
                self._assess(s, verify)

        def done(_):
            for s in sel:
                self.log_line(f"Ocena źródła „{s.name}”: {s.security_level}")
            self.refresh_tree()
            self.show_details()
            self.notebook.select(0)

        self.run_background(f"Ocena źródeł aktualizacji ({len(sel)})...", work, done)

    def assess_all_updates(self) -> None:
        targets = [s for s in self.items if s.has_update and s.winget_id]
        if not targets:
            messagebox.showinfo("Brak aktualizacji", "Brak programów z dostępną aktualizacją.", parent=self.root)
            return
        verify = self.verify_tls_var.get()

        def work():
            for n, s in enumerate(targets, 1):
                self.ui(lambda s=s, n=n: self.status_var.set(f"Ocena źródła {n}/{len(targets)}: {s.name}..."))
                try:
                    self._assess(s, verify)
                except winget.WingetError as exc:
                    s.security_level = "?"
                    s.security_report = str(exc)
                self.ui(lambda s=s: self.log_line(f"Ocena źródła „{s.name}”: {s.security_level}"))

        self.run_background(f"Ocena źródeł {len(targets)} aktualizacji...", work, lambda _: self.refresh_tree())

    def upgrade_selected(self) -> None:
        sel = self._require_selection()
        if not sel:
            return
        targets = [s for s in sel if s.can_upgrade]
        skipped = [s for s in sel if not s.can_upgrade]
        if not targets:
            messagebox.showinfo(
                "Brak aktualizacji",
                "Zaznaczone programy nie mają aktualizacji dostępnej przez zaufane repozytorium.\n"
                "Dla pozostałych użyj „Strona producenta”.",
                parent=self.root,
            )
            return
        low = [s for s in targets if s.security_level == security.LEVEL_LOW]
        unchecked = [s for s in targets if not s.security_level]
        msg = "Zostaną zaktualizowane:\n\n" + "\n".join(
            f"  • {s.name}: {s.version} → {s.available_version}  [{s.security_level or 'nie oceniono'}]"
            for s in targets
        )
        if skipped:
            msg += f"\n\nPominięte (brak aktualizacji w repozytorium): {len(skipped)}"
        if unchecked:
            msg += "\n\nNiektóre źródła nie zostały ocenione - zalecane jest wcześniejsze użycie „Oceń źródło”."
        if low:
            msg += "\n\nUWAGA: część źródeł ma NISKI poziom zaufania!"
        msg += "\n\nInstalatory mogą poprosić o uprawnienia administratora (UAC). Kontynuować?"
        if not messagebox.askyesno("Potwierdź aktualizację", msg, icon="warning" if low else "question",
                                   parent=self.root):
            return
        self.notebook.select(1)

        def work():
            results = []
            for s in targets:
                self.ui(lambda s=s: self.log_line(f"Aktualizacja {s.name} ({s.winget_id})..."))
                code = winget.upgrade(s.winget_id, lambda line: self.ui(lambda l=line: self.log_line("  " + l)),
                                      s.winget_source)
                results.append((s, code))
            return results

        def done(results):
            ok = [s for s, c in results if c == 0]
            failed = [(s, c) for s, c in results if c != 0]
            for s, c in failed:
                self.log_line(f"Niepowodzenie: {s.name} (kod {c & 0xFFFFFFFF:#010x})")
            messagebox.showinfo(
                "Zakończono",
                f"Zaktualizowano: {len(ok)}\nNiepowodzenia: {len(failed)}\n\nSzczegóły w zakładce „Dziennik”.",
                parent=self.root,
            )
            self.check_updates()

        self.run_background(f"Aktualizowanie {len(targets)} programów...", work, done)

    def search_selected(self) -> None:
        sel = self._require_selection()
        if not sel:
            return
        s = sel[0]
        query = re.sub(r"\(.*?\)|\bv?\d+(?:\.\d+)+[\w.\-+]*", " ", s.name)
        query = re.sub(r"\s+", " ", query).strip() or s.name
        def work():
            results: list[catalog.CatalogPackage] = []
            errors = []
            providers = []
            if winget.is_available():
                providers.append(("winget", lambda: winget.search(query)))
            else:
                errors.append("winget: nie znaleziono programu.")
            providers.extend([
                ("Scoop Main", lambda: catalog.search_scoop(query)),
                ("Chocolatey Community", lambda: catalog.search_chocolatey(query)),
            ])
            for name, search in providers:
                try:
                    found = search()
                    if name == "winget":
                        results.extend(catalog.CatalogPackage(
                            manager="winget", name=p.name, id=p.id, version=p.version,
                            source=p.source,
                            details_url="https://github.com/microsoft/winget-pkgs/search?q="
                            + quote(p.id) + "&type=code",
                        ) for p in found)
                    else:
                        results.extend(found)
                except (catalog.CatalogError, winget.WingetError) as exc:
                    errors.append(f"{name}: {exc}")
            return results, errors

        self.run_background(
            f"Wyszukiwanie „{query}” w winget, Scoop Main i Chocolatey Community...",
            work,
            lambda result: SearchDialog(self, s, query, *result),
        )

    def open_homepage(self) -> None:
        sel = self._require_selection()
        if not sel:
            return
        s = sel[0]
        urls = [u for u in [s.extra.get("homepage", ""), *s.vendor_urls()] if re.match(r"^https?://", u, re.I)]
        if not urls:
            messagebox.showinfo("Brak adresu", "Brak zapisanego adresu strony producenta.", parent=self.root)
            return
        url = urls[0]
        if not url.lower().startswith("https://"):
            https_url = "https://" + url.split("://", 1)[1]
            answer = messagebox.askyesnocancel(
                "Niezaszyfrowane połączenie",
                f"Adres {url} nie używa HTTPS - pobieranie plików przez HTTP jest ryzykowne.\n\n"
                f"Tak - otwórz bezpieczny wariant: {https_url}\nNie - otwórz oryginalny adres",
                icon="warning", parent=self.root,
            )
            if answer is None:
                return
            if answer:
                url = https_url
        webbrowser.open(url)

    def export_report(self) -> None:
        if not self.items:
            return
        path = filedialog.asksaveasfilename(
            parent=self.root, title="Eksportuj raport", defaultextension=".csv",
            initialfile=f"raport_oprogramowania_{datetime.now():%Y%m%d_%H%M}.csv",
            filetypes=[("CSV", "*.csv"), ("JSON", "*.json")],
        )
        if not path:
            return
        rows = []
        for s in self.items:
            d = asdict(s)
            d.pop("extra", None)
            d["has_update"] = s.has_update
            rows.append(d)
        if path.lower().endswith(".json"):
            with open(path, "w", encoding="utf-8") as f:
                json.dump(rows, f, ensure_ascii=False, indent=2)
        else:
            with open(path, "w", encoding="utf-8-sig", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()), delimiter=";")
                writer.writeheader()
                writer.writerows(rows)
        self.log_line(f"Zapisano raport: {path}")


class SearchDialog(tk.Toplevel):
    """Przegląda wyniki z kilku katalogów i pozwala ocenić wybrany pakiet."""

    def __init__(self, app: App, software: Software, query: str,
                 results: list[catalog.CatalogPackage], errors: list[str]):
        super().__init__(app.root)
        self.app, self.software, self.results = app, software, results
        self.title(f"Wyniki wyszukiwania: {query}")
        self.geometry("760x380")
        self.transient(app.root)

        ttk.Label(self, text=f"Program: {software.name} {software.version}  —  wybierz pasujący pakiet:",
                  padding=6).pack(fill="x")
        ttk.Label(
            self,
            text="Scoop Main: zwykle Średnie zaufanie (skrypty lub brak SHA256 obniżają ocenę). "
            "Chocolatey Community: zawsze Niskie zaufanie; pakiety mogą uruchamiać skrypty.",
            wraplength=730,
            foreground="#8a4b08",
            padding=(6, 0, 6, 6),
        ).pack(fill="x")
        cols = (("name", "Nazwa", 240), ("id", "Identyfikator", 220), ("version", "Wersja", 100),
                ("source", "Źródło", 150))
        self.tree = ttk.Treeview(self, columns=[c[0] for c in cols], show="headings", selectmode="browse")
        for key, title, width in cols:
            self.tree.heading(key, text=title)
            self.tree.column(key, width=width)
        for i, p in enumerate(results):
            self.tree.insert("", "end", iid=str(i), values=(p.name, p.id, p.version, p.source))
        self.tree.pack(fill="both", expand=True, padx=6)
        self.tree.bind("<Double-1>", lambda _e: self.link())
        buttons = ttk.Frame(self, padding=6)
        buttons.pack(fill="x")
        if not results:
            ttk.Label(buttons, text="Nie znaleziono pasujących pakietów.").pack(side="left")
        if errors:
            ttk.Label(self, text="Niektóre źródła są niedostępne: " + " | ".join(errors),
                      wraplength=730, foreground="#9b4f00").pack(fill="x", padx=8, pady=(0, 4))
        ttk.Button(buttons, text="Zamknij", command=self.destroy).pack(side="right")
        ttk.Button(buttons, text="Otwórz stronę pakietu", command=self.open_package).pack(side="right", padx=4)
        ttk.Button(buttons, text="Powiąż i oceń źródło", command=self.link).pack(side="right", padx=4)

    def selected_package(self) -> Optional[catalog.CatalogPackage]:
        sel = self.tree.selection()
        return self.results[int(sel[0])] if sel else None

    def open_package(self) -> None:
        package = self.selected_package()
        if not package or not package.details_url:
            return
        parsed = urlparse(package.details_url)
        trusted_hosts = {"github.com", "community.chocolatey.org"}
        if parsed.scheme != "https" or parsed.hostname not in trusted_hosts:
            messagebox.showerror(
                "Nieznany adres pakietu",
                "Odrzucono adres strony spoza oficjalnego katalogu.",
                parent=self,
            )
            return
        webbrowser.open(package.details_url)

    def link(self) -> None:
        p = self.selected_package()
        if not p:
            return
        s = self.software
        if p.manager == "winget":
            s.winget_id = p.id
            s.winget_source = p.source
            known_version = p.version and p.version.casefold() != "unknown"
            s.available_version = p.version if known_version and p.version != s.version else ""
            s.extra["search_hint"] = (
                f"Ręcznie powiązano z pakietem {p.id} ({p.source}). "
                f"Aby zainstalować najnowszą wersję: winget install --id {p.id} --exact"
            )
            self.destroy()
            self.app.refresh_tree()
            for iid, item in self.app.by_iid.items():
                if item is s:
                    self.app.tree.selection_set(iid)
                    self.app.tree.see(iid)
            self.app.assess_selected()
            return

        self.app.run_background(
            f"Ocena pakietu {p.id} z {p.source}...",
            lambda: (
                catalog.assess_scoop(p, self.app.verify_tls_var.get())
                if p.manager == "scoop" else catalog.assess_chocolatey(p)
            ),
            lambda assessment: self.link_external(p, assessment),
        )

    def link_external(self, p: catalog.CatalogPackage, assessment: security.Assessment) -> None:
        s = self.software
        s.security_level = assessment.level
        s.security_report = assessment.report()
        s.extra["catalog_id"] = p.id
        s.extra["catalog_source"] = p.source
        s.extra["catalog_url"] = p.details_url
        if p.manager == "scoop":
            command = f"scoop install {p.id}"
        else:
            command = f"choco install {p.id} --source https://community.chocolatey.org/api/v2/"
        s.extra["search_hint"] = (
            f"Wynik wyszukiwania z {p.source}. Ta aplikacja nie uruchamia instalacji z tego źródła. "
            f"Jeśli zdecydujesz się na instalację, użyj menedżera po sprawdzeniu raportu: {command}"
        )
        self.app.log_line(f"Ocena źródła „{p.id}” ({p.source}): {assessment.level}")
        self.app.refresh_tree()
        self.destroy()
        for iid, item in self.app.by_iid.items():
            if item is s:
                self.app.tree.selection_set(iid)
                self.app.tree.see(iid)
        self.app.show_details()


def main() -> None:
    try:
        import ctypes

        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:  # noqa: BLE001 - dostępne tylko w Windows 8.1+
        pass
    root = tk.Tk()
    try:
        ttk.Style(root).theme_use("vista")
    except tk.TclError:
        pass
    root.title(f"Bezpieczny Aktualizator {__version__}")
    root.geometry("1280x760")
    root.minsize(900, 500)
    tabs = ttk.Notebook(root)
    tabs.pack(fill="both", expand=True, padx=4, pady=4)
    software = App(tabs, root)
    tabs.add(software, text="Oprogramowanie")
    from .drivers_gui import DriversTab

    drivers_tab = DriversTab(tabs, root)
    tabs.add(drivers_tab, text="Sterowniki")
    root.app, root.drivers_tab, root.tabs = software, drivers_tab, tabs
    root.mainloop()
