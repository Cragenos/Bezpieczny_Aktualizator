# Bezpieczny Aktualizator

Repozytorium zawiera rozwijaną wersję [C#/WPF (.NET 10)](dotnet/README.md) oraz wcześniejszą
wersję Python opisaną poniżej.

Aplikacja okienkowa dla Windows, która:

1. **Wyszukuje zainstalowane oprogramowanie**: odczytuje klucze `Uninstall` z rejestru (HKLM 64/32-bit, HKCU) i dodaje pakiety rozpoznane przez winget (np. aplikacje MSIX/Store).
2. **Wyszukuje oprogramowanie w katalogach**: [winget-pkgs](https://github.com/microsoft/winget-pkgs), Microsoft Store, [Scoop Main](https://github.com/ScoopInstaller/Main) i [Chocolatey Community](https://community.chocolatey.org/packages).
3. **Ocenia, czy źródło aktualizacji jest bezpieczne**, zanim cokolwiek zainstaluje.
4. **Aktualizuje wybrane programy** przez winget. Winget odrzuca instalator, jeśli jego suma SHA256 nie zgadza się z manifestem.
5. **Zarządza sterownikami** w zakładce **Sterowniki**: wyszukuje sterowniki zainstalowane na komputerze, sprawdza nowsze wersje w Windows Update i instaluje je.

## Wymagania

- Windows 10/11
- Python 3.10+ (z modułem tkinter instalowanym domyślnie)
- [winget](https://github.com/microsoft/winget-cli) (wbudowany w Windows 11, w Windows 10 to „Instalator aplikacji” z Microsoft Store)

Aplikacja nie ma zewnętrznych zależności i korzysta tylko z biblioteki standardowej Pythona.

## Uruchomienie

```powershell
python -m updater      # z konsolą (widoczne ewentualne błędy)
pythonw run.pyw        # bez okna konsoli
```

## Jak oceniane jest źródło

| Kontrola | Opis |
|---|---|
| Źródło pakietu | `winget` (walidowane manifesty, skan AV) lub `msstore` (certyfikacja Microsoft) |
| HTTPS | Adres instalatora musi używać szyfrowanego połączenia |
| SHA256 | Manifest musi zawierać sumę kontrolną, którą winget weryfikuje |
| Domena | Domena instalatora jest zgodna ze stroną producenta albo to znany serwis (GitHub, SourceForge…) |
| Wydawca | Wydawca w repozytorium zgadza się z wydawcą zainstalowanego programu |
| Certyfikat TLS | Rzeczywiste połączenie z serwerem z pełną weryfikacją certyfikatu (zapytanie HEAD, bez pobierania pliku) |

Wynik to poziom zaufania: **Wysoki**, **Średni** lub **Niski**. Programy spoza repozytoriów są oceniane na podstawie adresów zapisanych przez instalator w rejestrze. Adresy `http://` są automatycznie sprawdzane w wariancie HTTPS.

### Dodatkowe katalogi

Przycisk **Szukaj w repozytorium** przeszukuje również:

- **Scoop Main** — oficjalny, domyślny bucket Scoop ([kryteria Main](https://github.com/ScoopInstaller/Scoop/wiki/Criteria-for-including-apps-in-the-main-bucket)). Aplikacja sprawdza adresy instalatorów i sumy SHA-256 z manifestu, a także obecność skryptów instalacyjnych. Ponieważ manifesty nie są kryptograficznie podpisane, wynik nie przekracza poziomu **Średni**; brak sumy, niezabezpieczony URL lub skrypt oznacza poziom **Niski**. Aplikacja nie instaluje pakietów z tego źródła.
- **Chocolatey Community** — oficjalny kanał społecznościowy z [moderacją publikowanych wersji](https://docs.chocolatey.org/en-us/community-repository/moderation/). Według [dokumentacji Chocolatey](https://docs.chocolatey.org/en-us/community-repository/community-packages-disclaimer/) moderacja nie obejmuje skanowania instalowanego programu, a pakiety mogą uruchamiać skrypty PowerShell. Z tego powodu aplikacja zawsze ocenia je jako **Niskie zaufanie** i nie uruchamia ich instalacji.

Wyniki z tych katalogów są przeznaczone do wyszukiwania, weryfikacji i otwierania strony pakietu. Aktualizacje aplikacja nadal wykonuje wyłącznie przez winget, które weryfikuje sumę SHA-256 instalatora względem manifestu. Instalowanie pakietów spoza winget wymaga osobnego, świadomego użycia Scoop/Chocolatey po sprawdzeniu raportu.

## Funkcje GUI

- **Skanuj komputer**: inwentaryzacja oprogramowania (po niej automatycznie uruchamia się sprawdzanie aktualizacji)
- **Sprawdź aktualizacje**: `winget list` i `winget upgrade --include-unknown`
- **Oceń źródło** (lub dwuklik): raport bezpieczeństwa dla zaznaczonych programów
- **Oceń wszystkie aktualizacje**: ocena wszystkich dostępnych aktualizacji
- **Aktualizuj zaznaczone**: `winget upgrade --id … --exact --silent` z potwierdzeniem i ostrzeżeniem przy niskim zaufaniu
- **Szukaj w repozytorium**: wyszukiwanie w winget, Scoop Main i Chocolatey Community; możliwość otwarcia strony pakietu i oceny źródła
- **Strona producenta**: otwiera stronę producenta, preferując HTTPS
- **Eksportuj raport**: CSV lub JSON
- Filtrowanie, sortowanie po kolumnach, dziennik operacji

## Zakładka „Sterowniki”

- **Skanuj sterowniki**: inwentarz z WMI (`Win32_PnPSignedDriver` + `Win32_PnPEntity`). Pokazuje wersję, datę, dostawcę, plik INF, podpis cyfrowy i identyfikatory sprzętu, a także urządzenia bez sterownika (kod 28).
- **Szukaj aktualizacji (Windows Update)**: zapytanie do Windows Update przez Windows Update Agent API (`Microsoft.Update.Session`, kryterium `Type='Driver'`). Aktualizacje są dopasowywane do urządzeń po identyfikatorze sprzętu.
- **Instaluj zaznaczone / wszystkie dostępne**: pobranie i instalacja przez Windows Update Agent w procesie z uprawnieniami administratora (monit UAC). Domyślnie przed instalacją tworzony jest punkt przywracania systemu. Postęp trafia do zakładki „Dziennik”, a na końcu aplikacja informuje, czy potrzebny jest restart.
- **Katalog Microsoft Update**: otwiera wyszukiwanie po identyfikatorze sprzętu w oficjalnym [Katalogu Microsoft Update](https://www.catalog.update.microsoft.com/) (HTTPS), przydatne do ręcznej weryfikacji.
- **Menedżer urządzeń**, **Eksportuj raport** (CSV/JSON), filtry („tylko z aktualizacją lub problemem”, „ukryj ogólne sterowniki Windows”).

Dlaczego to źródło jest bezpieczne:

| Kontrola | Opis |
|---|---|
| Źródło | Wyłącznie Windows Update. Sterowniki muszą być podpisane przez Microsoft (WHQL/attestation) |
| Integralność | Windows Update Agent weryfikuje podpis i skrót pobranego pakietu przed instalacją |
| Dopasowanie | Identyfikator sprzętu zgodny z urządzeniem (dopasowanie po ID zgodności daje ostrzeżenie) |
| Wersja | Ostrzeżenie, jeśli wersja nie jest nowsza od zainstalowanej |
| Dostawca | Ostrzeżenie, jeśli dostawca różni się od dotychczasowego |
| Obecny sterownik | Niepodpisany sterownik daje poziom **Niski**; podpis „Microsoft Windows Hardware Compatibility Publisher” oznacza WHQL |

Aplikacja nie pobiera sterowników ze stron firm trzecich ani agregatorów sterowników.

## Testy

```powershell
python -m unittest discover -s tests -t .
```

## Struktura

```
updater/
  inventory.py  - odczyt rejestru Windows
  winget.py     - integracja z winget (parsowanie list, manifestów, aktualizacja)
  catalog.py    - wyszukiwanie i ocena katalogów Scoop Main / Chocolatey Community
  drivers.py    - inwentarz sterowników, Windows Update Agent, instalacja, ocena
  drivers_gui.py - zakładka „Sterowniki”
  security.py   - ocena wiarygodności źródeł
  gui.py        - interfejs tkinter/ttk
  models.py     - model danych
tests/          - testy jednostkowe
```

## Wykorzystane projekty open source

- [winget-cli](https://github.com/microsoft/winget-cli) (MIT): menedżer pakietów
- [winget-pkgs](https://github.com/microsoft/winget-pkgs) (MIT): repozytorium manifestów z sumami SHA256
- Windows Update Agent API (komponent systemu Windows, wywoływany przez PowerShell)
- Python i tkinter/Tcl/Tk (licencje PSF i BSD)
