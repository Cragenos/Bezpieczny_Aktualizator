# Bezpieczny Aktualizator 2.1 (C# / WPF)

Wersja aplikacji napisana w C# na .NET 10 z interfejsem WPF. Funkcje są takie same jak w wersji Python (zob. [README](../README.md)):

- **Oprogramowanie**:
  - inwentaryzacja programów z rejestru i z winget;
  - wyszukiwanie w katalogach winget, Microsoft Store, Scoop Main i Chocolatey Community;
  - ocena źródła aktualizacji;
  - aktualizacja przez winget;
  - sprawdzanie podatności (CVE) w bazie NVD i oznaczanie programów z lukami jako **pilne**;
  - wykrywanie programów nieobsługiwanych (EOL) i porzuconych;
  - skanowanie pobranego instalatora programem Microsoft Defender przed instalacją;
  - historia aktualizacji i wycofanie do poprzedniej wersji;
  - eksport raportu do CSV lub JSON.
- **Sterowniki**:
  - inwentaryzacja przez WMI (`Win32_PnPSignedDriver` i `Win32_PnPEntity`), w tym urządzenia z problemami;
  - wyszukiwanie nowszych wersji w Windows Update przez API Windows Update Agent (COM);
  - ocena źródła;
  - instalacja z podniesionymi uprawnieniami (UAC) z opcjonalnym punktem przywracania.
- **Program**: ikona w zasobniku, powiadomienia o dostępnych aktualizacjach, podpisana aktualizacja aplikacji z GitHub Releases i instalator MSI.

## Wymagania

- Windows 10/11 x64
- [.NET 10 SDK](https://dotnet.microsoft.com/download), potrzebny tylko do budowania. Opublikowany plik `.exe` jest samodzielny (self-contained), więc działa bez zainstalowanego .NET.
- [winget](https://github.com/microsoft/winget-cli), potrzebny do sprawdzania i instalowania aktualizacji programów.

## Budowanie i uruchamianie

```powershell
cd dotnet
dotnet build
dotnet run --project src\BezpiecznyAktualizator
```

## Testy

```powershell
dotnet test --filter "Category!=Live"   # testy jednostkowe (bez dostępu do systemu i sieci)
dotnet test --filter "Category=Live"    # testy na żywym systemie: rejestr, WMI, winget, Windows Update
```

## Paczka instalacyjna z .NET i podpisem cyfrowym (zalecane)

```powershell
.\packaging\Build-Package.ps1                       # certyfikat własny (tworzony automatycznie)
.\packaging\Build-Package.ps1 -PfxPath firma.pfx -PfxPassword (Read-Host -AsSecureString)   # certyfikat komercyjny
.\packaging\Build-Package.ps1 -CertThumbprint <odcisk>                                       # certyfikat z magazynu
```

Skrypt tworzy `dist\BezpiecznyAktualizator-<wersja>-win-x64\` oraz archiwum `.zip` (ok. 57 MB) z plikiem `.zip.sha256`:

| Element | Opis |
|---|---|
| `app\BezpiecznyAktualizator.exe` | aplikacja (pojedynczy plik ~1,7 MB, zależny od .NET Desktop Runtime, **wydanie chronione**), **podpisana Authenticode** |
| `dotnet\windowsdesktop-runtime-*.exe` | oficjalny instalator **.NET Desktop Runtime** (najnowsza wersja 10.0.x), pobrany na podstawie [metadanych wydań Microsoft](https://builds.dotnet.microsoft.com/dotnet/release-metadata/10.0/releases.json), zweryfikowany SHA512 i podpisem Microsoft |
| `Instaluj.cmd`, `Install.ps1` | instalator (podpisany): sprawdza sumy SHA256 i podpisy, instaluje .NET (jeśli brak), opcjonalnie ufa certyfikatowi wydawcy, kopiuje do `Program Files`, tworzy skrót w menu Start i wpis w „Aplikacje i funkcje” |
| `app\Uninstall.ps1` | deinstalator (podpisany) – usuwa aplikację, skróty i certyfikat z magazynów zaufanych |
| `cert\BezpiecznyAktualizator.cer` | publiczny certyfikat wydawcy |
| `runtime.json`, `SHA256SUMS.txt` | wersja/SHA512 instalatora .NET oraz sumy kontrolne wszystkich plików |

`Instaluj.cmd -VerifyOnly` sprawdza paczkę bez instalowania czegokolwiek.

Oprócz tego skrypt tworzy osobną **paczkę przenośną** `dist\BezpiecznyAktualizator-<wersja>-portable-win-x64.zip` (ok. 67 MB): jeden samodzielny plik `BezpiecznyAktualizator.exe` z wbudowanym środowiskiem .NET (chroniony, skompresowany, podpisany), certyfikat wydawcy, `CZYTAJ.txt`, `INSTRUKCJA.txt` i `SHA256SUMS.txt`. Nie wymaga instalacji ani .NET – wystarczy rozpakować i uruchomić.

Przełączniki: `-NoPortable` (bez paczki przenośnej), `-NoProtect` (wydanie bez zaciemniania i kontroli integralności, np. do diagnozowania błędów), `-NoZip`.

Skrypt tworzy również samodzielny, podpisany MSI `dist\BezpiecznyAktualizator-<wersja>-win-x64.msi` i plik `.msi.sha256`. MSI instaluje aplikację w `Program Files`, tworzy skrót w menu Start, jest widoczny w „Aplikacje i funkcje” i obsługuje aktualizacje główne (Major Upgrade). Ustawienia użytkownika pozostają poza katalogiem instalacji.

### Instalator MSI i aktualizacja samego programu

MSI jest budowany przez [WiX Toolset 6](packaging/msi/BezpiecznyAktualizator.wixproj) i zawiera samodzielną wersję aplikacji, więc nie wymaga osobnego .NET Runtime. Uruchom plik MSI i zatwierdź UAC, aby zainstalować. Odinstalowanie odbywa się standardowo przez „Aplikacje i funkcje”; MSI nie usuwa ustawień w `%APPDATA%`.

Domyślne repozytorium aktualizacji to [Cragenos/Bezpieczny_Aktualizator](https://github.com/Cragenos/Bezpieczny_Aktualizator). Można je zmienić w [Directory.Build.props](Directory.Build.props) (`UpdateRepository`) albo podczas pakowania: `.\packaging\Build-Package.ps1 -UpdateRepository owner/repo`. Repozytorium musi być publiczne i zawierać opublikowane stabilne wydanie. Jeśli wartość jest pusta, automatyczne sprawdzanie pozostaje wyłączone, a ręczne sprawdzenie wyświetli instrukcję konfiguracji. Aplikacja sprawdza najnowsze stabilne wydanie GitHub najwyżej raz na 24 godziny przy starcie (można wyłączyć w menu „Sprawdzanie przy starcie”) lub na żądanie z menu ikony zasobnika. Wydanie musi zawierać:

- `BezpiecznyAktualizator-<wersja>-win-x64.msi`,
- opcjonalnie `BezpiecznyAktualizator-<wersja>-win-x64.msi.sha256` (skrypt budowania tworzy ten plik; GitHub API może też dostarczyć własny digest SHA-256).

Przed uruchomieniem MSI program weryfikuje sumę SHA-256 i podpis Authenticode przypięty do odcisku certyfikatu z bieżącego wydania. Instalator Windows prosi o UAC; aplikacja zamyka się, aby pliki nie były używane podczas aktualizacji. Aktualizacje MSI są dostępne dla wersji zainstalowanej z MSI; paczki ZIP/skryptowe i przenośne mogą otworzyć stronę wydania, ale nie są podmieniane automatycznie.

Sprawdzenie wydania kontaktuje się z publicznym GitHub API; nie wysyła danych o komputerze ani listy zainstalowanych programów. Do automatycznych aktualizacji kolejna wersja musi być podpisana tym samym certyfikatem. Zmiana certyfikatu wymaga ponownej instalacji bieżącej wersji lub zaplanowanej rotacji klucza.

### Ikona zasobnika i powiadomienia

Minimalizacja oraz zamknięcie głównego okna ukrywają je w zasobniku — nie kończą procesu ani harmonogramu w tle. Dwukrotne kliknięcie ikony przywraca okno; menu kontekstowe pozwala sprawdzić aktualizację programu lub zakończyć aplikację. Dymek powiadomienia informuje o dostępnej aktualizacji programu i wyjaśnia, że aplikacja pozostaje uruchomiona po ukryciu. Ikona jest widoczna wyłącznie w trybie interaktywnym; procesy Harmonogramu zadań i instalacji sterowników pozostają bez okna i bez ikony.

**Podpis cyfrowy.** Pliki są podpisywane przez `signtool` (Windows SDK): SHA256 + znacznik czasu RFC 3161 (DigiCert, zapasowo Sectigo/GlobalSign), więc podpis pozostaje ważny po wygaśnięciu certyfikatu. Domyślnie używany jest certyfikat **własny (self-signed)** `CN=Bezpieczny Aktualizator Code Signing` z magazynu `Cert:\CurrentUser\My`; klucz prywatny jest nieeksportowalny i nie trafia do paczki. Windows uzna taki podpis za zaufany dopiero po dodaniu certyfikatu do zaufanych (instalator pyta o to). Aby podpis był rozpoznawany wszędzie i ograniczał ostrzeżenia SmartScreen/antywirusów, użyj certyfikatu od zaufanego urzędu (np. OV/EV Code Signing albo Azure Trusted Signing) przez `-PfxPath` lub `-CertThumbprint`.

## Publikacja jako samodzielny pojedynczy plik .exe

```powershell
dotnet publish src\BezpiecznyAktualizator -c Release -r win-x64 --self-contained `
  -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:DebugType=none -o publish
```

Wynikowy plik to `publish\BezpiecznyAktualizator.exe` (ok. 140 MB).

> **Uwaga:** opcji `-p:EnableCompressionInSingleFile=true` nie należy używać w plikach, które nie zostaną podpisane. Skompresowany, samorozpakowujący się i niepodpisany plik exe bywa blokowany przez heurystykę antywirusów (np. ESET), co kończy się błędem „Odmowa dostępu”. Wydanie chronione (`-p:Protect=true`) włącza kompresję automatycznie, a `Build-Package.ps1` od razu je podpisuje.

## O programie

Przycisk ⓘ w nagłówku okna otwiera okno **O programie** ([AboutWindow](src/BezpiecznyAktualizator/Views/AboutWindow.xaml.cs)):
- autor, prawa autorskie i wersja, odczytywane z atrybutów zestawu (`Authors`, `Company` i `Copyright` w [Directory.Build.props](Directory.Build.props));
- środowisko uruchomieniowe;
- stan podpisu cyfrowego, odcisk certyfikatu, stan ochrony pliku programu i ścieżka pliku;
- lista użytych projektów open source;
- przycisk „Kopiuj informacje”, który kopiuje te dane do schowka.

## Ochrona przed inżynierią wsteczną i modyfikacją

Paczki z `Build-Package.ps1` zawierają **wydanie chronione**. Ręcznie można je zbudować tak: `dotnet publish ... -p:Protect=true -p:SignerThumbprint=<odcisk certyfikatu>`. Ustawienia są w [Protection.targets](src/BezpiecznyAktualizator/Protection.targets).

| Zabezpieczenie | Działanie |
|---|---|
| Zaciemnianie kodu ([Obfuscar](https://github.com/obfuscar/obfuscar), MIT) | Obejmuje oba zestawy (aplikację i Core) przed spakowaniem w jeden plik. Nazwy prywatnych i wewnętrznych typów, metod, pól, właściwości i zdarzeń są zamieniane na nieczytelne znaki Unicode. Powiązania XAML są analizowane i zachowane. |
| Szyfrowanie napisów | Obfuscar (`HideStrings`): napisy z kodu nie są widoczne w pliku i są odszyfrowywane w czasie działania. |
| Kontrola integralności | [SelfProtection](src/BezpiecznyAktualizator/Services/SelfProtection.cs) i `IntegrityCheck` w [Authenticode.cs](src/BezpiecznyAktualizator.Core/Security/Authenticode.cs). Przy starcie program sprawdza swój podpis Authenticode (skrót pliku) i porównuje odcisk certyfikatu z odciskiem wbudowanym podczas budowania. Plik zmieniony, niepodpisany lub podpisany innym certyfikatem kończy działanie z kodem 3 i wpisem `INTEGRITY` (Alert) w dzienniku syslog. |
| Wykrywanie debugera | `IsDebuggerPresent` i `CheckRemoteDebuggerPresent` przy starcie i co 2 s. Po wykryciu debugera program kończy działanie. |
| Brak symboli, kompresja | Plik nie zawiera `.pdb`. Wersja samodzielna ma skompresowane zestawy w pakiecie single-file. |

Zasady zgodności z zaciemnianiem:
- Nazwy **publiczne** pozostają bez zmian (`KeepPublicApi`), ponieważ używają ich powiązania WPF i serializacja `System.Text.Json`.
- Prywatne klasy zapisywane do JSON oznacza się atrybutem `[Obfuscation(Exclude = true)]`.
- Mapowanie nazw do odczytu stosów wywołań z dziennika jest w `obj\Release\net10.0-windows\win-x64\obfuscar\out\Mapping.txt`. Ten plik nie trafia do paczki.

> **Ograniczenia:** żadna ochrona aplikacji .NET nie jest absolutna. Obfuscar nie zaciemnia przepływu sterowania, a kod IL nadal da się zdekompilować. Ochrona utrudnia analizę i modyfikację oraz wykrywa podmianę pliku, ale nie powstrzyma zdeterminowanego atakującego. Kompilacja do kodu natywnego (NativeAOT) nie jest obsługiwana dla WPF.

## Języki interfejsu

Interfejs jest dostępny w 13 językach: polskim, angielskim, niemieckim, francuskim, hiszpańskim, włoskim, portugalskim (Brazylia), rosyjskim, ukraińskim, tureckim, chińskim uproszczonym, japońskim i koreańskim.

- Język zmienia się na liście **Język** w prawym górnym rogu okna. Zmiana działa od razu, bez ponownego uruchamiania.
- Wybór jest zapisywany w `%APPDATA%\BezpiecznyAktualizator\settings.json` (`{"language": "en"}`). Przy pierwszym uruchomieniu aplikacja używa języka systemu Windows, a jeśli nie jest obsługiwany — angielskiego.
- Tłumaczenia są osadzone w `BezpiecznyAktualizator.Core.dll` jako pliki `src/BezpiecznyAktualizator.Core/Localization/Strings/<kod>.json`. Kluczem jest polski tekst źródłowy. Brakujące tłumaczenie zastępuje tekst angielski, a w ostateczności polski.

Dodawanie nowych tekstów:

1. W kodzie C# opakuj tekst w `L.T("…")`, tekst z parametrami w `L.F("… {0}", x)`, tekst przeliczany po zmianie języka (raporty, opisy kontroli) w `L.Txt(...)`, a stałą tłumaczoną dopiero przy wyświetlaniu w `L.N("…")`. W XAML użyj `{l:Tr 'tekst'}`.
2. Uruchom `powershell -File tools\Update-Translations.ps1`. Skrypt doda nowe klucze (z pustą wartością) do każdego pliku JSON i usunie nieużywane.
3. Uzupełnij puste wartości. `tools\Update-Translations.ps1 -Check` oraz test `LocalizationTests` sprawdzają, czy wszystkie teksty mają tłumaczenia z zachowanymi symbolami `{0}`, i wykrywają polskie napisy w kodzie, które nie przechodzą przez `L.*`.

Nowy język: dodaj wpis do `L.Languages` w `Localization/L.cs` i uruchom skrypt. Utworzy on plik `<kod>.json` do wypełnienia.
## Dziennik zdarzeń (syslog)

Każde działanie aplikacji jest zapisywane w pliku zgodnym ze standardem syslog — **RFC 5424**:

```
%LOCALAPPDATA%\BezpiecznyAktualizator\Logs\BezpiecznyAktualizator.log
```

Plik otwiera przycisk **Dziennik zdarzeń (syslog)** w prawym górnym rogu okna (otwiera Eksplorator z zaznaczonym plikiem).

Przykładowy wpis:

```
<13>1 2026-10-30T16:25:10.245823+01:00 CKUS BezpiecznyAktualizator 32584 APP [origin software="BezpiecznyAktualizator" swVersion="2.0.0"][meta sequenceId="1" language="pl"] Uruchomiono aplikację 2.0.0 (...)
```

| Pole RFC 5424 | Wartość |
|---|---|
| PRI | facility `user` (1) × 8 + ważność: 3 = error, 4 = warning, 5 = notice (instalacje, start/zamknięcie), 6 = informational, 2 = critical (awaria) |
| TIMESTAMP | czas lokalny z przesunięciem UTC i mikrosekundami (RFC 3339) |
| HOSTNAME / APP-NAME / PROCID | nazwa komputera (FQDN w domenie), `BezpiecznyAktualizator`, PID procesu |
| MSGID | typ zdarzenia: `APP`, `SETTINGS`, `SW_SCAN`, `SW_UPDATE_CHECK`, `SW_ASSESS`, `SW_UPGRADE`, `SW_VERIFY` (weryfikacja plików kontrolnych), `SW_SEARCH`, `DRV_SCAN`, `DRV_UPDATE_CHECK`, `DRV_INSTALL`, `REPORT`, `ERROR` |
| STRUCTURED-DATA | zarejestrowane w IANA elementy `origin` (program i wersja) oraz `meta` (`sequenceId` — numer kolejny w procesie, `language` — język komunikatu) |
| MSG | UTF-8 poprzedzony znakiem BOM (wymóg RFC 5424 dla MSG-UTF8), w języku interfejsu |

Rejestrowane są m.in.: uruchomienie i zamknięcie aplikacji (z użytkownikiem i informacją o uprawnieniach administratora), zmiana języka, skanowanie, sprawdzanie aktualizacji, oceny źródeł, wyszukiwanie, każda instalowana aktualizacja programu i sterownika z wynikiem, punkt przywracania, zapis raportów, błędy (z pełnym stosem wywołań) i czas trwania operacji.

- Jeden wpis = jeden wiersz (LF). Znaki sterujące w treści, np. przejścia do nowej linii w stosie wywołań, są kodowane jak w rsyslog (`#012`, `#011`).
- Rotacja: po przekroczeniu 5 MB plik jest przenoszony do `.log.1` (zachowywanych jest 5 archiwów: `.log.1` … `.log.5`).
- Zapis jest synchronizowany między procesami (np. proces instalacji sterowników z uprawnieniami administratora) i nigdy nie przerywa działania aplikacji.
- Plik można wczytać narzędziami obsługującymi RFC 5424 (rsyslog `imfile` + `pmrfc5424`, syslog-ng `syslog-parser`, Graylog, Splunk, Elastic Agent itp.).

## Sprawdzanie plików kontrolnych przed instalacją

Opcja **Sprawdzaj pliki kontrolne przed instalacją** w zakładce „Oprogramowanie” jest domyślnie włączona. Przed instalacją każdej aktualizacji aplikacja:

1. Pobiera instalator i jego manifest do prywatnego katalogu tymczasowego (`winget download`). Po weryfikacji katalog jest usuwany.
2. Oblicza sumy **SHA256** i **SHA512** pliku i porównuje SHA256 z manifestem winget.
3. Szuka **plików kontrolnych publikowanych przez wydawcę**, o ile są dostępne. Pobiera je tylko przez HTTPS, także po przekierowaniach, z limitem 1 MB i krótkim czasem oczekiwania. Sprawdzane źródła:
   - **GitHub Releases** — suma `digest` zasobu z API GitHub oraz pliki kontrolne dołączone do wydania (np. `*.checksums.sha256`, `SHA256SUMS`, `checksums.txt`);
   - pliki „obok” instalatora: `<plik>.sha256`, `.sha256sum`, `.sha256.txt`, `.sha512`, `.sha512sum`;
   - listy w tym samym katalogu: `SHA256SUMS`, `SHA256SUMS.txt`, `sha256sums.txt`, `checksums.txt`, `SHA512SUMS`.

   Obsługiwane formaty to GNU (`suma  plik`), BSD (`SHA256 (plik) = suma`), sama suma oraz `plik: suma`.
4. Weryfikuje **podpis Authenticode** instalatora (WinVerifyTrust, z kontrolą unieważnienia certyfikatów) i zapisuje nazwę podpisującego.
5. Instaluje dokładnie zweryfikowaną wersję (`winget upgrade --version`). Winget przy instalacji ponownie sprawdza tę samą sumę SHA256.

| Wynik | Działanie |
|---|---|
| Niezgodna suma (manifest lub plik wydawcy), nieprawidłowy lub unieważniony podpis | instalacja tego programu jest **wstrzymywana** bez pytania |
| Brak pliku kontrolnego wydawcy, instalator niepodpisany | ostrzeżenie w dzienniku, instalacja jest kontynuowana |
| Weryfikacji nie można przeprowadzić (np. wydawca blokuje pobieranie) | pytanie, czy kontynuować (domyślnie **nie**) |
| Pakiety Microsoft Store | weryfikację wykonuje sam Sklep |

Wyniki każdego sprawdzenia trafiają do zakładki „Dziennik” i do dziennika syslog (MSGID `SW_VERIFY`). Sterowniki z Windows Update są weryfikowane przez agenta Windows Update: sprawdza on podpis i skrót pakietu przed instalacją.

## Automatyczne sprawdzanie wersji po uruchomieniu

Po otwarciu okna aplikacja sama skanuje programy i sterowniki. Następnie w tle i równolegle sprawdza dostępne nowsze wersje:

- **programów** — w repozytoriach winget i Microsoft Store (zwykle kilka sekund);
- **sterowników** — w Windows Update (może potrwać kilka minut, nie wymaga uprawnień administratora).

W trakcie sprawdzania okno działa normalnie. Nad zakładkami pojawia się pasek z informacją „Trwa sprawdzanie…”. Po zakończeniu pasek pokazuje liczbę dostępnych aktualizacji programów i nowszych sterowników oraz przyciski **Pokaż programy** / **Pokaż sterowniki**. Przyciski przełączają na właściwą zakładkę i włączają filtr „Tylko z dostępną aktualizacją”. Aplikacja niczego nie instaluje bez potwierdzenia.

Przycisk **Sprawdzanie przy starcie ▾** (obok „Dziennik zdarzeń”) otwiera menu z opcjami:

- **Sprawdzaj aktualizacje programów po uruchomieniu** (domyślnie włączone);
- **Sprawdzaj sterowniki w Windows Update po uruchomieniu** (domyślnie włączone);
- **Sprawdź teraz** — ponownie wykonuje pełne sprawdzenie.

Ustawienia są zapisywane w `%APPDATA%\BezpiecznyAktualizator\settings.json` (klucze `checkSoftwareOnStart`, `checkDriversOnStart`). Przy obu opcjach wyłączonych aplikacja tylko skanuje zainstalowane programy i sterowniki. Początek i wynik sprawdzania są zapisywane w dzienniku syslog (MSGID `APP`, poziom Notice).

## Wygląd i motyw (jasny / ciemny)

Interfejs korzysta z wbudowanego w WPF (.NET 9+) open-source'owego motywu **Fluent** (styl Windows 11):

- zaokrąglone kontrolki i ikony Segoe Fluent Icons;
- tło Mica oraz pasek tytułu w kolorze motywu;
- kolorowy pasek informacyjny z wynikiem sprawdzania wersji;
- wyróżnienie wierszy z aktualizacją (żółte) i z problemem (czerwone), czytelne w obu motywach;
- okna komunikatów w stylu aplikacji. W pytaniach z ostrzeżeniem domyślnym przyciskiem jest „Nie”.

Lista **Motyw** w nagłówku okna (ikona słońca) pozwala wybrać:

- **Systemowy** (domyślnie) — zgodnie z ustawieniem Windows „Tryb aplikacji”;
- **Jasny**;
- **Ciemny**.

Zmiana działa od razu, bez ponownego uruchamiania. Wybór jest zapisywany w `settings.json` (klucz `theme`: `system` / `light` / `dark`) i w dzienniku syslog (MSGID `SETTINGS`).

> Obsługa motywów w WPF (`Application.ThemeMode`) jest oznaczona przez Microsoft jako eksperymentalna (ostrzeżenie WPF0001). Aplikacja używa jej świadomie w [Theme.cs](src/BezpiecznyAktualizator/Services/Theme.cs).

## Harmonogram: ciche aktualizacje podczas bezczynności

Aplikacja może sama sprawdzać i instalować aktualizacje, gdy użytkownik nie korzysta z komputera. Zadanie uruchamia **Harmonogram zadań Windows**. Konfiguracja: **Sprawdzanie przy starcie ▾ → Harmonogram cichych aktualizacji…**.

Opcje okna:

- **Włącz ciche sprawdzanie podczas bezczynności komputera**;
- **Tryb działania**:
  - **tylko sprawdzaj** — wynik jest pokazywany na pasku informacyjnym po następnym otwarciu programu;
  - **sprawdzaj i instaluj aktualizacje z zaufanych źródeł** (domyślnie);
- **Rozpocznij po bezczynności**: 5–60 min (domyślnie 10);
- **Nie częściej niż co**: 4–168 godz. (domyślnie 24);
- **Sterowniki**: sprawdzanie w Windows Update (domyślnie włączone) oraz opcjonalna automatyczna instalacja z punktem przywracania systemu (domyślnie wyłączona);
- **Zasady aktualizacji**: podsumowanie wymaganego poziomu zaufania, wykluczeń i wstrzymanych wersji oraz przycisk otwierający okno zasad (zobacz [Zasady aktualizacji](#zasady-aktualizacji));
- **Uruchom teraz** — natychmiastowe ciche sprawdzanie z ustawieniami z okna.

Zadanie `\BezpiecznyAktualizator\SilentUpdate-<użytkownik>`:

- wyzwalacz **bezczynność komputera**;
- działa tylko, gdy użytkownik jest zalogowany. Hasło nie jest zapisywane (`InteractiveToken`);
- działa z **najwyższymi dostępnymi uprawnieniami**, więc instalatory nie wyświetlają monitów UAC. Z tego powodu utworzenie lub usunięcie zadania wymaga jednorazowego potwierdzenia UAC;
- nie startuje na zasilaniu bateryjnym ani bez sieci;
- limit czasu działania to 3 godz., zadanie nie uruchamia się w kilku kopiach jednocześnie.

Przebieg cichego uruchomienia (`BezpiecznyAktualizator.exe --scheduled`, bez okna):

1. Sprawdza, czy od ostatniego uruchomienia minął minimalny odstęp. Bezczynność występuje wiele razy dziennie.
2. Sprawdza, czy użytkownik jest nieaktywny przez wymagany czas (`GetLastInputInfo`).
3. Skanuje programy i sprawdza aktualizacje w winget / Microsoft Store. Pomija programy wykluczone i wstrzymane przez zasady aktualizacji (powód trafia do dziennika, MSGID `POLICY`).
4. Dla każdej aktualizacji:
   - ocenia źródło i akceptuje tylko poziom zaufania wymagany przez zasady;
   - pobiera i weryfikuje instalator (suma SHA-256 z manifestu, pliki kontrolne wydawcy, podpis Authenticode, skanowanie Microsoft Defender);
   - instaluje przez winget **dokładnie zweryfikowaną wersję**.
   
   Pakiety, których nie da się w pełni zweryfikować, są **pomijane**. Dotyczy to też sytuacji, gdy Defender jest niedostępny, chyba że w ustawieniach harmonogramu zaznaczono opcję instalacji bez skanowania (domyślnie wyłączoną). Program w oknie w takiej sytuacji pyta użytkownika.
5. Przed każdym kolejnym pakietem sprawdza, czy użytkownik wrócił do komputera (aktywność w ostatniej minucie). Jeśli tak, przerywa. Rozpoczęta instalacja nigdy nie jest przerywana.
6. Sprawdza sterowniki w Windows Update. Instaluje je tylko po zaznaczeniu tej opcji, zawsze z punktem przywracania.
7. Zapisuje wynik w `%LOCALAPPDATA%\BezpiecznyAktualizator\schedule-state.json` i w dzienniku syslog (MSGID `SCHEDULED`, `SW_UPGRADE`, `SW_VERIFY`, `DRV_INSTALL`). Podsumowanie pojawia się na pasku informacyjnym przy następnym otwarciu programu.

Bez uprawnień administratora (konto standardowe) ciche uruchomienie tylko sprawdza dostępne wersje. Ustawienia są zapisywane w `settings.json` (klucz `schedule`). Deinstalator usuwa zadania z folderu `\BezpiecznyAktualizator`.

## Zasady aktualizacji

Zasady obowiązują **zarówno przy aktualizacjach z okna programu, jak i w harmonogramie**. Okno zasad otwiera przycisk **Zasady** w zakładce „Oprogramowanie”, polecenie **Sprawdzanie przy starcie ▾ → Zasady aktualizacji…** lub przycisk w oknie harmonogramu.

- **Wykluczone programy** — program nigdy nie jest aktualizowany (identyfikator winget, nazwa, powód).
- **Wstrzymane wersje** — program pozostaje na wybranej wersji:
  - puste pole *Wersja* — żadna aktualizacja nie jest instalowana;
  - wzorzec z gwiazdką, np. `24.*` — dozwolone są tylko aktualizacje w tej gałęzi (24.1, 24.8.3), a nie 25.0;
  - konkretny numer, np. `24.8.3` — dozwolona jest tylko ta wersja;
  - **Do dnia** (RRRR-MM-DD, opcjonalnie) — po tej dacie wstrzymanie przestaje obowiązywać.
- **Zaufane źródła**:
  - **Automatycznie instaluj tylko ze źródeł o zaufaniu** *Wysokim* (domyślnie) lub *Wysokim lub średnim* — dotyczy harmonogramu; źródła o niskim zaufaniu i nieocenione nigdy nie są instalowane automatycznie;
  - **Także ręczne aktualizacje wymagają zaufanego źródła** — w oknie programu nieocenione źródła są najpierw oceniane, a pakiety o niewystarczającym zaufaniu są pomijane (lista pominiętych jest w potwierdzeniu i w dzienniku).

Kolumna **Zasada** pokazuje regułę programu, a status aktualizacji zablokowanej przez zasadę to **Aktualizacja wstrzymana**. Menu kontekstowe tabeli (PPM) zawiera polecenia **Wyklucz z aktualizacji**, **Wstrzymaj na bieżącej wersji** i **Usuń zasadę**. Po wycofaniu aktualizacji program proponuje wstrzymanie na przywróconej wersji. Każda zmiana zasad i każde pominięcie pakietu jest zapisywane w dzienniku syslog (MSGID `POLICY`). Zasady użytkownika są w `settings.json` (klucz `policies`). Dotychczasowe wykluczenia i ustawienie zaufania z harmonogramu są przenoszone automatycznie.

**Zasady komputera (administrator).** Plik `%ProgramData%\BezpiecznyAktualizator\policies.json` (format jak w **Eksportuj…**) obowiązuje wszystkich użytkowników komputera. Jego reguły są oznaczone jako „administrator” i nie można ich zmienić ani usunąć w programie, a ustawienia zaufania są łączone tak, by obowiązywało ostrzejsze. Poziom `autoTrust` jest narzucany tylko wtedy, gdy plik go zawiera. Uszkodzony plik jest zgłaszany w oknie zasad i w dzienniku. Przykład:

```json
{
  "autoTrust": "High",
  "manualRequireTrusted": true,
  "excluded": [ { "wingetId": "7zip.7zip", "name": "7-Zip", "reason": "wersja zatwierdzona przez dział IT" } ],
  "holds": [ { "wingetId": "Oracle.JavaRuntimeEnvironment", "version": "8.*", "until": "2026-12-31T23:59:59+01:00", "reason": "aplikacja księgowa" } ]
}
```

Aby zwykli użytkownicy nie mogli zmienić pliku, pozostaw domyślne uprawnienia folderu `ProgramData` (zapis tylko dla administratorów) lub ustaw je jawnie.
## Podatności (CVE) i wsparcie (EOL)

Przycisk **Sprawdź podatności i wsparcie** w zakładce „Oprogramowanie” sprawdza zaznaczone programy albo wszystkie. Wynik pojawia się w kolumnie **Ryzyko**, w szczegółach programu, w raporcie CSV/JSON i w dzienniku syslog (MSGID `SW_VULN`). Filtr **Tylko pilne i nieobsługiwane** pokazuje wyłącznie programy wymagające uwagi.

**Podatności — [NVD](https://nvd.nist.gov/developers/vulnerabilities) (National Vulnerability Database, NIST):**

1. Program jest przypisywany do produktu CPE (`vendor:product`). Najpierw sprawdzana jest wbudowana, przetestowana lista popularnych programów, potem identyfikator CPE z endoflife.date, a na końcu słownik CPE bazy NVD. Wynik ze słownika jest przyjmowany tylko przy jednoznacznym dopasowaniu nazwy (lub nazwy i wydawcy). Lepiej nie sprawdzić programu niż przypisać mu cudze luki.
2. Luki zainstalowanej wersji są pobierane zapytaniem `virtualMatchString`, które uwzględnia zakresy wersji.
3. Aplikacja dodatkowo sprawdza konfiguracje CVE i odrzuca luki dotyczące tej wersji tylko na innym systemie (np. macOS).
4. Program z co najmniej jedną znaną luką jest oznaczany jako **PILNE** (czerwony wiersz). Wyświetlane są: liczba luk, najwyższa ocena CVSS i znacznik **KEV**, jeśli luka jest w katalogu CISA aktywnie wykorzystywanych podatności.
5. Pakiety MSIX/Microsoft Store są pomijane: numer wersji pakietu nie odpowiada wersji programu, a takie pakiety aktualizuje Sklep.

Ograniczenia i wydajność:

- Bez klucza API NVD przyjmuje 5 zapytań na 30 s, więc pierwsze sprawdzenie wszystkich programów może potrwać kilkanaście minut.
- Bezpłatny [klucz API](https://nvd.nist.gov/developers/request-an-api-key) zwiększa limit do 50 zapytań. Klucz podaje się w zmiennej środowiskowej `NVD_API_KEY` albo w `settings.json` (klucz `NvdApiKey`).
- Wyniki są zapamiętywane na 24 godz., a dopasowania CPE na 30 dni (`%LOCALAPPDATA%\BezpiecznyAktualizator\Cache`).

> Baza [OSV](https://osv.dev) obejmuje ekosystemy pakietów (npm, PyPI, Maven, NuGet itd.), a nie programy instalowane w Windows. Dlatego aplikacja korzysta z NVD.

**Wsparcie — [endoflife.date](https://endoflife.date) (MIT):**

- **Nieobsługiwany (EOL)** — cykl wydawniczy zainstalowanej wersji (np. Python 3.8, .NET Core 3.1) nie otrzymuje już poprawek. Wiersz jest żółty, a szczegóły podają datę końca wsparcia i nowszą wspieraną wersję.
  - Wsparcie rozszerzone (np. Java 8) liczy się jako wspierane do końca tego wsparcia.
  - Wersja, której wsparcie skończyło się niedawno (do 60 dni) w związku z wydaniem następcy (np. Firefox), nie jest oznaczana jako EOL. Wystarczy zwykła aktualizacja.
- **Porzucony** — repozytorium GitHub projektu jest zarchiwizowane lub nieaktywne od ponad 3 lat, albo ostatnie wydanie w winget jest starsze niż 3 lata.

## Skanowanie instalatora programem Microsoft Defender

Przy włączonej opcji **Sprawdzaj pliki kontrolne przed instalacją** pobrany instalator jest dodatkowo skanowany programem Microsoft Defender. Używane jest polecenie `MpCmdRun.exe -Scan -ScanType 3 -File <plik> -DisableRemediation`. Działa to także w harmonogramie cichych aktualizacji i przy wycofywaniu aktualizacji. Instalator jest uznany za zweryfikowany tylko przy czystym wyniku skanowania.

| Wynik | Działanie |
|---|---|
| Wykryto zagrożenie | instalacja jest **blokowana** (także w trybie cichym), nazwa zagrożenia trafia do dziennika |
| Brak zagrożeń | instalacja może być kontynuowana |
| Defender niedostępny (np. aktywny inny antywirus, który go wyłącza) | w oknie programu instalacja jest **wstrzymywana** do wyraźnej decyzji użytkownika (domyślny przycisk to „Nie”). W harmonogramie pakiet jest **pomijany**, chyba że w ustawieniach harmonogramu zaznaczono „Instaluj także wtedy, gdy Microsoft Defender jest niedostępny”. Każda decyzja trafia do dziennika |

Wyłączenie opcji **Sprawdzaj pliki kontrolne przed instalacją** wyłącza także skanowanie, dlatego program prosi wtedy o potwierdzenie i zapisuje tę zmianę w dzienniku.

## Historia i wycofanie aktualizacji

Każda udana aktualizacja, z okna lub z harmonogramu, jest zapisywana w `%LOCALAPPDATA%\BezpiecznyAktualizator\update-history.json` (do 500 wpisów). Wpis zawiera:

- poprzednią i nową wersję;
- identyfikator winget;
- sumę SHA-256 instalatora.

W szczegółach programu widać wtedy wiersz „Poprzednia wersja…”.

Przycisk **Historia i wycofanie** pokazuje listę zmian. Po wybraniu aktualizacji i **Wycofaj do poprzedniej wersji** aplikacja:

1. sprawdza, czy poprzednia wersja jest nadal dostępna w repozytorium winget (`winget show --versions`);
2. pobiera i weryfikuje jej instalator (sumy, pliki kontrolne, podpis, Defender);
3. instaluje ją poleceniem `winget install --version <wersja> --force`;
4. zapisuje wycofanie w historii i w dzienniku syslog (MSGID `SW_ROLLBACK`);
5. proponuje wstrzymanie programu na przywróconej wersji (zasada aktualizacji), aby ani ciche aktualizacje, ani aktualizacja z okna nie zainstalowały ponownie nowszej wersji.

> Wycofanie przywraca wersję programu, nie jego dane ani ustawienia. Część instalatorów nie pozwala zainstalować starszej wersji na nowszą. Wtedy należy najpierw odinstalować program.

## Struktura

```
dotnet/
├─ BezpiecznyAktualizator.slnx
├─ Directory.Build.props                 # net10.0-windows, nullable, wspólne ustawienia
├─ src/
│  ├─ BezpiecznyAktualizator.Core/       # logika bez UI
│  │  ├─ Localization/  L.cs, Strings/*.json         (tłumaczenia interfejsu)
│  │  ├─ Logging/       Syslog.cs                   (dziennik RFC 5424 w pliku)
│  │  ├─ Models/        Software.cs
│  │  ├─ Scheduling/    SilentUpdate.cs             (opcje, stan, zadanie Harmonogramu zadań XML)
│  │  ├─ Policies/      UpdatePolicies.cs           (wykluczenia, wstrzymane wersje, zaufane źródła, zasady komputera)
│  │  ├─ Inventory/     SoftwareInventory.cs        (rejestr Uninstall)
│  │  ├─ Winget/        WingetClient.cs             (CLI winget, parsowanie wyników)
│  │  ├─ Catalogs/      CatalogClient.cs            (Scoop Main, Chocolatey Community)
│  │  ├─ Security/      Assessment.cs, SoftwareAssessor.cs,
│  │  │              InstallerVerifier.cs, ChecksumFiles.cs, Authenticode.cs (pliki kontrolne, podpis),
│  │  │              DefenderScanner.cs (skanowanie MpCmdRun)
│  │  ├─ Risk/          NvdClient.cs (CVE z NVD), LifecycleClient.cs (EOL / porzucone), RiskModels.cs
│  │  ├─ History/       UpdateHistory.cs            (historia aktualizacji i wycofania)
│  │  └─ Drivers/       DriverModels.cs, DriverInventory.cs (WMI),
│  │                    WindowsUpdateDrivers.cs (WUA COM + instalacja z UAC), DriverAssessor.cs
│  └─ BezpiecznyAktualizator/            # aplikacja WPF
│     ├─ App.xaml(.cs)                   # motyw Fluent i wspólne style, tryby bez okna --install-drivers <katalog> i --scheduled
│     ├─ MainWindow.xaml                 # nagłówek, pasek informacyjny, zakładki „Oprogramowanie” i „Sterowniki”
│     ├─ Views/         SoftwareView, DriversView, SearchWindow, ScheduleWindow (harmonogram), HistoryWindow (wycofanie),
│     │                 PoliciesWindow (zasady aktualizacji), AboutWindow (o programie), MessageDialog (okna komunikatów zgodne z motywem)
│     ├─ Services/      Ui.cs  (okna dialogowe, BackgroundRunner, raporty), Localization.cs ({l:Tr}, ustawienia),
│     │                 Theme.cs (motyw systemowy / jasny / ciemny), ScheduledRunner.cs (ciche aktualizacje),
│     │                 SelfProtection.cs (kontrola integralności, wykrywanie debugera)
│     └─ Protection.targets              # wydanie chronione: Obfuscar, PROTECTED, odcisk certyfikatu wydawcy
├─ packaging/                            # Build-Package.ps1, Install.ps1, Uninstall.ps1, INSTRUKCJA.txt, CZYTAJ-PRZENOSNA.txt
├─ tools/Update-Translations.ps1        # synchronizacja plików tłumaczeń z kodem
└─ tests/BezpiecznyAktualizator.Tests/   # xUnit: CoreTests, DriverTests, LocalizationTests, SyslogTests, InstallerVerificationTests, ScheduleTests, PolicyTests, RiskTests, IntegrityCheckTests, GitHubReleaseTests, LiveSystemTests
```

## Bezpieczeństwo

- Programy są instalowane wyłącznie przez winget. Winget sprawdza sumę SHA256 instalatora względem manifestu. Dodatkowo aplikacja porównuje instalator z plikami kontrolnymi wydawcy i sprawdza jego podpis cyfrowy (zob. „Sprawdzanie plików kontrolnych przed instalacją”). Ocena źródła opiera się na tych kryteriach:
  - repozytorium;
  - HTTPS;
  - domena wydawcy;
  - zgodność wydawcy.
- Sterowniki są instalowane tylko z Windows Update. Sterowniki z Windows Update są podpisane przez Microsoft (WHQL). Każdy identyfikator aktualizacji jest sprawdzany przed instalacją: musi być prawidłowym GUID-em.
- Do instalacji sterowników aplikacja uruchamia samą siebie z podniesionymi uprawnieniami (`--install-drivers`). Nie potrzebuje zewnętrznych skryptów. Dane między procesami są wymieniane przez pliki w prywatnym katalogu tymczasowym.
- Strony pakietów są otwierane tylko przez HTTPS i tylko w zaufanych domenach.

## Użyte komponenty open source

- [.NET](https://github.com/dotnet/runtime) i [WPF](https://github.com/dotnet/wpf) (MIT), w tym motyw Fluent (`PresentationFramework.Fluent`)
- [winget-cli](https://github.com/microsoft/winget-cli) i [winget-pkgs](https://github.com/microsoft/winget-pkgs) (MIT)
- [Scoop Main](https://github.com/ScoopInstaller/Main) (Unlicense / licencje manifestów)
- [xUnit](https://github.com/xunit/xunit) (Apache-2.0)
- [System.Management](https://www.nuget.org/packages/System.Management) (MIT)
- [Obfuscar](https://github.com/obfuscar/obfuscar) (MIT) – zaciemnianie kodu w wydaniu chronionym (tylko podczas budowania)
- [WiX Toolset](https://github.com/wixtoolset/wix) 6.0.2 (otwarty kod źródłowy; przed użyciem komercyjnym sprawdź warunki licencyjne i opłatę utrzymaniową WiX)
- Dane: [NVD API 2.0](https://nvd.nist.gov/developers) (NIST, domena publiczna), [katalog CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (przez NVD), [endoflife.date](https://github.com/endoflife-date/endoflife.date) (MIT)
