# Bezpieczny Aktualizator 2.1 (C# / WPF)

Wersja aplikacji napisana w C# na .NET 10 z interfejsem WPF, rozwijająca funkcje wersji Python (zob. [README](../README.md)):

- **Oprogramowanie**:
  - inwentaryzacja programów z rejestru i z winget;
  - wyszukiwanie w katalogach winget, Microsoft Store, Scoop Main i Chocolatey Community;
  - ocena źródła aktualizacji;
  - aktualizacja przez winget;
  - sprawdzanie podatności w NVD i OSV, ocen EPSS oraz oznaczanie programów z lukami jako **pilne**;
  - wykrywanie programów nieobsługiwanych (EOL) i porzuconych;
  - skanowanie pobranego instalatora programem Microsoft Defender, a gdy jest niedostępny — zaufanym skanerem ESET i następnie AMSI aktywnego antywirusa;
  - tworzenie punktu przywracania Windows przed instalacją lub aktualizacją (domyślnie włączone);
  - anulowanie długich skanów, sprawdzania repozytoriów, ocen źródeł, kontroli podatności oraz wyszukiwania aktualizacji Windows i sterowników; instalacje pozostają nieprzerywane;
  - historia aktualizacji i wycofanie do poprzedniej wersji;
  - eksport raportu do CSV, JSON i PDF.
- **Sterowniki**:
  - inwentaryzacja przez WMI (`Win32_PnPSignedDriver` i `Win32_PnPEntity`), w tym urządzenia z problemami;
  - wyszukiwanie nowszych wersji w Windows Update przez API Windows Update Agent (COM), z możliwością anulowania;
  - ocena źródła;
  - instalacja z podniesionymi uprawnieniami (UAC), z punktem przywracania zgodnie z ustawieniem kopii bezpieczeństwa.
- **Windows Update**:
  - wyszukiwanie aktualizacji oprogramowania i identyfikatorów CVE dostępnych w metadanych Windows Update;
  - osobne pobieranie i ręczna instalacja wybranych aktualizacji;
  - przygotowanie paczki offline z plików MSU/CAB pobranych z Katalogu Microsoft Update.
- **Microsoft Store**:
  - ręczne wyszukiwanie aktualizacji rozpoznanych przez oficjalne źródło `msstore` w WinGet oraz aktualizacja wybranych pozycji z potwierdzoną wersją;
  - otwieranie strony aktualizacji Microsoft Store, która może pokazać aplikacje niewykryte przez WinGet.
- **Program**: ikona w nagłówku, pasku tytułu, pasku zadań i zasobniku; powiadomienia o aktualizacjach, podpisana aktualizacja aplikacji z GitHub Releases i instalator MSI.
- **Diagnostyka**: historia ostrzeżeń i błędów z dziennika syslog, podgląd zanonimizowanego pakietu diagnostycznego przed zapisem oraz opcjonalne powiadomienia e-mail/Teams.
- **Lokalny agent AI** (opcjonalny): model językowy uruchomiony na tym komputerze (Ollama, LM Studio, llama.cpp, LocalAI) wybiera, które z dozwolonych aktualizacji zainstalować teraz, a które odłożyć — zob. „Lokalny agent AI”.
- **Kopia profilu**: paczka z folderami wybranego użytkownika Windows (Pulpit, Dokumenty, Obrazy itd.) do przeniesienia na inny komputer i odtworzenia, z sumami SHA256 i opcjonalnym szyfrowaniem hasłem — zob. „Kopia i migracja profilu użytkownika”.

W menu **Sprawdzanie przy starcie** można opcjonalnie włączyć wydania testowe aplikacji. Są one wyświetlane z fragmentem informacji o wydaniu, ale nie są pobierane ani instalowane automatycznie. Przed zapisaniem pakietu diagnostycznego sprawdź jego podgląd, a przed udostępnieniem również zapisany plik, ponieważ wpisy dziennika mogą ujawniać nazwy programów lub ścieżki. Wersja MSI używa wyłącznie numeru liczbowego z tagu wydania, dlatego stabilne wydanie po wersji testowej musi mieć wyższy numer liczbowy (np. po `v2.2.0-rc.1` użyj `v2.2.1`), aby aplikacja wykryła aktualizację.

## Wymagania

- Windows 10/11 x64
- [.NET 10 SDK](https://dotnet.microsoft.com/download), potrzebny tylko do budowania. Opublikowany plik `.exe` jest samodzielny (self-contained), więc działa bez zainstalowanego .NET.
- [winget](https://github.com/microsoft/winget-cli), potrzebny do sprawdzania i instalowania aktualizacji programów.

Zakładka Microsoft Store wymaga WinGet obsługującego `source export` i oficjalnie skonfigurowanego źródła `msstore`. Wyszukiwanie jest uruchamiane ręcznie po potwierdzeniu: WinGet może przekazać Microsoft informacje o zainstalowanych aplikacjach i zaakceptować warunki źródła. Dostępność i wersje zależą od danych Store i bieżącego konta; WinGet nie wykrywa wszystkich aktualizacji, a pozycje bez potwierdzonych wersji nie są wymuszane ani ponownie instalowane. Jeżeli WinGet nie zwróci tabeli wyników, program pokaże jego komunikat zamiast uznawać go za potwierdzenie braku aktualizacji. Instalacja wybranych pozycji przestrzega wykluczeń i może zaakceptować warunki pakietu. Program przekazuje WinGet rozpoznaną wersję, ale Microsoft Store może zainstalować nowszą; dlatego przy aktywnym wstrzymaniu wersji aktualizacja z `msstore` jest blokowana również w zakładce programów i harmonogramie, a wycofanie do wcześniejszej wersji jest niedostępne. Zgodność zainstalowanej wersji jest sprawdzana po aktualizacji w zakładce Microsoft Store, a niepotwierdzony wynik nie jest zapisywany jako sukces. WinGet lub Microsoft Store obsługują pobranie i instalację; program nie skanuje dodatkowo pliku Store w Microsoft Defender. Aktualizacje wykonane bezpośrednio w aplikacji Microsoft Store nie podlegają zasadom Bezpiecznego Aktualizatora.

## Kopia systemu i skanowanie przed instalacją

Ustawienie **Twórz punkt przywracania systemu przed instalacją** jest domyślnie włączone. Przed aktualizacją z WinGet, wycofaniem, instalacją przez Microsoft Store, instalacją pobranego pakietu MSU, aktualizacją sterownika oraz aktualizacją samego programu aplikacja sprawdza istniejący punkt z ostatnich 24 godzin lub próbuje utworzyć nowy. Wymaga to włączonej Ochrony systemu. Gdy nie można potwierdzić punktu, instalacja interaktywna wymaga jawnej zgody na kontynuację bez niego; cichy harmonogram pomija instalację i zgłasza błąd zadania. Użytkownik może wyłączyć ustawienie w menu aplikacji.

Punkt przywracania Windows **nie jest pełną kopią zapasową**: nie zabezpiecza plików osobistych, a możliwość cofnięcia zmian zależy od Ochrony systemu, dostępnego miejsca i obsługi danego składnika przez Windows. Windows może ograniczyć tworzenie nowych punktów (zwykle do jednego na 24 godziny), dlatego aplikacja może użyć istniejącego punktu z tego okresu. Przed aktualizacją samej aplikacji dodatkowo tworzona jest osobna kopia jej ustawień i historii.

Pliki pobierane przez aplikację dla instalacji są skanowane dostępnym, zaufanym antywirusem: Microsoft Defender, następnie ESET, a gdy te nie są dostępne — przez AMSI, o ile aktywny antywirus udostępnia zaufanego dostawcę. Wykryte zagrożenie blokuje instalację; brak skanera wymaga jawnej decyzji użytkownika (w harmonogramie instalacja bez skanowania jest domyślnie zabroniona). Aktualizacje pobierane i instalowane wewnętrznie przez usługę Windows Update lub Microsoft Store nie udostępniają aplikacji pliku do niezależnego skanowania; pobrany przez użytkownika pakiet MSU jest skanowany przed uruchomieniem instalatora.

Integracja z WinGet uruchamia wyłącznie `winget.exe` z zarejestrowanego pakietu Microsoft App Installer o podpisie Microsoft; nie wybiera przypadkowego pliku `winget` z `PATH`. Dla aktualizacji z repozytorium program pobiera jeden instalator i jego manifest, wymaga sumy SHA-256, zgodności identyfikatora pakietu i wersji oraz wiąże skanowanie z tym samym lokalnym manifestem używanym do instalacji. Zależności nie są pobierane jako dodatkowe instalatory, a błędy kontroli blokują instalację. Aktualizacje Store są osobne, ręczne i wymagają potwierdzenia przez Store. Jeśli plik historii aktualizacji jest uszkodzony lub nie można go zapisać, błąd jest jawnie zgłaszany; aplikacja nie zastępuje historii pustą listą.

Przy aktualizacji programu wykrytego w rejestrze aplikacja uwzględnia znacznik `WindowsInstaller`: dla MSI wybiera MSI/WiX, a dla EXE jedną ze zgodnych technologii EXE/Nullsoft/Inno/Burn. Zapobiega to pobieraniu MSI dla zainstalowanego EXE (np. 7-Zip) i błędowi zmiany technologii instalacji. Inny zgodny typ jest sprawdzany tylko po błędzie braku odpowiedniego instalatora `0x8A150010`; błąd pobierania lub sumy kontrolnej zatrzymuje operację. Nie jest wymuszane odinstalowanie ani przejście EXE–MSI. Dla pakietów bez wpisu w rejestrze pozostaje standardowy dobór WinGet.

Instalacja i wycofanie ze zweryfikowanego manifestu wymagają ustawienia administracyjnego WinGet `LocalManifestFiles=true`. Aplikacja odczytuje je przez `winget settings export` przed pobieraniem instalatora do instalacji oraz ponownie przed uruchomieniem instalacji. Gdy ustawienie jest wyłączone, aplikacja wyjaśnia, że jego włączenie zmienia konfigurację WinGet dla całego konta, i pyta o zgodę. Po potwierdzeniu uruchamia wyłącznie `winget settings --enable LocalManifestFiles` z monitem UAC, a następnie ponownie odczytuje ustawienie; odmowa zgody, anulowanie UAC, błąd lub niepotwierdzona zmiana zatrzymują zweryfikowaną instalację. Aplikacja nigdy nie przechodzi na instalację bez zweryfikowanego manifestu. Nieczytelne ustawienie również zatrzymuje operację z komunikatem, zamiast wyświetlać pomoc WinGet i kod `0x8A150002`. Sama weryfikacja pliku w bibliotece nie wymaga włączania tej opcji. Gdy Defender jest niedostępny, ESET jest używany tylko wtedy, gdy produkt jest aktywny w Zabezpieczeniach Windows, a `ecls.exe` w znanej lokalizacji ma prawidłowy podpis Authenticode wydawcy ESET; jeśli i ten skaner jest niedostępny, aplikacja sprawdza zaufanego dostawcę AMSI aktywnego antywirusa. Skanowanie nie wykonuje czyszczenia pliku; wykrycie blokuje instalację, a brak/awaria skanerów nadal wymaga osobnej zgody na pominięcie skanu. Samo wykrycie antywirusa, podpis instalatora ani jego suma kontrolna nie oznaczają wykonania skanu.

Polecenia WinGet uruchamiane przez jeden proces aplikacji nie nakładają się. Odczyt listy, wyszukiwanie i odczyt metadanych po błędzie pamięci podręcznej źródła `0x80071130` są ponawiane jeden raz po sekundzie, z ostrzeżeniem w syslog. Ponowne niepowodzenie jest zgłaszane jawnie. Instalacje, pobieranie i zmiany źródeł nie są automatycznie ponawiane przez ten mechanizm; program nie resetuje źródeł ani nie usuwa pamięci podręcznej. Nie wyklucza to konfliktów z innymi procesami WinGet uruchomionymi poza aplikacją.

## Budowanie i uruchamianie

```powershell
cd dotnet
dotnet build
dotnet run --project src\BezpiecznyAktualizator
```

## Testy

```powershell
dotnet test --filter "Category!=Live&Category!=VmIntegration"   # testy offline
dotnet test --filter "Category=Live"    # testy na żywym systemie: rejestr, WMI, winget, Windows Update
```

Testy paczek offline tworzą krótkotrwały certyfikat w magazynie bieżącego użytkownika i tymczasowo dodają go do zaufanych wydawców oraz urzędów głównych. Przy normalnym zakończeniu usuwają utworzony certyfikat; po przerwaniu procesu może być konieczne ręczne usunięcie go z tych magazynów. Uruchamiaj je w odizolowanym środowisku testowym, nie na komputerze produkcyjnym. Na jednorazowej maszynie GitHub-hosted CI może jawnie wybrać magazyn główny komputera, aby uniknąć ukrytego monitu zaufania; test odrzuca tę opcję na innych runnerach.

GitHub Actions uruchamia testy Python, kompilację i testy .NET oraz izolowany test MSI: instalację, aktualizację główną i odinstalowanie. Test zamknięcia pliku po weryfikacji oraz błędów pobierania działa bez dostępu do sieci. Osobny, ręczny workflow dla dedykowanej maszyny Windows sprawdza uruchomienie zaufanego WinGet i skan katalogu Windows Update bez instalowania aktualizacji. Testy kategorii `Live` obejmują również skanowanie tymczasowego, nieszkodliwego pliku przez ESET, jeśli aktywny ESET jest zgłoszony do Zabezpieczeń Windows. Przywracanie zależności w CI kończy się błędem, jeśli audyt NuGet zgłosi podatność (w tym w zależnościach przechodnich) lub nie może pobrać danych audytu. Każde uruchomienie tworzy SBOM CycloneDX JSON dla projektów produkcyjnych; na opublikowanym wydaniu plik jest dołączany do GitHub Release. Generator jest przypięty do wersji 6.3.1.

## Paczka instalacyjna z .NET i podpisem cyfrowym (zalecane)

```powershell
.\packaging\Build-Package.ps1                       # certyfikat własny (tworzony automatycznie)
.\packaging\Build-Package.ps1 -PfxPath firma.pfx -PfxPassword (Read-Host -AsSecureString)   # certyfikat komercyjny
.\packaging\Build-Package.ps1 -CertThumbprint <odcisk>                                       # certyfikat z magazynu
.\packaging\Build-Package.ps1 -PfxPath firma.pfx -PfxPassword (Read-Host -AsSecureString) -PublicRelease
```

`-PublicRelease` jest wymagane dla wydania publicznego. Odrzuca certyfikaty self-signed, certyfikaty nieważne lub bez prywatnego klucza i rozszerzenia Code Signing, nie ufa łańcuchowi certyfikatów albo nieprawidłowe podpisy/znaczniki czasu plików. Tryb wymaga połączenia sieciowego do sprawdzenia odwołania certyfikatu. Nie przekazuj PFX ani hasła do repozytorium; używaj kontrolowanego środowiska wydawniczego i certyfikatu dostarczonego przez zaufany kanał. Bez dostępnego certyfikatu wydawcy można zbudować paczkę testową, ale nie należy publikować jej jako zaufanego wydania.

Rotację należy przećwiczyć przed produkcyjnym użyciem: (1) zbuduj wersję pomostową z dotychczasowym certyfikatem, `-PublicRelease` i `-PreviousSignerThumbprints <NOWY_ODCISK>`; (2) sprawdź jej instalację/aktualizację oraz przejście do wydania podpisanego nowym certyfikatem; (3) zbuduj kolejne wydanie nowym certyfikatem z odciskiem poprzedniego, a następnie wydanie usuwające stary odcisk. Dodatkowe odciski muszą pochodzić z autentycznych, wcześniej opublikowanych certyfikatów projektu. Nigdy nie wyłączaj weryfikacji podpisu.

Skrypt tworzy `dist\BezpiecznyAktualizator-<wersja>-win-x64\` oraz archiwum `.zip` (ok. 57 MB) z plikiem `.zip.sha256`:

| Element | Opis |
|---|---|
| `app\BezpiecznyAktualizator.exe` | aplikacja (pojedynczy plik ~1,7 MB, zależny od .NET Desktop Runtime, **wydanie chronione**), **podpisana Authenticode** |
| `dotnet\windowsdesktop-runtime-*.exe` | oficjalny instalator **.NET Desktop Runtime** (najnowsza wersja 10.0.x), pobrany na podstawie [metadanych wydań Microsoft](https://builds.dotnet.microsoft.com/dotnet/release-metadata/10.0/releases.json), zweryfikowany SHA512 i podpisem Microsoft |
| `Instaluj.cmd`, `Install.ps1` | instalator (podpisany): sprawdza sumy SHA256 i podpisy, instaluje .NET (jeśli brak), opcjonalnie ufa certyfikatowi wydawcy, kopiuje do `Program Files`, tworzy skrót w menu Start i wpis w „Aplikacje i funkcje” |
| `app\Uninstall.ps1` | deinstalator (podpisany) – usuwa aplikację, skróty i certyfikat z magazynów zaufanych |
| `cert\BezpiecznyAktualizator.cer` | publiczny certyfikat wydawcy |
| `LICENSE`, `THIRD-PARTY-NOTICES.txt` | licencja MIT projektu i informacje o zależnościach aplikacji |
| `DOTNET-LICENSE.txt`, `DOTNET-THIRD-PARTY-NOTICES.txt` | informacje licencyjne środowiska .NET z użytego SDK |
| `runtime.json`, `SHA256SUMS.txt` | wersja/SHA512 instalatora .NET oraz sumy kontrolne wszystkich plików |

`Instaluj.cmd -VerifyOnly` sprawdza paczkę bez instalowania czegokolwiek.

Oprócz tego skrypt tworzy osobną **paczkę przenośną** `dist\BezpiecznyAktualizator-<wersja>-portable-win-x64.zip` (ok. 67 MB): jeden samodzielny plik `BezpiecznyAktualizator.exe` z wbudowanym środowiskiem .NET (chroniony, skompresowany, podpisany), certyfikat wydawcy, pliki licencyjne, `CZYTAJ.txt`, `INSTRUKCJA.txt` i `SHA256SUMS.txt`. Nie wymaga instalacji ani .NET – wystarczy rozpakować i uruchomić.

Przełączniki: `-NoPortable` (bez paczki przenośnej), `-NoProtect` (wydanie bez zaciemniania i kontroli integralności, np. do diagnozowania błędów), `-NoZip`, `-NoRestore` (używa wcześniej przywróconych zależności). Parametr `-OutputDirectory <ścieżka>` zmienia katalog wyjściowy; skrypt może nadpisać istniejące paczki o tej samej wersji w wybranym katalogu.

Skrypt tworzy również samodzielny, podpisany MSI `dist\BezpiecznyAktualizator-<wersja>-win-x64.msi` i plik `.msi.sha256`. MSI instaluje aplikację w `Program Files`, tworzy skrót w menu Start, jest widoczny w „Aplikacje i funkcje” i obsługuje aktualizacje główne (Major Upgrade). Ustawienia użytkownika pozostają poza katalogiem instalacji.

### Instalator MSI i aktualizacja samego programu

MSI jest budowany przez [WiX Toolset 6](packaging/msi/BezpiecznyAktualizator.wixproj) i zawiera samodzielną wersję aplikacji, więc nie wymaga osobnego .NET Runtime. Zawiera też pliki licencji projektu, zależności aplikacji i .NET. Uruchom plik MSI i zatwierdź UAC, aby zainstalować. Odinstalowanie odbywa się standardowo przez „Aplikacje i funkcje”; MSI nie usuwa ustawień w `%APPDATA%`.

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
| MSGID | typ zdarzenia: `APP`, `SETTINGS`, `SW_SCAN`, `SW_UPDATE_CHECK`, `SW_ASSESS`, `SW_UPGRADE`, `SW_VERIFY` (weryfikacja plików kontrolnych), `ANTIVIRUS` (wykrywanie antywirusów), `SW_SEARCH`, `DRV_SCAN`, `DRV_UPDATE_CHECK`, `DRV_INSTALL`, `REPORT`, `ERROR` |
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
5. Skanuje pobrany instalator programem Microsoft Defender. Jeśli Defender jest niedostępny, używa ESET tylko wtedy, gdy jest aktywny w Zabezpieczeniach Windows, a jego skaner ma prawidłowy podpis ESET.
6. Instaluje dokładnie zweryfikowaną wersję przy użyciu lokalnego manifestu. Winget przy instalacji ponownie sprawdza tę samą sumę SHA256.

| Wynik | Działanie |
|---|---|
| Niezgodna suma (manifest lub plik wydawcy), nieprawidłowy lub unieważniony podpis | instalacja tego programu jest **wstrzymywana** bez pytania |
| Brak pliku kontrolnego wydawcy, instalator niepodpisany | ostrzeżenie w dzienniku, instalacja jest kontynuowana |
| Defender i zaufany skaner ESET niedostępne | ostrzeżenie i pytanie o wyraźną zgodę na instalację bez skanowania (domyślnie **nie**); harmonogram domyślnie pomija aktualizację |
| Weryfikacji nie można przeprowadzić (np. wydawca blokuje pobieranie) | aktualizacja jest wstrzymywana; można świadomie wyłączyć dodatkową weryfikację i zaakceptować ostrzeżenie |
| Pakiety Microsoft Store | weryfikację wykonuje sam Sklep |

Wyniki każdego sprawdzenia trafiają do zakładki „Dziennik” i do dziennika syslog (MSGID `SW_VERIFY`). Sterowniki z Windows Update są weryfikowane przez agenta Windows Update: sprawdza on podpis i skrót pakietu przed instalacją.

Przycisk **Sprawdź antywirusa** w zakładce „Oprogramowanie” odczytuje z Centrum zabezpieczeń Windows listę zgłoszonych programów, ich stan ochrony oraz aktualność sygnatur; samo sprawdzenie listy nie uruchamia skanera. Podczas weryfikacji instalatora program może uruchomić ESET wyłącznie jako awaryjny skaner, gdy Defender jest niedostępny, ESET jest aktywny, a `ecls.exe` z jednej ze znanych lokalizacji ma prawidłowy podpis Authenticode wydawcy `ESET, spol. s r.o.`. Skanowanie używa trybu bez automatycznego czyszczenia i dotyczy tylko pobranego instalatora; wykrycie blokuje instalację. Brak ESET, nieprawidłowy podpis, błąd lub niejednoznaczny wynik nie są uznawane za czysty skan i nadal wymagają osobnej zgody na pominięcie skanowania. Interfejs Centrum zabezpieczeń jest dostępny na klienckim systemie Windows 8 lub nowszym; Windows Server nie jest obsługiwany.

Przycisk **Sprawdź gotowość aktualizacji** pokazuje, czy WinGet jest dostępny i zweryfikowany, czy administrator włączył `LocalManifestFiles`, oraz czy w Zabezpieczeniach Windows jest aktywny Defender lub ESET z dostępnym skanerem. Nie zmienia ustawień administracyjnych i nie uruchamia skanowania.

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
- **Okno serwisowe** (w tym zakres przechodzący przez północ), pomijanie instalacji na baterii i w sieci taryfowej lub o nieznanym koszcie;
- **Ponowienia instalacji**: 0–3 próby z opóźnieniem 30/60/90 sekund;
- **Sterowniki**: sprawdzanie w Windows Update (domyślnie włączone) oraz opcjonalna automatyczna instalacja (domyślnie wyłączona); przed instalacją tworzony jest punkt przywracania, jeśli globalne ustawienie kopii bezpieczeństwa jest włączone;
- **Windows Update**: opcjonalne sprawdzanie (domyślnie wyłączone) oraz osobna, domyślnie wyłączona instalacja wyłącznie aktualizacji oznaczonych przez WUA jako obowiązkowe, z wcześniej zaakceptowaną licencją;
- **Zasady aktualizacji**: podsumowanie wymaganego poziomu zaufania, wykluczeń i wstrzymanych wersji oraz przycisk otwierający okno zasad (zobacz [Zasady aktualizacji](#zasady-aktualizacji));
- **Uruchom teraz** — natychmiastowe ciche sprawdzanie z ustawieniami z okna.

Zadanie `\BezpiecznyAktualizator\SilentUpdate-<użytkownik>`:

- wyzwalacz **bezczynność komputera**;
- działa tylko, gdy użytkownik jest zalogowany. Hasło nie jest zapisywane (`InteractiveToken`);
- działa z **najwyższymi dostępnymi uprawnieniami**, więc instalatory nie wyświetlają monitów UAC. Z tego powodu utworzenie lub usunięcie zadania wymaga jednorazowego potwierdzenia UAC;
- opcjonalnie pomija instalacje na baterii oraz w sieci taryfowej lub o nierozpoznanym koszcie; sam Windows nie uruchamia zadania na baterii, gdy zaznaczono tę regułę;
- limit czasu działania to 3 godz., zadanie nie uruchamia się w kilku kopiach jednocześnie.

Przebieg cichego uruchomienia (`BezpiecznyAktualizator.exe --scheduled`, bez okna):

1. Sprawdza, czy od ostatniego uruchomienia minął minimalny odstęp. Bezczynność występuje wiele razy dziennie.
2. Sprawdza, czy użytkownik jest nieaktywny przez wymagany czas (`GetLastInputInfo`).
3. Skanuje programy i sprawdza aktualizacje w winget / Microsoft Store. Pomija programy wykluczone i wstrzymane przez zasady aktualizacji (powód trafia do dziennika, MSGID `POLICY`).
4. Dla każdej aktualizacji:
   - ocenia źródło i akceptuje tylko poziom zaufania wymagany przez zasady;
   - pobiera i weryfikuje instalator (suma SHA-256 z manifestu, pliki kontrolne wydawcy, podpis Authenticode, skanowanie Defendera, zaufanego ESET lub AMSI aktywnego antywirusa);
   - instaluje przez winget **dokładnie zweryfikowaną wersję**.
   
   Pakiety, których nie da się w pełni zweryfikować, są **pomijane**. Jeśli żaden zaufany skaner (Defender, ESET ani AMSI aktywnego antywirusa) nie jest dostępny, harmonogram pomija aktualizację, chyba że w ustawieniach zaznaczono opcję instalacji bez skanowania (domyślnie wyłączoną). Program w oknie w takiej sytuacji pyta użytkownika.
5. Przed każdą instalacją tworzy jeden punkt przywracania na cały przebieg (jeśli ustawienie kopii jest włączone); bez potwierdzonego punktu pomija instalacje, zapisuje błąd i zwraca niezerowy kod zadania. Przed każdym kolejnym pakietem sprawdza też, czy użytkownik wrócił do komputera (aktywność w ostatniej minucie). Jeśli tak, przerywa. Rozpoczęta instalacja nigdy nie jest przerywana.
6. Opcjonalnie sprawdza aktualizacje Windows. Automatyczna instalacja wymaga włączenia obu opcji, oznaczenia aktualizacji jako obowiązkowej i wcześniej zaakceptowanej licencji. W przypadku błędu lub potrzeby restartu dalsza instalacja aktualizacji Windows jest zatrzymywana.
7. Sprawdza sterowniki w Windows Update. Instaluje je tylko po zaznaczeniu tej opcji, zawsze z punktem przywracania.
8. Zapisuje wynik w `%LOCALAPPDATA%\BezpiecznyAktualizator\schedule-state.json` i w dzienniku syslog (MSGID `SCHEDULED`, `SW_UPGRADE`, `SW_VERIFY`, `DRV_INSTALL`, `WINDOWS_UPDATE`). Podsumowanie pojawia się na pasku informacyjnym przy następnym otwarciu programu.
9. Po zakończeniu może wysłać podsumowanie e-mailem przez SMTP/TLS albo webhookiem Teams. Niepowodzenia kanału są zapisywane jako ostrzeżenia, bez ujawniania sekretu.

Bez uprawnień administratora (konto standardowe) ciche uruchomienie tylko sprawdza dostępne wersje. Ustawienia są zapisywane w `settings.json` (klucz `schedule`). Deinstalator usuwa zadania z folderu `\BezpiecznyAktualizator`.

## Lokalny agent AI

Menu nagłówka **Lokalny agent AI...** podłącza model językowy działający na tym komputerze przez API zgodne z OpenAI (`GET /models`, `POST /chat/completions`). Typowe adresy:

| Serwer | Adres API |
|---|---|
| [Ollama](https://github.com/ollama/ollama) | `http://127.0.0.1:11434/v1` |
| [LM Studio](https://lmstudio.ai/) | `http://127.0.0.1:1234/v1` |
| [llama.cpp](https://github.com/ggml-org/llama.cpp) (`llama-server`) | `http://127.0.0.1:8080/v1` |

Przycisk **Testuj połączenie** pobiera listę modeli. Opcjonalne wskazówki (np. „nie aktualizuj przeglądarek w dni robocze”) są dołączane do zapytania.

- **Zakładka Oprogramowanie → Zapytaj agenta AI**: agent ocenia dostępne aktualizacje dozwolone przez zasady (bez Microsoft Store), zaznacza zalecane na liście i zapisuje uzasadnienia w dzienniku. Instalację uruchamia użytkownik przyciskiem **Aktualizuj zaznaczone**.
- **Harmonogram**: gdy opcja „Ciche aktualizacje instalują tylko programy zatwierdzone przez agenta” jest włączona, przed instalacją harmonogram wysyła agentowi listę kandydatów i instaluje tylko pozycje z jednoznaczną zgodą (`"install": true`). Gdy agent jest niedostępny, przekroczy limit czasu lub odpowie nieprawidłowo, ciche instalacje programów są pomijane.

Ograniczenia bezpieczeństwa:

- adres musi wskazywać pętlę zwrotną (`localhost`, `127.0.0.0/8`, `[::1]`) przez HTTP/HTTPS, bez danych logowania; klient nie używa proxy ani przekierowań, a odpowiedź jest ograniczona do 1 MB;
- agent otrzymuje tylko identyfikator, nazwę, wydawcę, wersje, źródło i ocenę ryzyka pakietu — bez ścieżek, kluczy rejestru i danych użytkownika;
- agent może jedynie zawęzić listę: nieznane identyfikatory, wartości inne niż logiczne `true` i sprzeczne decyzje są traktowane jako odrzucenie. Weryfikacja sum kontrolnych i podpisu, punkt przywracania oraz skanowanie antywirusowe działają zawsze;
- decyzje są zapisywane w dzienniku z MSGID `AI_AGENT`, a ustawienia w `settings.json` (klucz `localAgent`).

## Kopia i migracja profilu użytkownika

Zakładka **Kopia profilu** tworzy paczkę `*.baprofile` z folderami wybranego użytkownika Windows, którą można przenieść (np. na pendrive) na inny komputer i tam odtworzyć.

1. **Utwórz paczkę profilu**: wybierz użytkownika (lista z rejestru `ProfileList`, bez kont systemowych) i foldery: Pulpit, Dokumenty, Obrazy, Muzyka, Wideo, Pobrane, Ulubione oraz opcjonalnie ustawienia programów (`AppData\Roaming`). Dla bieżącego użytkownika uwzględniane są foldery przekierowane, np. do OneDrive. **Oszacuj rozmiar** liczy pliki przed spakowaniem.
2. Opcjonalne **hasło** (min. 8 znaków) szyfruje całą paczkę: klucz z PBKDF2-SHA256 (600 000 iteracji, losowa sól), AES-256-GCM w porcjach po 1 MiB z uwierzytelnieniem kolejności i końca pliku. Bez hasła program ostrzega, że paczkę odczyta każdy, kto ją otrzyma. Hasła nie da się odzyskać.
3. **Przywróć z paczki** na drugim komputerze: wybierz plik, podaj hasło, a następnie cel — foldery profilu wybranego użytkownika albo dowolny folder (podfoldery `Desktop`, `Documents`…). Dla istniejących plików wybierz: pomiń, zachowaj oba (np. `raport (2).docx`) lub zastąp — zastępowane pliki są przenoszone do folderu `BezpiecznyAktualizator-kopia-przed-przywroceniem-<data>`.

Zabezpieczenia:

- paczka to archiwum ZIP z `manifest.json` (komputer, użytkownik, data, lista plików z rozmiarem i SHA256); przed przywróceniem cała paczka jest weryfikowana i przy jakiejkolwiek niezgodności nic nie jest zapisywane, a każdy plik jest ponownie sprawdzany przy zapisie (najpierw do pliku `.partial`);
- odrzucane są paczki z plikami spoza manifestu oraz ścieżkami z `..`, dyskami, strumieniami NTFS lub nazwami zarezerwowanymi (ochrona przed „zip slip”); program nie zapisuje przez dowiązania (junction/symlink) w folderze docelowym;
- przy pakowaniu pomijane są dowiązania (np. `Moje dokumenty`, linki do innych dysków), pliki tymczasowe i blokady Office (`~$*`, `*.tmp`), `NTUSER.DAT` oraz pliki zablokowane przez inne programy — lista pominiętych trafia do dziennika;
- dostęp do profilu innego użytkownika wymaga uprawnień administratora — program proponuje ponowne uruchomienie przez UAC;
- po utworzeniu paczki dziennik zawiera jej sumę SHA256 do porównania na drugim komputerze; operacje są zapisywane z MSGID `PROFILE_BACKUP`.

Paczka przenosi pliki użytkownika, a nie zainstalowane programy, konta, hasła zapisane w systemie (DPAPI) ani ustawienia rejestru.

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
## Windows Update i paczka offline

Zakładka **Windows Update** wyszukuje przez Windows Update Agent (WUA) nieukryte, niezainstalowane aktualizacje typu „Software” oferowane **bieżącemu komputerowi**. WUA korzysta z usługi skonfigurowanej w systemie, która może być zarządzana przez organizację (WSUS). Sterowniki pozostają w osobnej zakładce. Lista i szczegóły pokazują m.in. KB, rozmiar, stan pobrania, warunki licencji i identyfikatory CVE udostępnione przez WUA, również dla składników aktualizacji. Brak identyfikatorów CVE oznacza brak danych w metadanych, a nie potwierdzenie braku podatności.

Wyszukiwanie można przerwać przyciskiem **Anuluj**. Wyniki są publikowane dopiero po zakończeniu wyszukiwania i pobrania metadanych MSRC; anulowanie nie zastępuje wcześniej wyświetlonej listy częściowym wynikiem.

**Pobierz zaznaczone** pobiera zawartość do pamięci WUA bez instalacji; **Instaluj pobrane** wykonuje osobną, ręcznie potwierdzoną instalację. Operacje wymagają UAC, ponownie sprawdzają identyfikator i numer rewizji aktualizacji oraz pokazują wyniki i ewentualną potrzebę restartu. Jeżeli wymagana licencja nie jest jeszcze zaakceptowana, jej treść znajduje się w szczegółach; kontynuacja oznacza akceptację. Błędy i ostrzeżenia są widoczne w dzienniku (`WINDOWS_UPDATE`).

**Korelacja MSRC:** aplikacja porównuje dokładny numer KB i miesiąc publikacji aktualizacji z danymi CVRF w API Microsoft Security Response Center. Tak uzyskane CVE są oznaczone osobno od metadanych WUA i nie są przypisywane na podstawie podobieństwa tytułu. API jest odpytywane przez HTTPS; odpowiedzi są pamiętane przez 12 godzin. Brak wyniku albo niedostępność MSRC nie potwierdza braku podatności.

**Skan komputera offline:** przyciskiem **Skanuj komputer offline...** wybierz aktualny `Wsusscn2.cab`, pobrany z oficjalnego [katalogu Microsoft](https://catalog.s.download.windowsupdate.com/microsoftupdate/v6/wsusscan/wsusscn2.cab). Windows Update Agent weryfikuje podpis Microsoft pliku i skanuje wyłącznie lokalny komputer bez połączenia z Windows Update/WSUS. Katalog zawiera metadane aktualizacji zabezpieczeń, nie instalatory i nie wszystkie aktualizacje. Wynik można wyeksportować do JSON; raport nie jest podpisany i może ujawniać stan aktualizacji komputera.

**Test na dedykowanej maszynie Windows:** ręczny workflow `Windows Update VM integration` pobiera ten katalog, a następnie uruchamia wyłącznie skan WUA; nie pobiera ani nie instaluje aktualizacji. Wymaga jednorazowego self-hosted runnera oznaczonego `windows-update-vm`, działającego jako administrator. Zwykłe CI pomija testy `Category=Live`. Test instalacji rzeczywistych aktualizacji nie jest częścią workflow; przeprowadzaj go osobno na odtwarzalnej maszynie testowej po jawnej zgodzie i z przygotowanym pakietem testowym.

Przycisk **Instaluj plik MSU...** pozwala ponadto wybrać pobrany wcześniej plik z Katalogu Microsoft Update i uruchomić interaktywny systemowy instalator WUSA z UAC. WUSA może poprosić o akceptację warunków i restart. Plik musi być przeznaczony dla bieżącego systemu.

### Instalacja na komputerze bez sieci

WUA nie gwarantuje, że pobrana do jego pamięci zawartość jest kompletnym, przenośnym instalatorem. Dlatego paczka offline **nie eksportuje pamięci WUA** i wymaga osobnego pobrania plików:

1. Na komputerze z Internetem otwórz **Katalog Microsoft Update** dla wybranej pozycji lub bez zaznaczenia. Pobierz z niego pełne pliki `.msu` albo serwisowe `.cab` odpowiednie dla **docelowej** edycji, wersji i architektury Windows. Uwzględnij wymagane aktualizacje wstępne zgodnie z artykułami KB; pliki UUP/PSF i sterownikowe CAB nie są obsługiwane przez ten instalator.
2. Wybierz **Utwórz paczkę offline**, dodaj pobrane pliki, wybierz ważny certyfikat podpisywania kodu z kluczem prywatnym i ustaw kolejność instalacji. Powstaje ZIP z manifestem podpisanym RSA, podpisanym Authenticode instalatorem PowerShell, certyfikatem publicznym i skrótami SHA-256 wszystkich plików.
3. Przed przeniesieniem zapoznaj się z warunkami licencji każdej aktualizacji — instalator offline ich nie wyświetla. Zapisz odcisk SHA-256 certyfikatu widoczny w kreatorze i przekaż go odbiorcy **oddzielnym, zaufanym kanałem**. Na komputerze docelowym zaufaj certyfikatowi wydawcy według polityki organizacji. Windows PowerShell musi potwierdzić ważny podpis Authenticode instalatora; nie omijaj `AllSigned` ani ostrzeżeń o podpisie. Następnie uruchom weryfikator i instalator jako administrator, wpisując niezależnie dostarczony odcisk. Skrypt nie pobiera plików z sieci i nie restartuje komputera automatycznie; używa systemowych WUSA dla MSU i DISM dla serwisowych CAB.
4. Jeśli instalacja wymaga restartu, uruchom komputer ponownie i ten sam instalator: wznowi od kolejnego pliku. Błąd lub niejednoznaczny wynik „niepasująca albo już zainstalowana” zatrzymuje dalszą instalację i wymaga sprawdzenia. W razie potrzeby przygotuj nową paczkę z pozostałymi plikami. Dziennik i stan wznowienia znajdują się w `%ProgramData%\BezpiecznyAktualizator\OfflineUpdates\<identyfikator>`.

Podpis uwierzytelnia manifest tylko wtedy, gdy odbiorca porówna odcisk z wartością uzyskaną niezależnie, a Windows ufa wydawcy podpisanego skryptu. SHA-256 wykrywa zmiany plików względem podpisanego manifestu, ale samo nie potwierdza pochodzenia plików MSU/CAB. Pobieraj je z oficjalnego katalogu i chroń nośnik. Systemowe narzędzia serwisowe stosują własne kontrole zaufania i zgodności; DISM nie sprawdza wszystkich zależności, więc należy samodzielnie zweryfikować wymagania KB i kolejność instalacji. Więcej informacji o zakresie i ograniczeniach zawiera dokumentacja Microsoft [skanowania WUA offline](https://learn.microsoft.com/en-us/windows/win32/wua_sdk/using-wua-to-scan-for-updates-offline).

## Podatności (CVE) i wsparcie (EOL)

Przycisk **Sprawdź podatności i wsparcie** w zakładce „Oprogramowanie” sprawdza zaznaczone programy albo wszystkie. Wynik pojawia się w kolumnie **Ryzyko**, w szczegółach programu, w raporcie CSV/JSON i w dzienniku syslog (MSGID `SW_VULN`). Filtr **Tylko pilne i nieobsługiwane** pokazuje wyłącznie programy wymagające uwagi.

**Podatności — [NVD](https://nvd.nist.gov/developers/vulnerabilities) (National Vulnerability Database, NIST):**

1. Program jest przypisywany do produktu CPE (`vendor:product`). Najpierw sprawdzana jest wbudowana, przetestowana lista popularnych programów, potem identyfikator CPE z endoflife.date, a na końcu słownik CPE bazy NVD. Wynik ze słownika jest przyjmowany tylko przy jednoznacznym dopasowaniu nazwy (lub nazwy i wydawcy). Lepiej nie sprawdzić programu niż przypisać mu cudze luki.
2. Luki zainstalowanej wersji są pobierane zapytaniem `virtualMatchString`, które uwzględnia zakresy wersji.
3. Aplikacja dodatkowo sprawdza konfiguracje CVE i odrzuca luki dotyczące tej wersji tylko na innym systemie (np. macOS).
4. Program z co najmniej jedną znaną luką jest oznaczany jako **PILNE** (czerwony wiersz). Wyświetlane są: liczba luk, najwyższa ocena CVSS, ocena EPSS (statystyczna szansa wykorzystania w ciągu 30 dni) i znacznik **KEV**, jeśli luka jest w katalogu CISA aktywnie wykorzystywanych podatności.
5. Pakiety MSIX/Microsoft Store są pomijane: numer wersji pakietu nie odpowiada wersji programu, a takie pakiety aktualizuje Sklep.

Ograniczenia i wydajność:

- Bez klucza API NVD przyjmuje 5 zapytań na 30 s, więc pierwsze sprawdzenie wszystkich programów może potrwać kilkanaście minut.
- Bezpłatny [klucz API](https://nvd.nist.gov/developers/request-an-api-key) zwiększa limit do 50 zapytań. Klucz podaje się w zmiennej środowiskowej `NVD_API_KEY` albo w `settings.json` (klucz `NvdApiKey`).
- Wyniki są zapamiętywane na 24 godz., a dopasowania CPE na 30 dni (`%LOCALAPPDATA%\BezpiecznyAktualizator\Cache`).

**Dodatkowe źródła:** FIRST EPSS uzupełnia CVE o wynik prawdopodobieństwa wykorzystania (nie jest to potwierdzenie ataku). OSV jest odpytywane tylko wtedy, gdy metadane pakietu wskazują dokładny adres `https://github.com/<właściciel>/<repozytorium>`; szczegóły pokazują to repozytorium i umiarkowaną pewność dopasowania. Brak wyniku OSV nie zastępuje NVD ani nie oznacza braku luk. Błędy usług zewnętrznych są widoczne w szczegółach i dzienniku.

**Wsparcie — [endoflife.date](https://endoflife.date) (MIT):**

- **Nieobsługiwany (EOL)** — cykl wydawniczy zainstalowanej wersji (np. Python 3.8, .NET Core 3.1) nie otrzymuje już poprawek. Wiersz jest żółty, a szczegóły podają datę końca wsparcia i nowszą wspieraną wersję.
  - Wsparcie rozszerzone (np. Java 8) liczy się jako wspierane do końca tego wsparcia.
  - Wersja, której wsparcie skończyło się niedawno (do 60 dni) w związku z wydaniem następcy (np. Firefox), nie jest oznaczana jako EOL. Wystarczy zwykła aktualizacja.
- **Porzucony** — repozytorium GitHub projektu jest zarchiwizowane lub nieaktywne od ponad 3 lat, albo ostatnie wydanie w winget jest starsze niż 3 lata.

## Skanowanie instalatora programem Microsoft Defender i ESET

Przy włączonej opcji **Sprawdzaj pliki kontrolne przed instalacją** pobrany instalator jest skanowany programem Microsoft Defender poleceniem `MpCmdRun.exe -Scan -ScanType 3 -File <plik> -DisableRemediation`. Jeśli Defender jest niedostępny, program używa skanera ESET tylko przy aktywnym produkcie zarejestrowanym w Zabezpieczeniach Windows i prawidłowym podpisie ESET pliku `ecls.exe`. Skan ESET używa `/clean-mode=none` i `/no-subdir`, więc skanuje wyłącznie wskazany plik bez automatycznego czyszczenia. Działa to także w harmonogramie cichych aktualizacji i przy wycofywaniu aktualizacji. Instalator jest uznany za przeskanowany tylko po czystym wyniku jednego ze skanerów; brak/awaria skanera nie oznacza czystego wyniku.

| Wynik | Działanie |
|---|---|
| Wykryto zagrożenie | instalacja jest **blokowana** (także w trybie cichym); Defender podaje nazwę zagrożenia, ESET kod wyniku |
| Brak zagrożeń | instalacja może być kontynuowana |
| Defender niedostępny | jeśli ESET nie jest aktywny lub jego skaner nie przejdzie kontroli podpisu, w oknie programu instalacja jest **wstrzymywana** do wyraźnej decyzji użytkownika (domyślny przycisk to „Nie”). W harmonogramie pakiet jest **pomijany**, chyba że w ustawieniach harmonogramu zaznaczono „Instaluj także wtedy, gdy Microsoft Defender jest niedostępny”. Każda decyzja trafia do dziennika |

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

Przed aktualizacją samego Bezpiecznego Aktualizatora tworzony jest punkt przywracania Windows (gdy globalne ustawienie kopii jest włączone) oraz weryfikowana kopia jego ustawień, historii i stanu harmonogramu w `%LOCALAPPDATA%\BezpiecznyAktualizator\Backups` (maksymalnie 10 archiwów z manifestem SHA-256). Z menu głównego można wybrać **Przywróć kopię ustawień...**: aplikacja weryfikuje archiwum, tworzy kopię bieżącego stanu, zachowuje aktualny klucz API NVD i po przywróceniu zaleca ponowne uruchomienie. Klucz API NVD nie jest zapisywany w kopii. To kopia danych aktualizatora, nie programów zewnętrznych; nie przywraca danych użytkownika ani nie zastępuje punktu przywracania Windows.

**Eksport i diagnostyka:** przycisk **Eksportuj raport** zapisuje CSV/JSON albo czytelny, wielostronicowy PDF. Menu nagłówka zawiera **Historia ostrzeżeń i błędów...**, która przegląda bieżący syslog i archiwa. Konfiguracja **Powiadomienia...** pozwala włączyć e-mail przez SMTP/TLS lub webhook Teams; URL webhooka i hasło SMTP są szyfrowane DPAPI dla bieżącego konta Windows, a dziennik nie zapisuje ich wartości.

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
│  │  ├─ Agent/         LocalAgentClient.cs         (lokalny agent AI: API zgodne z OpenAI, tylko localhost)
│  │  ├─ Profiles/      UserProfiles.cs, ProfilePackage.cs, ProfilePackageCrypto.cs (kopia i migracja profilu użytkownika)
│  │  ├─ Inventory/     SoftwareInventory.cs        (rejestr Uninstall)
│  │  ├─ Winget/        WingetClient.cs             (CLI winget, parsowanie wyników)
│  │  ├─ Catalogs/      CatalogClient.cs            (Scoop Main, Chocolatey Community)
│  │  ├─ Security/      Assessment.cs, SoftwareAssessor.cs,
│  │  │              InstallerVerifier.cs, ChecksumFiles.cs, Authenticode.cs (pliki kontrolne, podpis),
│  │  │              DefenderScanner.cs (skanowanie MpCmdRun)
│  │  ├─ Risk/          NvdClient.cs (NVD), OsvClient.cs (dokładne repozytorium GitHub), EpssClient.cs (FIRST EPSS),
│  │  │                 LifecycleClient.cs (EOL / porzucone), RiskModels.cs
│  │  ├─ History/       UpdateHistory.cs            (historia aktualizacji i wycofania)
│  │  └─ Drivers/       DriverModels.cs, DriverInventory.cs (WMI),
│  │                    WindowsUpdateDrivers.cs (WUA COM + instalacja z UAC), DriverAssessor.cs
│  └─ BezpiecznyAktualizator/            # aplikacja WPF
│     ├─ App.xaml(.cs)                   # motyw Fluent i wspólne style, tryby bez okna --install-drivers <katalog> i --scheduled
│     ├─ MainWindow.xaml                 # nagłówek, pasek informacyjny, zakładki „Oprogramowanie” i „Sterowniki”
│     ├─ Views/         SoftwareView, DriversView, ProfileBackupView, SearchWindow, ScheduleWindow, HistoryWindow, NotificationWindow, LocalAgentWindow, LogHistoryWindow,
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

- Projekt jest udostępniany na warunkach licencji [MIT](../LICENSE). Paczki instalacyjna, przenośna i MSI zawierają licencję projektu oraz informacje o licencjach użytych zależności; wydania .NET zawierają także pliki licencyjne pobrane z użytego SDK.
- [.NET](https://github.com/dotnet/runtime) i [WPF](https://github.com/dotnet/wpf) (MIT), w tym motyw Fluent (`PresentationFramework.Fluent`)
- [winget-cli](https://github.com/microsoft/winget-cli) i [winget-pkgs](https://github.com/microsoft/winget-pkgs) (MIT)
- [Scoop Main](https://github.com/ScoopInstaller/Main) (Unlicense / licencje manifestów)
- [xUnit](https://github.com/xunit/xunit) (Apache-2.0)
- [System.Management](https://www.nuget.org/packages/System.Management) (MIT)
- [PDFsharp](https://github.com/empira/PDFsharp) (MIT) – raport PDF
- [Obfuscar](https://github.com/obfuscar/obfuscar) (MIT) – zaciemnianie kodu w wydaniu chronionym (tylko podczas budowania)
- [WiX Toolset](https://github.com/wixtoolset/wix) 6.0.2 (narzędzie wyłącznie do budowania MSI, nie jest dołączane do aplikacji; kod źródłowy jest na MS-RL, a warunki dystrybucji binariów i opłat utrzymaniowych określają aktualne dokumenty WiX, w tym OSMFEULA)
- Dane: [NVD API 2.0](https://nvd.nist.gov/developers) (NIST, domena publiczna), [FIRST EPSS](https://www.first.org/epss/), [OSV](https://osv.dev), [katalog CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (przez NVD), [endoflife.date](https://github.com/endoflife-date/endoflife.date) (MIT)
