# Historia zmian

## 2.1.2 — zmiany względem wydania 2.1.0

### Windows Update i pakiety offline

- Dodano zakładkę Windows Update z wyszukiwaniem aktualizacji dla bieżącego komputera, informacjami o KB i dostępnych identyfikatorach CVE oraz osobnym pobieraniem i instalacją.
- Dodano dokładniejszą korelację numerów KB z danymi Microsoft Security Response Center oraz możliwość uruchomienia instalatora MSU i otwarcia Katalogu Microsoft Update.
- Dodano skanowanie offline z podpisanym katalogiem Microsoft `Wsusscn2.cab` i eksport wyników do JSON. Katalog zawiera metadane aktualizacji zabezpieczeń, a nie instalatory ani wszystkie aktualizacje.
- Dodano tworzenie paczek offline z ręcznie pobranych plików MSU/CAB, podpisanym manifestem, kontrolą SHA-256 i podpisanym instalatorem. Instalacja uwzględnia kolejność, błędy i wznowienie po restarcie.
- Rozszerzono harmonogram o opcjonalne sprawdzanie Windows Update i instalację obowiązkowych aktualizacji z wcześniej zaakceptowaną licencją.

### Microsoft Store

- Dodano oddzielną zakładkę do ręcznego wyszukiwania i instalowania aktualizacji rozpoznanych przez oficjalne źródło `msstore` w WinGet oraz odsyłacz do aktualizacji w Microsoft Store.
- Dodano potwierdzenia, sprawdzanie źródła i zasad, kontrolę zainstalowanej wersji oraz raportowanie niepotwierdzonych wyników. Aktualizacje Store nie są instalowane przez harmonogram.
- WinGet nie wykrywa wszystkich aktualizacji Store, a sam Store może zainstalować wersję nowszą niż wyświetlona. Aktywne wstrzymanie wersji blokuje aktualizację Store w aplikacji.

### Bezpieczeństwo i niezawodność aktualizacji

- WinGet jest wybierany z zarejestrowanego pakietu Microsoft App Installer i sprawdzany pod kątem podpisu Microsoft, zamiast być pobierany z dowolnej ścieżki `PATH`.
- Weryfikacja aktualizacji programów wiąże skanowanie z lokalnym manifestem używanym do instalacji; sprawdza identyfikator, wersję i SHA-256 oraz blokuje niekompletne wyniki. Zależności nie są pobierane jako dodatkowe instalatory.
- Usprawniono obsługę historii aktualizacji: błędy odczytu i zapisu są zgłaszane, a uszkodzona historia nie jest zastępowana pustą listą. Wycofywanie pakietów Store pozostaje niedostępne.
- Poprawiono zamykanie pliku pobranego instalatora własnej aktualizacji oraz dodano sprawdzaną kopię ustawień i historii przed instalacją nowszej wersji MSI.
- Dodano kontrolę certyfikatu, łańcucha zaufania i znacznika czasu dla trybu budowania wydania publicznego oraz opis przygotowania rotacji certyfikatów.

### Informacje o ryzyku, harmonogram i diagnostyka

- Rozszerzono informacje o podatnościach o OSV i FIRST EPSS, obok NVD i katalogu CISA KEV. Dopasowanie OSV wymaga dokładnego repozytorium GitHub; brak wyniku nie oznacza braku luk.
- Dodano okno serwisowe, warunki dotyczące baterii i sieci taryfowej, ponowienia oraz opcjonalne powiadomienia e-mail/Teams. Sekrety powiadomień są zabezpieczane dla bieżącego użytkownika przez DPAPI.
- Dodano historię ostrzeżeń i błędów oraz eksport pakietu diagnostycznego zawierającego ograniczone metadane i ostatnie problemy. Przed udostępnieniem należy sprawdzić jego zawartość.
- Dodano podgląd informacji o wydaniu i opcjonalny kanał wersji testowych. Wersje testowe wymagają ręcznego pobrania i nie są instalowane automatycznie.

### Interfejs, dokumentacja i proces wydań

- Dodano ikonę aplikacji, lepsze komunikaty postępu, eksport raportu PDF i tłumaczenia komunikatów w obsługiwanych językach.
- Uzupełniono instrukcje i dołączono licencję MIT projektu oraz informacje o licencjach zależności do paczek ZIP i MSI.
- Dodano workflow GitHub Actions z testami Python i .NET, audytem NuGet, SBOM CycloneDX oraz testem instalacji i aktualizacji MSI. Osobny, ręczny workflow służy do testów na dedykowanej maszynie Windows.

### Ważne ograniczenia

- Brak danych CVE lub wyników skanowania nie potwierdza braku podatności. Pliki MSU/CAB do paczki offline należy samodzielnie dobrać do systemu docelowego i pobrać z zaufanego źródła.
- Paczki z certyfikatem samopodpisanym nie mają publicznie zaufanego podpisu. Przed publicznym wydaniem wymagane jest zbudowanie i zweryfikowanie paczek z zaufanym certyfikatem podpisywania kodu zgodnie z instrukcją projektu.
- Wersja MSI korzysta z numeru liczbowego: kolejne wydanie po wersji testowej musi mieć wyższy numer, aby zostało wykryte jako aktualizacja.
