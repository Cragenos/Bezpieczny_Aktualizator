#Requires -Version 5.1
<#
.SYNOPSIS
    Buduje podpisaną paczkę instalacyjną Bezpiecznego Aktualizatora z dołączonym instalatorem .NET Desktop Runtime.

.DESCRIPTION
    1. Publikuje aplikację jako pojedynczy plik .exe zależny od frameworka (.NET 10 Desktop Runtime)
       w wersji chronionej: zaciemnianie kodu (Obfuscar), szyfrowanie napisów, kontrola integralności
       (podpis i odcisk certyfikatu wydawcy wbudowany w program) oraz wykrywanie debugera.
    2. Pobiera oficjalny instalator .NET Desktop Runtime na podstawie metadanych wydań Microsoft
       i weryfikuje jego sumę SHA512 oraz podpis Authenticode firmy Microsoft.
    3. Podpisuje aplikację i skrypty instalacyjne certyfikatem do podpisywania kodu (Authenticode, SHA256,
       znacznik czasu RFC 3161). Domyślnie używa certyfikatu własnego (self-signed) z magazynu bieżącego
       użytkownika i tworzy go przy pierwszym uruchomieniu. Można też podać certyfikat komercyjny (-PfxPath)
       lub wskazać certyfikat z magazynu (-CertThumbprint).
    4. Tworzy sumy kontrolne SHA256 i archiwum ZIP w katalogu dist.
    5. Tworzy osobną paczkę przenośną: jeden samodzielny plik .exe (z wbudowanym środowiskiem .NET,
       bez instalacji), również chroniony i podpisany.

.EXAMPLE
    .\Build-Package.ps1
.EXAMPLE
    .\Build-Package.ps1 -PfxPath C:\certs\firma.pfx -PfxPassword (Read-Host -AsSecureString)
#>
[CmdletBinding(DefaultParameterSetName = 'SelfSigned')]
param(
    [Parameter(ParameterSetName = 'Pfx', Mandatory)] [string]$PfxPath,
    [Parameter(ParameterSetName = 'Pfx')] [SecureString]$PfxPassword,
    [Parameter(ParameterSetName = 'Store', Mandatory)] [string]$CertThumbprint,
    [string]$Configuration = 'Release',
    [string]$UpdateRepository,
    [switch]$NoZip,
    # Wydanie bez zaciemniania i kontroli integralności (np. do diagnozowania błędów).
    [switch]$NoProtect,
    [switch]$NoPortable
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$Root = Split-Path $PSScriptRoot -Parent
$Version = (Select-Xml -Path (Join-Path $Root 'Directory.Build.props') -XPath '//Version').Node.InnerText
$ConfiguredUpdateRepository = (Select-Xml -Path (Join-Path $Root 'Directory.Build.props') -XPath '//UpdateRepository').Node.InnerText
if ([string]::IsNullOrWhiteSpace($UpdateRepository)) { $UpdateRepository = $ConfiguredUpdateRepository }
if (-not [string]::IsNullOrWhiteSpace($UpdateRepository) -and $UpdateRepository -notmatch '^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$') {
    throw 'UpdateRepository musi mieć format GitHub owner/name.'
}
$PackageName = "BezpiecznyAktualizator-$Version-win-x64"
$Dist = Join-Path $Root 'dist'
$Stage = Join-Path $Dist $PackageName
$Cache = Join-Path $Dist 'cache'
$RuntimeMajor = '10.0'
$SelfSignedSubject = 'CN=Bezpieczny Aktualizator Code Signing'
$TimestampUrls = @(
    'http://timestamp.digicert.com',
    'http://timestamp.sectigo.com',
    'http://timestamp.globalsign.com/tsa/r6advanced1'
)
$Utf8Bom = New-Object System.Text.UTF8Encoding($true)

function Write-Step([string]$Message) { Write-Host "==> $Message" -ForegroundColor Cyan }

# Antywirusy (np. ESET) blokują świeżo zapisane pliki wykonywalne i skrypty na czas skanowania.
function Wait-FileReady([string[]]$Paths, [int]$TimeoutSec = 300) {
    foreach ($path in $Paths) {
        $deadline = (Get-Date).AddSeconds($TimeoutSec)
        while ($true) {
            try { [IO.File]::Open($path, 'Open', 'Read', 'Read').Dispose(); break }
            catch {
                if ((Get-Date) -gt $deadline) { throw "Plik jest zablokowany (antywirus?): $path" }
                Start-Sleep -Seconds 3
            }
        }
    }
}

function Get-DotnetExe {
    $local = Join-Path $env:LOCALAPPDATA 'Microsoft\dotnet\dotnet.exe'
    if (Test-Path $local) { $env:DOTNET_ROOT = Split-Path $local; return $local }
    $cmd = Get-Command dotnet -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    throw 'Nie znaleziono .NET SDK (dotnet.exe).'
}

function Get-SignTool {
    $cmd = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $kits = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
    $found = Get-ChildItem $kits -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
        Where-Object { $_.Directory.Name -eq 'x64' } |
        Sort-Object { $_.Directory.Parent.Name } -Descending |
        Select-Object -First 1
    if ($found) { return $found.FullName }
    throw 'Nie znaleziono signtool.exe. Zainstaluj Windows SDK (składnik "Signing Tools for Desktop Apps").'
}

function Get-SigningCertificate([string]$Mode) {
    switch ($Mode) {
        'Pfx' {
            $plain = ''
            if ($PfxPassword) {
                $plain = [Runtime.InteropServices.Marshal]::PtrToStringUni(
                    [Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($PfxPassword))
            }
            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($PfxPath, $plain)
            return @{ Cert = $cert; SignArgs = @('/f', $PfxPath, '/p', $plain) }
        }
        'Store' {
            $cert = Get-ChildItem Cert:\CurrentUser\My, Cert:\LocalMachine\My |
                Where-Object Thumbprint -eq $CertThumbprint | Select-Object -First 1
            if (-not $cert) { throw "Nie znaleziono certyfikatu o odcisku $CertThumbprint." }
            $storeArgs = @()
            if ($cert.PSParentPath -like '*LocalMachine*') { $storeArgs = @('/sm') }
            return @{ Cert = $cert; SignArgs = $storeArgs + @('/sha1', $cert.Thumbprint) }
        }
        default {
            $cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert |
                Where-Object { $_.Subject -eq $SelfSignedSubject -and $_.HasPrivateKey -and $_.NotAfter -gt (Get-Date).AddDays(30) } |
                Sort-Object NotAfter -Descending | Select-Object -First 1
            if (-not $cert) {
                Write-Host '    Tworzę nowy certyfikat do podpisywania kodu (self-signed, RSA 3072, 5 lat)...'
                $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject $SelfSignedSubject `
                    -FriendlyName 'Bezpieczny Aktualizator - podpis kodu' `
                    -CertStoreLocation Cert:\CurrentUser\My -KeyAlgorithm RSA -KeyLength 3072 `
                    -HashAlgorithm SHA256 -KeyExportPolicy NonExportable -NotAfter (Get-Date).AddYears(5)
            }
            return @{ Cert = $cert; SignArgs = @('/sha1', $cert.Thumbprint) }
        }
    }
}

function Invoke-Sign([string]$SignTool, [string[]]$SignArgs, [string[]]$Files) {
    foreach ($ts in $TimestampUrls) {
        $all = @('sign', '/fd', 'SHA256', '/tr', $ts, '/td', 'SHA256', '/d', 'Bezpieczny Aktualizator') + $SignArgs + $Files
        $out = & $SignTool @all 2>&1
        if ($LASTEXITCODE -eq 0) { Write-Host "    Podpisano (znacznik czasu: $ts)."; return }
        Write-Warning "Podpisywanie z serwerem znaczników czasu $ts nie powiodło się: $($out | Select-Object -Last 2)"
    }
    throw 'Nie udało się podpisać plików.'
}

function Assert-OwnSignature([string]$Path, [string]$Thumbprint) {
    Wait-FileReady $Path
    $sig = Get-AuthenticodeSignature -FilePath $Path
    if (-not $sig.SignerCertificate -or $sig.SignerCertificate.Thumbprint -ne $Thumbprint -or
        $sig.Status -in 'HashMismatch', 'NotSigned', 'NotSupportedFileFormat') {
        throw "Weryfikacja podpisu nie powiodła się: $Path ($($sig.Status))"
    }
    if (-not $sig.TimeStamperCertificate) { throw "Brak znacznika czasu w podpisie: $Path" }
}

function Get-DesktopRuntimeInstaller {
    $metaUrl = "https://builds.dotnet.microsoft.com/dotnet/release-metadata/$RuntimeMajor/releases.json"
    $meta = Invoke-RestMethod -Uri $metaUrl
    $release = $meta.releases | Where-Object { $_.windowsdesktop.version -eq $meta.'latest-runtime' } | Select-Object -First 1
    if (-not $release) { throw "Brak wydania $($meta.'latest-runtime') w metadanych." }
    $file = $release.windowsdesktop.files | Where-Object name -eq 'windowsdesktop-runtime-win-x64.exe'
    $uri = [Uri]$file.url
    if ($uri.Scheme -ne 'https' -or $uri.Host -notmatch '(^|\.)(dotnet\.microsoft\.com|download\.visualstudio\.microsoft\.com)$') {
        throw "Niezaufany adres pobierania: $uri"
    }
    $fileName = Split-Path $uri.AbsolutePath -Leaf
    $target = Join-Path $Cache $fileName
    $expected = $file.hash.ToLowerInvariant()

    if (-not (Test-Path $target) -or (Get-FileHash $target -Algorithm SHA512).Hash.ToLowerInvariant() -ne $expected) {
        Write-Host "    Pobieranie $uri"
        Invoke-WebRequest -Uri $uri -OutFile $target -UseBasicParsing
    }
    $actual = (Get-FileHash $target -Algorithm SHA512).Hash.ToLowerInvariant()
    if ($actual -ne $expected) { Remove-Item $target -Force; throw 'Suma SHA512 instalatora .NET jest niezgodna z metadanymi Microsoft.' }

    $sig = Get-AuthenticodeSignature -FilePath $target
    if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
        throw "Instalator .NET nie ma prawidłowego podpisu Microsoft ($($sig.Status))."
    }
    Write-Host "    .NET Desktop Runtime $($release.windowsdesktop.version): SHA512 OK, podpis Microsoft OK."
    return [pscustomobject]@{
        version = $release.windowsdesktop.version
        file    = $fileName
        sha512  = $expected
        url     = $uri.AbsoluteUri
        path    = $target
    }
}

function Copy-Script([string]$Source, [string]$Destination) {
    $text = [IO.File]::ReadAllText($Source)
    [IO.File]::WriteAllText($Destination, $text, $Utf8Bom)
}

function Publish-App([string]$Output, [bool]$SelfContained) {
    $publishArgs = @('publish', (Join-Path $Root 'src\BezpiecznyAktualizator'), '-c', $Configuration, '-r', 'win-x64',
        '--self-contained', $SelfContained.ToString().ToLowerInvariant(), '-p:PublishSingleFile=true', '-p:DebugType=none', '-o', $Output)
    if ($SelfContained) { $publishArgs += '-p:IncludeNativeLibrariesForSelfExtract=true' }
    if (-not $NoProtect) { $publishArgs += @('-p:Protect=true', "-p:SignerThumbprint=$($cert.Thumbprint)") }
    if (-not [string]::IsNullOrWhiteSpace($UpdateRepository)) { $publishArgs += "-p:UpdateRepository=$UpdateRepository" }
    & $dotnet @publishArgs
    if ($LASTEXITCODE -ne 0) { throw 'dotnet publish zakończył się błędem.' }
    $extra = Get-ChildItem $Output -File | Where-Object Name -ne 'BezpiecznyAktualizator.exe'
    if ($extra) { throw "Nieoczekiwane pliki w publikacji: $($extra.Name -join ', ')" }
}

function Write-Checksums([string]$Dir) {
    $lines = Get-ChildItem $Dir -Recurse -File | Where-Object Name -ne 'SHA256SUMS.txt' | Sort-Object FullName | ForEach-Object {
        $rel = $_.FullName.Substring($Dir.Length + 1)
        Wait-FileReady $_.FullName
        '{0} *{1}' -f (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant(), $rel
    }
    [IO.File]::WriteAllLines((Join-Path $Dir 'SHA256SUMS.txt'), [string[]]$lines, $Utf8Bom)
}

function New-Zip([string]$Dir, [string]$Name) {
    $zip = Join-Path $Dist "$Name.zip"
    if (Test-Path $zip) { Remove-Item $zip -Force }
    Wait-FileReady (Get-ChildItem $Dir -Recurse -File).FullName
    Compress-Archive -Path "$Dir\*" -DestinationPath $zip -CompressionLevel Optimal
    $zipHash = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLowerInvariant()
    [IO.File]::WriteAllText("$zip.sha256", "$zipHash *$Name.zip`r`n", $Utf8Bom)
    Write-Host "    $zip ($([math]::Round((Get-Item $zip).Length / 1MB, 1)) MB)"
    Write-Host "    SHA256: $zipHash"
}

# ---------------------------------------------------------------------------

$dotnet = Get-DotnetExe
$signTool = Get-SignTool
$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'; $env:DOTNET_NOLOGO = '1'

Write-Step "Przygotowanie katalogu $Stage"
if (Test-Path $Stage) { Remove-Item $Stage -Recurse -Force }
foreach ($d in $Stage, $Cache, "$Stage\app", "$Stage\dotnet", "$Stage\cert") { New-Item -ItemType Directory $d -Force | Out-Null }

# Certyfikat jest potrzebny przed publikacją: jego odcisk zostaje wbudowany w program (kontrola integralności).
Write-Step 'Certyfikat do podpisywania kodu'
$signing = Get-SigningCertificate $PSCmdlet.ParameterSetName
$cert = $signing.Cert
Write-Host "    $($cert.Subject)  odcisk: $($cert.Thumbprint)  ważny do: $($cert.NotAfter.ToString('yyyy-MM-dd'))"
$certBytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
[IO.File]::WriteAllBytes((Join-Path $Stage 'cert\BezpiecznyAktualizator.cer'), $certBytes)

$protection = if ($NoProtect) { 'bez ochrony' } else { 'wersja chroniona: zaciemnianie kodu, kontrola integralności' }
Write-Step "Publikacja aplikacji (pojedynczy plik, zależny od .NET Desktop Runtime; $protection)"
Publish-App "$Stage\app" $false

Write-Step 'Instalator .NET Desktop Runtime'
$runtime = Get-DesktopRuntimeInstaller
Copy-Item $runtime.path (Join-Path $Stage "dotnet\$($runtime.file)")
$runtimeJson = $runtime | Select-Object version, file, sha512, url | ConvertTo-Json
[IO.File]::WriteAllText((Join-Path $Stage 'runtime.json'), $runtimeJson, $Utf8Bom)

Write-Step 'Kopiowanie skryptów instalacyjnych'
Copy-Script (Join-Path $PSScriptRoot 'Install.ps1') (Join-Path $Stage 'Install.ps1')
Copy-Script (Join-Path $PSScriptRoot 'Uninstall.ps1') (Join-Path $Stage 'app\Uninstall.ps1')
Copy-Item (Join-Path $PSScriptRoot 'Instaluj.cmd') $Stage
Copy-Script (Join-Path $PSScriptRoot 'INSTRUKCJA.txt') (Join-Path $Stage 'INSTRUKCJA.txt')

Write-Step 'Podpisywanie (Authenticode SHA256 + znacznik czasu)'
$toSign = @(
    (Join-Path $Stage 'app\BezpiecznyAktualizator.exe'),
    (Join-Path $Stage 'app\Uninstall.ps1'),
    (Join-Path $Stage 'Install.ps1')
)
Wait-FileReady $toSign
Invoke-Sign $signTool $signing.SignArgs $toSign
foreach ($f in $toSign) { Assert-OwnSignature $f $cert.Thumbprint }

Write-Step 'Sumy kontrolne SHA256'
Write-Checksums $Stage

if (-not $NoZip) {
    Write-Step 'Archiwum ZIP'
    New-Zip $Stage $PackageName
}

$PortableName = "BezpiecznyAktualizator-$Version-portable-win-x64"
$Portable = Join-Path $Dist $PortableName
$portableBuild = Join-Path $Dist 'portable-build'
if (Test-Path $portableBuild) { Remove-Item $portableBuild -Recurse -Force }
Write-Step 'Publikacja samodzielnego pliku .NET (wspólne źródło paczki przenośnej i MSI)'
Publish-App $portableBuild $true
$msiSourceExe = Join-Path $portableBuild 'BezpiecznyAktualizator.exe'
Wait-FileReady $msiSourceExe
Invoke-Sign $signTool $signing.SignArgs @($msiSourceExe)
Assert-OwnSignature $msiSourceExe $cert.Thumbprint

if (-not $NoPortable) {
    Write-Step "Paczka przenośna $Portable (samodzielny plik .exe z wbudowanym .NET, bez instalacji)"
    if (Test-Path $Portable) { Remove-Item $Portable -Recurse -Force }
    foreach ($d in $Portable, "$Portable\cert") { New-Item -ItemType Directory $d -Force | Out-Null }
    Copy-Item $msiSourceExe (Join-Path $Portable 'BezpiecznyAktualizator.exe')
    [IO.File]::WriteAllBytes((Join-Path $Portable 'cert\BezpiecznyAktualizator.cer'), $certBytes)
    Copy-Script (Join-Path $PSScriptRoot 'CZYTAJ-PRZENOSNA.txt') (Join-Path $Portable 'CZYTAJ.txt')
    Copy-Script (Join-Path $PSScriptRoot 'INSTRUKCJA.txt') (Join-Path $Portable 'INSTRUKCJA.txt')
    Write-Checksums $Portable
    if (-not $NoZip) { New-Zip $Portable $PortableName }
}

Write-Step 'Budowanie instalatora MSI (WiX Toolset)'
$msiName = "BezpiecznyAktualizator-$Version-win-x64.msi"
$msiBuild = Join-Path $Dist 'msi-build'
if (Test-Path $msiBuild) { Remove-Item $msiBuild -Recurse -Force }
$msiOutput = Join-Path $msiBuild 'out'
$msiIntermediate = Join-Path $msiBuild 'obj'
foreach ($dir in $msiOutput, $msiIntermediate) { New-Item -ItemType Directory $dir -Force | Out-Null }
$wixProject = Join-Path $PSScriptRoot 'msi\BezpiecznyAktualizator.wixproj'
& $dotnet build $wixProject -c $Configuration -p:Platform=x64 "-p:PackageVersion=$Version" `
    "-p:AppExePath=$msiSourceExe" "-p:CertificatePath=$(Join-Path $Stage 'cert\BezpiecznyAktualizator.cer')" `
    "-p:OutputPath=$msiOutput\" "-p:IntermediateOutputPath=$msiIntermediate\"
if ($LASTEXITCODE -ne 0) { throw 'Budowanie instalatora MSI przez WiX zakończyło się błędem.' }
$builtMsi = Get-ChildItem $msiBuild -Filter '*.msi' -Recurse | Select-Object -First 1
if (-not $builtMsi) { throw "WiX nie utworzył pliku MSI w katalogu $msiBuild." }
$publishedMsi = Join-Path $Dist $msiName
Copy-Item $builtMsi.FullName $publishedMsi -Force
Wait-FileReady $publishedMsi
Invoke-Sign $signTool $signing.SignArgs @($publishedMsi)
Assert-OwnSignature $publishedMsi $cert.Thumbprint
$msiHash = (Get-FileHash $publishedMsi -Algorithm SHA256).Hash.ToLowerInvariant()
[IO.File]::WriteAllText("$publishedMsi.sha256", "$msiHash *$msiName`r`n", $Utf8Bom)
Remove-Item $portableBuild -Recurse -Force
Remove-Item $msiBuild -Recurse -Force
Write-Host "    $publishedMsi ($([math]::Round((Get-Item $publishedMsi).Length / 1MB, 1)) MB)"
Write-Host "    SHA256: $msiHash"

Write-Host ''
Write-Host "Gotowe: $Stage" -ForegroundColor Green
if ($cert.Subject -eq $cert.Issuer) {
    Write-Host 'Uwaga: certyfikat jest własny (self-signed). Instalator może dodać go do zaufanych na komputerze docelowym.' -ForegroundColor Yellow
}
