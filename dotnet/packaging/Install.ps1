#Requires -Version 5.1
<#
.SYNOPSIS
    Instaluje Bezpieczny Aktualizator wraz z .NET Desktop Runtime (jeśli go brakuje).

.PARAMETER VerifyOnly
    Tylko sprawdza integralność paczki, podpisy i obecność .NET. Nic nie instaluje i nie wymaga uprawnień administratora.
.PARAMETER TrustCertificate
    Ask (domyślnie) / Yes / No - czy dodać własny (self-signed) certyfikat wydawcy do zaufanych na tym komputerze.
.PARAMETER DesktopShortcut
    Tworzy też skrót na pulpicie publicznym.
#>
[CmdletBinding()]
param(
    [switch]$VerifyOnly,
    [ValidateSet('Ask', 'Yes', 'No')] [string]$TrustCertificate = 'Ask',
    [switch]$DesktopShortcut,
    [string]$InstallDir = (Join-Path $env:ProgramFiles 'Bezpieczny Aktualizator'),
    [switch]$Elevated
)

$ErrorActionPreference = 'Stop'
$Pkg = $PSScriptRoot
$AppName = 'Bezpieczny Aktualizator'
$ExeName = 'BezpiecznyAktualizator.exe'
$RuntimeMajor = 10
$UninstallKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\BezpiecznyAktualizator'
$StartMenuLnk = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\$AppName.lnk"
$DesktopLnk = Join-Path $env:PUBLIC "Desktop\$AppName.lnk"

function Write-Step([string]$m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Write-Ok([string]$m) { Write-Host "    $m" -ForegroundColor Green }
function Write-Note([string]$m) { Write-Host "    $m" -ForegroundColor Yellow }

# Antywirus może chwilowo blokować świeżo rozpakowane pliki na czas skanowania.
function Wait-FileReady([string]$Path, [int]$TimeoutSec = 180) {
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ($true) {
        try { [IO.File]::Open($Path, 'Open', 'Read', 'Read').Dispose(); return }
        catch {
            if ((Get-Date) -gt $deadline) { throw "Plik jest zablokowany (antywirus?): $Path" }
            Start-Sleep -Seconds 2
        }
    }
}
function Test-Admin {
    $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-PackageIntegrity {
    $sums = Join-Path $Pkg 'SHA256SUMS.txt'
    if (-not (Test-Path $sums)) { throw 'Brak pliku SHA256SUMS.txt - paczka jest niekompletna.' }
    $count = 0
    foreach ($line in Get-Content $sums -Encoding UTF8) {
        if (-not $line.Trim()) { continue }
        $parts = $line -split ' \*', 2
        if ($parts.Count -ne 2 -or $parts[1] -match '\.\.|^[\\/]|:') { throw "Nieprawidłowy wpis w SHA256SUMS.txt: $line" }
        $file = Join-Path $Pkg $parts[1]
        if (-not (Test-Path $file)) { throw "Brak pliku w paczce: $($parts[1])" }
        Wait-FileReady $file
        if ((Get-FileHash $file -Algorithm SHA256).Hash -ne $parts[0]) { throw "Plik został zmieniony lub uszkodzony: $($parts[1])" }
        $count++
    }
    Write-Ok "Sumy SHA256 zgodne ($count plików)."
}

function Get-PublisherCertificate {
    $path = Join-Path $Pkg 'cert\BezpiecznyAktualizator.cer'
    return New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($path)
}

function Test-OwnSignature([string]$Path, $Cert) {
    $sig = Get-AuthenticodeSignature -FilePath $Path
    if (-not $sig.SignerCertificate -or $sig.SignerCertificate.Thumbprint -ne $Cert.Thumbprint) {
        throw "Plik $Path nie jest podpisany certyfikatem wydawcy z paczki ($($sig.Status))."
    }
    if ($sig.Status -eq 'Valid') { return 'zaufany' }
    if ($sig.Status -eq 'UnknownError' -or $sig.Status -eq 'NotTrusted') { return 'poprawny, certyfikat jeszcze niezaufany' }
    throw "Podpis pliku $Path jest nieprawidłowy ($($sig.Status))."
}

function Get-RuntimeInfo {
    $info = Get-Content (Join-Path $Pkg 'runtime.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    $info | Add-Member -NotePropertyName path -NotePropertyValue (Join-Path $Pkg "dotnet\$($info.file)")
    return $info
}

function Test-RuntimeInstaller($Runtime) {
    if ((Get-FileHash $Runtime.path -Algorithm SHA512).Hash.ToLowerInvariant() -ne $Runtime.sha512) {
        throw 'Suma SHA512 instalatora .NET nie zgadza się z wartością opublikowaną przez Microsoft.'
    }
    $sig = Get-AuthenticodeSignature -FilePath $Runtime.path
    if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
        throw "Instalator .NET nie ma prawidłowego podpisu Microsoft ($($sig.Status))."
    }
    Write-Ok "Instalator .NET Desktop Runtime $($Runtime.version): SHA512 i podpis Microsoft poprawne."
}

function Get-InstalledDesktopRuntime {
    $dir = Join-Path $env:ProgramFiles 'dotnet\shared\Microsoft.WindowsDesktop.App'
    if (-not (Test-Path $dir)) { return $null }
    return Get-ChildItem $dir -Directory | Where-Object { $_.Name -match "^$RuntimeMajor\.\d+\.\d+" } |
        Sort-Object { [version]($_.Name -replace '-.*$', '') } -Descending | Select-Object -First 1 -ExpandProperty Name
}

function Read-YesNo([string]$Question) {
    while ($true) {
        $a = (Read-Host "$Question [T/N]").Trim().ToUpperInvariant()
        if ($a -in 'T', 'TAK', 'Y', 'YES') { return $true }
        if ($a -in 'N', 'NIE', 'NO') { return $false }
    }
}

function New-Shortcut([string]$Path, [string]$Target) {
    $shell = New-Object -ComObject WScript.Shell
    $lnk = $shell.CreateShortcut($Path)
    $lnk.TargetPath = $Target
    $lnk.WorkingDirectory = Split-Path $Target
    $lnk.IconLocation = "$Target,0"
    $lnk.Description = $AppName
    $lnk.Save()
}

# ---------------------------------------------------------------------------

try {
    Write-Host "$AppName - instalator" -ForegroundColor White
    Write-Step 'Weryfikacja paczki'
    Test-PackageIntegrity
    $cert = Get-PublisherCertificate
    $selfSigned = $cert.Subject -eq $cert.Issuer
    Write-Ok "Wydawca: $($cert.Subject)  (odcisk $($cert.Thumbprint))"
    foreach ($f in (Join-Path $Pkg "app\$ExeName"), (Join-Path $Pkg 'app\Uninstall.ps1')) {
        Write-Ok "Podpis $(Split-Path $f -Leaf): $(Test-OwnSignature $f $cert)"
    }
    $runtime = Get-RuntimeInfo
    Test-RuntimeInstaller $runtime

    $installed = Get-InstalledDesktopRuntime
    if ($installed) { Write-Ok ".NET Desktop Runtime $installed jest już zainstalowany." }
    else { Write-Note ".NET Desktop Runtime $RuntimeMajor nie jest zainstalowany - zostanie zainstalowany z paczki." }

    if ($VerifyOnly) {
        Write-Host ''
        Write-Host 'Weryfikacja zakończona pomyślnie (tryb -VerifyOnly, nic nie zainstalowano).' -ForegroundColor Green
        exit 0
    }

    if (-not (Test-Admin)) {
        Write-Step 'Wymagane uprawnienia administratora - uruchamiam ponownie (UAC)...'
        $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"",
            '-TrustCertificate', $TrustCertificate, '-InstallDir', "`"$InstallDir`"", '-Elevated')
        if ($DesktopShortcut) { $argList += '-DesktopShortcut' }
        $p = Start-Process powershell.exe -Verb RunAs -ArgumentList $argList -Wait -PassThru
        exit $p.ExitCode
    }

    if (-not $installed) {
        Write-Step "Instalacja .NET Desktop Runtime $($runtime.version)"
        $p = Start-Process -FilePath $runtime.path -ArgumentList '/install', '/quiet', '/norestart' -Wait -PassThru
        switch ($p.ExitCode) {
            0 { Write-Ok 'Zainstalowano.' }
            { $_ -in 1641, 3010 } { Write-Note 'Zainstalowano. Wymagane ponowne uruchomienie komputera.' }
            default { throw "Instalator .NET zakończył się kodem $($p.ExitCode)." }
        }
        if (-not (Get-InstalledDesktopRuntime)) { throw '.NET Desktop Runtime nadal nie jest wykrywany.' }
    }

    if ($selfSigned) {
        Write-Step 'Certyfikat wydawcy'
        $trusted = Test-Path "Cert:\LocalMachine\TrustedPublisher\$($cert.Thumbprint)"
        if ($trusted) { Write-Ok 'Certyfikat jest już zaufany na tym komputerze.' }
        else {
            $doTrust = $TrustCertificate -eq 'Yes'
            if ($TrustCertificate -eq 'Ask') {
                Write-Host '    Aplikacja jest podpisana własnym certyfikatem wydawcy (self-signed).'
                Write-Host '    Dodanie go do "Zaufanych głównych urzędów" i "Zaufanych wydawców" sprawi, że Windows'
                Write-Host '    będzie pokazywał podpis jako prawidłowy. Rób to tylko, jeśli ufasz źródłu tej paczki.'
                $doTrust = Read-YesNo '    Dodać certyfikat do zaufanych?'
            }
            if ($doTrust) {
                $cerPath = Join-Path $Pkg 'cert\BezpiecznyAktualizator.cer'
                Import-Certificate -FilePath $cerPath -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
                Import-Certificate -FilePath $cerPath -CertStoreLocation Cert:\LocalMachine\TrustedPublisher | Out-Null
                Write-Ok 'Certyfikat dodany do zaufanych.'
            }
            else { Write-Note 'Pominięto - podpis będzie widoczny jako niezaufany.' }
        }
    }

    Write-Step "Kopiowanie plików do $InstallDir"
    $running = Get-Process -Name ([IO.Path]::GetFileNameWithoutExtension($ExeName)) -ErrorAction SilentlyContinue |
        Where-Object { $_.Path -and $_.Path.StartsWith($InstallDir, [StringComparison]::OrdinalIgnoreCase) }
    if ($running) { throw "Zamknij uruchomioną aplikację $AppName i spróbuj ponownie." }
    New-Item -ItemType Directory $InstallDir -Force | Out-Null
    Copy-Item (Join-Path $Pkg 'app\*') $InstallDir -Recurse -Force
    Copy-Item (Join-Path $Pkg 'cert\BezpiecznyAktualizator.cer') $InstallDir -Force
    foreach ($notice in 'LICENSE', 'THIRD-PARTY-NOTICES.txt', 'DOTNET-LICENSE.txt', 'DOTNET-THIRD-PARTY-NOTICES.txt') {
        Copy-Item (Join-Path $Pkg $notice) $InstallDir -Force
    }
    $exe = Join-Path $InstallDir $ExeName
    Write-Ok "Podpis zainstalowanego pliku: $(Test-OwnSignature $exe $cert)"

    Write-Step 'Skróty i rejestracja w "Aplikacje i funkcje"'
    New-Shortcut $StartMenuLnk $exe
    if ($DesktopShortcut) { New-Shortcut $DesktopLnk $exe }
    $version = (Get-Item $exe).VersionInfo.ProductVersion -replace '\+.*$', ''
    $sizeKb = [int]((Get-ChildItem $InstallDir -Recurse -File | Measure-Object Length -Sum).Sum / 1KB)
    New-Item $UninstallKey -Force | Out-Null
    $props = @{
        DisplayName     = $AppName
        DisplayVersion  = $version
        Publisher       = $AppName
        InstallLocation = $InstallDir
        DisplayIcon     = "$exe,0"
        UninstallString = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$InstallDir\Uninstall.ps1`""
        InstallDate     = (Get-Date).ToString('yyyyMMdd')
    }
    foreach ($k in $props.Keys) { Set-ItemProperty $UninstallKey -Name $k -Value $props[$k] }
    Set-ItemProperty $UninstallKey -Name NoModify -Value 1 -Type DWord
    Set-ItemProperty $UninstallKey -Name NoRepair -Value 1 -Type DWord
    Set-ItemProperty $UninstallKey -Name EstimatedSize -Value $sizeKb -Type DWord
    Write-Ok 'Gotowe.'

    Write-Host ''
    Write-Host "Zainstalowano $AppName $version. Uruchom z menu Start." -ForegroundColor Green
    $exitCode = 0
}
catch {
    Write-Host ''
    Write-Host "BŁĄD: $($_.Exception.Message)" -ForegroundColor Red
    $exitCode = 1
}

if ($Elevated) { Read-Host 'Naciśnij Enter, aby zamknąć' | Out-Null }
exit $exitCode
