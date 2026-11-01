#Requires -Version 5.1
<#
.SYNOPSIS
    Odinstalowuje Bezpieczny Aktualizator. .NET Desktop Runtime pozostaje (mogą go używać inne programy).
.PARAMETER KeepCertificate
    Nie usuwa certyfikatu wydawcy z magazynów zaufanych certyfikatów.
#>
[CmdletBinding()]
param(
    [switch]$KeepCertificate,
    [switch]$Elevated
)

$ErrorActionPreference = 'Stop'
$AppName = 'Bezpieczny Aktualizator'
$InstallDir = $PSScriptRoot
$UninstallKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\BezpiecznyAktualizator'
$Shortcuts = @(
    (Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\$AppName.lnk"),
    (Join-Path $env:PUBLIC "Desktop\$AppName.lnk")
)

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"", '-Elevated')
    if ($KeepCertificate) { $argList += '-KeepCertificate' }
    $p = Start-Process powershell.exe -Verb RunAs -ArgumentList $argList -Wait -PassThru
    exit $p.ExitCode
}

try {
    Set-Location $env:TEMP
    $running = Get-Process -Name BezpiecznyAktualizator -ErrorAction SilentlyContinue |
        Where-Object { $_.Path -and $_.Path.StartsWith($InstallDir, [StringComparison]::OrdinalIgnoreCase) }
    foreach ($proc in $running) {
        Write-Host "Zamykanie uruchomionej aplikacji (PID $($proc.Id))..."
        Stop-Process -Id $proc.Id -Force
    }

    $cerPath = Join-Path $InstallDir 'BezpiecznyAktualizator.cer'
    if (-not $KeepCertificate -and (Test-Path $cerPath)) {
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($cerPath)
        if ($cert.Subject -eq $cert.Issuer) {
            foreach ($store in 'Root', 'TrustedPublisher') {
                $item = "Cert:\LocalMachine\$store\$($cert.Thumbprint)"
                if (Test-Path $item) { Remove-Item $item -Force; Write-Host "Usunięto certyfikat wydawcy z magazynu $store." }
            }
        }
    }

    foreach ($s in $Shortcuts) { if (Test-Path $s) { Remove-Item $s -Force } }

    # Zadania cichych aktualizacji (Harmonogram zadań) wszystkich użytkowników tego komputera.
    try {
        $tasks = @(Get-ScheduledTask -TaskPath '\BezpiecznyAktualizator\' -ErrorAction Stop)
        foreach ($t in $tasks) {
            Unregister-ScheduledTask -TaskPath $t.TaskPath -TaskName $t.TaskName -Confirm:$false
            Write-Host "Usunięto zadanie Harmonogramu zadań $($t.TaskPath)$($t.TaskName)."
        }
        $scheduler = New-Object -ComObject Schedule.Service
        $scheduler.Connect()
        $scheduler.GetFolder('\').DeleteFolder('BezpiecznyAktualizator', 0)
    }
    catch { }
    if (Test-Path $UninstallKey) { Remove-Item $UninstallKey -Recurse -Force }
    Remove-Item $InstallDir -Recurse -Force
    Write-Host "Odinstalowano $AppName." -ForegroundColor Green
    $exitCode = 0
}
catch {
    Write-Host "BŁĄD: $($_.Exception.Message)" -ForegroundColor Red
    $exitCode = 1
}

if ($Elevated) { Read-Host 'Naciśnij Enter, aby zamknąć' | Out-Null }
exit $exitCode
