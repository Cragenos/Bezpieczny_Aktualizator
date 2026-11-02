$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
try {
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'The Windows Update VM runner must run with administrator privileges.'
    }
} finally {
    $identity.Dispose()
}

$catalogPath = Join-Path $env:RUNNER_TEMP ("wsusscn2-" + [Guid]::NewGuid().ToString('N') + '.cab')
$catalogUrl = 'https://catalog.s.download.windowsupdate.com/microsoftupdate/v6/wsusscan/wsusscn2.cab'
try {
    Write-Host "Downloading the Microsoft security-update scan catalog from $catalogUrl"
    Invoke-WebRequest -UseBasicParsing -Uri $catalogUrl -OutFile $catalogPath
    if ((Get-Item -LiteralPath $catalogPath).Length -lt 1MB) {
        throw 'The downloaded Windows Update scan catalog is unexpectedly small.'
    }

    $env:BA_WSUSSCN2_PATH = $catalogPath
    dotnet test .\dotnet\tests\BezpiecznyAktualizator.Tests\BezpiecznyAktualizator.Tests.csproj `
        --configuration Release `
        --filter 'FullyQualifiedName~WindowsUpdateOfflineCatalogLiveTests'
    if ($LASTEXITCODE -ne 0) {
        throw "Offline catalog scan test failed with exit code $LASTEXITCODE."
    }
} finally {
    Remove-Item -LiteralPath $catalogPath -Force -ErrorAction SilentlyContinue
}
