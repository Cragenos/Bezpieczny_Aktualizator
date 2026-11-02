param(
    [switch]$ValidateOnly,
    [Parameter(Mandatory = $true)][string]$ExpectedSignerSha256
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:OfflineLogPath = ''

function Write-Status([string]$Text) {
    Write-Host $Text
    if ($script:OfflineLogPath) {
        $line = '{0:o} {1}' -f [DateTimeOffset]::Now, $Text
        [IO.File]::AppendAllText($script:OfflineLogPath, $line + [Environment]::NewLine, [Text.Encoding]::UTF8)
    }
}

function Get-OfflineSha256([string]$Path) {
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $algorithm = [Security.Cryptography.SHA256]::Create()
        try { return [BitConverter]::ToString($algorithm.ComputeHash($stream)).Replace('-', '') }
        finally { $algorithm.Dispose() }
    } finally { $stream.Dispose() }
}

function Read-OfflineManifest([string]$Root, [string]$ExpectedFingerprint) {
    if ($ExpectedFingerprint -notmatch '^[0-9a-fA-F]{64}$') {
        throw 'Enter the independently verified 64-character SHA-256 certificate fingerprint.'
    }
    $manifestPath = Join-Path $Root 'manifest.json'
    $signaturePath = Join-Path $Root 'manifest.sig'
    $certificatePath = Join-Path $Root 'signer.cer'
    foreach ($path in @($manifestPath, $signaturePath, $certificatePath)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Required signed package file is missing: $([IO.Path]::GetFileName($path))" }
        if ((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "Signed package file must not be a link: $([IO.Path]::GetFileName($path))"
        }
    }
    $manifestBytes = [IO.File]::ReadAllBytes($manifestPath)
    $manifest = [Text.Encoding]::UTF8.GetString($manifestBytes) | ConvertFrom-Json
    if ($manifest.Version -ne 2) { throw 'Unsupported or unsigned offline package manifest.' }
    $expected = $ExpectedFingerprint.ToUpperInvariant()
    if ([string]$manifest.SigningCertificateSha256 -ne $expected) {
        throw 'The signing certificate fingerprint does not match the independently verified fingerprint.'
    }
    $certificate = New-Object Security.Cryptography.X509Certificates.X509Certificate2($certificatePath)
    $rsa = $null
    try {
        $actual = [BitConverter]::ToString(
            [Security.Cryptography.SHA256]::Create().ComputeHash($certificate.RawData)).Replace('-', '')
        if ($actual -ne $expected) { throw 'The package signing certificate does not match the independently verified fingerprint.' }
        $signature = [Convert]::FromBase64String((Get-Content -LiteralPath $signaturePath -Raw -Encoding ASCII).Trim())
        $rsa = $certificate.PublicKey.Key
        if (-not $rsa.VerifyData($manifestBytes, 'SHA256', $signature)) {
            throw 'The offline package manifest signature is invalid.'
        }
    } finally {
        if ($rsa) { $rsa.Dispose() }
        $certificate.Dispose()
    }
    return $manifest
}

function Test-OfflineFiles($Manifest, [string]$Root) {
    $files = @($Manifest.Files)
    if ($files.Count -lt 4 -or $files.Count -gt 10003) { throw 'Invalid signed file list.' }
    $seenFiles = @{}
    foreach ($item in $files) {
        $name = [string]$item.File
        if ($name -notmatch '^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$' -or
            @($name.Split('/')) -contains '..' -or $seenFiles.ContainsKey($name)) {
            throw "Invalid or duplicate signed file path: $name"
        }
        $seenFiles[$name] = $true
        if ([string]$item.Sha256 -notmatch '^[0-9a-fA-F]{64}$' -or [long]$item.Size -le 0) {
            throw "Invalid signed file metadata: $name"
        }
        $path = Join-Path $Root ($name.Replace('/', '\'))
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Signed file missing: $name" }
        $file = Get-Item -LiteralPath $path -Force
        if (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $file.Length -ne [long]$item.Size) {
            throw "Signed file is a link or has an unexpected size: $name"
        }
        if ((Get-OfflineSha256 $path) -ne [string]$item.Sha256) { throw "Signed file SHA-256 mismatch: $name" }
    }
    foreach ($required in @('Install-OfflineUpdates.ps1', 'Install-OfflineUpdates.cmd', 'Verify-OfflineUpdates.cmd', 'README.txt')) {
        if (-not $seenFiles.ContainsKey($required)) { throw "Required installer file is not signed: $required" }
    }
}

function Read-OfflinePackages($Manifest, [string]$Root) {
    $id = [Guid]::Empty
    if (-not [Guid]::TryParseExact([string]$Manifest.PackageId, 'D', [ref]$id) -or $id -eq [Guid]::Empty) {
        throw 'Invalid package version or identifier.'
    }
    $packages = @($Manifest.Packages)
    if ($packages.Count -eq 0 -or $packages.Count -gt 9999) { throw 'Invalid package count.' }
    $packageDir = Get-Item -LiteralPath (Join-Path $Root 'packages') -Force
    if (($packageDir.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'The packages directory must not be a link.'
    }
    $seen = @{}
    foreach ($item in $packages) {
        $name = [string]$item.File
        if ($name -notmatch '^packages/[^\\/:*?"<>|\x00-\x1f]+[.](msu|cab)$' -or $seen.ContainsKey($name)) {
            throw "Invalid or duplicate package path: $name"
        }
        $seen[$name] = $true
        if ([string]$item.Sha256 -notmatch '^[0-9a-fA-F]{64}$' -or [long]$item.Size -le 0) {
            throw "Invalid package metadata: $name"
        }
        $path = Join-Path $Root ($name.Replace('/', '\'))
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Package file missing: $name" }
        $file = Get-Item -LiteralPath $path -Force
        if (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $file.Length -ne [long]$item.Size) {
            throw "Package file is a link or has an unexpected size: $name"
        }
        $hash = Get-OfflineSha256 $path
        if ($hash -ne [string]$item.Sha256) { throw "SHA-256 mismatch: $name" }
    }
}

function Read-VerifiedOfflinePackage([string]$Root, [string]$ExpectedFingerprint) {
    $manifest = Read-OfflineManifest $Root $ExpectedFingerprint
    Test-OfflineFiles $manifest $Root
    Read-OfflinePackages $manifest $Root
    return $manifest
}

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } finally {
        $identity.Dispose()
    }
}

function Get-BootMarker {
    $boot = (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime
    return ([DateTime]$boot).ToUniversalTime().Ticks.ToString()
}

function Confirm-Installation {
    $answer = Read-Host 'Review the license terms for each package first. Type INSTALL to confirm acceptance and start installation, or press Enter to cancel'
    return $answer -ceq 'INSTALL'
}

function Invoke-WindowsPackage([string]$Path) {
    $system = [Environment]::SystemDirectory
    if ([IO.Path]::GetExtension($Path) -ieq '.msu') {
        $exe = Join-Path $system 'wusa.exe'
        $arguments = @("`"$Path`"", '/quiet', '/norestart')
    } else {
        $exe = Join-Path $system 'dism.exe'
        $arguments = @('/Online', '/Add-Package', "/PackagePath:`"$Path`"", '/Quiet', '/NoRestart')
    }
    if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { throw "Windows servicing tool not found: $exe" }
    $process = Start-Process -FilePath $exe -ArgumentList $arguments -Wait -PassThru
    return $process.ExitCode
}

function Save-OfflineState($State, [string]$Path) {
    $temporary = $Path + '.tmp'
    $State | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $temporary -Encoding UTF8
    Move-Item -LiteralPath $temporary -Destination $Path -Force
}

function Invoke-OfflinePackage {
    param([string]$Root, [switch]$ValidateOnly, [string]$StateRoot,
          [string]$ExpectedSignerSha256 = $script:ExpectedSignerSha256)

    $script:OfflineLogPath = ''
    $manifest = Read-VerifiedOfflinePackage $Root $ExpectedSignerSha256
    Write-Status 'The manifest signature, independently pinned signer and all package file hashes are valid.'
    if ($ValidateOnly) { return 0 }
    if (-not (Test-Administrator)) { throw 'Run Install-OfflineUpdates.cmd as an administrator.' }

    if (-not $StateRoot) {
        $StateRoot = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'BezpiecznyAktualizator\OfflineUpdates'
    }
    $stateDir = Join-Path $StateRoot ([string]$manifest.PackageId)
    [IO.Directory]::CreateDirectory($stateDir) | Out-Null
    $script:OfflineLogPath = Join-Path $stateDir 'install.log'
    $statePath = Join-Path $stateDir 'state.json'
    $manifestHash = Get-OfflineSha256 (Join-Path $Root 'manifest.json')
    if (Test-Path -LiteralPath $statePath -PathType Leaf) {
        $state = Get-Content -LiteralPath $statePath -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($state.Version -ne 1 -or $state.ManifestSha256 -ne $manifestHash) {
            throw 'Saved installation state does not match this manifest.'
        }
        $validNames = @($manifest.Packages | ForEach-Object { [string]$_.File })
        $seenCompleted = @{}
        foreach ($completed in @($state.Completed)) {
            if ($validNames -notcontains [string]$completed -or $seenCompleted.ContainsKey([string]$completed)) {
                throw 'Saved installation state is invalid.'
            }
            $seenCompleted[[string]$completed] = $true
        }
    } else {
        $state = [PSCustomObject]@{ Version = 1; ManifestSha256 = $manifestHash; Completed = @(); RebootBootTime = '' }
    }
    $boot = Get-BootMarker
    if ($state.RebootBootTime) {
        if ($state.RebootBootTime -eq $boot) {
            Write-Status 'A restart is required before the remaining packages can be installed.'
            return 3010
        }
        $state.RebootBootTime = ''
        Save-OfflineState $state $statePath
    }
    if (@($state.Completed).Count -eq @($manifest.Packages).Count) {
        Write-Status 'All packages recorded by this installer have already been processed successfully.'
        return 0
    }
    Write-Status "Log and installation state: $stateDir"
    Write-Status 'Install only on a compatible Windows version and architecture. Check prerequisites and order.'
    if (-not (Confirm-Installation)) {
        Write-Status 'Installation cancelled.'
        return 1
    }

    foreach ($item in @($manifest.Packages)) {
        $name = [string]$item.File
        if (@($state.Completed) -contains $name) {
            Write-Status "Already completed by this package: $name"
            continue
        }
        $path = Join-Path $Root ($name.Replace('/', '\'))
        if ((Get-OfflineSha256 $path) -ne [string]$item.Sha256) {
            throw "SHA-256 mismatch before installation: $name"
        }
        Write-Status "Installing $name ..."
        $code = [int](Invoke-WindowsPackage $path)
        $hex = '{0:X8}' -f [BitConverter]::ToUInt32([BitConverter]::GetBytes($code), 0)
        $needsRestart = $code -eq 3010 -or $code -eq 1641 -or $hex -eq '00240005'
        if ($code -eq 0 -or $hex -eq '00240006' -or $needsRestart) {
            $state.Completed = @($state.Completed) + $name
            if ($needsRestart) { $state.RebootBootTime = $boot }
            Save-OfflineState $state $statePath
            Write-Status "Completed: $name (0x$hex)."
            if ($state.RebootBootTime) {
                Write-Status 'Restart Windows, then run this installer again to continue.'
                return 3010
            }
        } elseif ($hex -eq '80240017') {
            Write-Status "Not applicable or already installed: $name (0x$hex). Verify it on the target computer; remaining packages were not installed."
            return 2
        } else {
            Write-Status "Installation failed: $name (0x$hex). Remaining packages were not installed."
            return 1
        }
    }
    Write-Status 'Installation completed. Check Windows Update history and restart if Windows requests it.'
    return 0
}

if ($MyInvocation.InvocationName -ne '.') {
    try {
        exit (Invoke-OfflinePackage -Root $PSScriptRoot -ValidateOnly:$ValidateOnly -ExpectedSignerSha256 $ExpectedSignerSha256)
    } catch {
        Write-Host ("ERROR: " + $_.Exception.Message) -ForegroundColor Red
        exit 1
    }
}
