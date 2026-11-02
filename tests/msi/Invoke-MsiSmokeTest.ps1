param(
    [switch]$BuildOnly,
    [switch]$NoRestore
)

$ErrorActionPreference = 'Stop'

function Get-MsiProductCode([string]$MsiPath) {
    $installer = New-Object -ComObject WindowsInstaller.Installer
    $database = $null
    $view = $null
    $record = $null
    try {
        $database = $installer.OpenDatabase($MsiPath, 0)
        $view = $database.OpenView('SELECT `Value` FROM `Property` WHERE `Property` = ''ProductCode''')
        [void]$view.Execute()
        $record = $view.Fetch()
        if (-not $record) { throw "No ProductCode found in $MsiPath." }
        return [string]$record.StringData(1)
    }
    finally {
        foreach ($comObject in @($record, $view, $database, $installer)) {
            if ($null -ne $comObject -and [Runtime.InteropServices.Marshal]::IsComObject($comObject)) {
                [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($comObject)
            }
        }
    }
}

function Get-ProductState([string]$ProductCode) {
    $installer = New-Object -ComObject WindowsInstaller.Installer
    try {
        return [int]$installer.ProductState($ProductCode)
    }
    finally {
        [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($installer)
    }
}

function Assert-MsiContainsNotices([string]$MsiPath, [string[]]$Names) {
    $installer = New-Object -ComObject WindowsInstaller.Installer
    $database = $null
    $view = $null
    try {
        $database = $installer.OpenDatabase($MsiPath, 0)
        $view = $database.OpenView('SELECT `FileName` FROM `File`')
        [void]$view.Execute()
        $files = @()
        while ($record = $view.Fetch()) {
            $files += ([string]$record.StringData(1) -split '\|')[-1]
            [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($record)
        }
        foreach ($name in $Names) {
            if ($name -notin $files) { throw "The MSI does not contain $name." }
        }
    }
    finally {
        foreach ($comObject in @($view, $database, $installer)) {
            if ($null -ne $comObject -and [Runtime.InteropServices.Marshal]::IsComObject($comObject)) {
                [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($comObject)
            }
        }
    }
}

function Invoke-Msi([string]$Operation, [string]$Target, [string]$LogPath, [switch]$Cleanup) {
    $arguments = "/$Operation `"$Target`" /qn /norestart /l*v `"$LogPath`""
    $process = Start-Process -FilePath (Join-Path $env:WINDIR 'System32\msiexec.exe') `
        -ArgumentList $arguments -Wait -PassThru -WindowStyle Hidden
    $allowedExitCodes = if ($Cleanup) { @(0, 1605, 1614, 3010) } else { @(0, 3010) }
    if ($process.ExitCode -notin $allowedExitCodes) {
        throw "msiexec /$Operation failed with exit code $($process.ExitCode). Log: $LogPath"
    }
}

function Assert-Installed([string]$ProductCode, [string]$PayloadHash, [string]$InstallPath, [hashtable]$NoticeHashes) {
    if ((Get-ProductState $ProductCode) -notin @(3, 5)) {
        throw "Expected MSI product $ProductCode to be installed."
    }

    $exe = Join-Path $InstallPath 'BezpiecznyAktualizator.exe'
    $certificate = Join-Path $InstallPath 'BezpiecznyAktualizator.cer'
    if (-not (Test-Path -LiteralPath $exe -PathType Leaf) -or
        (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash -ne $PayloadHash) {
        throw 'The installed executable payload is missing or has changed.'
    }
    if (-not (Test-Path -LiteralPath $certificate -PathType Leaf)) {
        throw 'The installed certificate payload is missing.'
    }
    foreach ($name in $NoticeHashes.Keys) {
        $notice = Join-Path $InstallPath $name
        if (-not (Test-Path -LiteralPath $notice -PathType Leaf) -or
            (Get-FileHash -LiteralPath $notice -Algorithm SHA256).Hash -ne $NoticeHashes[$name]) {
            throw "The installed license or notice is missing or has changed: $name."
        }
    }
}

$identityToken = [guid]::NewGuid().ToString('N')
$identityName = "BezpiecznyAktualizator-CI-$identityToken"
$registryKey = "Software\Cragenos\BezpiecznyAktualizator-CI-$identityToken"
$upgradeCode = ([guid]::NewGuid()).ToString('B').ToUpperInvariant()
$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) "BezpiecznyAktualizator-MsiSmoke-$identityToken"
$productCodes = @()
$installPath = Join-Path $env:ProgramFiles $identityName
$menuPath = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\$identityName"
$machineRegistryPath = "Registry::HKEY_LOCAL_MACHINE\$registryKey"
$userRegistryPath = "Registry::HKEY_CURRENT_USER\$registryKey"
try {
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $BuildOnly -and -not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'The MSI smoke test requires an elevated Windows runner.'
    }

    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
    $msiSource = Join-Path $repoRoot 'dotnet\packaging\msi'
    $originalWxs = [IO.File]::ReadAllText((Join-Path $msiSource 'Package.wxs'))
    $testWxs = $originalWxs.
        Replace('UpgradeCode="{7E4B86E3-1DC1-4E9E-8D41-3AFCBBF6B010}"', "UpgradeCode=`"$upgradeCode`"").
        Replace('Name="Bezpieczny Aktualizator"', "Name=`"$identityName`"").
        Replace('Manufacturer="Cragenos"', 'Manufacturer="Bezpieczny Aktualizator CI"').
        Replace('Software\Cragenos\BezpiecznyAktualizator', $registryKey)
    if ($testWxs -eq $originalWxs) {
        throw 'Could not create an isolated MSI identity from Package.wxs.'
    }

    New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
    $payloadDirectory = Join-Path $tempRoot 'payload'
    New-Item -ItemType Directory -Path $payloadDirectory -Force | Out-Null
    $payloadPath = Join-Path $payloadDirectory 'BezpiecznyAktualizator.exe'
    $certificatePath = Join-Path $payloadDirectory 'BezpiecznyAktualizator.cer'
    $utf8 = [Text.UTF8Encoding]::new($false)
    [IO.File]::WriteAllText($payloadPath, "CI MSI smoke-test payload $identityToken", $utf8)
    [IO.File]::WriteAllText($certificatePath, "CI MSI smoke-test certificate placeholder $identityToken", $utf8)
    $payloadHash = (Get-FileHash -LiteralPath $payloadPath -Algorithm SHA256).Hash
    $noticeFiles = [ordered]@{
        LicensePath = 'LICENSE'
        ThirdPartyNoticesPath = 'THIRD-PARTY-NOTICES.txt'
        DotnetLicensePath = 'DOTNET-LICENSE.txt'
        DotnetThirdPartyNoticesPath = 'DOTNET-THIRD-PARTY-NOTICES.txt'
    }
    $noticeHashes = @{}
    foreach ($name in $noticeFiles.Values) {
        $path = Join-Path $payloadDirectory $name
        [IO.File]::WriteAllText($path, "CI MSI smoke-test notice $name $identityToken", $utf8)
        $noticeHashes[$name] = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
    }

    $versions = @('1.0.0', '1.0.1')
    foreach ($version in $versions) {
        $buildDirectory = Join-Path $tempRoot $version
        $outputDirectory = Join-Path $buildDirectory 'out'
        $intermediateDirectory = Join-Path $buildDirectory 'obj'
        New-Item -ItemType Directory -Path $buildDirectory, $outputDirectory, $intermediateDirectory -Force | Out-Null
        Copy-Item (Join-Path $msiSource 'BezpiecznyAktualizator.wixproj') $buildDirectory
        [IO.File]::WriteAllText((Join-Path $buildDirectory 'Package.wxs'), $testWxs, $utf8)

        $wixProject = Join-Path $buildDirectory 'BezpiecznyAktualizator.wixproj'
        $buildArguments = @(
            'build', $wixProject, '--configuration', 'Release', '--verbosity', 'minimal',
            '-p:Platform=x64',
            "-p:PackageVersion=$version",
            "-p:AppExePath=$payloadPath",
            "-p:CertificatePath=$certificatePath",
            "-p:OutputPath=$outputDirectory\",
            "-p:IntermediateOutputPath=$intermediateDirectory\"
        )
        foreach ($notice in $noticeFiles.GetEnumerator()) {
            $buildArguments += "-p:$($notice.Key)=$(Join-Path $payloadDirectory $notice.Value)"
        }
        if ($NoRestore) { $buildArguments += '--no-restore' }
        & dotnet @buildArguments
        if ($LASTEXITCODE -ne 0) { throw "WiX build failed for MSI version $version." }

        $msi = Get-ChildItem -LiteralPath $outputDirectory -Filter '*.msi' -File -Recurse |
            Select-Object -First 1
        if (-not $msi) { throw "WiX did not produce an MSI for version $version." }
        Assert-MsiContainsNotices $msi.FullName @($noticeFiles.Values)
        $codes = @(Get-MsiProductCode $msi.FullName)
        $parsedCode = [guid]::Empty
        if ($codes.Count -ne 1 -or -not [guid]::TryParse([string]$codes[0], [ref]$parsedCode) -or
            $parsedCode -eq [guid]::Empty) {
            throw "MSI version $version did not provide exactly one valid ProductCode."
        }
        $productCodes += [string]$codes[0]
    }

    if ($productCodes[0] -eq $productCodes[1]) {
        throw 'The two MSI builds did not receive distinct ProductCodes.'
    }

    if ($BuildOnly) {
        Write-Host 'MSI build-only test passed: both packages contain notices and distinct valid ProductCodes.'
        return
    }

    $installLog = Join-Path $tempRoot 'install-v1.log'
    Invoke-Msi 'i' (Get-ChildItem -LiteralPath (Join-Path $tempRoot '1.0.0\out') -Filter '*.msi' -File -Recurse |
        Select-Object -First 1 -ExpandProperty FullName) $installLog
    Assert-Installed $productCodes[0] $payloadHash $installPath $noticeHashes

    $upgradeLog = Join-Path $tempRoot 'upgrade-v2.log'
    Invoke-Msi 'i' (Get-ChildItem -LiteralPath (Join-Path $tempRoot '1.0.1\out') -Filter '*.msi' -File -Recurse |
        Select-Object -First 1 -ExpandProperty FullName) $upgradeLog
    Assert-Installed $productCodes[1] $payloadHash $installPath $noticeHashes
    if ((Get-ProductState $productCodes[0]) -in @(3, 4, 5)) {
        throw 'The previous MSI product remains installed after the major upgrade.'
    }

    $uninstallLog = Join-Path $tempRoot 'uninstall-v2.log'
    Invoke-Msi 'x' $productCodes[1] $uninstallLog
    if ((Get-ProductState $productCodes[1]) -in @(3, 4, 5) -or
        (Test-Path -LiteralPath $installPath) -or (Test-Path -LiteralPath $menuPath)) {
        throw 'The MSI product or its installed files remain after uninstall.'
    }

    Write-Host 'MSI smoke test passed: clean install, major upgrade, and uninstall.'
}
catch {
    foreach ($log in (Get-ChildItem -LiteralPath $tempRoot -Filter '*.log' -File -Recurse -ErrorAction SilentlyContinue)) {
        Write-Host "`n--- MSI log tail: $($log.FullName) ---"
        Get-Content -LiteralPath $log.FullName -Tail 40
    }
    throw
}
finally {
    if (-not $BuildOnly) {
        $cleanupProductCodes = @($productCodes | Select-Object -Unique)
        [array]::Reverse($cleanupProductCodes)
        foreach ($productCode in $cleanupProductCodes) {
            try {
                Invoke-Msi 'x' $productCode (Join-Path $tempRoot "cleanup-$($productCode.Trim('{}')).log") -Cleanup
            }
            catch {
                Write-Warning "Could not remove test MSI product ${productCode}: $_"
            }
        }
        foreach ($path in @($installPath, $menuPath)) {
            if (Test-Path -LiteralPath $path) {
                Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
        foreach ($path in @($machineRegistryPath, $userRegistryPath)) {
            if (Test-Path -LiteralPath $path) {
                Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
    if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}
