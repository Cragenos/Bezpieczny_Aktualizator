<#
.SYNOPSIS
    Synchronizuje pliki tłumaczeń (Localization\Strings\<kod>.json) z tekstami użytymi w kodzie.

.DESCRIPTION
    Kluczem tłumaczenia jest polski tekst źródłowy. Skrypt zbiera literały z wywołań
    L.T("..."), L.F("..."), L.Txt("..."), L.N("...") w plikach *.cs oraz {l:Tr '...'} w plikach *.xaml,
    a następnie w każdym pliku językowym:
      * dodaje brakujące klucze z pustą wartością (do przetłumaczenia),
      * usuwa klucze, które nie występują już w kodzie,
      * zachowuje istniejące tłumaczenia i porządkuje klucze według kolejności w kodzie.
    Puste wartości są w aplikacji zastępowane tekstem angielskim, a w razie jego braku polskim.

.PARAMETER Check
    Tylko sprawdza - kończy się kodem 1, jeśli którykolwiek plik wymaga zmian lub ma puste tłumaczenia.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File tools\Update-Translations.ps1
#>
[CmdletBinding()]
param([switch]$Check)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$src = Join-Path $root 'src'
$stringsDir = Join-Path $src 'BezpiecznyAktualizator.Core\Localization\Strings'
$languages = 'en', 'de', 'fr', 'es', 'it', 'pt', 'ru', 'uk', 'tr', 'zh', 'ja', 'ko'

function ConvertFrom-CSharpLiteral([string]$s) {
    [regex]::Replace($s, '\\(u[0-9a-fA-F]{4}|.)', {
        param($m)
        $c = $m.Groups[1].Value
        switch -CaseSensitive ($c) {
            'n' { "`n" } 'r' { "`r" } 't' { "`t" } '0' { [string][char]0 }
            default { if ($c.Length -eq 5) { [string][char][Convert]::ToInt32($c.Substring(1), 16) } else { $c } }
        }
    })
}

function Read-Json([string]$path) {
    $text = [IO.File]::ReadAllText($path, [Text.Encoding]::UTF8)
    $result = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([StringComparer]::Ordinal)
    if ($PSVersionTable.PSEdition -eq 'Core') {
        $doc = [System.Text.Json.JsonDocument]::Parse($text)
        foreach ($p in $doc.RootElement.EnumerateObject()) { $result[$p.Name] = $p.Value.GetString() }
        $doc.Dispose()
    } else {
        Add-Type -AssemblyName System.Web.Extensions
        $serializer = New-Object System.Web.Script.Serialization.JavaScriptSerializer
        $serializer.MaxJsonLength = [int]::MaxValue
        $parsed = $serializer.DeserializeObject($text)
        foreach ($k in $parsed.Keys) { $result[$k] = [string]$parsed[$k] }
    }
    return , $result
}

function ConvertTo-JsonString([string]$s) {
    $sb = New-Object Text.StringBuilder
    [void]$sb.Append('"')
    foreach ($ch in $s.ToCharArray()) {
        switch ($ch) {
            '"' { [void]$sb.Append('\"') }
            '\' { [void]$sb.Append('\\') }
            "`n" { [void]$sb.Append('\n') }
            "`r" { [void]$sb.Append('\r') }
            "`t" { [void]$sb.Append('\t') }
            default {
                if ([int]$ch -lt 32) { [void]$sb.AppendFormat('\u{0:x4}', [int]$ch) } else { [void]$sb.Append($ch) }
            }
        }
    }
    [void]$sb.Append('"')
    $sb.ToString()
}

# ---------------------------------------------------------------- zbieranie kluczy
$keys = New-Object 'System.Collections.Generic.List[string]'
$seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
$csPattern = 'L\.(?:T|F|Txt|N)\(\s*"((?:[^"\\]|\\.)*)"'
$xamlPattern = "\{l:Tr '([^']*)'\}"
$files = Get-ChildItem $src -Recurse -File -Include *.cs, *.xaml |
    Where-Object { $_.FullName -notmatch '\\(obj|bin)\\' } | Sort-Object FullName
foreach ($file in $files) {
    $text = [IO.File]::ReadAllText($file.FullName, [Text.Encoding]::UTF8)
    if ($file.Extension -eq '.cs') {
        $found = [regex]::Matches($text, $csPattern) | ForEach-Object { ConvertFrom-CSharpLiteral $_.Groups[1].Value }
    } else {
        $found = [regex]::Matches($text, $xamlPattern) | ForEach-Object { [Net.WebUtility]::HtmlDecode($_.Groups[1].Value) }
    }
    foreach ($k in $found) { if ($k.Length -gt 0 -and $seen.Add($k)) { $keys.Add($k) } }
}
Write-Host "Teksty do tłumaczenia: $($keys.Count)"

# ---------------------------------------------------------------- synchronizacja plików
New-Item -ItemType Directory -Force -Path $stringsDir | Out-Null
$problems = 0
foreach ($lang in $languages) {
    $path = Join-Path $stringsDir "$lang.json"
    $existing = if (Test-Path $path) { Read-Json $path } else { New-Object 'System.Collections.Generic.Dictionary[string,string]' }
    $lines = foreach ($k in $keys) {
        $v = if ($existing.ContainsKey($k)) { $existing[$k] } else { '' }
        '  ' + (ConvertTo-JsonString $k) + ': ' + (ConvertTo-JsonString $v)
    }
    $json = "{`n" + ($lines -join ",`n") + "`n}`n"
    $added = @($keys | Where-Object { -not $existing.ContainsKey($_) }).Count
    $removed = @($existing.Keys | Where-Object { -not $seen.Contains($_) }).Count
    $empty = @($keys | Where-Object { -not $existing.ContainsKey($_) -or $existing[$_].Length -eq 0 }).Count
    Write-Host ("{0}: +{1} nowych, -{2} usuniętych, {3} bez tłumaczenia" -f $lang, $added, $removed, $empty)
    if ($Check) {
        if ($added -or $removed -or $empty) { $problems++ }
    } else {
        $current = if (Test-Path $path) { [IO.File]::ReadAllText($path, [Text.Encoding]::UTF8) } else { '' }
        if ($current -ne $json) { [IO.File]::WriteAllText($path, $json, (New-Object Text.UTF8Encoding($false))) }
    }
}
if ($Check -and $problems) { Write-Warning "Pliki wymagające aktualizacji: $problems"; exit 1 }
