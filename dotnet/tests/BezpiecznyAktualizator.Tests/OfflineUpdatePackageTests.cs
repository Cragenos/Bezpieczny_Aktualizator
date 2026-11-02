using System.Diagnostics;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using BezpiecznyAktualizator.Core.Updates;

namespace BezpiecznyAktualizator.Tests;

public class OfflineUpdatePackageTests
{
    [Fact]
    public async Task PackageContainsOrderedFilesHashesInstallerAndInformationalCves()
    {
        using var signer = OfflinePackageTestSigner.Create();
        var root = Directory.CreateTempSubdirectory("ba_offline_test_");
        try
        {
            var first = Path.Combine(root.FullName, "windows-kb123-x64.msu");
            var second = Path.Combine(root.FullName, "servicing.cab");
            await File.WriteAllTextAsync(first, "first update");
            await File.WriteAllTextAsync(second, "second update");
            var archivePath = Path.Combine(root.FullName, "offline.zip");
            var reference = new WindowsUpdateItem
            {
                Identity = new(Guid.Parse("11111111-2222-3333-4444-555555555555"), 2),
                Title = "Update", KbIds = ["123"], CveIds = ["CVE-2025-1234"],
            };
            var progress = new List<string>();
            await OfflineUpdatePackage.CreateAsync(archivePath, [first, second], [reference], signer.Certificate,
                progress: new RecordingProgress(progress));
            Assert.Equal(8, progress.Count);
            Assert.Contains(progress, message => message.Contains(Path.GetFileName(first), StringComparison.Ordinal));
            Assert.Contains(progress, message => message.Contains(Path.GetFileName(second), StringComparison.Ordinal));

            using var archive = ZipFile.OpenRead(archivePath);
            Assert.NotNull(archive.GetEntry("Install-OfflineUpdates.cmd"));
            Assert.NotNull(archive.GetEntry("Install-OfflineUpdates.ps1"));
            Assert.NotNull(archive.GetEntry("Verify-OfflineUpdates.cmd"));
            Assert.NotNull(archive.GetEntry("manifest.sig"));
            Assert.NotNull(archive.GetEntry("signer.cer"));
            Assert.NotNull(archive.GetEntry("README.txt"));
            using var readme = new StreamReader(archive.GetEntry("README.txt")!.Open());
            Assert.Contains("this installer does not display those terms", await readme.ReadToEndAsync(), StringComparison.OrdinalIgnoreCase);
            await using var manifestStream = archive.GetEntry("manifest.json")!.Open();
            using var manifestBuffer = new MemoryStream();
            await manifestStream.CopyToAsync(manifestBuffer);
            var manifestBytes = manifestBuffer.ToArray();
            var manifest = JsonNode.Parse(manifestBytes)!.AsObject();
            Assert.Equal(2, manifest["version"]!.GetValue<int>());
            Assert.Equal(signer.Sha256, manifest["signingCertificateSha256"]!.GetValue<string>());
            Assert.Contains(manifest["files"]!.AsArray(), entry =>
                entry!["file"]!.GetValue<string>() == "Install-OfflineUpdates.ps1");
            using var signatureReader = new StreamReader(archive.GetEntry("manifest.sig")!.Open());
            var signature = Convert.FromBase64String(await signatureReader.ReadToEndAsync());
            Assert.True(OfflineUpdatePackage.VerifyManifest(manifestBytes, signature, signer.Certificate));
            Assert.True(Guid.TryParse(manifest["packageId"]!.GetValue<string>(), out _));
            var packages = manifest["packages"]!.AsArray();
            Assert.Equal(2, packages.Count);
            Assert.Equal("packages/windows-kb123-x64.msu", packages[0]!["file"]!.GetValue<string>());
            Assert.Equal("packages/servicing.cab", packages[1]!["file"]!.GetValue<string>());
            Assert.Equal(Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(first))),
                packages[0]!["sha256"]!.GetValue<string>());
            Assert.Equal("CVE-2025-1234", manifest["references"]![0]!["cveIds"]![0]!.GetValue<string>());
        }
        finally { root.Delete(true); }
    }

    [Fact]
    public async Task OfflineValidationDetectsTamperingAndUnsafeManifestPaths()
    {
        using var signer = OfflinePackageTestSigner.Create();
        var root = Directory.CreateTempSubdirectory("ba_offline_validation_");
        try
        {
            var source = Path.Combine(root.FullName, "test.msu");
            await File.WriteAllTextAsync(source, "test payload");
            var archivePath = Path.Combine(root.FullName, "offline.zip");
            await OfflineUpdatePackage.CreateAsync(archivePath, [source], [], signer.Certificate);
            var extracted = Path.Combine(root.FullName, "extracted");
            ZipFile.ExtractToDirectory(archivePath, extracted);
            var installer = Path.Combine(extracted, "Install-OfflineUpdates.ps1");
            var good = await RunPowerShellAsync(installer, "AllSigned", "-ExpectedSignerSha256", signer.Sha256, "-ValidateOnly");
            Assert.True(good.ExitCode == 0, good.Output);
            Assert.Contains("manifest signature", good.Output, StringComparison.OrdinalIgnoreCase);

            var badPin = await RunPowerShellAsync(installer, "AllSigned", "-ExpectedSignerSha256",
                new string('0', 64), "-ValidateOnly");
            Assert.NotEqual(0, badPin.ExitCode);
            Assert.Contains("independently verified fingerprint", badPin.Output, StringComparison.OrdinalIgnoreCase);

            var payloadPath = Path.Combine(extracted, "packages", "test.msu");
            var originalPayload = await File.ReadAllBytesAsync(payloadPath);
            await File.WriteAllTextAsync(payloadPath, "evil payload");
            var badHash = await RunPowerShellAsync(installer, "AllSigned", "-ExpectedSignerSha256", signer.Sha256, "-ValidateOnly");
            Assert.NotEqual(0, badHash.ExitCode);
            Assert.Contains("SHA-256 mismatch", badHash.Output);
            await File.WriteAllBytesAsync(payloadPath, originalPayload);

            var manifestPath = Path.Combine(extracted, "manifest.json");
            var manifest = JsonNode.Parse(await File.ReadAllTextAsync(manifestPath))!;
            manifest["packages"]![0]!["file"] = "packages/../test.msu";
            var manifestBytes = Encoding.UTF8.GetBytes(manifest.ToJsonString());
            await File.WriteAllBytesAsync(manifestPath, manifestBytes);
            await File.WriteAllTextAsync(Path.Combine(extracted, "manifest.sig"),
                Convert.ToBase64String(OfflineUpdatePackage.SignManifest(manifestBytes, signer.Certificate)));
            var badPath = await RunPowerShellAsync(installer, "AllSigned", "-ExpectedSignerSha256", signer.Sha256, "-ValidateOnly");
            Assert.NotEqual(0, badPath.ExitCode);
            Assert.Contains("Invalid or duplicate package path", badPath.Output);

            var originalScript = await File.ReadAllBytesAsync(installer);
            await File.AppendAllTextAsync(installer, "# tampered");
            var badScriptSignature = await RunPowerShellAsync(installer, "AllSigned", "-ExpectedSignerSha256",
                signer.Sha256, "-ValidateOnly");
            Assert.NotEqual(0, badScriptSignature.ExitCode);
            await File.WriteAllBytesAsync(installer, originalScript);
        }
        finally { root.Delete(true); }
    }

    [Fact]
    public async Task InstallerResumesOnlyAfterRebootAndReportsFailures()
    {
        using var signer = OfflinePackageTestSigner.Create();
        var root = Directory.CreateTempSubdirectory("ba_offline_resume_");
        try
        {
            var first = Path.Combine(root.FullName, "first.msu");
            var second = Path.Combine(root.FullName, "second.cab");
            await File.WriteAllTextAsync(first, "first");
            await File.WriteAllTextAsync(second, "second");
            var archivePath = Path.Combine(root.FullName, "offline.zip");
            await OfflineUpdatePackage.CreateAsync(archivePath, [first, second], [], signer.Certificate);
            var extracted = Path.Combine(root.FullName, "extracted");
            ZipFile.ExtractToDirectory(archivePath, extracted);
            var installer = Path.Combine(extracted, "Install-OfflineUpdates.ps1");
            var harness = Path.Combine(root.FullName, "harness.ps1");
            var text = $$"""
                . {{Quote(installer)}} -ExpectedSignerSha256 '{{signer.Sha256}}'
                function Test-Administrator { return $true }
                function Get-BootMarker { return $script:Boot }
                function Confirm-Installation { return $true }
                function Invoke-WindowsPackage([string]$Path) {
                    $script:Calls += [IO.Path]::GetFileName($Path)
                    if ($script:Mode -eq 'reboot' -and $script:Calls.Count -eq 1) { return 3010 }
                    if ($script:Mode -eq 'wu-reboot' -and $script:Calls.Count -eq 1) { return 2359301 }
                    if ($script:Mode -eq 'notapplicable' -and $script:Calls.Count -eq 1) { return -2145124329 }
                    if ($script:Mode -eq 'failure') { return 123 }
                    return 0
                }
                $script:Boot = 'boot-a'
                $script:Calls = @()
                $script:Mode = 'reboot'
                $first = Invoke-OfflinePackage -Root {{Quote(extracted)}} -StateRoot {{Quote(Path.Combine(root.FullName, "resume"))}}
                if ($first -ne 3010 -or $script:Calls.Count -ne 1) { throw 'First run did not stop for reboot.' }
                $again = Invoke-OfflinePackage -Root {{Quote(extracted)}} -StateRoot {{Quote(Path.Combine(root.FullName, "resume"))}}
                if ($again -ne 3010 -or $script:Calls.Count -ne 1) { throw 'Continued without a reboot.' }
                $script:Boot = 'boot-b'
                $done = Invoke-OfflinePackage -Root {{Quote(extracted)}} -StateRoot {{Quote(Path.Combine(root.FullName, "resume"))}}
                if ($done -ne 0 -or $script:Calls.Count -ne 2 -or $script:Calls[1] -ne 'second.cab') { throw 'Resume failed.' }
                $manifest = Get-Content -Raw -LiteralPath (Join-Path {{Quote(extracted)}} 'manifest.json') | ConvertFrom-Json
                $statePath = Join-Path (Join-Path {{Quote(Path.Combine(root.FullName, "resume"))}} $manifest.PackageId) 'state.json'
                $state = Get-Content -Raw -LiteralPath $statePath | ConvertFrom-Json
                $state.Completed = @('packages/first.msu', 'packages/first.msu')
                $state | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $statePath -Encoding UTF8
                $rejected = $false
                try { $null = Invoke-OfflinePackage -Root {{Quote(extracted)}} -StateRoot {{Quote(Path.Combine(root.FullName, "resume"))}} }
                catch { $rejected = $_.Exception.Message -like '*state is invalid*' }
                if (-not $rejected) { throw 'Duplicate completed entries were accepted.' }

                $script:Calls = @()
                $script:Mode = 'wu-reboot'
                $wuReboot = Invoke-OfflinePackage -Root {{Quote(extracted)}} -StateRoot {{Quote(Path.Combine(root.FullName, "wu-reboot"))}}
                if ($wuReboot -ne 3010 -or $script:Calls.Count -ne 1) { throw 'WU_S_REBOOT_REQUIRED was not honored.' }
                $wuBlocked = Invoke-OfflinePackage -Root {{Quote(extracted)}} -StateRoot {{Quote(Path.Combine(root.FullName, "wu-reboot"))}}
                if ($wuBlocked -ne 3010 -or $script:Calls.Count -ne 1) { throw 'WU_S_REBOOT_REQUIRED continued without reboot.' }
                $script:Boot = 'boot-c'
                $wuDone = Invoke-OfflinePackage -Root {{Quote(extracted)}} -StateRoot {{Quote(Path.Combine(root.FullName, "wu-reboot"))}}
                if ($wuDone -ne 0 -or $script:Calls.Count -ne 2) { throw 'WU_S_REBOOT_REQUIRED did not resume after reboot.' }

                $script:Calls = @()
                $script:Mode = 'notapplicable'
                $partial = Invoke-OfflinePackage -Root {{Quote(extracted)}} -StateRoot {{Quote(Path.Combine(root.FullName, "partial"))}}
                if ($partial -ne 2 -or $script:Calls.Count -ne 1) { throw 'Inapplicable package did not stop the sequence.' }

                $script:Calls = @()
                $script:Mode = 'failure'
                $failed = Invoke-OfflinePackage -Root {{Quote(extracted)}} -StateRoot {{Quote(Path.Combine(root.FullName, "failure"))}}
                if ($failed -ne 1 -or $script:Calls.Count -ne 1) { throw 'Failed package did not stop the sequence.' }
                Write-Host 'Offline installer scenarios passed.'
                """;
            await File.WriteAllTextAsync(harness, text, new UTF8Encoding(true));
            var result = await RunPowerShellAsync(harness);
            Assert.True(result.ExitCode == 0, result.Output);
            Assert.Contains("Offline installer scenarios passed.", result.Output);
        }
        finally { root.Delete(true); }
    }

    [Fact]
    public async Task RejectsInvalidInputsAndKeepsExistingOutputOnCancellation()
    {
        using var signer = OfflinePackageTestSigner.Create();
        var root = Directory.CreateTempSubdirectory("ba_offline_invalid_");
        try
        {
            var source = Path.Combine(root.FullName, "file.msu");
            await File.WriteAllTextAsync(source, "valid bytes");
            var invalid = Path.Combine(root.FullName, "file.exe");
            await File.WriteAllTextAsync(invalid, "not an update");
            var destination = Path.Combine(root.FullName, "existing.zip");
            await File.WriteAllTextAsync(destination, "original");
            await Assert.ThrowsAsync<WindowsUpdateException>(() =>
                OfflineUpdatePackage.CreateAsync(destination, [invalid], [], signer.Certificate, true));
            await Assert.ThrowsAsync<WindowsUpdateException>(() =>
                OfflineUpdatePackage.CreateAsync(destination, [source, source], [], signer.Certificate, true));
            using var cancelled = new CancellationTokenSource();
            cancelled.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
                OfflineUpdatePackage.CreateAsync(destination, [source], [], signer.Certificate, true, cancelled.Token));
            Assert.Equal("original", await File.ReadAllTextAsync(destination));
            Assert.Empty(Directory.GetFiles(root.FullName, "*.tmp"));
        }
        finally { root.Delete(true); }
    }

    [Fact]
    [Trait("Category", "Live")]
    public async Task OfflineInstallerReadsTheActualLocalBootMarker()
    {
        using var signer = OfflinePackageTestSigner.Create();
        var root = Directory.CreateTempSubdirectory("ba_offline_boot_");
        try
        {
            var source = Path.Combine(root.FullName, "test.msu");
            await File.WriteAllTextAsync(source, "test");
            var archive = Path.Combine(root.FullName, "offline.zip");
            await OfflineUpdatePackage.CreateAsync(archive, [source], [], signer.Certificate);
            var extracted = Path.Combine(root.FullName, "extracted");
            ZipFile.ExtractToDirectory(archive, extracted);
            var harness = Path.Combine(root.FullName, "boot.ps1");
            var script = $". {Quote(Path.Combine(extracted, "Install-OfflineUpdates.ps1"))} -ExpectedSignerSha256 '{signer.Sha256}'\n" +
                         "$marker = Get-BootMarker\n" +
                         "if ($marker -notmatch '^\\d+$') { throw 'Invalid boot marker.' }\n" +
                         "Write-Host 'Boot marker OK.'\n";
            await File.WriteAllTextAsync(harness, script, new UTF8Encoding(true));
            var result = await RunPowerShellAsync(harness);
            Assert.True(result.ExitCode == 0, result.Output);
            Assert.Contains("Boot marker OK.", result.Output);
        }
        finally { root.Delete(true); }
    }

    private static string Quote(string value) => "'" + value.Replace("'", "''") + "'";

    private static async Task<(int ExitCode, string Output)> RunPowerShellAsync(string script,
        string executionPolicy = "Bypass", params string[] arguments)
    {
        var executable = Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe");
        var start = new ProcessStartInfo(executable)
        {
            UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true,
        };
        foreach (var argument in new[] { "-NoProfile", "-NonInteractive", "-ExecutionPolicy", executionPolicy, "-File", script }.Concat(arguments))
            start.ArgumentList.Add(argument);
        using var process = Process.Start(start) ?? throw new InvalidOperationException("PowerShell did not start.");
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        try { await process.WaitForExitAsync(timeout.Token); }
        catch (OperationCanceledException) { process.Kill(entireProcessTree: true); throw; }
        return (process.ExitCode, await stdout + await stderr);
    }

    private sealed class RecordingProgress(List<string> messages) : IProgress<string>
    {
        public void Report(string value) => messages.Add(value);
    }
}
