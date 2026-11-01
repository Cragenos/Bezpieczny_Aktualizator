using BezpiecznyAktualizator.Core.Security;

namespace BezpiecznyAktualizator.Tests;

public class ChecksumFileTests
{
    private const string H256 = "3fe4ab99fa15629c652944309a2b2bc6e41fc933fc6b63f5df1ebcf3aea68263";
    private static readonly string H512 = new('a', 128);
    private static readonly FileDigests Digests = new(H256, H512);

    [Fact]
    public void ParsesGnuBsdAndReversedFormats()
    {
        var text = "# komentarz\n" +
                   $"{H256}  7z2605-x64.msi\n" +
                   $"{H256.ToUpperInvariant()} *bin/other.exe\r\n" +
                   $"SHA512 (setup.exe) = {H512}\n" +
                   $"SHA-256(tool.zip)= {H256}\n" +
                   $"portable.zip: {H256}\n" +
                   "nie jest to suma\n";
        var entries = ChecksumFiles.Parse(text);
        Assert.Equal(5, entries.Count);
        Assert.Equal(new ChecksumEntry("SHA256", H256, "7z2605-x64.msi"), entries[0]);
        Assert.Equal("bin/other.exe", entries[1].FileName);
        Assert.Equal(H256, entries[1].Hash);
        Assert.Equal(new ChecksumEntry("SHA512", H512, "setup.exe"), entries[2]);
        Assert.Equal("SHA256", entries[3].Algorithm);
        Assert.Equal("portable.zip", entries[4].FileName);
    }

    [Fact]
    public void BsdWithWrongLengthIsIgnored()
    {
        Assert.Empty(ChecksumFiles.Parse($"SHA512 (setup.exe) = {H256}"));
    }

    [Fact]
    public void SingleHashSidecarHasNoName()
    {
        var entries = ChecksumFiles.Parse(H256 + "\n");
        Assert.Single(entries);
        Assert.Null(entries[0].FileName);
        Assert.NotNull(ChecksumFiles.Find(entries, "7z2605-x64.msi", allowUnnamed: true));
        Assert.Null(ChecksumFiles.Find(entries, "7z2605-x64.msi", allowUnnamed: false));
    }

    [Fact]
    public void FindMatchesBaseNameCaseInsensitively()
    {
        var entries = ChecksumFiles.Parse($"{H256} *dist/7Z2605-X64.MSI\n{H512}  other.exe");
        var entry = ChecksumFiles.Find(entries, "7z2605-x64.msi", allowUnnamed: false);
        Assert.NotNull(entry);
        Assert.True(ChecksumFiles.Matches(entry, Digests));
        Assert.Null(ChecksumFiles.Find(entries, "missing.exe", allowUnnamed: true));
    }

    [Fact]
    public void MatchesUsesAlgorithmOfEntry()
    {
        Assert.True(ChecksumFiles.Matches(new("SHA512", H512, null), Digests));
        Assert.False(ChecksumFiles.Matches(new("SHA512", H256, null), Digests));
        Assert.False(ChecksumFiles.Matches(new("SHA256", new string('0', 64), null), Digests));
    }

    [Fact]
    public void CandidatesAreHttpsSidecarsAndDirectoryFiles()
    {
        var list = ChecksumFiles.Candidates("https://example.org/dl/v1/setup%201.exe?x=1");
        Assert.Contains(list, c => c.Sidecar && c.Url.AbsoluteUri == "https://example.org/dl/v1/setup%201.exe.sha256");
        Assert.Contains(list, c => !c.Sidecar && c.Url.AbsoluteUri == "https://example.org/dl/v1/SHA256SUMS");
        Assert.All(list, c => Assert.Equal("https", c.Url.Scheme));
        Assert.Empty(ChecksumFiles.Candidates("http://example.org/setup.exe"));
        Assert.Equal("setup 1.exe", ChecksumFiles.FileNameFromUrl("https://example.org/dl/v1/setup%201.exe?x=1"));
    }

    [Fact]
    public void ParsesGitHubReleaseUrls()
    {
        var r = ChecksumFiles.ParseGitHubRelease("https://github.com/ip7z/7zip/releases/download/26.05/7z2605-x64.msi");
        Assert.Equal(new ChecksumFiles.GitHubRelease("ip7z", "7zip", "26.05", "7z2605-x64.msi"), r);
        Assert.Null(ChecksumFiles.ParseGitHubRelease("https://github.com/ip7z/7zip/archive/refs/tags/26.05.zip"));
        Assert.Null(ChecksumFiles.ParseGitHubRelease("https://example.org/a/b/releases/download/1/x.exe"));
    }

    [Theory]
    [InlineData("SHA256SUMS", true)]
    [InlineData("checksums.txt", true)]
    [InlineData("app-1.0.exe.sha256", true)]
    [InlineData("app-1.0-sha512.txt", true)]
    [InlineData("SHA256SUMS.asc", false)]
    [InlineData("app-1.0.exe", false)]
    [InlineData("readme.md", false)]
    public void RecognisesChecksumAssets(string name, bool expected)
    {
        Assert.Equal(expected, ChecksumFiles.IsChecksumAsset(name, "app-1.0.exe"));
    }

    [Fact]
    public void ComputesSha256AndSha512()
    {
        var path = Path.GetTempFileName();
        try
        {
            File.WriteAllText(path, "abc");
            var d = FileDigests.Compute(path);
            Assert.Equal("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", d.Sha256);
            Assert.StartsWith("ddaf35a193617aba", d.Sha512);
        }
        finally { File.Delete(path); }
    }
}

public class InstallerVerifierTests
{
    private const string H256 = "3fe4ab99fa15629c652944309a2b2bc6e41fc933fc6b63f5df1ebcf3aea68263";
    private static readonly FileDigests Digests = new(H256, new string('a', 128));

    [Fact]
    public void ParsesDownloadedManifest()
    {
        const string yaml = "PackageIdentifier: 7zip.7zip\nPackageVersion: '26.05'\nLocalization:\n  PackageLocale: zh-CN\n" +
                            "Installers:\n  InstallerType: wix\n  InstallerSha256: 3FE4AB99FA15629C652944309A2B2BC6E41FC933FC6B63F5DF1EBCF3AEA68263\n" +
                            "  InstallerUrl: https://github.com/ip7z/7zip/releases/download/26.05/7z2605-x64.msi\n";
        var m = InstallerVerifier.ParseManifest(yaml);
        Assert.Equal("26.05", m.Version);
        Assert.Equal(H256, m.Sha256);
        Assert.Equal("https://github.com/ip7z/7zip/releases/download/26.05/7z2605-x64.msi", m.InstallerUrl);
    }

    [Fact]
    public void ManifestCheckDetectsMismatch()
    {
        Assert.Equal(CheckStatus.Ok, InstallerVerifier.ManifestCheck(new("1", "", H256.ToUpperInvariant()), Digests).Status);
        Assert.Equal(CheckStatus.Fail, InstallerVerifier.ManifestCheck(new("1", "", new string('0', 64)), Digests).Status);
        Assert.Equal(CheckStatus.Warn, InstallerVerifier.ManifestCheck(new("1", "", ""), Digests).Status);
    }

    [Fact]
    public void PublisherEvaluation()
    {
        var good = ("SHA256SUMS", new ChecksumEntry("SHA256", H256, "a.exe"));
        var bad = ("a.exe.sha256", new ChecksumEntry("SHA256", new string('0', 64), null));
        Assert.Equal(CheckStatus.Ok, InstallerVerifier.EvaluatePublisher([good], Digests).Status);
        Assert.Equal(CheckStatus.Fail, InstallerVerifier.EvaluatePublisher([good, bad], Digests).Status);
        Assert.Equal(CheckStatus.Warn, InstallerVerifier.EvaluatePublisher([], Digests).Status);
    }

    [Fact]
    public void SignatureClassification()
    {
        Assert.Equal(SignatureState.Valid, Authenticode.Classify(0));
        Assert.Equal(SignatureState.Unsigned, Authenticode.Classify(unchecked((int)0x800B0100)));
        Assert.Equal(SignatureState.Invalid, Authenticode.Classify(unchecked((int)0x80096010)));
        Assert.Equal(SignatureState.Unknown, Authenticode.Classify(unchecked((int)0x80092013)));
        Assert.Equal(CheckStatus.Fail, InstallerVerifier.SignatureCheck(new(SignatureState.Invalid, 1, "")).Status);
        Assert.Equal(CheckStatus.Warn, InstallerVerifier.SignatureCheck(new(SignatureState.Unsigned, 1, "")).Status);
    }

    [Fact]
    public void VerifiesAuthenticodeSignatures()
    {
        var unsigned = Path.GetTempFileName();
        try
        {
            File.WriteAllText(unsigned, "MZ test");
            Assert.Equal(SignatureState.Unsigned, Authenticode.Verify(unsigned).State);
        }
        finally { File.Delete(unsigned); }
        // Host testów (testhost/dotnet) ma osadzony podpis Microsoft.
        var signed = Authenticode.Verify(Environment.ProcessPath!);
        Assert.NotEqual(SignatureState.Invalid, signed.State);
        Assert.Contains("Microsoft", signed.Signer);
    }
}

[Trait("Category", "Live")]
public class InstallerVerifierLiveTests
{
    [Fact]
    public async Task Verifies7Zip()
    {
        var result = await InstallerVerifier.VerifyAsync("7zip.7zip", "winget");
        Assert.True(result.Completed, result.Error?.ToString());
        Assert.False(result.Blocked);
        Assert.Contains(result.Checks, c => c.Status == CheckStatus.Ok && c.Label.ToString().Contains("wydawcy"));
        // Bez czystego wyniku skanowania Defender instalator nie może zostać uznany za zweryfikowany.
        Assert.Equal(!result.DefenderUnavailable, result.Passed);
        Assert.Equal(result.DefenderUnavailable, result.PassedWithoutScan);
    }
}
