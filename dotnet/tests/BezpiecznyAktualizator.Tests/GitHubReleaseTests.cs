using BezpiecznyAktualizator.Core.Updates;

namespace BezpiecznyAktualizator.Tests;

public class GitHubReleaseTests
{
    private const string Hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    [Fact]
    public void ParsesNewerStableMsiReleaseAndDigest()
    {
        var release = GitHubReleaseClient.ParseLatestRelease(ReleaseJson(), new Version(2, 0, 0));
        Assert.NotNull(release);
        Assert.Equal(new Version(2, 1, 0), release.Version);
        Assert.Equal("v2.1.0", release.Tag);
        Assert.Equal(Hash, release.Sha256);
        Assert.Equal(123456, release.Size);
        Assert.Equal("https://github.com/Cragenos/BezpiecznyAktualizator/releases/download/v2.1.0/BezpiecznyAktualizator-2.1.0-win-x64.msi",
            release.InstallerUrl.AbsoluteUri);
    }

    [Fact]
    public void IgnoresCurrentOrOlderReleases() =>
        Assert.Null(GitHubReleaseClient.ParseLatestRelease(ReleaseJson(), new Version(2, 1, 0)));

    [Fact]
    public void ClassifiesCurrentReleaseAsUpToDate() =>
        Assert.Equal(ReleaseCheckStatus.UpToDate,
            GitHubReleaseClient.ParseLatestStatus(ReleaseJson(), new Version(2, 1, 0)));

    [Fact]
    public void RecognizesPatchReleaseAsNewerThanPreviousVersion()
    {
        var json = ReleaseJson().Replace("2.1.0", "2.1.1");
        var release = GitHubReleaseClient.ParseLatestRelease(json, new Version(2, 1, 0));
        Assert.NotNull(release);
        Assert.Equal(new Version(2, 1, 1), release.Version);
        Assert.EndsWith("/BezpiecznyAktualizator-2.1.1-win-x64.msi", release.InstallerUrl.AbsoluteUri);
    }

    [Fact]
    public void ClassifiesMissingInstallerSeparately()
    {
        var json = ReleaseJson().Replace("BezpiecznyAktualizator-2.1.0-win-x64.msi", "other.msi");
        Assert.Equal(ReleaseCheckStatus.MissingInstaller,
            GitHubReleaseClient.ParseLatestStatus(json, new Version(2, 0, 0)));
    }

    [Fact]
    public void ClassifiesPrereleaseAsNoStableRelease()
    {
        var json = ReleaseJson().Replace("\"prerelease\":false", "\"prerelease\":true");
        Assert.Equal(ReleaseCheckStatus.NoRelease,
            GitHubReleaseClient.ParseLatestStatus(json, new Version(2, 0, 0)));
    }

    [Fact]
    public void TreatsPrereleaseTagAsPreviewEvenWhenGitHubFlagIsFalse()
    {
        var json = ReleaseJson().Replace("v2.1.0", "v2.1.0-rc.1");
        Assert.Equal(ReleaseCheckStatus.NoRelease,
            GitHubReleaseClient.ParseLatestStatus(json, new Version(2, 0, 0)));

        var result = GitHubReleaseClient.ParseReleaseList($"[{json}]", new Version(2, 0, 0));
        Assert.True(result.Release?.IsPrerelease);
    }

    [Fact]
    public void IgnoresPrerelease()
    {
        var json = ReleaseJson().Replace("\"prerelease\":false", "\"prerelease\":true");
        Assert.Null(GitHubReleaseClient.ParseLatestRelease(json, new Version(2, 0, 0)));
    }

    [Fact]
    public void IgnoresDraftReleases()
    {
        var json = ReleaseJson().Replace("\"draft\":false", "\"draft\":true");
        Assert.Equal(ReleaseCheckStatus.NoRelease,
            GitHubReleaseClient.ParseLatestStatus(json, new Version(2, 0, 0)));

        var result = GitHubReleaseClient.ParseReleaseList($"[{json}]", new Version(2, 0, 0));
        Assert.Equal(ReleaseCheckStatus.NoRelease, result.Status);
    }

    [Fact]
    public void RejectsMalformedReleaseVersionTags()
    {
        var json = ReleaseJson().Replace("v2.1.0", "v2.1.0-rc..1");
        Assert.Throws<InvalidDataException>(() =>
            GitHubReleaseClient.ParseLatestStatus(json, new Version(2, 0, 0)));
    }

    [Fact]
    public void PreviewChannelSelectsNewerPrereleaseAndUsesNumericMsiVersion()
    {
        var result = GitHubReleaseClient.ParseReleaseList(PreviewReleaseListJson(), new Version(2, 1, 0));
        Assert.Equal(ReleaseCheckStatus.UpdateAvailable, result.Status);
        Assert.NotNull(result.Release);
        Assert.True(result.Release.IsPrerelease);
        Assert.Equal("v2.2.0-rc.1", result.Release.Tag);
        Assert.Equal(new Version(2, 2, 0), result.Release.Version);
        Assert.EndsWith("/BezpiecznyAktualizator-2.2.0-win-x64.msi", result.Release.InstallerUrl.AbsoluteUri);
    }

    [Fact]
    public void PreviewChannelPrefersStableReleaseForSameVersion()
    {
        var json = PreviewReleaseListJson()
            .Replace("v2.2.0-rc.1", "v2.2.0")
            .Replace("\"prerelease\":true", "\"prerelease\":false");
        var result = GitHubReleaseClient.ParseReleaseList(json, new Version(2, 1, 0));
        Assert.NotNull(result.Release);
        Assert.False(result.Release.IsPrerelease);
    }

    [Fact]
    public void PreviewChannelDoesNotOfferCurrentOrOlderNumericVersion()
    {
        var result = GitHubReleaseClient.ParseReleaseList(PreviewReleaseListJson(), new Version(2, 2, 0));
        Assert.Equal(ReleaseCheckStatus.UpToDate, result.Status);
        Assert.Null(result.Release);
    }

    [Fact]
    public void RequiresExpectedMsiAsset()
    {
        var json = ReleaseJson().Replace("BezpiecznyAktualizator-2.1.0-win-x64.msi", "other.msi");
        Assert.Null(GitHubReleaseClient.ParseLatestRelease(json, new Version(2, 0, 0)));
    }

    [Fact]
    public void RejectsNonHttpsOrNonGitHubAssetUrl()
    {
        var json = ReleaseJson().Replace(
            "https://github.com/Cragenos/BezpiecznyAktualizator/releases/download/",
            "http://example.org/releases/download/");
        Assert.Throws<InvalidDataException>(() =>
            GitHubReleaseClient.ParseLatestRelease(json, new Version(2, 0, 0)));
    }

    [Fact]
    public async Task RequiresValidRepositoryName()
    {
        await Assert.ThrowsAsync<ArgumentException>(() =>
            GitHubReleaseClient.GetLatestAsync("../other", new Version(2, 0, 0)));
    }

    private static string ReleaseJson() => $$"""
        {
          "tag_name":"v2.1.0",
          "draft":false,
          "prerelease":false,
          "html_url":"https://github.com/Cragenos/BezpiecznyAktualizator/releases/tag/v2.1.0",
          "body":"Security and reliability improvements.",
          "assets":[
            {
              "name":"BezpiecznyAktualizator-2.1.0-win-x64.msi",
              "size":123456,
              "digest":"sha256:{{Hash}}",
              "browser_download_url":"https://github.com/Cragenos/BezpiecznyAktualizator/releases/download/v2.1.0/BezpiecznyAktualizator-2.1.0-win-x64.msi"
            }
          ]
        }
        """;

    private static string PreviewReleaseListJson() => $$"""
        [{
          "tag_name":"v2.2.0-rc.1",
          "draft":false,
          "prerelease":true,
          "html_url":"https://github.com/Cragenos/BezpiecznyAktualizator/releases/tag/v2.2.0-rc.1",
          "body":"Preview release notes.",
          "assets":[{
            "name":"BezpiecznyAktualizator-2.2.0-win-x64.msi",
            "size":123456,
            "digest":"sha256:{{Hash}}",
            "browser_download_url":"https://github.com/Cragenos/BezpiecznyAktualizator/releases/download/v2.2.0-rc.1/BezpiecznyAktualizator-2.2.0-win-x64.msi"
          }]
        }]
        """;
}
