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
    public void IgnoresPrerelease()
    {
        var json = ReleaseJson().Replace("\"prerelease\":false", "\"prerelease\":true");
        Assert.Null(GitHubReleaseClient.ParseLatestRelease(json, new Version(2, 0, 0)));
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
}
