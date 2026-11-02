using System.Security.Cryptography;
using System.Net;
using BezpiecznyAktualizator.Services;
using BezpiecznyAktualizator.Core.Updates;

namespace BezpiecznyAktualizator.Tests;

public class ApplicationUpdateServiceTests
{
    [Fact]
    [Trait("Category", "WindowsIntegration")]
    public async Task HashingReleaseInstallerClosesFileBeforePromotion()
    {
        var directory = Path.Combine(Path.GetTempPath(), "ba-update-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var partial = Path.Combine(directory, "installer.download");
        var final = Path.Combine(directory, "installer.msi");
        var payload = Enumerable.Range(0, 8192).Select(index => (byte)(index % 251)).ToArray();
        await File.WriteAllBytesAsync(partial, payload);
        try
        {
            var actual = await ApplicationUpdateService.HashFileAsync(partial);
            Assert.Equal(SHA256.HashData(payload), actual);
            File.Move(partial, final);
            Assert.Equal(payload, await File.ReadAllBytesAsync(final));
        }
        finally
        {
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task DownloadFailureDoesNotLeavePartialInstaller()
    {
        var directory = Path.Combine(Path.GetTempPath(), "ba-update-" + Guid.NewGuid().ToString("N"));
        using var response = new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);
        using var client = new HttpClient(new StubHandler(response));
        var release = TestRelease(3);
        try
        {
            await Assert.ThrowsAsync<HttpRequestException>(() =>
                ApplicationUpdateService.DownloadAndVerifyCoreAsync(release, [new string('A', 40)], client, directory));
            Assert.Empty(Directory.GetFiles(directory));
        }
        finally
        {
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task DigestMismatchDeletesDownloadedInstaller()
    {
        var directory = Path.Combine(Path.GetTempPath(), "ba-update-" + Guid.NewGuid().ToString("N"));
        using var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent([1, 2, 3]),
        };
        using var client = new HttpClient(new StubHandler(response));
        var release = TestRelease(3);
        try
        {
            await Assert.ThrowsAsync<InvalidDataException>(() =>
                ApplicationUpdateService.DownloadAndVerifyCoreAsync(release, [new string('A', 40)], client, directory));
            Assert.Empty(Directory.GetFiles(directory));
        }
        finally
        {
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
        }
    }

    private static ApplicationRelease TestRelease(long size) => new(
        new Version(1, 0), "v1.0", new Uri("https://example.invalid/update.msi"), new string('0', 64), size,
        "https://example.invalid/release", "");

    private sealed class StubHandler(HttpResponseMessage response) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(response);
    }
}
