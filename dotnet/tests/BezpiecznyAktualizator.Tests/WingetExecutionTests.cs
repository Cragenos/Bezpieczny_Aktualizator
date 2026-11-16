using BezpiecznyAktualizator.Core.Logging;
using BezpiecznyAktualizator.Core.Models;
using BezpiecznyAktualizator.Core.Winget;

namespace BezpiecznyAktualizator.Tests;

[Collection(nameof(SyslogTests))]
public sealed class WingetExecutionTests : IDisposable
{
    private readonly string _originalLogDirectory = Syslog.Directory;
    private readonly string _logDirectory = Path.Combine(Path.GetTempPath(), "winget-tests-" + Guid.NewGuid().ToString("N"));

    public WingetExecutionTests() => Syslog.Configure(_logDirectory);

    public void Dispose()
    {
        Syslog.Configure(_originalLogDirectory);
        if (Directory.Exists(_logDirectory)) Directory.Delete(_logDirectory, recursive: true);
    }

    [Theory]
    [InlineData("list|--disable-interactivity")]
    [InlineData("search|--query|Example")]
    [InlineData("show|--id|Example.App|--exact")]
    [InlineData("upgrade|--include-unknown|--accept-source-agreements|--disable-interactivity")]
    [InlineData("upgrade|--source|msstore|--accept-source-agreements|--disable-interactivity")]
    public async Task RetriesOnlyTheSameSourceReadOnce(string command)
    {
        var args = command.Split('|');
        var calls = 0;
        using var cts = new CancellationTokenSource();
        var result = await WingetClient.RunWithSourceRetryAsync(args, (actual, ct) =>
        {
            Assert.Equal(args, actual);
            Assert.Equal(cts.Token, ct);
            calls++;
            return Task.FromResult(calls == 1
                ? (WingetClient.SourceCacheMissingCode, "source cache unavailable")
                : (0, "read succeeded"));
        }, cts.Token);
        Assert.Equal(2, calls);
        Assert.Equal((0, "read succeeded"), result);
        Assert.Contains("0x80071130", File.ReadAllText(Syslog.FilePath));
    }

    [Fact]
    public async Task PersistentCacheFailureIsNotReportedAsAnEmptyOrPartialSuccess()
    {
        var calls = 0;
        var error = await Assert.ThrowsAsync<WingetException>(() =>
            WingetClient.RunWithSourceRetryAsync(["list"], (_, _) =>
            {
                calls++;
                return Task.FromResult((WingetClient.SourceCacheMissingCode, WingetParsingTests.ListOutput));
            }));
        Assert.Equal(2, calls);
        Assert.Contains("0x80071130", error.Message);
        Assert.Contains("7zip.7zip", error.Message);
    }

    [Theory]
    [InlineData("upgrade|--id|Example.App|--exact")]
    [InlineData("upgrade|--manifest|example.yaml")]
    [InlineData("upgrade|--all")]
    [InlineData("upgrade|-r")]
    [InlineData("upgrade|Example.App")]
    [InlineData("install|--id|Example.App")]
    [InlineData("download|--id|Example.App")]
    [InlineData("source|reset")]
    public async Task NeverRetriesMutatingCommands(string command)
    {
        var calls = 0;
        var result = await WingetClient.RunWithSourceRetryAsync(command.Split('|'), (_, _) =>
        {
            calls++;
            return Task.FromResult((WingetClient.SourceCacheMissingCode, "error"));
        });
        Assert.Equal(1, calls);
        Assert.Equal(WingetClient.SourceCacheMissingCode, result.Code);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(unchecked((int)0x8A150002))]
    [InlineData(unchecked((int)0x8A150011))]
    public async Task DoesNotRetryOtherResults(int code)
    {
        var calls = 0;
        var result = await WingetClient.RunWithSourceRetryAsync(["list"], (_, _) =>
        {
            calls++;
            return Task.FromResult((code, "original output"));
        });
        Assert.Equal(1, calls);
        Assert.Equal((code, "original output"), result);
    }

    [Fact]
    public async Task CancellationPreventsTheRetry()
    {
        using var cts = new CancellationTokenSource();
        var calls = 0;
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            WingetClient.RunWithSourceRetryAsync(["list"], (_, _) =>
            {
                calls++;
                cts.Cancel();
                return Task.FromResult((WingetClient.SourceCacheMissingCode, "error"));
            }, cts.Token));
        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task CommandsDoNotOverlapAndCancelledWaitersDoNotRun()
    {
        var release = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
        var first = WingetClient.WithCommandGateAsync(() => release.Task, CancellationToken.None);
        using var cts = new CancellationTokenSource();
        var secondRan = false;
        var second = WingetClient.WithCommandGateAsync(() =>
        {
            secondRan = true;
            return Task.FromResult(2);
        }, cts.Token);
        try
        {
            Assert.False(second.IsCompleted);
            cts.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => second);
            Assert.False(secondRan);
        }
        finally
        {
            release.TrySetResult(1);
            await first;
        }
        Assert.Equal(3, await WingetClient.WithCommandGateAsync(() => Task.FromResult(3), CancellationToken.None));
    }

    [Fact]
    public async Task FailedCommandsReleaseTheGate()
    {
        await Assert.ThrowsAsync<IOException>(() => WingetClient.WithCommandGateAsync<int>(
            () => throw new IOException("test failure"), CancellationToken.None));
        Assert.Equal(1, await WingetClient.WithCommandGateAsync(() => Task.FromResult(1), CancellationToken.None));
    }

    [Fact]
    public async Task CommandGateIsSharedWithOtherProcessHandles()
    {
        await WingetClient.WithCommandGateAsync(() => Task.FromResult(0), CancellationToken.None);
        using var otherProcessGate = Mutex.OpenExisting(WingetClient.ProcessCommandGateName);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var operation = WingetClient.WithCommandGateAsync(async () =>
        {
            entered.SetResult();
            await release.Task;
            return 0;
        }, CancellationToken.None);

        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        var wasAvailableWhileHeld = otherProcessGate.WaitOne(0);
        if (wasAvailableWhileHeld) otherProcessGate.ReleaseMutex();
        release.SetResult();
        await operation;
        Assert.False(wasAvailableWhileHeld);
        Assert.True(otherProcessGate.WaitOne(TimeSpan.FromSeconds(1)));
        otherProcessGate.ReleaseMutex();
    }

    [Fact]
    public async Task CancelledUpdateCheckPreservesTheExistingSoftwareState()
    {
        var software = new Software
        {
            Name = "Example App", Version = "1.0", WingetDetected = true, WingetId = "Example.App",
            WingetSource = "winget", AvailableVersion = "2.0",
        };
        using var cts = new CancellationTokenSource();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => WingetClient.CheckUpdatesCoreAsync(
            [software],
            _ => Task.FromResult(new List<WingetPackage> { new("Example App", "Example.App", "1.0", "", "winget") }),
            _ =>
            {
                cts.Cancel();
                return Task.FromResult(new List<WingetPackage> { new("Example App", "Example.App", "1.0", "3.0", "winget") });
            },
            cts.Token));

        Assert.True(software.WingetDetected);
        Assert.Equal("Example.App", software.WingetId);
        Assert.Equal("winget", software.WingetSource);
        Assert.Equal("2.0", software.AvailableVersion);
    }

    [Fact]
    public async Task SuccessfulUpdateCheckReturnsUpdatedCopies()
    {
        var software = new Software { Name = "Example App", Version = "1.0", Origin = "HKLM" };
        var (items, count) = await WingetClient.CheckUpdatesCoreAsync(
            [software],
            _ => Task.FromResult(new List<WingetPackage> { new("Example App", "Example.App", "1.0", "", "winget") }),
            _ => Task.FromResult(new List<WingetPackage> { new("Example App", "Example.App", "1.0", "2.0", "winget") }));

        Assert.Equal(1, count);
        Assert.True(items.Single().CanUpgrade);
        Assert.False(software.WingetDetected);
        Assert.Null(software.WingetId);
        Assert.Empty(software.AvailableVersion);
    }

    [Fact]
    public async Task AcceptsExplicitlyEnabledLocalManifestsWithoutChangingSettings()
    {
        await WingetClient.EnsureLocalManifestFilesEnabledCoreAsync((args, _) =>
        {
            Assert.Equal(["settings", "export", "--disable-interactivity"], args);
            return Task.FromResult((0, """{"adminSettings":{"LocalManifestFiles":true}}"""));
        });
    }

    [Theory]
    [InlineData(true, """{"adminSettings":{"LocalManifestFiles":true}}""")]
    [InlineData(false, """{"adminSettings":{"LocalManifestFiles":false}}""")]
    public async Task ReportsLocalManifestSettingWithoutChangingIt(bool expected, string output)
    {
        var enabled = await WingetClient.IsLocalManifestFilesEnabledCoreAsync((args, _) =>
        {
            Assert.Equal(["settings", "export", "--disable-interactivity"], args);
            return Task.FromResult((0, output));
        });

        Assert.Equal(expected, enabled);
    }

    [Theory]
    [InlineData(0, """{"adminSettings":{"LocalManifestFiles":false}}""")]
    [InlineData(0, "{}")]
    [InlineData(0, "[]")]
    [InlineData(0, """{"adminSettings":null}""")]
    [InlineData(0, """{"adminSettings":{"LocalManifestFiles":"true"}}""")]
    [InlineData(0, "not json")]
    [InlineData(1, """{"adminSettings":{"LocalManifestFiles":true}}""")]
    public async Task RejectsDisabledUnknownOrUnreadableLocalManifestSettings(int code, string output)
    {
        var calls = 0;
        var error = await Assert.ThrowsAsync<WingetException>(() =>
            WingetClient.EnsureLocalManifestFilesEnabledCoreAsync((args, _) =>
            {
                Assert.Equal(["settings", "export", "--disable-interactivity"], args);
                calls++;
                return Task.FromResult((code, output));
            }));
        Assert.Equal(1, calls);
        Assert.Contains("LocalManifestFiles", error.Message);
        Assert.DoesNotContain("usage: winget", error.Message);
    }
}
