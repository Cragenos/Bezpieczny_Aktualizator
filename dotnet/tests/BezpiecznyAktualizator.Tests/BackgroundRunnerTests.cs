using System.Runtime.ExceptionServices;
using System.Windows.Controls;
using BezpiecznyAktualizator.Core.Logging;
using BezpiecznyAktualizator.Services;

namespace BezpiecznyAktualizator.Tests;

[Collection(nameof(SyslogTests))]
public class BackgroundRunnerTests
{
    [Fact]
    public void IndependentOperationDoesNotUseSharedResourceGuard()
    {
        Exception? failure = null;
        var thread = new Thread(() =>
        {
            var logEnabled = Syslog.Enabled;
            try
            {
                Syslog.Enabled = false;
                var checks = 0;
                var runs = 0;
                var toolbar = new WrapPanel();
                var log = new TextBox();
                var runner = new BackgroundRunner(new Border(), toolbar, new ProgressBar(), new TextBlock(), log,
                    () => "ready", LogEvent.Antivirus, () => { checks++; return false; });
                Assert.False(runner.RunAsync(LogEvent.Antivirus, "guarded test", () =>
                    { runs++; return Task.CompletedTask; }).GetAwaiter().GetResult());
                Assert.True(runner.RunIndependentAsync(LogEvent.Antivirus, "independent test", () =>
                    { runs++; return Task.CompletedTask; }).GetAwaiter().GetResult());
                Assert.Equal(1, checks);
                Assert.Equal(1, runs);
                Assert.False(runner.IsBusy);
                Assert.True(toolbar.IsEnabled);
                Assert.Contains("independent test", log.Text);
            }
            catch (Exception ex)
            {
                failure = ex;
            }
            finally
            {
                Syslog.Enabled = logEnabled;
            }
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        Assert.True(thread.Join(TimeSpan.FromSeconds(15)), "The WPF test did not finish.");
        if (failure is not null) ExceptionDispatchInfo.Capture(failure).Throw();
    }
}
