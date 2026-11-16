using System.Runtime.ExceptionServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
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

    [Fact]
    public void CancellingAnOperationRestoresTheUiAndIsNotReportedAsAnError()
    {
        Exception? failure = null;
        var thread = new Thread(() =>
        {
            var logEnabled = Syslog.Enabled;
            try
            {
                Syslog.Enabled = false;
                var dispatcher = Dispatcher.CurrentDispatcher;
                SynchronizationContext.SetSynchronizationContext(new DispatcherSynchronizationContext(dispatcher));
                var toolbar = new WrapPanel();
                var cancelButton = new Button { Visibility = Visibility.Collapsed };
                var log = new TextBox();
                var runner = new BackgroundRunner(new Border(), toolbar, new ProgressBar(), new TextBlock(), log,
                    () => "ready", LogEvent.UpdateCheck, cancelButton: cancelButton);
                var operation = runner.RunCancellableAsync(LogEvent.UpdateCheck, "cancellable test",
                    ct => Task.Delay(Timeout.Infinite, ct));
                var frame = new DispatcherFrame();
                _ = operation.ContinueWith(_ => dispatcher.BeginInvoke(() => frame.Continue = false),
                    CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);

                Assert.True(runner.IsBusy);
                Assert.False(toolbar.IsEnabled);
                Assert.Equal(Visibility.Visible, cancelButton.Visibility);
                Assert.True(cancelButton.IsEnabled);

                runner.CancelCurrentOperation();
                Dispatcher.PushFrame(frame);

                Assert.False(operation.GetAwaiter().GetResult());
                Assert.False(runner.IsBusy);
                Assert.True(toolbar.IsEnabled);
                Assert.Equal(Visibility.Collapsed, cancelButton.Visibility);
                Assert.Contains("Anulowano: cancellable test", log.Text);
                Assert.DoesNotContain("BŁĄD", log.Text);
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
