using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Windows;
using System.Windows.Controls;
using BezpiecznyAktualizator.Core.Models;
using BezpiecznyAktualizator.Core.Security;
using BezpiecznyAktualizator.Views;

namespace BezpiecznyAktualizator.Tests;

public class MicrosoftStoreViewTests
{
    [Fact]
    public void MainWindowContainsStoreTabWithExpectedControls()
    {
        Exception? failure = null;
        var thread = new Thread(() =>
        {
            try
            {
                var app = new App();
                app.InitializeComponent();
                var window = new MainWindow();
                var tabs = Assert.IsType<TabControl>(window.FindName("Tabs"));
                Assert.Equal(4, tabs.Items.Count);
                var tab = Assert.IsType<TabItem>(tabs.Items[3]);
                var view = Assert.IsType<MicrosoftStoreView>(tab.Content);
                var toolbar = Assert.IsType<WrapPanel>(view.FindName("Toolbar"));
                Assert.Equal(4, toolbar.Children.Count);
                var table = Assert.IsType<DataGrid>(view.FindName("Table"));
                Assert.Equal(6, table.Columns.Count);
                Assert.Empty(table.Items);
                var details = Assert.IsType<TextBox>(view.FindName("Details"));
                Assert.IsType<TextBox>(view.FindName("LogBox"));
                Assert.False(view.IsBusy);
                var items = new List<Software>
                {
                    new() { Name = "Example Notes", WingetId = "9WZDNCRFHVJL", WingetSource = "msstore",
                            Version = "1.0", AvailableVersion = "1.2", WingetDetected = true, SecurityLevel = Levels.High },
                    new() { Name = "Example Editor", WingetId = "9NBLGGH4NNS1", WingetSource = "msstore",
                            Version = "2.0", AvailableVersion = "2.4", WingetDetected = true, SecurityLevel = Levels.High },
                };
                typeof(MicrosoftStoreView).GetMethod("SetItems", BindingFlags.NonPublic | BindingFlags.Instance)!.Invoke(view, [items]);
                var filter = Assert.IsType<TextBox>(view.FindName("FilterBox"));
                filter.Text = "Notes";
                Assert.Single(table.Items);
                filter.Text = "";
                Assert.Equal(2, table.Items.Count);
                table.SelectedIndex = 0;
                Assert.Contains("Example Notes", details.Text);
                Assert.Contains("1.2", details.Text);
                tabs.SelectedIndex = 3;
                var root = Assert.IsAssignableFrom<FrameworkElement>(window.Content);
                root.Measure(new Size(1200, 800));
                root.Arrange(new Rect(0, 0, 1200, 800));
                root.UpdateLayout();
                app.Shutdown();
            }
            catch (Exception ex)
            {
                failure = ex;
            }
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        Assert.True(thread.Join(TimeSpan.FromSeconds(15)), "The WPF test did not finish.");
        if (failure is not null) ExceptionDispatchInfo.Capture(failure).Throw();
    }
}
