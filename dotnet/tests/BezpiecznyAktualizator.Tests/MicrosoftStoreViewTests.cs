using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Windows;
using System.Windows.Automation.Peers;
using System.Windows.Automation.Provider;
using System.Windows.Controls;
using System.Windows.Threading;
using BezpiecznyAktualizator.Core.Inventory;
using BezpiecznyAktualizator.Core.Models;
using BezpiecznyAktualizator.Core.Policies;
using BezpiecznyAktualizator.Core.Security;
using BezpiecznyAktualizator.Core.Winget;
using BezpiecznyAktualizator.Views;

namespace BezpiecznyAktualizator.Tests;

[Collection(nameof(SyslogTests))]
public class MicrosoftStoreViewTests
{
    [Fact]
    public void ImportedAppPolicyChecksVerifiedVersionRatherThanSourceComputerVersion()
    {
        var software = new Software { WingetId = "Vendor.App", WingetSource = "winget", Version = "1.0" };
        var policies = new UpdatePolicies
        {
            Holds = [new VersionHold { WingetId = "Vendor.App", Version = "1.0" }],
        };
        var now = DateTimeOffset.Now;

        Assert.Equal(PolicyVerdict.Held, SoftwareView.EvaluateImportPolicy(policies, software, "2.0", now, null).Verdict);
        Assert.Equal(PolicyVerdict.Allowed, SoftwareView.EvaluateImportPolicy(policies, software, "1.0", now, null).Verdict);
        Assert.Equal(PolicyVerdict.MachinePolicyUnavailable,
            SoftwareView.EvaluateImportPolicy(policies, software, "1.0", now, "error").Verdict);
        Assert.Throws<WingetException>(() => SoftwareView.EvaluateImportPolicy(policies, software, "", now, null));
    }

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
                Assert.Equal(5, tabs.Items.Count);
                var profileView = Assert.IsType<ProfileBackupView>(Assert.IsType<TabItem>(tabs.Items[4]).Content);
                Assert.IsType<ComboBox>(profileView.FindName("SourceUser"));
                Assert.IsType<PasswordBox>(profileView.FindName("CreatePassword"));
                Assert.IsType<ComboBox>(profileView.FindName("ConflictBox"));
                var softwareTab = Assert.IsType<TabItem>(tabs.Items[0]);
                var softwareView = Assert.IsType<SoftwareView>(softwareTab.Content);
                var antivirus = Assert.IsType<Button>(softwareView.FindName("AntivirusButton"));
                Assert.True(antivirus.IsEnabled);
                Assert.NotNull(antivirus.ToolTip);
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

                var packages = Enumerable.Range(1, 25)
                    .Select(i => new AppTransferEntry($"Vendor.App{i}", $"App {i}", "winget", "1.0"))
                    .ToList();
                var importWindow = new AppImportWindow(AppTransferManifestFile.Create(packages, "PC"), packages);
                var grid = Assert.IsType<DataGrid>(importWindow.FindName("Packages"));
                var continueButton = Assert.IsType<Button>(importWindow.FindName("ContinueButton"));
                Assert.Equal(25, grid.Items.Count);
                Assert.Empty(importWindow.SelectedApps);
                Assert.False(continueButton.IsEnabled);
                var last = Assert.IsType<AppImportOption>(grid.Items[24]);
                var selectionColumn = Assert.IsType<DataGridTemplateColumn>(grid.Columns[0]);
                var checkbox = Assert.IsType<CheckBox>(selectionColumn.CellTemplate.LoadContent());
                checkbox.DataContext = last;
                var testHost = new ContentControl { Content = checkbox };
                testHost.Measure(new Size(100, 50));
                testHost.Arrange(new Rect(0, 0, 100, 50));
                testHost.UpdateLayout();
                Dispatcher.CurrentDispatcher.Invoke(() => { }, DispatcherPriority.ContextIdle);
                checkbox.GetBindingExpression(CheckBox.IsCheckedProperty)!.UpdateTarget();
                Assert.Same(last, checkbox.GetBindingExpression(CheckBox.IsCheckedProperty)!.DataItem);
                var toggle = Assert.IsAssignableFrom<IToggleProvider>(
                    new CheckBoxAutomationPeer(checkbox).GetPattern(PatternInterface.Toggle));
                toggle.Toggle();
                Assert.Equal("Vendor.App25", Assert.Single(importWindow.SelectedApps).Id);
                Assert.True(continueButton.IsEnabled);
                var selectAll = Assert.IsType<Button>(importWindow.FindName("SelectAllButton"));
                selectAll.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
                Assert.Equal(25, importWindow.SelectedApps.Count);
                var clear = Assert.IsType<Button>(importWindow.FindName("ClearSelectionButton"));
                clear.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
                Assert.Empty(importWindow.SelectedApps);
                Assert.False(continueButton.IsEnabled);
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
