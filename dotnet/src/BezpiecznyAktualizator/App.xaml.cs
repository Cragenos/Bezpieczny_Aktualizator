using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Windows;
using System.Windows.Threading;
using BezpiecznyAktualizator.Core.Drivers;
using BezpiecznyAktualizator.Core.Localization;
using BezpiecznyAktualizator.Core.Logging;
using BezpiecznyAktualizator.Core.Scheduling;
using BezpiecznyAktualizator.Services;
using Application = System.Windows.Application;
using MessageBox = System.Windows.MessageBox;

namespace BezpiecznyAktualizator;

public partial class App : Application
{
    private bool _interactive;
    internal ApplicationTray? TrayIcon { get; private set; }

    protected override void OnStartup(StartupEventArgs e)
    {
        L.Language = Settings.LoadLanguage();
        if (Settings.NvdApiKey is { Length: > 0 } nvdKey) Core.Risk.NvdClient.ApiKey = nvdKey;
        AppDomain.CurrentDomain.UnhandledException += (_, args) =>
            Syslog.Write(SyslogSeverity.Critical, LogEvent.Error, L.T("Nieoczekiwany błąd:") + "\n" + args.ExceptionObject);

        // Wydanie chronione: plik zmieniony po podpisaniu albo uruchomiony pod debugerem nie jest uruchamiany.
        if (SelfProtection.Check() is { } problem)
        {
            Syslog.Write(SyslogSeverity.Alert, LogEvent.Integrity, problem + " " + L.T("Program został zamknięty."));
            if (e.Args.Length == 0)
                MessageBox.Show(problem + "\n\n" + L.T("Ze względów bezpieczeństwa program zostanie zamknięty. Pobierz go ponownie z zaufanego źródła."),
                                "Bezpieczny Aktualizator", MessageBoxButton.OK, MessageBoxImage.Stop);
            Shutdown(3);
            return;
        }
        SelfProtection.StartDebuggerWatch();

        // Tryb bez okna: proces uruchomiony z podniesionymi uprawnieniami do instalacji sterowników.
        if (e.Args.Length == 2 && e.Args[0] == WindowsUpdateDrivers.InstallArgument)
        {
            ShutdownMode = ShutdownMode.OnExplicitShutdown;
            Syslog.Notice(LogEvent.DriverInstall, L.F("Uruchomiono proces instalacji sterowników z uprawnieniami administratora ({0}).", UserDescription()));
            int code;
            try
            {
                code = WindowsUpdateDrivers.RunInstallJob(e.Args[1]);
            }
            catch (Exception ex)
            {
                Syslog.Error(LogEvent.DriverInstall, L.T("Błąd procesu instalacji sterowników."), ex);
                code = 1;
            }
            Syslog.Notice(LogEvent.DriverInstall, L.F("Proces instalacji sterowników zakończony (kod {0}).", code));
            Shutdown(code);
            return;
        }

        // Tryb bez okna: ciche sprawdzanie/aktualizacja uruchamiane przez Harmonogram zadań Windows.
        if (e.Args.Contains(ScheduledTask.RunArgument))
        {
            ShutdownMode = ShutdownMode.OnExplicitShutdown;
            _ = RunScheduledAsync(e.Args.Contains(ScheduledTask.NowArgument));
            return;
        }

        Syslog.Notice(LogEvent.App, L.F("Uruchomiono aplikację {0} ({1}; system: {2}; .NET {3}).",
            typeof(App).Assembly.GetName().Version?.ToString(3), UserDescription(), RuntimeInformation.OSDescription, Environment.Version));
        _interactive = true;
        base.OnStartup(e);
        DispatcherUnhandledException += OnUnhandledException;
        Theme.Apply(Settings.Theme);
        var window = new MainWindow();
        MainWindow = window;
        TrayIcon = new ApplicationTray(window.ShowFromTray, window.ExitFromTray, window.CheckApplicationUpdateFromTray);
        window.Show();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        TrayIcon?.Dispose();
        TrayIcon = null;
        if (_interactive) Syslog.Notice(LogEvent.App, L.F("Zamknięto aplikację (kod {0}).", e.ApplicationExitCode));
        base.OnExit(e);
    }

    private async Task RunScheduledAsync(bool now)
    {
        Syslog.Info(LogEvent.Scheduled, L.F("Uruchomiono tryb cichego sprawdzania ({0}).", UserDescription()));
        int code;
        try
        {
            code = await ScheduledRunner.RunAsync(now);
        }
        catch (Exception ex)
        {
            Syslog.Error(LogEvent.Scheduled, L.T("Błąd cichego sprawdzania."), ex);
            code = 1;
        }
        Shutdown(code);
    }

    private static string UserDescription()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var admin = new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        return L.F("użytkownik: {0}, administrator: {1}", identity.Name, admin ? L.T("tak") : L.T("nie"));
    }

    private static void OnUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        Syslog.Error(LogEvent.Error, L.T("Nieoczekiwany błąd:"), e.Exception);
        MessageBox.Show(L.T("Nieoczekiwany błąd:") + "\n\n" + e.Exception.Message, "Bezpieczny Aktualizator",
                        MessageBoxButton.OK, MessageBoxImage.Error);
        e.Handled = true;
    }
}
