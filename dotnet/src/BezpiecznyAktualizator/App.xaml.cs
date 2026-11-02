using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Windows;
using System.Windows.Threading;
using BezpiecznyAktualizator.Core.Drivers;
using BezpiecznyAktualizator.Core.Localization;
using BezpiecznyAktualizator.Core.Logging;
using BezpiecznyAktualizator.Core.Scheduling;
using BezpiecznyAktualizator.Core.Updates;
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

        if (e.Args.Length > 0 && e.Args[0] == WindowsUpdateAgent.OperationArgument)
        {
            ShutdownMode = ShutdownMode.OnExplicitShutdown;
            _ = RunWindowsUpdateOperationAsync(e.Args);
            return;
        }

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

    private async Task RunWindowsUpdateOperationAsync(string[] args)
    {
        var exitCode = 1;
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
                throw new WindowsUpdateException(L.T("Operacja Windows Update wymaga uprawnień administratora."));
            if (args.Length != 3 || args[1] is not ("download" or "install"))
                throw new WindowsUpdateException(L.T("Nieprawidłowa operacja Windows Update."));
            var action = args[1] == "download" ? WindowsUpdateAction.Download : WindowsUpdateAction.Install;
            var selected = WindowsUpdateAgent.ParseSelection(args[2]);
            var report = await Task.Run(() => WindowsUpdateAgent.Execute(action, selected));
            var lines = new List<string>();
            foreach (var result in report.Outcomes)
            {
                var status = result.ResultCode switch
                {
                    2 => L.T("Zakończono pomyślnie"),
                    3 => L.T("Zakończono z błędami"),
                    5 => L.T("Przerwano"),
                    _ => L.T("Błąd"),
                };
                var line = $"{result.Title}: {status}";
                if (result.HResult != 0) line += $" (0x{unchecked((uint)result.HResult):X8})";
                if (result.Message.Length > 0) line += " - " + result.Message;
                lines.Add(line);
                Syslog.Write(result.Succeeded ? SyslogSeverity.Notice : SyslogSeverity.Error, LogEvent.WindowsUpdate, line);
            }
            foreach (var warning in report.Warnings) Syslog.Warning(LogEvent.WindowsUpdate, warning);
            var message = L.F("Pomyślnie: {0} z {1}.", report.Outcomes.Count(o => o.Succeeded), report.Outcomes.Count) +
                          "\n\n" + string.Join("\n", lines.Take(20));
            if (lines.Count > 20) message += "\n…";
            if (report.Warnings.Count > 0) message += "\n\n" + string.Join("\n", report.Warnings);
            if (report.RebootRequired)
                message += "\n\n" + L.T("Wymagane jest ponowne uruchomienie komputera, aby zakończyć instalację.");
            MessageBox.Show(message, L.T("Windows Update"), MessageBoxButton.OK,
                report.Succeeded ? MessageBoxImage.Information : MessageBoxImage.Warning);
            exitCode = report.Succeeded ? (report.RebootRequired ? 3010 : 0) : (report.RebootRequired ? 3011 : 1);
        }
        catch (Exception ex)
        {
            Syslog.Error(LogEvent.WindowsUpdate, L.T("Błąd operacji Windows Update."), ex);
            MessageBox.Show(ex.Message, L.T("Windows Update"), MessageBoxButton.OK, MessageBoxImage.Error);
        }
        Shutdown(exitCode);
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
