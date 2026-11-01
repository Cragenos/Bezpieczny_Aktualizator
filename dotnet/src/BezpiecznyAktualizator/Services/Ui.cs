using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using BezpiecznyAktualizator.Core.Localization;
using BezpiecznyAktualizator.Core.Logging;
using BezpiecznyAktualizator.Views;
using Microsoft.Win32;

namespace BezpiecznyAktualizator.Services;

/// <summary>Wspólne okna dialogowe, otwieranie adresów i zapis raportów.</summary>
public static class Ui
{
    public static void Info(DependencyObject owner, string title, string text) =>
        MessageDialog.Show(Window.GetWindow(owner), text, title, MessageBoxButton.OK, MessageBoxImage.Information);

    public static void Warn(DependencyObject owner, string title, string text) =>
        MessageDialog.Show(Window.GetWindow(owner), text, title, MessageBoxButton.OK, MessageBoxImage.Warning);

    public static void Error(DependencyObject owner, string title, string text) =>
        MessageDialog.Show(Window.GetWindow(owner), text, title, MessageBoxButton.OK, MessageBoxImage.Error);

    /// <summary>Pytanie Tak/Nie; przy ostrzeżeniach domyślnym (Enter) przyciskiem jest bezpieczniejsze „Nie”.</summary>
    public static bool Confirm(DependencyObject owner, string title, string text, bool warning = false) =>
        MessageDialog.Show(Window.GetWindow(owner), text, title, MessageBoxButton.YesNo,
                           warning ? MessageBoxImage.Warning : MessageBoxImage.Question, defaultNo: warning) == MessageBoxResult.Yes;

    public static MessageBoxResult Ask(DependencyObject owner, string title, string text, MessageBoxButton buttons, MessageBoxImage image) =>
        MessageDialog.Show(Window.GetWindow(owner), text, title, buttons, image);

    /// <summary>Formatuje pary „etykieta: wartość” z wartościami wyrównanymi do najdłuższej (przetłumaczonej) etykiety.</summary>
    public static List<string> FormatFields(IEnumerable<(string Label, string Value)> fields)
    {
        var list = fields.ToList();
        var width = list.Count == 0 ? 0 : list.Max(f => f.Label.Length) + 2;
        return list.Select(f => (f.Label + ":").PadRight(width) + f.Value).ToList();
    }

    public static void OpenUrl(string url) => Process.Start(new ProcessStartInfo(url) { UseShellExecute = true })?.Dispose();

    public static string? AskSavePath(DependencyObject owner, string title, string fileName)
    {
        var dialog = new SaveFileDialog
        {
            Title = title, FileName = fileName, DefaultExt = ".csv", AddExtension = true,
            Filter = "CSV (*.csv)|*.csv|JSON (*.json)|*.json",
        };
        return dialog.ShowDialog(Window.GetWindow(owner)) == true ? dialog.FileName : null;
    }

    /// <summary>Zapisuje wiersze jako JSON (UTF-8) lub CSV (separator „;”, UTF-8 z BOM – czytelne dla Excela).</summary>
    public static void WriteReport(string path, IReadOnlyList<IReadOnlyDictionary<string, object?>> rows)
    {
        if (path.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
        {
            var options = new JsonSerializerOptions { WriteIndented = true, Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };
            File.WriteAllText(path, JsonSerializer.Serialize(rows, options), new UTF8Encoding(false));
            return;
        }
        static string Cell(object? value)
        {
            var s = value switch { null => "", bool b => b ? "True" : "False", _ => value.ToString() ?? "" };
            return s.IndexOfAny([';', '"', '\n', '\r']) >= 0 ? $"\"{s.Replace("\"", "\"\"")}\"" : s;
        }
        var sb = new StringBuilder();
        var headers = rows.Count > 0 ? rows[0].Keys.ToList() : [];
        sb.Append(string.Join(';', headers.Select(Cell))).Append("\r\n");
        foreach (var row in rows)
            sb.Append(string.Join(';', headers.Select(h => Cell(row.GetValueOrDefault(h))))).Append("\r\n");
        File.WriteAllText(path, sb.ToString(), new UTF8Encoding(true));
    }
}

/// <summary>
/// Uruchamia operacje w tle: blokuje pasek narzędzi, pokazuje postęp i status,
/// zapisuje przebieg w dzienniku i prezentuje błędy.
/// </summary>
public sealed class BackgroundRunner(FrameworkElement owner, Panel toolbar, ProgressBar progress, TextBlock status,
                                     TextBox log, Func<string> summary, string defaultEvent)
{
    private int _busy;
    private string? _event;

    public bool IsBusy => _busy > 0;

    /// <summary>Dopisuje wiersz do dziennika w oknie i do pliku syslog (MSGID: bieżąca operacja lub domyślny dla widoku).</summary>
    public void Log(string line, SyslogSeverity severity = SyslogSeverity.Informational, string? msgId = null)
    {
        Append(line);
        Syslog.Write(severity, msgId ?? _event ?? defaultEvent, line);
    }

    private void Append(string line)
    {
        log.AppendText($"[{DateTime.Now:HH:mm:ss}] {line}{Environment.NewLine}");
        log.ScrollToEnd();
    }

    public void SetStatus(string text) => status.Text = text;

    public void UpdateSummary()
    {
        if (!IsBusy) status.Text = summary();
    }

    private void SetBusy(bool busy, string description = "")
    {
        _busy += busy ? 1 : -1;
        toolbar.IsEnabled = _busy == 0;
        progress.IsIndeterminate = _busy > 0;
        progress.Visibility = _busy > 0 ? Visibility.Visible : Visibility.Hidden;
        if (_busy > 0)
        {
            if (description.Length > 0) status.Text = description;
        }
        else
        {
            status.Text = summary();
        }
    }

    /// <summary>Wykonuje <paramref name="work"/>; zwraca false, jeśli wystąpił błąd (już zgłoszony użytkownikowi).</summary>
    public async Task<bool> RunAsync(string msgId, string description, Func<Task> work, params Type[] expectedErrors)
    {
        var previousEvent = _event;
        _event = msgId;
        var watch = Stopwatch.StartNew();
        SetBusy(true, description);
        Log(description);
        try
        {
            await work();
            Syslog.Info(msgId, L.F("Zakończono: {0} ({1:0.0} s)", description, watch.Elapsed.TotalSeconds));
            return true;
        }
        catch (Exception ex)
        {
            var expected = expectedErrors.Any(t => t.IsInstanceOfType(ex));
            var line = L.F("BŁĄD ({0}): {1}", description, ex.Message);
            Append(line);
            if (!expected) Append(ex.ToString());
            Syslog.Error(msgId, line, expected ? null : ex);
            Ui.Error(owner, L.T("Błąd"), $"{description}\n\n{ex.Message}");
            return false;
        }
        finally
        {
            _event = previousEvent;
            SetBusy(false);
        }
    }
}
