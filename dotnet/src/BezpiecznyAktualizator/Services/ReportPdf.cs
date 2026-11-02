using System.Globalization;
using BezpiecznyAktualizator.Core.Localization;
using BezpiecznyAktualizator.Core.Models;
using PdfSharp.Drawing;
using PdfSharp.Fonts;
using PdfSharp.Pdf;

namespace BezpiecznyAktualizator.Services;

public static class ReportPdf
{
    private const double Margin = 32;
    private const double LineHeight = 12;
    private static readonly object FontSettingsLock = new();
    private static bool _fontSettingsConfigured;

    public static void Write(string path, IReadOnlyList<Software> software)
    {
        lock (FontSettingsLock)
        {
            if (!_fontSettingsConfigured)
            {
                GlobalFontSettings.UseWindowsFontsUnderWindows = true;
                _fontSettingsConfigured = true;
            }
        }
        using var document = new PdfDocument();
        document.Info.Title = L.T("Raport zainstalowanego oprogramowania");
        var titleFont = new XFont("Arial", 15, XFontStyleEx.Bold);
        var headerFont = new XFont("Arial", 8.5, XFontStyleEx.Bold);
        var bodyFont = new XFont("Arial", 8.5, XFontStyleEx.Regular);
        XGraphics? graphics = null;
        PdfPage page = null!;
        var y = 0d;
        var headers = new[] { L.T("Nazwa"), L.T("Wersja"), L.T("Dostępna"), L.T("Ryzyko"), L.T("Źródło aktualizacji") };

        void NewPage()
        {
            graphics?.Dispose();
            page = document.AddPage();
            page.Width = XUnit.FromPoint(595.28);
            page.Height = XUnit.FromPoint(841.89);
            graphics = XGraphics.FromPdfPage(page);
            graphics.DrawString(L.T("Raport zainstalowanego oprogramowania"), titleFont, XBrushes.Black,
                new XPoint(Margin, Margin + 15));
            graphics.DrawString(L.F("Wygenerowano: {0}    Programów: {1}    Aktualizacje: {2}    Pilne: {3}",
                    DateTime.Now.ToString("g", CultureInfo.CurrentCulture), software.Count,
                    software.Count(item => item.HasUpdate), software.Count(item => item.IsUrgent)),
                bodyFont, XBrushes.Black, new XPoint(Margin, Margin + 34));
            y = Margin + 52;
            DrawRow(graphics, headerFont, headers, ColumnWidths, y, LineHeight + 2, shaded: true);
            y += LineHeight + 4;
        }

        NewPage();
        foreach (var item in software)
        {
            var cells = Cells(item);
            var wrapped = cells.Select((text, index) => Wrap(text, bodyFont, ColumnWidths[index] - 6, graphics!)).ToArray();
            var lineCount = wrapped.Max(lines => lines.Count);
            var height = Math.Max(LineHeight + 2, lineCount * LineHeight + 2);
            if (y + height > page.Height.Point - Margin)
            {
                NewPage();
                wrapped = cells.Select((text, index) => Wrap(text, bodyFont, ColumnWidths[index] - 6, graphics!)).ToArray();
                lineCount = wrapped.Max(lines => lines.Count);
                height = Math.Max(LineHeight + 2, lineCount * LineHeight + 2);
            }
            for (var column = 0; column < wrapped.Length; column++)
            {
                var x = Margin + ColumnWidths.Take(column).Sum();
                for (var line = 0; line < wrapped[column].Count; line++)
                    graphics!.DrawString(wrapped[column][line], bodyFont, XBrushes.Black,
                        new XPoint(x + 3, y + 9 + line * LineHeight));
            }
            graphics!.DrawLine(XPens.LightGray, Margin, y + height, Margin + ColumnWidths.Sum(), y + height);
            y += height;
        }
        graphics?.Dispose();
        document.Save(path);
    }

    private static readonly double[] ColumnWidths = [150, 70, 70, 145, 96];

    private static string[] Cells(Software item) =>
    [
        item.Name,
        item.Version,
        item.AvailableDisplay,
        string.Join(" | ", new[] { item.RiskDisplay, item.IsUnsupported ? L.T("nieobsługiwany") : "" }
            .Where(value => value.Length > 0)),
        item.SourceDisplay,
    ];

    private static IReadOnlyList<string> Wrap(string text, XFont font, double width, XGraphics graphics)
    {
        if (text.Length == 0) return [""];
        var lines = new List<string>();
        var current = "";
        foreach (var word in text.Split(' ', StringSplitOptions.RemoveEmptyEntries))
        {
            var candidate = current.Length == 0 ? word : current + " " + word;
            if (current.Length > 0 && graphics.MeasureString(candidate, font).Width > width)
            {
                lines.Add(current);
                current = word;
            }
            else current = candidate;
        }
        if (current.Length > 0) lines.Add(current);
        return lines;
    }

    private static void DrawRow(XGraphics graphics, XFont font, IReadOnlyList<string> cells,
        IReadOnlyList<double> widths, double top, double height, bool shaded)
    {
        if (shaded) graphics.DrawRectangle(XBrushes.Gainsboro, Margin, top, widths.Sum(), height);
        for (var index = 0; index < cells.Count; index++)
        {
            var x = Margin + widths.Take(index).Sum();
            graphics.DrawString(cells[index], font, XBrushes.Black, new XPoint(x + 3, top + 9));
        }
    }
}
