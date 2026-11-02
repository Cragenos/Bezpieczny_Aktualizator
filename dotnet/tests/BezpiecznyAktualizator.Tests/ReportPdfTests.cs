using BezpiecznyAktualizator.Core.Models;
using BezpiecznyAktualizator.Services;
using PdfSharp.Pdf.IO;

namespace BezpiecznyAktualizator.Tests;

public class ReportPdfTests
{
    [Fact]
    public void WritesReadableMultipagePdf()
    {
        var path = Path.Combine(Path.GetTempPath(), $"ba-report-{Guid.NewGuid():N}.pdf");
        try
        {
            var items = Enumerable.Range(1, 100).Select(index => new Software
            {
                Name = $"Test application {index}",
                Version = "1.0.0",
                AvailableVersion = "1.1.0",
                WingetSource = "winget",
            }).ToList();
            ReportPdf.Write(path, items);

            Assert.True(File.ReadAllBytes(path).AsSpan(0, 5).SequenceEqual("%PDF-"u8));
            using var document = PdfReader.Open(path, PdfDocumentOpenMode.Import);
            Assert.True(document.PageCount >= 2);
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }
}
