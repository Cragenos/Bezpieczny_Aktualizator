using System.Text;
using System.Text.RegularExpressions;
using BezpiecznyAktualizator.Core.Logging;

namespace BezpiecznyAktualizator.Tests;

/// <summary>Format RFC 5424 i zapis do pliku. Klasa nie działa równolegle z innymi (stan statyczny Syslog).</summary>
[Collection(nameof(SyslogTests))]
public partial class SyslogTests
{
    private static readonly DateTimeOffset Time = new(2026, 10, 30, 16, 18, 0, 278, TimeSpan.FromHours(1));

    [Fact]
    public void FormatMatchesRfc5424Grammar()
    {
        var line = Syslog.Format(SyslogSeverity.Informational, LogEvent.Scan, "Znaleziono 246 programów", Time, 7, "pl");
        var m = Rfc5424().Match(line);
        Assert.True(m.Success, line);
        Assert.Equal("14", m.Groups["pri"].Value); // facility user (1) * 8 + informational (6)
        Assert.Equal("2026-10-30T16:18:00.278000+01:00", m.Groups["ts"].Value);
        Assert.Equal(Syslog.AppName, m.Groups["app"].Value);
        Assert.Equal(Environment.ProcessId.ToString(), m.Groups["proc"].Value);
        Assert.Equal("SW_SCAN", m.Groups["msgid"].Value);
        Assert.Contains("[origin software=\"BezpiecznyAktualizator\" swVersion=\"", m.Groups["sd"].Value);
        Assert.EndsWith("[meta sequenceId=\"7\" language=\"pl\"]", m.Groups["sd"].Value);
        Assert.Equal("\uFEFFZnaleziono 246 programów", m.Groups["msg"].Value);
    }

    [Theory]
    [InlineData(SyslogSeverity.Emergency, 8)]
    [InlineData(SyslogSeverity.Error, 11)]
    [InlineData(SyslogSeverity.Warning, 12)]
    [InlineData(SyslogSeverity.Notice, 13)]
    [InlineData(SyslogSeverity.Debug, 15)]
    public void PriorityCombinesFacilityAndSeverity(SyslogSeverity severity, int pri) =>
        Assert.StartsWith($"<{pri}>1 ", Syslog.Format(severity, "X", "", Time, 1, "en"));

    [Fact]
    public void MultilineMessagesStayOnOneLine()
    {
        var line = Syslog.Format(SyslogSeverity.Error, LogEvent.Error, "Błąd\r\nStack\tline\nnext", Time, 1, "pl");
        Assert.DoesNotContain('\n', line);
        Assert.DoesNotContain('\r', line);
        Assert.EndsWith("\uFEFFBłąd#012Stack#011line#012next", line);
    }

    [Fact]
    public void EmptyMessageHasNoMsgPart() =>
        Assert.EndsWith("language=\"en\"]", Syslog.Format(SyslogSeverity.Notice, "APP", "", Time, 1, "en"));

    [Fact]
    public void HeaderFieldsArePrintableAscii()
    {
        Assert.Equal("-", Syslog.Header("", 32));
        Assert.Equal("Za_____x", Syslog.Header("Zażółć x", 32));
        Assert.Equal("Za____", Syslog.Header("Zażółć gęślą", 6));
        Assert.Equal(32, Syslog.Header(new string('A', 50), 32).Length);
    }

    [Fact]
    public void StructuredDataValuesAreEscaped() =>
        Assert.Equal("a\\\"b\\\\c\\]d", Syslog.SdValue("a\"b\\c]d"));

    [Theory]
    [InlineData("pt", "pt-BR")]
    [InlineData("zh", "zh-Hans")]
    [InlineData("de", "de")]
    public void LanguageTagsFollowRfc4646(string code, string tag) => Assert.Equal(tag, Syslog.LanguageTag(code));

    [Fact]
    public void WritesUtf8LinesAndRotates()
    {
        var dir = Path.Combine(Path.GetTempPath(), "BA-syslog-" + Guid.NewGuid().ToString("N"));
        var (oldDir, oldSize, oldArchives) = (Syslog.Directory, Syslog.MaxFileSize, Syslog.MaxArchives);
        try
        {
            Syslog.Configure(dir);
            Syslog.MaxFileSize = 1024;
            Syslog.MaxArchives = 2;
            for (var i = 0; i < 40; i++) Syslog.Info(LogEvent.App, $"komunikat {i} – zażółć gęślą jaźń");
            Assert.Null(Syslog.LastError);

            var lines = File.ReadAllLines(Syslog.FilePath, Encoding.UTF8);
            Assert.NotEmpty(lines);
            Assert.All(lines, l => Assert.Matches(Rfc5424(), l));
            Assert.EndsWith("komunikat 39 – zażółć gęślą jaźń", lines[^1]);
            Assert.True(new FileInfo(Syslog.FilePath).Length <= 1024);
            Assert.True(File.Exists(Syslog.FilePath + ".1"));
            Assert.True(File.Exists(Syslog.FilePath + ".2"));
            Assert.False(File.Exists(Syslog.FilePath + ".3"));

            var sequence = lines.Select(l => int.Parse(SequenceId().Match(l).Groups[1].Value)).ToList();
            Assert.Equal(sequence.Order().ToList(), sequence);
        }
        finally
        {
            Syslog.Configure(oldDir);
            Syslog.MaxFileSize = oldSize;
            Syslog.MaxArchives = oldArchives;
            try { Directory.Delete(dir, true); } catch (IOException) { }
        }
    }

    [Fact]
    public void ReadsRecentWarningsAndErrorsFromCurrentAndRotatedLogs()
    {
        var dir = Path.Combine(Path.GetTempPath(), "BA-syslog-issues-" + Guid.NewGuid().ToString("N"));
        var oldDir = Syslog.Directory;
        try
        {
            Syslog.Configure(dir);
            Directory.CreateDirectory(dir);
            File.WriteAllLines(Syslog.FilePath,
            [
                Syslog.Format(SyslogSeverity.Warning, "WARN", "new warning", Time.AddMinutes(2), 1, "en"),
                Syslog.Format(SyslogSeverity.Informational, "INFO", "not an issue", Time.AddMinutes(3), 2, "en"),
                Syslog.Format(SyslogSeverity.Error, "ERROR", "new error", Time.AddMinutes(4), 3, "en"),
            ]);
            File.WriteAllLines(Syslog.FilePath + ".1",
                [Syslog.Format(SyslogSeverity.Error, "ERROR", "old error", Time, 4, "en")]);

            var issues = Syslog.ReadRecentIssues(3);
            Assert.Equal(3, issues.Count);
            Assert.Contains("new error", issues[0]);
            Assert.Contains("new warning", issues[1]);
            Assert.Contains("old error", issues[2]);
            Assert.DoesNotContain(issues, line => line.Contains("not an issue", StringComparison.Ordinal));
        }
        finally
        {
            Syslog.Configure(oldDir);
            Directory.Delete(dir, true);
        }
    }

    // RFC 5424: PRI VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID SP STRUCTURED-DATA [SP MSG]
    [GeneratedRegex("""^<(?<pri>\d{1,3})>1 (?<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})) (?<host>[!-~]{1,255}) (?<app>[!-~]{1,48}) (?<proc>[!-~]{1,128}) (?<msgid>[!-~]{1,32}) (?<sd>-|(?:\[[^ =\]"]{1,32}(?: [^ =\]"]{1,32}="(?:[^"\\\]]|\\.)*")*\])+)(?: (?<msg>.*))?$""")]
    private static partial Regex Rfc5424();

    [GeneratedRegex(@"sequenceId=""(\d+)""")]
    private static partial Regex SequenceId();
}
