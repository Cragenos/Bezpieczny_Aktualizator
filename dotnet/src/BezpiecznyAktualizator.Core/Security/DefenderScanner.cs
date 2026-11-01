using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;

namespace BezpiecznyAktualizator.Core.Security;

public enum DefenderVerdict { Clean, Threat, Unavailable }

public sealed record DefenderScan(DefenderVerdict Verdict, IReadOnlyList<string> Threats, string Detail);

/// <summary>
/// Skanowanie pliku programem Microsoft Defender z wiersza poleceń (MpCmdRun.exe -Scan -ScanType 3 -File).
/// Używany jest parametr -DisableRemediation, aby skaner tylko raportował (plik i tak zostanie usunięty po weryfikacji).
/// Kod wyjścia 2 oznacza zarówno wykrycie zagrożenia, jak i błąd (np. gdy Defender jest wyłączony przez inny antywirus),
/// dlatego wynik jest ustalany na podstawie treści raportu.
/// </summary>
public static partial class DefenderScanner
{
    private static readonly TimeSpan Timeout = TimeSpan.FromMinutes(5);

    /// <summary>Najnowsza wersja MpCmdRun.exe (platforma z ProgramData ma pierwszeństwo przed Program Files).</summary>
    public static string? FindMpCmdRun()
    {
        try
        {
            var platform = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                                        "Microsoft", "Windows Defender", "Platform");
            if (Directory.Exists(platform))
            {
                var latest = Directory.GetDirectories(platform)
                    .Select(d => (Dir: d, Version: Version.TryParse(Path.GetFileName(d).Split('-')[0], out var v) ? v : null))
                    .Where(x => x.Version is not null && File.Exists(Path.Combine(x.Dir, "MpCmdRun.exe")))
                    .OrderByDescending(x => x.Version).FirstOrDefault();
                if (latest.Dir is not null) return Path.Combine(latest.Dir, "MpCmdRun.exe");
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        var fallback = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Windows Defender", "MpCmdRun.exe");
        return File.Exists(fallback) ? fallback : null;
    }

    /// <summary>Interpretuje wynik MpCmdRun.</summary>
    public static DefenderScan Parse(int exitCode, string output)
    {
        var threats = ThreatLine().Matches(output).Select(m => m.Groups["name"].Value.Trim()).Where(t => t.Length > 0).Distinct().ToList();
        var found = FoundThreats().Match(output);
        if (threats.Count > 0 || (found.Success && found.Groups["n"].Value != "0"))
            return new DefenderScan(DefenderVerdict.Threat, threats, found.Success ? found.Value.Trim() : "");
        if (exitCode == 0 && (NoThreats().IsMatch(output) || output.Contains("Scan finished", StringComparison.OrdinalIgnoreCase)))
            return new DefenderScan(DefenderVerdict.Clean, [], "");
        var failure = Failure().Match(output);
        var detail = failure.Success ? failure.Value.Trim()
            : output.Split('\n').Select(l => l.Trim()).LastOrDefault(l => l.Length > 0) ?? $"exit code {exitCode}";
        return new DefenderScan(DefenderVerdict.Unavailable, [], detail);
    }

    public static async Task<DefenderScan> ScanFileAsync(string path, CancellationToken ct = default)
    {
        var exe = FindMpCmdRun();
        if (exe is null) return new DefenderScan(DefenderVerdict.Unavailable, [], "MpCmdRun.exe not found");
        var psi = new ProcessStartInfo(exe)
        {
            UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8,
        };
        foreach (var a in new[] { "-Scan", "-ScanType", "3", "-File", Path.GetFullPath(path), "-DisableRemediation" })
            psi.ArgumentList.Add(a);
        try
        {
            using var proc = Process.Start(psi);
            if (proc is null) return new DefenderScan(DefenderVerdict.Unavailable, [], "MpCmdRun.exe did not start");
            var stdout = proc.StandardOutput.ReadToEndAsync(ct);
            var stderr = proc.StandardError.ReadToEndAsync(ct);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(Timeout);
            try
            {
                await proc.WaitForExitAsync(timeout.Token);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                try { proc.Kill(true); } catch (InvalidOperationException) { }
                return new DefenderScan(DefenderVerdict.Unavailable, [], "timeout");
            }
            return Parse(proc.ExitCode, await stdout + await stderr);
        }
        catch (System.ComponentModel.Win32Exception ex)
        {
            return new DefenderScan(DefenderVerdict.Unavailable, [], ex.Message);
        }
    }

    [GeneratedRegex(@"^\s*Threat\s*:\s*(?<name>.+)$", RegexOptions.Multiline | RegexOptions.IgnoreCase)]
    private static partial Regex ThreatLine();

    [GeneratedRegex(@"found (?<n>\d+) threats?", RegexOptions.IgnoreCase)]
    private static partial Regex FoundThreats();

    [GeneratedRegex(@"found no threats", RegexOptions.IgnoreCase)]
    private static partial Regex NoThreats();

    [GeneratedRegex(@"Failed with hr = 0x[0-9A-Fa-f]+", RegexOptions.IgnoreCase)]
    private static partial Regex Failure();
}
