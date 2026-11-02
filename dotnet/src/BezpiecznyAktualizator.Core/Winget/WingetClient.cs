using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;
using BezpiecznyAktualizator.Core.Localization;
using BezpiecznyAktualizator.Core.Models;
using BezpiecznyAktualizator.Core.Security;

namespace BezpiecznyAktualizator.Core.Winget;

public sealed class WingetException(string message) : Exception(message);

public sealed record WingetPackage(string Name, string Id, string Version = "", string Available = "", string Source = "")
{
    public bool IsLocalOnly => Id.StartsWith(@"ARP\", StringComparison.Ordinal) ||
                               Id.StartsWith(@"MSIX\", StringComparison.Ordinal);
}

/// <summary>Integracja z Windows Package Manager (winget-cli, licencja MIT).</summary>
public static partial class WingetClient
{
    private static readonly string[] CommonArgs = ["--accept-source-agreements", "--disable-interactivity"];
    private static readonly object ExecutableGate = new();
    private static string? _cachedExecutable;

    public static bool IsAvailable()
    {
        try { return FindExecutable() is not null; }
        catch (WingetException) { return false; }
    }

    private static string? FindExecutable()
    {
        lock (ExecutableGate)
        {
            if (_cachedExecutable is { } cached && IsTrustedExecutable(cached)) return cached;
            _cachedExecutable = ResolveAppInstallerExecutable();
            return _cachedExecutable is { } resolved && IsTrustedExecutable(resolved) ? resolved : null;
        }
    }

    private static string? ResolveAppInstallerExecutable()
    {
        var powershell = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
        if (!File.Exists(powershell)) return null;

        const string query = "$ErrorActionPreference='Stop'; " +
            "$p=Get-AppxPackage -Name 'Microsoft.DesktopAppInstaller' | " +
            "Where-Object { $_.Status -eq 'Ok' -and $_.SignatureKind -eq 'Store' -and " +
            "$_.Publisher -eq 'CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US' } | " +
            "Sort-Object Version -Descending | Select-Object -First 1; " +
            "if ($p) { $e=Join-Path $p.InstallLocation 'winget.exe'; " +
            "if (Test-Path -LiteralPath $e -PathType Leaf) { Write-Output $e } }";
        using var process = Process.Start(new ProcessStartInfo(powershell)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
            ArgumentList = { "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", query },
        }) ?? throw new WingetException(L.T("Nie udało się sprawdzić instalacji Microsoft App Installer."));
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        try
        {
            if (!process.WaitForExit(15000))
            {
                process.Kill(true);
                throw new WingetException(L.T("Przekroczono czas sprawdzania instalacji Microsoft App Installer."));
            }
        }
        catch (InvalidOperationException ex)
        {
            throw new WingetException(L.F("Nie udało się sprawdzić instalacji Microsoft App Installer: {0}", ex.Message));
        }
        var output = stdout.GetAwaiter().GetResult().Trim();
        var error = stderr.GetAwaiter().GetResult().Trim();
        if (process.ExitCode != 0)
            throw new WingetException(L.F("Nie udało się sprawdzić instalacji Microsoft App Installer: {0}", error));
        return output.Length > 0 ? output : null;
    }

    internal static bool IsTrustedWingetSignature(SignatureInfo signature) =>
        signature.State == SignatureState.Valid &&
        signature.Signer.Equals("Microsoft Corporation", StringComparison.OrdinalIgnoreCase);

    private static bool IsTrustedExecutable(string path)
    {
        if (!File.Exists(path)) return false;
        try
        {
            var signature = Authenticode.Verify(path, checkRevocation: false);
            return IsTrustedWingetSignature(signature);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            return false;
        }
    }

    private static ProcessStartInfo StartInfo(IEnumerable<string> args)
    {
        var exe = FindExecutable() ?? throw new WingetException(
            L.T("Nie znaleziono prawidłowo podpisanego programu winget z pakietu Microsoft App Installer. Zainstaluj go z Microsoft Store."));
        var psi = new ProcessStartInfo(exe)
        {
            UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8,
        };
        foreach (var a in args) psi.ArgumentList.Add(a);
        return psi;
    }

    public static async Task<(int Code, string Output)> RunAsync(IEnumerable<string> args, int timeoutSeconds = 300,
                                                                 CancellationToken ct = default)
    {
        using var proc = Process.Start(StartInfo(args)) ?? throw new WingetException(L.T("Nie udało się uruchomić winget."));
        var stdout = proc.StandardOutput.ReadToEndAsync(ct);
        var stderr = proc.StandardError.ReadToEndAsync(ct);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(timeoutSeconds));
        try
        {
            await proc.WaitForExitAsync(timeout.Token);
        }
        catch (OperationCanceledException)
        {
            try { proc.Kill(true); } catch (InvalidOperationException) { }
            throw new WingetException($"Przekroczono czas oczekiwania na winget ({timeoutSeconds} s).");
        }
        return (proc.ExitCode, await stdout + await stderr);
    }

    /// <summary>winget rysuje paski postępu przy użyciu \r - interesuje nas tylko ostatni stan linii.</summary>
    internal static List<string> SplitLines(string text) =>
        text.Split('\n').Select(raw =>
        {
            var parts = raw.Split('\r').Where(p => p.Trim().Length > 0).ToArray();
            return parts.Length > 0 ? parts[^1].TrimEnd() : "";
        }).ToList();

    /// <summary>Parsuje tabele o stałej szerokości kolumn wypisywane przez winget (list/upgrade/search).</summary>
    public static List<string[]> ParseTable(string text)
    {
        var lines = SplitLines(text);
        var rows = new List<string[]>();
        for (var idx = 0; idx < lines.Count; idx++)
        {
            if (!Separator().IsMatch(lines[idx].Trim())) continue;
            var headerIdx = idx - 1;
            while (headerIdx >= 0 && lines[headerIdx].Trim().Length == 0) headerIdx--;
            if (headerIdx < 0) continue;
            var starts = Words().Matches(lines[headerIdx]).Select(m => m.Index).ToArray();
            if (starts.Length < 3) continue;
            foreach (var row in lines.Skip(idx + 1))
            {
                if (row.Trim().Length == 0) break;
                if (row.Length <= starts[1] || row[starts[1] - 1] != ' ') break;
                var cells = new string[starts.Length];
                for (var i = 0; i < starts.Length; i++)
                {
                    var start = Math.Min(starts[i], row.Length);
                    var end = i + 1 < starts.Length ? Math.Min(starts[i + 1], row.Length) : row.Length;
                    cells[i] = row[start..end].Trim();
                }
                if (cells[1].Length == 0) break;
                rows.Add(cells);
            }
        }
        return rows;
    }

    public static List<WingetPackage> RowsToPackages(IEnumerable<string[]> rows) =>
        rows.Select(c =>
        {
            string At(int i) => i < c.Length ? c[i] : "";
            return new WingetPackage(At(0), At(1), At(2), At(3), At(4));
        }).ToList();

    public static async Task<List<WingetPackage>> ListInstalledAsync(CancellationToken ct = default)
    {
        var (code, output) = await RunAsync(["list", .. CommonArgs], ct: ct);
        var packages = RowsToPackages(ParseTable(output));
        if (code != 0 && packages.Count == 0)
            throw new WingetException(L.F("winget list zakończył się kodem 0x{0:X8}:", code) + "\n" + output.Trim());
        return packages;
    }

    public static async Task<List<WingetPackage>> ListUpgradesAsync(CancellationToken ct = default)
    {
        var (code, output) = await RunAsync(["upgrade", "--include-unknown", .. CommonArgs], ct: ct);
        var packages = RowsToPackages(ParseTable(output));
        if (code != 0 && packages.Count == 0 && !output.Contains("No installed package"))
            throw new WingetException(L.F("winget upgrade zakończył się kodem 0x{0:X8}:", code) + "\n" + output.Trim());
        return packages;
    }

    public static async Task<List<WingetPackage>> SearchAsync(string query, CancellationToken ct = default)
    {
        var (_, output) = await RunAsync(["search", "--query", query, .. CommonArgs], 120, ct);
        // Kolumny: Name, Id, Version, [Match], Source
        return ParseTable(output)
            .Select(c => new WingetPackage(c[0], c[1], c[2], "", c.Length >= 4 ? c[^1] : ""))
            .ToList();
    }

    /// <summary>Parsuje wynik `winget show`. Klucze sekcji Installer mają prefiks "Installer.".</summary>
    public static Dictionary<string, string> ParseShow(string text)
    {
        var info = new Dictionary<string, string>();
        string? section = null;
        foreach (var line in SplitLines(text))
        {
            var found = ShowHeader().Match(line);
            if (found.Success && !info.ContainsKey("name") && !line.Split('[')[0].Contains(':'))
            {
                info["id"] = found.Groups["id"].Value;
                var space = line.IndexOf(' ');
                var rest = space >= 0 ? line[(space + 1)..] : "";
                var bracket = rest.LastIndexOf('[');
                info["name"] = (bracket >= 0 ? rest[..bracket] : rest).Trim();
                continue;
            }
            var m = ShowKey().Match(line);
            if (!m.Success) continue;
            var indent = m.Groups["indent"].Value.Length;
            var key = m.Groups["key"].Value.Trim();
            var value = m.Groups["value"].Value.Trim();
            if (indent == 0)
            {
                if (value.Length > 0) { info[key] = value; section = null; }
                else section = key;
            }
            else if (section is not null && section.StartsWith("installer", StringComparison.OrdinalIgnoreCase) &&
                     indent <= 4 && value.Length > 0)
            {
                info[$"Installer.{key}"] = value;
            }
        }
        return info;
    }

    private static string InstallerValue(Dictionary<string, string> info, Func<string, bool> keyMatches,
                                         Func<string, bool>? valueMatches = null) =>
        info.FirstOrDefault(kv => kv.Key.StartsWith("Installer.", StringComparison.Ordinal) &&
                                  keyMatches(kv.Key.ToLowerInvariant()) && (valueMatches?.Invoke(kv.Value) ?? true)).Value ?? "";

    public static string InstallerUrl(Dictionary<string, string> info) =>
        InstallerValue(info, k => k.Contains("url"), v => v.StartsWith("http", StringComparison.OrdinalIgnoreCase));

    public static string InstallerSha256(Dictionary<string, string> info) => InstallerValue(info, k => k.Contains("sha256"));

    public static string InstallerType(Dictionary<string, string> info) => InstallerValue(info, k => k.Contains("type"));

    public static async Task<Dictionary<string, string>> ShowAsync(string packageId, string source = "",
                                                                   CancellationToken ct = default)
    {
        List<string> args = ["show", "--id", packageId, "--exact", .. CommonArgs];
        if (source.Length > 0) args.AddRange(["--source", source]);
        var (code, output) = await RunAsync(args, 120, ct);
        var info = ParseShow(output);
        if (code != 0 || !info.ContainsKey("id"))
            throw new WingetException(L.F("Nie udało się pobrać manifestu {0} (kod 0x{1:X8}):", packageId, code) + "\n" + output.Trim());
        return info;
    }

    /// <summary>winget: suma SHA256 pobranego instalatora jest niezgodna z manifestem.</summary>
    public const int HashMismatchCode = unchecked((int)0x8A150011);

    /// <summary>Pobiera instalator i jego manifest (.yaml) do katalogu, bez instalowania.</summary>
    public static Task<(int Code, string Output)> DownloadAsync(string packageId, string directory, string source = "",
                                                               string version = "", CancellationToken ct = default)
        => RunAsync(DownloadArguments(packageId, directory, source, version), 900, ct);

    internal static List<string> DownloadArguments(string packageId, string directory, string source, string version)
    {
        List<string> args = ["download", "--id", packageId, "--exact", "--download-directory", directory,
                             "--skip-dependencies", "--accept-package-agreements", .. CommonArgs];
        if (source.Length > 0) args.AddRange(["--source", source]);
        if (version.Length > 0) args.AddRange(["--version", version]);
        return args;
    }

    /// <summary>Uruchamia aktualizację. winget sam weryfikuje sumę SHA256 instalatora przed uruchomieniem.</summary>
    public static Task<int> UpgradeAsync(string packageId, Action<string> onOutput, string source = "",
                                         string version = "", CancellationToken ct = default) =>
        RunStreamingAsync(UpgradeArguments(packageId, source, version), onOutput, ct);

    public static Task<int> UpgradeVerifiedAsync(VerifiedInstaller installer, Action<string> onOutput,
                                                  CancellationToken ct = default)
    {
        installer.Validate();
        return RunStreamingAsync(VerifiedUpgradeArguments(installer.ManifestPath), onOutput, ct);
    }

    public static Task<int> InstallVerifiedAsync(VerifiedInstaller installer, Action<string> onOutput,
                                                  bool allowDowngrade = false, CancellationToken ct = default)
    {
        installer.Validate();
        return RunStreamingAsync(VerifiedInstallArguments(installer.ManifestPath, allowDowngrade), onOutput, ct);
    }

    internal static List<string> VerifiedUpgradeArguments(string manifestPath) =>
        ["upgrade", "--manifest", manifestPath, "--silent", "--accept-package-agreements", .. CommonArgs];

    internal static List<string> VerifiedInstallArguments(string manifestPath, bool allowDowngrade) =>
        allowDowngrade
            ? ["install", "--manifest", manifestPath, "--force", "--silent", "--accept-package-agreements", .. CommonArgs]
            : ["install", "--manifest", manifestPath, "--silent", "--accept-package-agreements", .. CommonArgs];

    internal static List<string> UpgradeArguments(string packageId, string source, string version)
    {
        List<string> args = ["upgrade", "--id", packageId, "--exact", "--silent", "--accept-package-agreements", .. CommonArgs];
        if (source.Length > 0) args.AddRange(["--source", source]);
        if (version.Length > 0) args.AddRange(["--version", version]);
        return args;
    }

    /// <summary>
    /// Instaluje wskazaną (np. poprzednią) wersję pakietu. --force pozwala zainstalować wersję starszą od obecnej.
    /// </summary>
    public static Task<int> InstallVersionAsync(string packageId, string version, Action<string> onOutput, string source = "",
                                                CancellationToken ct = default)
    {
        List<string> args = ["install", "--id", packageId, "--exact", "--version", version, "--force", "--silent",
                             "--accept-package-agreements", .. CommonArgs];
        if (source.Length > 0) args.AddRange(["--source", source]);
        return RunStreamingAsync(args, onOutput, ct);
    }

    /// <summary>Parsuje wynik `winget show --versions` (lista wersji pod nagłówkiem i linią myślników).</summary>
    public static List<string> ParseVersions(string text)
    {
        var lines = SplitLines(text);
        var start = lines.FindIndex(l => l.Trim().Length > 2 && l.Trim().All(c => c == '-'));
        return start < 0 ? [] : lines.Skip(start + 1).Select(l => l.Trim()).Where(l => l.Length > 0 && !l.Contains(' ')).ToList();
    }

    /// <summary>Wersje pakietu dostępne w repozytorium winget.</summary>
    public static async Task<List<string>> ListVersionsAsync(string packageId, string source = "", CancellationToken ct = default)
    {
        List<string> args = ["show", "--id", packageId, "--exact", "--versions", .. CommonArgs];
        if (source.Length > 0) args.AddRange(["--source", source]);
        var (code, output) = await RunAsync(args, 120, ct);
        if (code != 0)
            throw new WingetException(L.F("Nie udało się pobrać listy wersji {0} (kod 0x{1:X8}).", packageId, code));
        return ParseVersions(output);
    }

    private static async Task<int> RunStreamingAsync(List<string> args, Action<string> onOutput, CancellationToken ct)
    {
        using var proc = Process.Start(StartInfo(args)) ?? throw new WingetException(L.T("Nie udało się uruchomić winget."));

        async Task Pump(StreamReader reader)
        {
            while (await reader.ReadLineAsync(ct) is { } raw)
            {
                var parts = raw.Split('\r').Where(p => p.Trim().Length > 0).ToArray();
                if (parts.Length == 0) continue;
                var line = parts[^1].Trim();
                if (!Spinner().IsMatch(line)) onOutput(line);
            }
        }

        await Task.WhenAll(Pump(proc.StandardOutput), Pump(proc.StandardError), proc.WaitForExitAsync(ct));
        return proc.ExitCode;
    }

    private static Software? MatchTarget(WingetPackage pkg, Dictionary<string, Software> byKey,
                                         Dictionary<string, List<Software>> byName, List<Software> software)
    {
        if (pkg.Id.StartsWith(@"ARP\", StringComparison.Ordinal))
        {
            var regKey = pkg.Id[(pkg.Id.LastIndexOf('\\') + 1)..];
            if (byKey.TryGetValue(regKey, out var direct)) return direct;
        }
        List<Software> candidates;
        if (pkg.Name.EndsWith('…'))
        {
            var prefix = Software.NormalizeName(pkg.Name[..^1]);
            candidates = prefix.Length > 0
                ? software.Where(s => Software.NormalizeName(s.Name).StartsWith(prefix, StringComparison.Ordinal)).ToList()
                : [];
        }
        else
        {
            candidates = byName.GetValueOrDefault(Software.NormalizeName(pkg.Name)) ?? [];
        }
        var free = candidates.Where(c => !c.WingetDetected).ToList();
        if (free.Count > 0) candidates = free;
        // Nie nadpisuj już powiązanego programu lokalnym wpisem (np. drugi Edge jako MSIX).
        else if (pkg.IsLocalOnly) return null;
        if (candidates.Count == 0) return null;
        return candidates.FirstOrDefault(c => c.Version == pkg.Version) ?? candidates[0];
    }

    /// <summary>Łączy inwentarz z rejestru z danymi winget (wraz z pakietami spoza rejestru).</summary>
    public static List<Software> Merge(List<Software> software, IEnumerable<WingetPackage> packages)
    {
        var byKey = new Dictionary<string, Software>();
        foreach (var s in software.Where(s => s.RegKey.Length > 0)) byKey[s.RegKey] = s;
        var byName = new Dictionary<string, List<Software>>();
        foreach (var s in software)
        {
            var key = Software.NormalizeName(s.Name);
            if (!byName.TryGetValue(key, out var list)) byName[key] = list = [];
            list.Add(s);
        }

        var merged = new List<Software>(software);
        foreach (var pkg in packages)
        {
            var target = MatchTarget(pkg, byKey, byName, software);
            if (target is null)
            {
                target = new Software
                {
                    Name = pkg.Name, Version = pkg.Version,
                    Origin = pkg.Id.StartsWith(@"MSIX\", StringComparison.Ordinal) ? "winget (MSIX/Store)" : "winget",
                };
                merged.Add(target);
            }
            target.WingetDetected = true;
            target.WingetId = pkg.IsLocalOnly ? null : pkg.Id;
            target.WingetSource = pkg.IsLocalOnly ? "" : pkg.Source;
            if (pkg.Available.Length > 0) target.AvailableVersion = pkg.Available;
        }
        return [.. merged.OrderBy(s => s.Name, StringComparer.CurrentCultureIgnoreCase)];
    }

    /// <summary>Pełne sprawdzenie: winget list + winget upgrade, połączone z inwentarzem rejestru.</summary>
    public static async Task<(List<Software> Items, int PackageCount)> CheckUpdatesAsync(List<Software> baseItems,
                                                                                       CancellationToken ct = default)
    {
        foreach (var s in baseItems)
        {
            s.WingetDetected = false;
            s.WingetId = null;
            s.WingetSource = "";
            s.AvailableVersion = "";
        }
        var packages = await ListInstalledAsync(ct);
        var upgrades = await ListUpgradesAsync(ct);
        var available = new Dictionary<string, string>();
        foreach (var u in upgrades.Where(u => u.Available.Length > 0)) available[u.Id] = u.Available;
        packages = packages.Select(p => available.TryGetValue(p.Id, out var a) ? p with { Available = a } : p).ToList();
        var known = packages.Select(p => p.Id).ToHashSet();
        packages.AddRange(upgrades.Where(u => !known.Contains(u.Id)));
        return (Merge(baseItems, packages), packages.Count);
    }

    [GeneratedRegex("^-{5,}$")]
    private static partial Regex Separator();

    [GeneratedRegex(@"\S+")]
    private static partial Regex Words();

    [GeneratedRegex(@"^\S.*?\[(?<id>[^\]]+)\]\s*$")]
    private static partial Regex ShowHeader();

    [GeneratedRegex(@"^(?<indent>\s*)(?<key>[^\W\d_][\w ]*?):(?:\s+(?<value>.*))?$")]
    private static partial Regex ShowKey();

    [GeneratedRegex(@"^[-\\|/ ]+$")]
    private static partial Regex Spinner();
}
