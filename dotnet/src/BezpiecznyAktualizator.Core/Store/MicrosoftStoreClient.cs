using System.Text.Json;
using System.Text.RegularExpressions;
using BezpiecznyAktualizator.Core.History;
using BezpiecznyAktualizator.Core.Localization;
using BezpiecznyAktualizator.Core.Models;
using BezpiecznyAktualizator.Core.Security;
using BezpiecznyAktualizator.Core.Winget;

namespace BezpiecznyAktualizator.Core.Store;

public sealed record StoreSearchResult(IReadOnlyList<Software> Updates, int UnknownVersions, string? UnparsedOutput = null);

/// <summary>Aktualizacje rozpoznane przez źródło Microsoft Store w Windows Package Manager.</summary>
public static partial class MicrosoftStoreClient
{
    public const string SourceName = "msstore";
    public const string UpdatesUri = "ms-windows-store://downloadsandupdates";
    private const int NoApplicationsFound = unchecked((int)0x8A150014);

    internal delegate Task<(int Code, string Output)> CommandRunner(IReadOnlyList<string> args, CancellationToken ct);
    internal delegate Task<int> UpgradeRunner(string id, Action<string> output, string source, string version, CancellationToken ct);

    private static Task<(int Code, string Output)> RunAsync(IReadOnlyList<string> args, CancellationToken ct) =>
        WingetClient.RunAsync(args, ct: ct);

    private static Task<int> RunUpgradeAsync(string id, Action<string> output, string source, string version, CancellationToken ct) =>
        WingetClient.UpgradeAsync(id, output, source, version, ct);

    public static Task<StoreSearchResult> FindUpdatesAsync(CancellationToken ct = default) =>
        FindUpdatesCoreAsync(RunAsync, ct);

    internal static async Task<StoreSearchResult> FindUpdatesCoreAsync(CommandRunner run, CancellationToken ct = default)
    {
        await VerifySourceAsync(run, ct);
        var (code, output) = await run(
            ["upgrade", "--source", SourceName, "--accept-source-agreements", "--disable-interactivity"], ct);
        if (code == NoApplicationsFound && !HasTableData(output) && !PossibleProductId().IsMatch(output)) return new([], 0);
        if (code != 0)
            throw new WingetException(L.F("Nie udało się sprawdzić aktualizacji Microsoft Store (kod 0x{0:X8}):", code) + "\n" + output.Trim());
        var rows = ParseUpgradeTable(output);
        if (rows.Count == 0)
        {
            var message = string.Join(Environment.NewLine, WingetClient.SplitLines(output)
                .Select(line => line.Trim()).Where(line => line.Length > 0));
            if (message.Length == 0) throw InvalidTable();
            return new([], 0, message);
        }

        var updates = new List<Software>();
        var ids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var unknown = 0;
        foreach (var row in rows)
        {
            if (!ids.Add(row.Id))
                throw new WingetException(L.T("Nie udało się odczytać listy aktualizacji Microsoft Store."));

            if (!IsSpecificVersion(row.Installed) || !IsSpecificVersion(row.Available))
            {
                unknown++;
                continue;
            }
            if (UpdateHistory.FindVersion([row.Installed], row.Available) is not null) continue;
            updates.Add(new Software
            {
                Name = row.Name, WingetId = row.Id, Version = row.Installed, AvailableVersion = row.Available,
                Origin = "Microsoft Store", WingetSource = SourceName, WingetDetected = true, SecurityLevel = Levels.High,
            });
        }
        return new(updates, unknown);
    }

    public static Task<string?> InstalledVersionAsync(Software item, CancellationToken ct = default) =>
        InstalledVersionCoreAsync(item, RunAsync, ct);

    internal static async Task<string?> InstalledVersionCoreAsync(Software item, CommandRunner run, CancellationToken ct = default)
    {
        if (!string.Equals(item.WingetSource, SourceName, StringComparison.OrdinalIgnoreCase) || !IsProductId(item.WingetId))
            throw new WingetException(L.T("Nieprawidłowy identyfikator lub wersja pakietu Microsoft Store."));
        await VerifySourceAsync(run, ct);
        var (code, output) = await run(
            ["list", "--id", item.WingetId!, "--exact", "--source", SourceName,
             "--accept-source-agreements", "--disable-interactivity"], ct);
        if (code == NoApplicationsFound && !HasTableData(output) && !PossibleProductId().IsMatch(output)) return null;
        if (code != 0)
            throw new WingetException(L.F("Nie udało się odczytać zainstalowanej wersji Microsoft Store (kod 0x{0:X8}):", code) + "\n" + output.Trim());
        return ParseInstalledVersion(output, item.WingetId!);
    }

    public static Task<int> UpgradeAsync(Software item, Action<string> output, CancellationToken ct = default) =>
        UpgradeCoreAsync(item, output, RunAsync, RunUpgradeAsync, ct);

    internal static async Task<int> UpgradeCoreAsync(Software item, Action<string> output, CommandRunner run,
                                                      UpgradeRunner upgrade, CancellationToken ct = default)
    {
        if (!string.Equals(item.WingetSource, SourceName, StringComparison.OrdinalIgnoreCase) ||
            !IsProductId(item.WingetId) || !IsSpecificVersion(item.Version) ||
            !IsSpecificVersion(item.AvailableVersion) || !item.CanUpgrade)
            throw new WingetException(L.T("Nieprawidłowy identyfikator lub wersja pakietu Microsoft Store."));
        await VerifySourceAsync(run, ct);
        return await upgrade(item.WingetId!, output, SourceName, item.AvailableVersion, ct);
    }

    private static async Task VerifySourceAsync(CommandRunner run, CancellationToken ct)
    {
        var (code, output) = await run(["source", "export", "--name", SourceName, "--disable-interactivity"], ct);
        if (code != 0)
            throw new WingetException(L.F("Nie można sprawdzić źródła Microsoft Store (kod 0x{0:X8}):", code) + "\n" + output.Trim());
        ValidateSource(output);
    }

    internal static void ValidateSource(string json)
    {
        try
        {
            using var document = JsonDocument.Parse(json);
            var root = document.RootElement;
            static string Property(JsonElement element, string name) =>
                element.ValueKind == JsonValueKind.Object && element.TryGetProperty(name, out var value) &&
                value.ValueKind == JsonValueKind.String ? value.GetString() ?? "" : "";
            var argument = Property(root, "Arg");
            if (!Property(root, "Name").Equals(SourceName, StringComparison.OrdinalIgnoreCase) ||
                !Property(root, "Type").Equals("Microsoft.Rest", StringComparison.OrdinalIgnoreCase) ||
                !Property(root, "Identifier").Equals("StoreEdgeFD", StringComparison.OrdinalIgnoreCase) ||
                !Uri.TryCreate(argument, UriKind.Absolute, out var uri) ||
                uri.Scheme != Uri.UriSchemeHttps || !uri.IdnHost.Equals("storeedgefd.dsx.mp.microsoft.com", StringComparison.OrdinalIgnoreCase) ||
                !uri.IsDefaultPort || uri.AbsolutePath.TrimEnd('/') != "/v9.0" ||
                uri.UserInfo.Length != 0 || uri.Query.Length != 0 || uri.Fragment.Length != 0)
                throw new WingetException(L.T("Nieprawidłowa konfiguracja oficjalnego źródła Microsoft Store."));
        }
        catch (JsonException ex)
        {
            throw new WingetException(L.F("Nie udało się odczytać konfiguracji źródła Microsoft Store: {0}", ex.Message));
        }
    }

    private static bool HasTableData(string output)
    {
        var lines = WingetClient.SplitLines(output);
        var separator = lines.FindIndex(line => line.Trim() is { Length: >= 5 } text && text.All(c => c == '-'));
        return separator >= 0 && lines.Skip(separator + 1).Any(line => !string.IsNullOrWhiteSpace(line));
    }

    private sealed record UpgradeRow(string Name, string Id, string Installed, string Available);

    private static List<UpgradeRow> ParseUpgradeTable(string output)
    {
        var lines = WingetClient.SplitLines(output);
        var separator = TableSeparator(lines);
        if (separator < 0)
        {
            if (lines.Any(line => PossibleProductId().IsMatch(line)))
                throw InvalidTable();
            return [];
        }

        var rows = new List<UpgradeRow>();
        var summaryFound = false;
        for (var index = separator + 1; index < lines.Count; index++)
        {
            var line = lines[index].Trim();
            if (line.Length == 0) continue;
            var summary = SummaryCount().Match(line);
            if (summary.Success)
            {
                if (!int.TryParse(summary.Groups["count"].Value, out var count) || count != rows.Count)
                    throw InvalidTable();
                summaryFound = true;
                if (lines.Skip(index + 1).Any(IsSeparator)) throw InvalidTable();
                break;
            }

            var parts = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            var sourceColumn = parts.Length >= 5 && parts[^1].Equals(SourceName, StringComparison.OrdinalIgnoreCase);
            var withSource = parts.Length >= 5 && IsProductId(parts[^4]);
            var withoutSource = parts.Length >= 4 && IsProductId(parts[^3]);
            if (sourceColumn && !withSource ||
                !sourceColumn && (!withoutSource || withSource && !IsSpecificVersion(parts[^1])))
                throw InvalidTable();
            var idIndex = sourceColumn ? parts.Length - 4 : parts.Length - 3;
            var name = string.Join(" ", parts[..idIndex]);
            if (name.Length == 0) throw InvalidTable();
            rows.Add(new UpgradeRow(name, parts[idIndex], parts[idIndex + 1], parts[idIndex + 2]));
        }
        if (!summaryFound || rows.Count == 0) throw InvalidTable();
        return rows;
    }

    private static string? ParseInstalledVersion(string output, string id)
    {
        var lines = WingetClient.SplitLines(output);
        var separator = TableSeparator(lines);
        if (separator < 0)
        {
            if (lines.Any(line => line.Contains(id, StringComparison.OrdinalIgnoreCase))) throw InvalidTable();
            return null;
        }

        var rows = lines.Skip(separator + 1).Where(line => !string.IsNullOrWhiteSpace(line)).ToList();
        if (rows.Count != 1) throw InvalidTable();
        var parts = rows[0].Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        var idIndex = Array.FindLastIndex(parts, part => part.Equals(id, StringComparison.OrdinalIgnoreCase));
        if (idIndex < 1 || idIndex + 1 >= parts.Length || parts.Length > idIndex + 4)
            throw InvalidTable();
        if (parts.Length == idIndex + 4 && !parts[^1].Equals(SourceName, StringComparison.OrdinalIgnoreCase))
            throw InvalidTable();
        return IsSpecificVersion(parts[idIndex + 1]) ? parts[idIndex + 1] : null;
    }

    private static int TableSeparator(List<string> lines)
    {
        var separators = lines.Select((line, index) => (line, index)).Where(x => IsSeparator(x.line)).ToList();
        if (separators.Count > 1 || separators.Count == 1 && separators[0].index == 0)
            throw InvalidTable();
        return separators.Count == 0 ? -1 : separators[0].index;
    }

    private static bool IsSeparator(string line) =>
        line.Trim() is { Length: >= 5 } text && text.All(c => c == '-');

    private static WingetException InvalidTable() =>
        new(L.T("Nie udało się odczytać listy aktualizacji Microsoft Store."));

    internal static bool IsProductId(string? id) =>
        id is { Length: >= 10 and <= 32 } && ProductId().IsMatch(id);

    internal static bool IsSpecificVersion(string? version) =>
        version is { Length: > 0 and <= 128 } && SpecificVersion().IsMatch(version);

    [GeneratedRegex("^[A-Za-z0-9]+$", RegexOptions.CultureInvariant)]
    private static partial Regex ProductId();

    [GeneratedRegex("^[vV]?[0-9][A-Za-z0-9._+\\-]*$", RegexOptions.CultureInvariant)]
    private static partial Regex SpecificVersion();

    [GeneratedRegex(@"(?<![A-Za-z0-9])(?=[A-Za-z0-9]*[0-9])[A-Za-z0-9]{10,32}(?![A-Za-z0-9])", RegexOptions.CultureInvariant)]
    private static partial Regex PossibleProductId();

    [GeneratedRegex(@"^(?:(?<count>[0-9]+)\s+[^0-9]+|[^0-9]+\s+(?<count>[0-9]+)[\p{P}\s]*)$", RegexOptions.CultureInvariant)]
    private static partial Regex SummaryCount();
}
