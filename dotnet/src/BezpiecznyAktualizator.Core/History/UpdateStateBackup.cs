using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace BezpiecznyAktualizator.Core.History;

public sealed record UpdateStateBackupResult(string Path, int Files, string Sha256);

public static class UpdateStateBackup
{
    private const int RetainedBackups = 10;
    private const long MaximumFileSize = 16 * 1024 * 1024;
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    public static UpdateStateBackupResult Create(string backupDirectory, string settingsPath, string localDataDirectory,
        DateTimeOffset now)
    {
        var files = new List<(string Name, byte[] Content)>();
        if (File.Exists(settingsPath))
        {
            var settings = JsonNode.Parse(File.ReadAllText(settingsPath))?.AsObject()
                ?? throw new InvalidDataException("Updater settings are not a JSON object.");
            settings.Remove("nvdApiKey");
            files.Add(("settings.json", JsonSerializer.SerializeToUtf8Bytes(settings, JsonOptions)));
        }
        AddIfExists("update-history.json");
        AddIfExists("schedule-state.json");
        if (files.Any(f => f.Content.LongLength > MaximumFileSize))
            throw new InvalidDataException("Updater state exceeds the backup size limit.");

        Directory.CreateDirectory(backupDirectory);
        var destination = Path.Combine(backupDirectory, $"state-{now:yyyyMMdd-HHmmss-fff}.zip");
        var temporary = destination + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using (var archive = ZipFile.Open(temporary, ZipArchiveMode.Create))
            {
                var manifest = new List<ManifestEntry>();
                foreach (var (name, content) in files)
                {
                    var entry = archive.CreateEntry(name, CompressionLevel.Optimal);
                    using (var stream = entry.Open()) stream.Write(content);
                    manifest.Add(new ManifestEntry
                    {
                        Name = name,
                        Size = content.LongLength,
                        Sha256 = Convert.ToHexStringLower(SHA256.HashData(content)),
                    });
                }
                var manifestEntry = archive.CreateEntry("manifest.json", CompressionLevel.Optimal);
                using var writer = new StreamWriter(manifestEntry.Open());
                writer.Write(JsonSerializer.Serialize(manifest, JsonOptions));
            }
            File.Move(temporary, destination);
            var hash = Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(destination)));
            Prune(backupDirectory, destination);
            return new UpdateStateBackupResult(destination, files.Count, hash);
        }
        finally
        {
            if (File.Exists(temporary)) File.Delete(temporary);
        }

        void AddIfExists(string name)
        {
            var source = Path.Combine(localDataDirectory, name);
            if (File.Exists(source)) files.Add((name, File.ReadAllBytes(source)));
        }
    }

    public static bool Verify(string path)
    {
        using var archive = ZipFile.OpenRead(path);
        if (archive.Entries.Count is < 1 or > 4) return false;
        var manifestEntry = archive.GetEntry("manifest.json");
        if (manifestEntry is null || manifestEntry.Length > 4096) return false;
        using var manifestStream = manifestEntry.Open();
        var manifest = JsonSerializer.Deserialize<List<ManifestEntry>>(manifestStream);
        if (manifest is null || manifest.Count > 3) return false;
        foreach (var item in manifest)
        {
            if (item.Name is not ("settings.json" or "update-history.json" or "schedule-state.json") ||
                item.Size is < 0 or > MaximumFileSize ||
                item.Sha256.Length != 64 || item.Sha256.Any(c => !Uri.IsHexDigit(c)))
                return false;
            var entry = archive.GetEntry(item.Name);
            if (entry is null || entry.Length != item.Size || entry.Length > MaximumFileSize) return false;
            using var stream = entry.Open();
            var hash = Convert.ToHexStringLower(SHA256.HashData(stream));
            if (!CryptographicOperations.FixedTimeEquals(Convert.FromHexString(hash), Convert.FromHexString(item.Sha256)))
                return false;
        }
        return archive.Entries.Count == manifest.Count + 1 &&
               archive.Entries.Select(e => e.FullName).Distinct(StringComparer.Ordinal).Count() == archive.Entries.Count;
    }

    private static void Prune(string directory, string retained)
    {
        foreach (var file in Directory.EnumerateFiles(directory, "state-*.zip")
                     .Where(path => !path.Equals(retained, StringComparison.OrdinalIgnoreCase))
                     .OrderByDescending(File.GetLastWriteTimeUtc).Skip(RetainedBackups - 1))
            File.Delete(file);
    }

    [System.Reflection.Obfuscation(Exclude = true)]
    private sealed class ManifestEntry
    {
        public string Name { get; set; } = "";
        public long Size { get; set; }
        public string Sha256 { get; set; } = "";
    }
}
