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
        DateTimeOffset now, string? protectedBackup = null)
    {
        var protectedPath = protectedBackup is null ? null : Path.GetFullPath(protectedBackup);
        var files = new List<(string Name, byte[] Content)>();
        if (File.Exists(settingsPath))
        {
            var settings = JsonNode.Parse(File.ReadAllText(settingsPath))?.AsObject()
                ?? throw new InvalidDataException("Updater settings are not a JSON object.");
            RemoveNvdApiKey(settings);
            files.Add(("settings.json", JsonSerializer.SerializeToUtf8Bytes(settings, JsonOptions)));
        }
        AddIfExists("update-history.json");
        AddIfExists("schedule-state.json");
        if (files.Any(f => f.Content.LongLength > MaximumFileSize))
            throw new InvalidDataException("Updater state exceeds the backup size limit.");

        var fullBackupDirectory = Path.GetFullPath(backupDirectory);
        Directory.CreateDirectory(fullBackupDirectory);
        var destination = Path.Combine(fullBackupDirectory, $"state-{now:yyyyMMdd-HHmmss-fff}.zip");
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
            Prune(fullBackupDirectory, destination, protectedPath);
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
        return Verify(archive);
    }

    private static bool Verify(ZipArchive archive)
    {
        if (archive.Entries.Count is < 1 or > 4) return false;
        var manifestEntry = archive.GetEntry("manifest.json");
        if (manifestEntry is null || manifestEntry.Length > 4096) return false;
        using var manifestStream = manifestEntry.Open();
        var manifest = JsonSerializer.Deserialize<List<ManifestEntry>>(manifestStream);
        if (manifest is null || manifest.Count > 3 ||
            manifest.Any(item => item is null) ||
            manifest.Select(item => item.Name).Distinct(StringComparer.Ordinal).Count() != manifest.Count)
            return false;
        foreach (var item in manifest)
        {
            if (item.Name is not ("settings.json" or "update-history.json" or "schedule-state.json") ||
                item.Size is < 0 or > MaximumFileSize ||
                string.IsNullOrEmpty(item.Sha256) || item.Sha256.Length != 64 ||
                item.Sha256.Any(c => !Uri.IsHexDigit(c)))
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

    public static IReadOnlyList<string> GetFileNames(string path)
    {
        using var archive = ZipFile.OpenRead(path);
        if (!Verify(archive)) throw new InvalidDataException("Updater state backup failed verification.");
        var manifest = ReadManifest(archive);
        return manifest.Select(item => item.Name).ToArray();
    }

    public static IReadOnlyList<string> Restore(string backupPath, string settingsPath, string localDataDirectory)
    {
        using var archive = ZipFile.OpenRead(backupPath);
        if (!Verify(archive)) throw new InvalidDataException("Updater state backup failed verification.");
        var manifest = ReadManifest(archive);
        var files = new List<(string Name, string Destination, byte[] Content)>();
        foreach (var item in manifest)
        {
            using var stream = archive.GetEntry(item.Name)!.Open();
            using var content = new MemoryStream();
            var buffer = new byte[81920];
            int read;
            while ((read = stream.Read(buffer)) > 0)
            {
                if (content.Length + read > MaximumFileSize)
                    throw new InvalidDataException("Updater state backup entry exceeds the size limit.");
                content.Write(buffer, 0, read);
            }
            if (content.Length != item.Size)
                throw new InvalidDataException("Updater state backup entry has an unexpected size.");
            var bytes = content.ToArray();
            if (item.Name == "settings.json")
            {
                var settings = JsonNode.Parse(bytes)?.AsObject()
                    ?? throw new InvalidDataException("Updater settings backup is not a JSON object.");
                string? currentApiKey = null;
                if (File.Exists(settingsPath))
                {
                    var currentSettings = JsonNode.Parse(File.ReadAllText(settingsPath))?.AsObject()
                        ?? throw new InvalidDataException("Current updater settings are not a JSON object.");
                    currentApiKey = FindNvdApiKey(currentSettings)?.GetValue<string>();
                }
                RemoveNvdApiKey(settings);
                if (currentApiKey is not null) settings["nvdApiKey"] = currentApiKey;
                bytes = JsonSerializer.SerializeToUtf8Bytes(settings, JsonOptions);
            }
            else
            {
                using var document = JsonDocument.Parse(bytes);
                if (item.Name == "update-history.json" && document.RootElement.ValueKind != JsonValueKind.Array)
                    throw new InvalidDataException("Update history backup is not a JSON array.");
                if (item.Name == "schedule-state.json" && document.RootElement.ValueKind != JsonValueKind.Object)
                    throw new InvalidDataException("Schedule state backup is not a JSON object.");
            }
            var destination = item.Name == "settings.json"
                ? Path.GetFullPath(settingsPath)
                : Path.Combine(Path.GetFullPath(localDataDirectory), item.Name);
            files.Add((item.Name, destination, bytes));
        }

        if (files.Select(file => file.Destination).Distinct(StringComparer.OrdinalIgnoreCase).Count() != files.Count)
            throw new InvalidDataException("Updater state backup destinations are ambiguous.");

        var staged = new List<(string Destination, string Temporary, byte[]? Previous)>();
        var committed = new List<(string Destination, byte[]? Previous)>();
        try
        {
            foreach (var file in files)
            {
                Directory.CreateDirectory(Path.GetDirectoryName(file.Destination)!);
                var previous = File.Exists(file.Destination) ? File.ReadAllBytes(file.Destination) : null;
                var temporary = file.Destination + "." + Guid.NewGuid().ToString("N") + ".tmp";
                using (var output = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                    output.Write(file.Content);
                staged.Add((file.Destination, temporary, previous));
            }

            foreach (var file in staged)
            {
                File.Move(file.Temporary, file.Destination, overwrite: true);
                committed.Add((file.Destination, file.Previous));
            }
            return files.Select(file => file.Name).ToArray();
        }
        catch (Exception ex)
        {
            var rollbackErrors = new List<Exception>();
            foreach (var file in committed.AsEnumerable().Reverse())
            {
                try
                {
                    if (file.Previous is null)
                        File.Delete(file.Destination);
                    else
                    {
                        var rollback = file.Destination + "." + Guid.NewGuid().ToString("N") + ".rollback";
                        try
                        {
                            File.WriteAllBytes(rollback, file.Previous);
                            File.Move(rollback, file.Destination, overwrite: true);
                        }
                        finally
                        {
                            if (File.Exists(rollback)) File.Delete(rollback);
                        }
                    }
                }
                catch (Exception rollbackError) when (rollbackError is IOException or UnauthorizedAccessException)
                {
                    rollbackErrors.Add(rollbackError);
                }
            }
            if (rollbackErrors.Count > 0)
                throw new IOException("Updater state restore failed and could not be fully rolled back.",
                    new AggregateException([ex, .. rollbackErrors]));
            throw;
        }
        finally
        {
            foreach (var file in staged)
                if (File.Exists(file.Temporary)) File.Delete(file.Temporary);
        }
    }

    private static List<ManifestEntry> ReadManifest(ZipArchive archive)
    {
        using var stream = archive.GetEntry("manifest.json")!.Open();
        return JsonSerializer.Deserialize<List<ManifestEntry>>(stream)
            ?? throw new InvalidDataException("Updater state backup manifest is invalid.");
    }

    private static JsonNode? FindNvdApiKey(JsonObject settings) =>
        settings.FirstOrDefault(pair => pair.Key.Equals("nvdApiKey", StringComparison.OrdinalIgnoreCase)).Value;

    private static void RemoveNvdApiKey(JsonObject settings)
    {
        foreach (var key in settings.Select(pair => pair.Key)
                     .Where(key => key.Equals("nvdApiKey", StringComparison.OrdinalIgnoreCase)).ToArray())
            settings.Remove(key);
    }

    private static void Prune(string directory, string retained, string? protectedBackup)
    {
        var protectedBackupIsLocal = protectedBackup is not null &&
            string.Equals(Path.GetDirectoryName(protectedBackup), Path.GetFullPath(directory), StringComparison.OrdinalIgnoreCase) &&
            File.Exists(protectedBackup);
        var retainCount = protectedBackupIsLocal ? RetainedBackups - 2 : RetainedBackups - 1;
        foreach (var file in Directory.EnumerateFiles(directory, "state-*.zip")
                     .Where(path => !path.Equals(retained, StringComparison.OrdinalIgnoreCase) &&
                                    !path.Equals(protectedBackup, StringComparison.OrdinalIgnoreCase))
                     .OrderByDescending(File.GetLastWriteTimeUtc).Skip(retainCount))
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
