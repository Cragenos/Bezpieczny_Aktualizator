using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using BezpiecznyAktualizator.Core.Localization;

namespace BezpiecznyAktualizator.Core.Profiles;

public sealed class ProfilePackageException(string message) : Exception(message);

/// <summary>Folder źródłowy lub docelowy przypisany do stałego klucza z <see cref="UserProfiles.Folders"/>.</summary>
public sealed record ProfileFolderPath(string Key, string Path);

public sealed record ProfilePackageProgress(long BytesDone, long BytesTotal, int FilesDone, int FilesTotal, string CurrentFile)
{
    public int Percent => BytesTotal > 0 ? (int)Math.Clamp(BytesDone * 100 / BytesTotal, 0, 100)
                        : FilesTotal > 0 ? FilesDone * 100 / FilesTotal : 0;
}

public sealed record ProfileFileEntry(string Path, long Size, string Sha256, DateTime ModifiedUtc);

public sealed record ProfilePackageManifest(int FormatVersion, DateTimeOffset Created, string Machine, string UserName,
                                            string SourceProfile, IReadOnlyList<string> Folders, IReadOnlyList<ProfileFileEntry> Files)
{
    public long TotalBytes => Files.Sum(f => f.Size);
}

public sealed record ProfileEstimate(int Files, long Bytes, int SkippedLinks, IReadOnlyList<string> MissingFolders,
                                     long? MaxFileSize = null, int SkippedLargeFiles = 0, long SkippedLargeBytes = 0);

public sealed record ProfilePackageResult(int Files, long Bytes, IReadOnlyList<string> Skipped, IReadOnlyList<string> Parts);

public sealed record ProfileVerification(ProfilePackageManifest Manifest, bool Encrypted, IReadOnlyList<string> Problems)
{
    public bool Succeeded => Problems.Count == 0;
}

public enum RestoreConflictMode
{
    /// <summary>Istniejący plik zostaje bez zmian.</summary>
    Skip,
    /// <summary>Istniejący plik zostaje przeniesiony do folderu kopii, a w jego miejsce trafia plik z paczki.</summary>
    Overwrite,
    /// <summary>Plik z paczki zostaje zapisany pod nową nazwą, np. „raport (2).docx”.</summary>
    KeepBoth,
}

public sealed record ProfileRestoreResult(int Restored, int Skipped, int BackedUp, int Renamed, string? BackupFolder, IReadOnlyList<string> Problems);

public sealed record ProfileRestorePreview(int FilesToWrite, long BytesToWrite, int ExistingFiles, long ExistingBytes,
                                           int SkippedFiles, IReadOnlyDictionary<string, long> BytesByVolume);

/// <summary>
/// Paczka do przeniesienia folderów profilu na inny komputer: archiwum ZIP z plikami w <c>files/&lt;klucz&gt;/…</c>
/// i <c>manifest.json</c> z rozmiarem i sumą SHA256 każdego pliku; opcjonalnie zaszyfrowana hasłem (AES-256-GCM).
/// Pomijane są dowiązania (junction/symlink), pliki tymczasowe i pliki zablokowane. Przywracanie najpierw weryfikuje
/// całą paczkę, odrzuca ścieżki wychodzące poza folder docelowy i nie zapisuje przez dowiązania.
/// </summary>
public static class ProfilePackage
{
    public const string Extension = ".baprofile";
    public const int FormatVersion = 1;
    public const long MaxPartBytes = 3_900_000_000;
    public const long LargeFileThreshold = 1_073_741_824;
    private const string FormatName = "BezpiecznyAktualizator.ProfilePackage";
    private const string ManifestEntry = "manifest.json";
    private const string FilesPrefix = "files/";
    private const long MaxManifestBytes = 256L * 1024 * 1024;

    private static readonly string[] ExcludedNames = ["Thumbs.db", "ehthumbs.db", "NTUSER.DAT", "UsrClass.dat"];
    private static readonly string[] ExcludedExtensions = [".tmp", ".temp", ".crdownload", ".partial", ".lock"];

    internal static bool IsExcluded(string fileName) =>
        fileName.StartsWith("~$", StringComparison.Ordinal) ||
        ExcludedNames.Any(n => string.Equals(n, fileName, StringComparison.OrdinalIgnoreCase)) ||
        ExcludedExtensions.Any(e => fileName.EndsWith(e, StringComparison.OrdinalIgnoreCase)) ||
        fileName.EndsWith(Extension + ".partial", StringComparison.OrdinalIgnoreCase);

    public static ProfileEstimate Estimate(IReadOnlyList<ProfileFolderPath> folders, CancellationToken cancellationToken = default,
                                           long? maxFileSize = null)
    {
        if (maxFileSize is <= 0) throw new ArgumentOutOfRangeException(nameof(maxFileSize));
        var files = 0;
        long bytes = 0;
        var links = 0;
        var skippedLargeFiles = 0;
        long skippedLargeBytes = 0;
        var missing = new List<string>();
        foreach (var folder in folders)
        {
            if (!Directory.Exists(folder.Path))
            {
                missing.Add(folder.Path);
                continue;
            }
            foreach (var item in Enumerate(folder, null, cancellationToken))
            {
                if (item.File is null) { links++; continue; }
                if (maxFileSize is long limit && item.File.Length > limit)
                {
                    skippedLargeFiles++;
                    skippedLargeBytes += item.File.Length;
                    continue;
                }
                files++;
                bytes += item.File.Length;
            }
        }
        return new ProfileEstimate(files, bytes, links, missing, maxFileSize, skippedLargeFiles, skippedLargeBytes);
    }

    /// <summary>Tworzy paczkę w częściach nieprzekraczających <see cref="MaxPartBytes"/> na plik.</summary>
    public static ProfilePackageResult Create(IReadOnlyList<ProfileFolderPath> folders, string outputPath, string userName,
                                              string sourceProfile, string? password = null,
                                              IProgress<ProfilePackageProgress>? progress = null, CancellationToken cancellationToken = default,
                                              ProfileEstimate? estimate = null) =>
        CreateCore(folders, outputPath, userName, sourceProfile, password, progress, cancellationToken, MaxPartBytes, estimate);

    internal static ProfilePackageResult CreateCore(IReadOnlyList<ProfileFolderPath> folders, string outputPath, string userName,
                                                    string sourceProfile, string? password,
                                                    IProgress<ProfilePackageProgress>? progress, CancellationToken cancellationToken,
                                                    long maxPartBytes, ProfileEstimate? knownEstimate = null)
    {
        foreach (var folder in folders)
            if (UserProfiles.Find(folder.Key) is null) throw new ArgumentException(L.F("Nieznany folder profilu: {0}", folder.Key));
        if (password is { Length: 0 }) password = null;
        if (maxPartBytes <= 0) throw new ArgumentOutOfRangeException(nameof(maxPartBytes));
        outputPath = Path.GetFullPath(outputPath);
        var estimate = knownEstimate ?? Estimate(folders, cancellationToken);
        var skipped = new List<string>();
        var entries = new List<ProfileFileEntry>();
        long done = 0;
        IReadOnlyList<string> parts;
        using (var packageStream = new PackagePartWriteStream(outputPath, maxPartBytes))
        {
            void WriteArchive(Stream target)
            {
                using var zip = new ZipArchive(target, ZipArchiveMode.Create, leaveOpen: true);
                var lastReport = DateTime.MinValue;
                foreach (var folder in folders)
                {
                    if (!Directory.Exists(folder.Path)) continue;
                    foreach (var item in Enumerate(folder, [outputPath], cancellationToken))
                    {
                        if (item.File is null)
                        {
                            skipped.Add(L.F("Pominięto dowiązanie: {0}", item.FullPath));
                            continue;
                        }
                        if (estimate.MaxFileSize is long limit && item.File.Length > limit)
                        {
                            skipped.Add(L.F("Pominięto duży plik: {0}", item.FullPath));
                            continue;
                        }
                        var entry = TryAddFile(zip, item, skipped, cancellationToken);
                        if (entry is null) continue;
                        entries.Add(entry);
                        done += entry.Size;
                        if (progress is not null && (DateTime.UtcNow - lastReport).TotalMilliseconds >= 200)
                        {
                            lastReport = DateTime.UtcNow;
                            progress.Report(new ProfilePackageProgress(done, estimate.Bytes, entries.Count, estimate.Files, item.RelativePath));
                        }
                    }
                }
                cancellationToken.ThrowIfCancellationRequested();
                var manifest = new ProfilePackageManifest(FormatVersion, DateTimeOffset.Now, Environment.MachineName, userName,
                                                          sourceProfile, folders.Select(f => f.Key).ToList(), entries);
                using var stream = zip.CreateEntry(ManifestEntry, CompressionLevel.Optimal).Open();
                stream.Write(SerializeManifest(manifest));
            }
            if (password is null) WriteArchive(packageStream);
            else
            {
                using var encrypted = ProfilePackageCrypto.CreateEncryptingStream(packageStream, password);
                WriteArchive(encrypted);
            }
            parts = packageStream.Commit();
        }
        progress?.Report(new ProfilePackageProgress(done, done, entries.Count, entries.Count, ""));
        return new ProfilePackageResult(entries.Count, done, skipped, parts);
    }

    public static bool IsEncrypted(string packagePath) => ProfilePackageCrypto.IsEncrypted(packagePath);

    public static IReadOnlyList<string> GetPackageParts(string packagePath)
    {
        var fullPath = Path.GetFullPath(packagePath);
        if (!File.Exists(fullPath)) throw new FileNotFoundException(L.T("Nie znaleziono pliku paczki."), fullPath);
        var numbered = FindNumberedParts(fullPath);
        var parts = new List<string> { fullPath };
        var expected = 2;
        foreach (var (number, path) in numbered.OrderBy(item => item.Key))
        {
            if (number != expected)
                throw new ProfilePackageException(L.F("Brakuje części paczki: {0}", PartPath(fullPath, expected)));
            parts.Add(path);
            expected++;
        }
        return parts;
    }

    public static string ComputeSha256(string packagePath)
    {
        using var stream = OpenPackageStream(packagePath);
        return Convert.ToHexStringLower(SHA256.HashData(stream));
    }

    /// <summary>Odczytuje manifest i sprawdza sumę SHA256 oraz rozmiar każdego pliku bez zapisywania czegokolwiek.</summary>
    public static ProfileVerification Verify(string packagePath, string? password = null,
                                             IProgress<ProfilePackageProgress>? progress = null, CancellationToken cancellationToken = default)
    {
        using var package = OpenPackage(packagePath, password, cancellationToken);
        return Verify(package, progress, cancellationToken);
    }

    private static ProfileVerification Verify(OpenedPackage package, IProgress<ProfilePackageProgress>? progress,
                                              CancellationToken cancellationToken)
    {
        var problems = new List<string>();
        var manifest = package.Manifest;
        long done = 0;
        var count = 0;
        var lastReport = DateTime.MinValue;
        foreach (var file in manifest.Files)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var entry = package.Zip.GetEntry(FilesPrefix + file.Path);
            if (entry is null)
            {
                problems.Add(L.F("Brak pliku w paczce: {0}", file.Path));
                continue;
            }
            using (var stream = entry.Open())
            {
                var (size, hash) = HashLimited(stream, file.Size, Stream.Null, cancellationToken);
                if (size != file.Size || !string.Equals(hash, file.Sha256, StringComparison.OrdinalIgnoreCase))
                    problems.Add(L.F("Niezgodna suma kontrolna lub rozmiar: {0}", file.Path));
            }
            done += file.Size;
            count++;
            if (progress is not null && (DateTime.UtcNow - lastReport).TotalMilliseconds >= 200)
            {
                lastReport = DateTime.UtcNow;
                progress.Report(new ProfilePackageProgress(done, manifest.TotalBytes, count, manifest.Files.Count, file.Path));
            }
        }
        return new ProfileVerification(manifest, package.Encrypted, problems);
    }

    /// <summary>Szacuje konflikty i wymagane miejsce bez zapisywania plików.</summary>
    public static ProfileRestorePreview PreviewRestore(ProfileVerification verification, IReadOnlyList<ProfileFolderPath> targets,
                                                        RestoreConflictMode mode, CancellationToken cancellationToken = default)
    {
        if (!verification.Succeeded)
            throw new ProfilePackageException(L.T("Paczka nie przeszła weryfikacji – niczego nie przywrócono."));

        var map = targets.ToDictionary(t => t.Key, t => Path.GetFullPath(t.Path), StringComparer.Ordinal);
        var bytesByVolume = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
        int filesToWrite = 0, existingFiles = 0, skippedFiles = 0;
        long bytesToWrite = 0, existingBytes = 0;

        foreach (var file in verification.Manifest.Files)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var separator = file.Path.IndexOf('/');
            if (separator <= 0 || !map.TryGetValue(file.Path[..separator], out var root))
            {
                skippedFiles++;
                continue;
            }

            var destination = SafeCombine(root, file.Path[(separator + 1)..]);
            if (ContainsLink(root, destination) || Directory.Exists(destination))
            {
                skippedFiles++;
                continue;
            }

            if (File.Exists(destination))
            {
                existingFiles++;
                existingBytes += new FileInfo(destination).Length;
                if (mode == RestoreConflictMode.Skip)
                {
                    skippedFiles++;
                    continue;
                }
            }

            filesToWrite++;
            bytesToWrite += file.Size;
            var volume = Path.GetPathRoot(destination);
            if (string.IsNullOrEmpty(volume)) continue;
            bytesByVolume[volume] = bytesByVolume.GetValueOrDefault(volume) + file.Size;
        }

        return new ProfileRestorePreview(filesToWrite, bytesToWrite, existingFiles, existingBytes, skippedFiles, bytesByVolume);
    }

    /// <summary>
    /// Przywraca pliki do folderów docelowych (klucz → ścieżka). Najpierw weryfikuje całą paczkę – jeśli cokolwiek się nie zgadza,
    /// nic nie jest zapisywane. Nadpisywane pliki trafiają do <paramref name="backupRoot"/>.
    /// </summary>
    public static ProfileRestoreResult Restore(string packagePath, IReadOnlyList<ProfileFolderPath> targets, RestoreConflictMode mode,
                                               string backupRoot, string? password = null,
                                               IProgress<ProfilePackageProgress>? progress = null, CancellationToken cancellationToken = default)
    {
        using var package = OpenPackage(packagePath, password, cancellationToken);
        var verification = Verify(package, progress, cancellationToken);
        if (!verification.Succeeded)
            throw new ProfilePackageException(L.T("Paczka nie przeszła weryfikacji – niczego nie przywrócono.") + "\n" +
                                              string.Join("\n", verification.Problems.Take(10)));
        var map = targets.ToDictionary(t => t.Key, t => Path.GetFullPath(t.Path), StringComparer.Ordinal);
        var manifest = package.Manifest;
        var problems = new List<string>();
        int restored = 0, skipped = 0, backedUp = 0, renamed = 0, count = 0;
        long done = 0;
        var lastReport = DateTime.MinValue;
        var backupUsed = false;
        foreach (var file in manifest.Files)
        {
            cancellationToken.ThrowIfCancellationRequested();
            count++;
            done += file.Size;
            var separator = file.Path.IndexOf('/');
            var key = file.Path[..separator];
            var relative = file.Path[(separator + 1)..];
            if (!map.TryGetValue(key, out var root))
            {
                skipped++;
                continue;
            }
            var destination = SafeCombine(root, relative);
            if (ContainsLink(root, destination))
            {
                problems.Add(L.F("Pominięto (ścieżka docelowa prowadzi przez dowiązanie): {0}", destination));
                skipped++;
                continue;
            }
            string? backupPath = null;
            var originalMovedToBackup = false;

            Exception? RestoreOriginal()
            {
                if (!originalMovedToBackup || backupPath is null || File.Exists(destination) || Directory.Exists(destination))
                    return null;
                try
                {
                    File.Move(backupPath, destination);
                    backedUp--;
                    backupUsed = backedUp > 0;
                    originalMovedToBackup = false;
                    return null;
                }
                catch (Exception rollbackException) when (rollbackException is IOException or UnauthorizedAccessException)
                {
                    return rollbackException;
                }
            }

            try
            {
                if (File.Exists(destination) || Directory.Exists(destination))
                {
                    if (Directory.Exists(destination) || mode == RestoreConflictMode.Skip)
                    {
                        skipped++;
                        continue;
                    }
                    if (mode == RestoreConflictMode.KeepBoth)
                    {
                        destination = UniqueName(destination);
                        renamed++;
                    }
                    else
                    {
                        backupPath = UniqueName(SafeCombine(Path.Combine(backupRoot, key), relative));
                        Directory.CreateDirectory(Path.GetDirectoryName(backupPath)!);
                        File.Move(destination, backupPath);
                        originalMovedToBackup = true;
                        backupUsed = true;
                        backedUp++;
                    }
                }
                Extract(package.Zip.GetEntry(FilesPrefix + file.Path)!, file, destination, cancellationToken);
                restored++;
            }
            catch (OperationCanceledException)
            {
                var rollbackError = RestoreOriginal();
                if (rollbackError is not null)
                    throw new ProfilePackageException(L.F("Nie przywrócono {0}: {1}", file.Path,
                        $"{backupPath}: {rollbackError.Message}"));
                throw;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ProfilePackageException)
            {
                var rollbackError = RestoreOriginal();
                var message = rollbackError is null
                    ? ex.Message
                    : $"{ex.Message}; {backupPath}: {rollbackError.Message}";
                problems.Add(L.F("Nie przywrócono {0}: {1}", file.Path, message));
            }
            if (progress is not null && (DateTime.UtcNow - lastReport).TotalMilliseconds >= 200)
            {
                lastReport = DateTime.UtcNow;
                progress.Report(new ProfilePackageProgress(done, manifest.TotalBytes, count, manifest.Files.Count, file.Path));
            }
        }
        return new ProfileRestoreResult(restored, skipped, backedUp, renamed, backupUsed ? backupRoot : null, problems);
    }

    private static void Extract(ZipArchiveEntry entry, ProfileFileEntry file, string destination, CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
        var temporary = destination + ".partial";
        try
        {
            using (var input = entry.Open())
            using (var output = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                var (size, hash) = HashLimited(input, file.Size, output, cancellationToken);
                if (size != file.Size || !string.Equals(hash, file.Sha256, StringComparison.OrdinalIgnoreCase))
                    throw new ProfilePackageException(L.F("Niezgodna suma kontrolna lub rozmiar: {0}", file.Path));
            }
            File.SetLastWriteTimeUtc(temporary, file.ModifiedUtc);
            File.Move(temporary, destination);
        }
        catch
        {
            TryDelete(temporary);
            throw;
        }
    }

    /// <summary>Kopiuje i liczy SHA256, czytając najwyżej <paramref name="expected"/>+1 bajtów (ochrona przed „bombą ZIP”).</summary>
    private static (long Size, string Hash) HashLimited(Stream input, long expected, Stream output, CancellationToken cancellationToken)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[81920];
        long total = 0;
        int read;
        while ((read = input.Read(buffer, 0, (int)Math.Min(buffer.Length, expected - total + 1))) > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            total += read;
            if (total > expected) break;
            hash.AppendData(buffer, 0, read);
            output.Write(buffer, 0, read);
        }
        return (total, Convert.ToHexStringLower(hash.GetHashAndReset()));
    }

    private static ProfileFileEntry? TryAddFile(ZipArchive zip, FileItem item, List<string> skipped, CancellationToken cancellationToken)
    {
        FileStream input;
        try
        {
            input = new FileStream(item.FullPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 81920);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            skipped.Add(L.F("Pominięto (plik zablokowany lub brak dostępu): {0}", item.FullPath));
            return null;
        }
        using (input)
        {
            var name = item.Key + "/" + item.RelativePath;
            var entry = zip.CreateEntry(FilesPrefix + name, CompressionLevel.Optimal);
            var modified = item.File!.LastWriteTimeUtc;
            if (modified.Year is >= 1980 and <= 2107) entry.LastWriteTime = modified.ToLocalTime();
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            using var output = entry.Open();
            var buffer = new byte[81920];
            long size = 0;
            int read;
            try
            {
                while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    hash.AppendData(buffer, 0, read);
                    output.Write(buffer, 0, read);
                    size += read;
                }
            }
            catch (IOException ex)
            {
                // Wpis w ZIP już istnieje – plik częściowo odczytany nie może trafić do manifestu jako poprawny.
                throw new ProfilePackageException(L.F("Błąd odczytu pliku {0}: {1}", item.FullPath, ex.Message));
            }
            return new ProfileFileEntry(name, size, Convert.ToHexStringLower(hash.GetHashAndReset()), modified);
        }
    }

    private sealed record FileItem(string Key, string FullPath, string RelativePath, FileInfo? File);

    /// <summary>Przechodzi drzewo folderu bez wchodzenia w dowiązania (junction/symlink); dowiązania zwraca z <c>File = null</c>.</summary>
    private static IEnumerable<FileItem> Enumerate(ProfileFolderPath folder, string[]? exclude, CancellationToken cancellationToken)
    {
        var root = Path.GetFullPath(folder.Path).TrimEnd(Path.DirectorySeparatorChar);
        var pending = new Stack<DirectoryInfo>();
        pending.Push(new DirectoryInfo(root));
        var options = new EnumerationOptions { RecurseSubdirectories = false, IgnoreInaccessible = true, AttributesToSkip = 0 };
        while (pending.Count > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var directory = pending.Pop();
            IEnumerable<FileSystemInfo> children;
            try
            {
                children = directory.EnumerateFileSystemInfos("*", options).ToList();
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                continue;
            }
            foreach (var child in children)
            {
                var relative = Path.GetRelativePath(root, child.FullName).Replace('\\', '/');
                if (child.Attributes.HasFlag(FileAttributes.ReparsePoint))
                {
                    yield return new FileItem(folder.Key, child.FullName, relative, null);
                    continue;
                }
                if (child is DirectoryInfo sub)
                {
                    pending.Push(sub);
                    continue;
                }
                if (IsExcluded(child.Name) || exclude?.Any(e => IsPackageOutputPath(child.FullName, e)) == true)
                    continue;
                yield return new FileItem(folder.Key, child.FullName, relative, (FileInfo)child);
            }
        }
    }

    private static bool IsPackageOutputPath(string candidate, string outputPath)
    {
        if (candidate.Equals(outputPath, StringComparison.OrdinalIgnoreCase)) return true;
        if (!candidate.StartsWith(outputPath + ".", StringComparison.OrdinalIgnoreCase)) return false;
        var suffix = candidate[(outputPath.Length + 1)..];
        return suffix.Length >= 3 && suffix.All(char.IsAsciiDigit);
    }

    private static string PartPath(string outputPath, int number) =>
        outputPath + "." + number.ToString("D3", System.Globalization.CultureInfo.InvariantCulture);

    private static Dictionary<int, string> FindNumberedParts(string outputPath)
    {
        var directory = Path.GetDirectoryName(outputPath)!;
        var prefix = Path.GetFileName(outputPath) + ".";
        var parts = new Dictionary<int, string>();
        foreach (var path in Directory.EnumerateFiles(directory))
        {
            var name = Path.GetFileName(path);
            if (!name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) continue;
            var suffix = name[prefix.Length..];
            if (suffix.Length < 3 || !suffix.All(char.IsAsciiDigit) ||
                !int.TryParse(suffix, System.Globalization.NumberStyles.None,
                              System.Globalization.CultureInfo.InvariantCulture, out var number) || number < 2)
                continue;
            if (!parts.TryAdd(number, path))
                throw new ProfilePackageException(L.T("Paczka zawiera powtórzony numer części."));
        }
        return parts;
    }

    private static Stream OpenPackageStream(string packagePath)
    {
        var parts = GetPackageParts(packagePath);
        return parts.Count == 1 ? File.OpenRead(parts[0]) : new PackagePartReadStream(parts);
    }

    private sealed class PackagePartWriteStream(string outputPath, long maxPartBytes) : Stream
    {
        private readonly List<(string Final, string Partial)> _parts = [];
        private readonly List<string> _published = [];
        private FileStream? _current;
        private long _currentBytes;
        private bool _committed;
        private bool _disposed;

        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => !_disposed;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() => _current?.Flush();
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));

        public override void Write(ReadOnlySpan<byte> buffer)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            while (!buffer.IsEmpty)
            {
                if (_current is null || _currentBytes == maxPartBytes) OpenNextPart();
                var count = (int)Math.Min(buffer.Length, maxPartBytes - _currentBytes);
                _current!.Write(buffer[..count]);
                _currentBytes += count;
                buffer = buffer[count..];
            }
        }

        private void OpenNextPart()
        {
            _current?.Flush(true);
            _current?.Dispose();
            var number = _parts.Count + 1;
            var final = number == 1 ? outputPath : PartPath(outputPath, number);
            var partial = final + ".partial";
            _current = new FileStream(partial, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            _parts.Add((final, partial));
            _currentBytes = 0;
        }

        public IReadOnlyList<string> Commit()
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            _current?.Flush(true);
            _current?.Dispose();
            _current = null;
            var existingParts = FindNumberedParts(outputPath);
            if (existingParts.Count > 0 || _parts.Count > 1 && File.Exists(outputPath))
                throw new IOException(L.T("Plik paczki lub jej części już istnieją. Wybierz inną nazwę, aby ich nie nadpisać."));
            for (var i = _parts.Count - 1; i >= 1; i--)
            {
                File.Move(_parts[i].Partial, _parts[i].Final);
                _published.Add(_parts[i].Final);
            }
            File.Move(_parts[0].Partial, _parts[0].Final, overwrite: _parts.Count == 1);
            _committed = true;
            return _parts.Select(part => part.Final).ToList();
        }

        protected override void Dispose(bool disposing)
        {
            if (!_disposed && disposing)
            {
                _disposed = true;
                _current?.Dispose();
                if (!_committed)
                {
                    foreach (var part in _parts) TryDelete(part.Partial);
                    foreach (var part in _published) TryDelete(part);
                }
            }
            base.Dispose(disposing);
        }
    }

    private sealed class PackagePartReadStream : Stream
    {
        private readonly IReadOnlyList<string> _paths;
        private readonly long[] _starts;
        private readonly long[] _lengths;
        private FileStream? _current;
        private int _currentIndex = -1;
        private long _position;
        private bool _disposed;

        public PackagePartReadStream(IReadOnlyList<string> paths)
        {
            _paths = paths;
            _starts = new long[paths.Count];
            _lengths = new long[paths.Count];
            for (var i = 0; i < paths.Count; i++)
            {
                _starts[i] = i == 0 ? 0 : _starts[i - 1] + _lengths[i - 1];
                _lengths[i] = new FileInfo(paths[i]).Length;
            }
        }

        public override bool CanRead => !_disposed;
        public override bool CanSeek => !_disposed;
        public override bool CanWrite => false;
        public override long Length => _lengths[^1] + _starts[^1];
        public override long Position { get => _position; set => Seek(value, SeekOrigin.Begin); }
        public override void Flush() { }
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

        public override int Read(Span<byte> buffer)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            var total = 0;
            while (!buffer.IsEmpty && _position < Length)
            {
                var index = FindPart(_position);
                EnsurePart(index);
                var localPosition = _position - _starts[index];
                if (_current!.Position != localPosition) _current.Position = localPosition;
                var available = (int)Math.Min(buffer.Length, _lengths[index] - localPosition);
                var read = _current.Read(buffer[..available]);
                if (read == 0) throw new EndOfStreamException(L.T("Brakuje danych w części paczki."));
                total += read;
                _position += read;
                buffer = buffer[read..];
            }
            return total;
        }

        private int FindPart(long position)
        {
            for (var i = 0; i < _paths.Count; i++)
                if (position < _starts[i] + _lengths[i] || i == _paths.Count - 1) return i;
            return _paths.Count - 1;
        }

        private void EnsurePart(int index)
        {
            if (_currentIndex == index) return;
            _current?.Dispose();
            _current = new FileStream(_paths[index], FileMode.Open, FileAccess.Read, FileShare.Read);
            _currentIndex = index;
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            var target = origin switch
            {
                SeekOrigin.Begin => offset,
                SeekOrigin.Current => _position + offset,
                SeekOrigin.End => Length + offset,
                _ => throw new ArgumentOutOfRangeException(nameof(origin)),
            };
            if (target < 0 || target > Length) throw new IOException(L.T("Nieprawidłowe przesunięcie w paczce."));
            _position = target;
            return _position;
        }

        protected override void Dispose(bool disposing)
        {
            if (!_disposed && disposing)
            {
                _disposed = true;
                _current?.Dispose();
            }
            base.Dispose(disposing);
        }
    }

    private sealed class OpenedPackage(ZipArchive zip, Stream stream, ProfilePackageManifest manifest, bool encrypted) : IDisposable
    {
        public ZipArchive Zip { get; } = zip;
        public ProfilePackageManifest Manifest { get; } = manifest;
        public bool Encrypted { get; } = encrypted;

        public void Dispose()
        {
            Zip.Dispose();
            stream.Dispose();
        }
    }

    private static OpenedPackage OpenPackage(string path, string? password, CancellationToken cancellationToken)
    {
        var encrypted = ProfilePackageCrypto.IsEncrypted(path);
        Stream stream;
        if (encrypted)
        {
            if (string.IsNullOrEmpty(password))
                throw new ProfilePackageException(L.T("Paczka jest zaszyfrowana – podaj hasło."));
            // Odszyfrowana kopia trafia do pliku tymczasowego usuwanego automatycznie po zamknięciu.
            stream = new FileStream(Path.Combine(Path.GetTempPath(), "baprofile-" + Guid.NewGuid().ToString("N") + ".tmp"),
                                    FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None, 81920, FileOptions.DeleteOnClose);
            try
            {
                using (var input = OpenPackageStream(path)) ProfilePackageCrypto.Decrypt(input, stream, password, cancellationToken);
                stream.Position = 0;
            }
            catch
            {
                stream.Dispose();
                throw;
            }
        }
        else
        {
            stream = OpenPackageStream(path);
        }
        try
        {
            ZipArchive zip;
            try
            {
                zip = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: true);
            }
            catch (InvalidDataException)
            {
                throw new ProfilePackageException(L.T("Plik nie jest paczką profilu (nieprawidłowy format)."));
            }
            try
            {
                var manifest = ReadManifest(zip);
                return new OpenedPackage(zip, stream, manifest, encrypted);
            }
            catch
            {
                zip.Dispose();
                throw;
            }
        }
        catch
        {
            stream.Dispose();
            throw;
        }
    }

    private static ProfilePackageManifest ReadManifest(ZipArchive zip)
    {
        var entry = zip.GetEntry(ManifestEntry) ?? throw new ProfilePackageException(L.T("W paczce brakuje pliku manifest.json."));
        if (entry.Length > MaxManifestBytes) throw new ProfilePackageException(L.T("Manifest paczki jest zbyt duży."));
        var manifest = ParseManifest(entry);
        var listed = new HashSet<string>(manifest.Files.Select(f => FilesPrefix + f.Path), StringComparer.OrdinalIgnoreCase);
        if (listed.Count != manifest.Files.Count) throw new ProfilePackageException(L.T("Manifest zawiera powtórzone ścieżki."));
        foreach (var item in zip.Entries)
            if (item.FullName != ManifestEntry && !listed.Contains(item.FullName))
                throw new ProfilePackageException(L.F("Paczka zawiera plik spoza manifestu: {0}", item.FullName));
        return manifest;
    }

    private static ProfilePackageManifest ParseManifest(ZipArchiveEntry entry)
    {
        try
        {
            using var stream = entry.Open();
            var root = JsonNode.Parse(stream)?.AsObject() ?? throw new JsonException();
            if ((string?)root["format"] != FormatName) throw new ProfilePackageException(L.T("Plik nie jest paczką profilu (nieprawidłowy format)."));
            var version = (int?)root["formatVersion"] ?? 0;
            if (version != FormatVersion) throw new ProfilePackageException(L.F("Nieobsługiwana wersja paczki: {0}", version));
            var folders = (root["folders"]?.AsArray() ?? []).Select(n => (string?)n ?? "").ToList();
            var files = new List<ProfileFileEntry>();
            foreach (var node in root["files"]?.AsArray() ?? throw new JsonException())
            {
                var path = (string?)node?["path"] ?? "";
                var size = (long?)node?["size"] ?? -1;
                var sha = (string?)node?["sha256"] ?? "";
                if (!IsSafeRelativePath(path) || size < 0 || sha.Length != 64 || !sha.All(char.IsAsciiHexDigit))
                    throw new ProfilePackageException(L.F("Manifest zawiera niedozwoloną pozycję: {0}", path));
                var modified = DateTime.TryParse((string?)node?["modifiedUtc"], null, System.Globalization.DateTimeStyles.RoundtripKind, out var m)
                    ? DateTime.SpecifyKind(m.ToUniversalTime(), DateTimeKind.Utc) : DateTime.UtcNow;
                files.Add(new ProfileFileEntry(path, size, sha.ToLowerInvariant(), modified));
            }
            var created = DateTimeOffset.TryParse((string?)root["created"], out var c) ? c : DateTimeOffset.MinValue;
            return new ProfilePackageManifest(version, created, (string?)root["machine"] ?? "", (string?)root["userName"] ?? "",
                                              (string?)root["sourceProfile"] ?? "", folders, files);
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or FormatException or InvalidDataException)
        {
            throw new ProfilePackageException(L.T("Manifest paczki jest uszkodzony."));
        }
    }

    private static byte[] SerializeManifest(ProfilePackageManifest manifest)
    {
        var files = new JsonArray();
        foreach (var file in manifest.Files)
            files.Add(new JsonObject
            {
                ["path"] = file.Path,
                ["size"] = file.Size,
                ["sha256"] = file.Sha256,
                ["modifiedUtc"] = file.ModifiedUtc.ToUniversalTime().ToString("O"),
            });
        var root = new JsonObject
        {
            ["format"] = FormatName,
            ["formatVersion"] = manifest.FormatVersion,
            ["created"] = manifest.Created.ToString("O"),
            ["machine"] = manifest.Machine,
            ["userName"] = manifest.UserName,
            ["sourceProfile"] = manifest.SourceProfile,
            ["folders"] = new JsonArray(manifest.Folders.Select(f => (JsonNode?)JsonValue.Create(f)).ToArray()),
            ["fileCount"] = manifest.Files.Count,
            ["totalBytes"] = manifest.TotalBytes,
            ["files"] = files,
        };
        return JsonSerializer.SerializeToUtf8Bytes(root, new JsonSerializerOptions { WriteIndented = true });
    }

    /// <summary>Ścieżka „Klucz/podfolder/plik”: znany klucz, bez „..”, „.”, dysków, strumieni NTFS ani nazw zarezerwowanych.</summary>
    internal static bool IsSafeRelativePath(string path)
    {
        if (path.Length == 0 || path.Length > 1024 || path.Contains('\\')) return false;
        var segments = path.Split('/');
        if (segments.Length < 2 || UserProfiles.Find(segments[0]) is null) return false;
        var invalid = Path.GetInvalidFileNameChars();
        foreach (var segment in segments.Skip(1))
        {
            if (segment.Length == 0 || segment is "." or ".." || segment.IndexOfAny(invalid) >= 0 || segment.Contains(':') ||
                segment.EndsWith(' ') || segment.EndsWith('.') || IsReservedName(segment))
                return false;
        }
        return true;
    }

    private static bool IsReservedName(string segment)
    {
        var stem = segment.Split('.')[0].TrimEnd().ToUpperInvariant();
        return stem is "CON" or "PRN" or "AUX" or "NUL" or "CONIN$" or "CONOUT$" ||
               stem.Length == 4 && (stem.StartsWith("COM", StringComparison.Ordinal) || stem.StartsWith("LPT", StringComparison.Ordinal)) &&
               stem[3] is >= '0' and <= '9' or '¹' or '²' or '³';
    }

    private static string SafeCombine(string root, string relative)
    {
        var full = Path.GetFullPath(Path.Combine(root, relative.Replace('/', Path.DirectorySeparatorChar)));
        var prefix = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        if (!full.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            throw new ProfilePackageException(L.F("Ścieżka wychodzi poza folder docelowy: {0}", relative));
        return full;
    }

    /// <summary>Czy którykolwiek istniejący element ścieżki pod <paramref name="root"/> (lub sam plik) jest dowiązaniem.</summary>
    private static bool ContainsLink(string root, string destination)
    {
        var rootFull = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar);
        for (var current = destination; current.Length > rootFull.Length; current = Path.GetDirectoryName(current)!)
        {
            try
            {
                var attributes = File.GetAttributes(current);
                if (attributes.HasFlag(FileAttributes.ReparsePoint)) return true;
            }
            catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException) { }
        }
        return false;
    }

    private static string UniqueName(string path)
    {
        if (!File.Exists(path) && !Directory.Exists(path)) return path;
        var directory = Path.GetDirectoryName(path)!;
        var stem = Path.GetFileNameWithoutExtension(path);
        var extension = Path.GetExtension(path);
        for (var i = 2; ; i++)
        {
            var candidate = Path.Combine(directory, $"{stem} ({i}){extension}");
            if (!File.Exists(candidate) && !Directory.Exists(candidate)) return candidate;
        }
    }

    private static void TryDelete(string path)
    {
        try { File.Delete(path); } catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }
}
