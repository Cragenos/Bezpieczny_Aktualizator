using System.Diagnostics;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using BezpiecznyAktualizator.Core.Profiles;

namespace BezpiecznyAktualizator.Tests;

public sealed class ProfilePackageTests : IDisposable
{
    private readonly DirectoryInfo _root = Directory.CreateTempSubdirectory("ba_profile_test_");

    public void Dispose()
    {
        // Najpierw usuwamy dowiązania, aby nie kasować przez nie zawartości celu.
        foreach (var link in _root.EnumerateDirectories("*", SearchOption.AllDirectories)
                     .Where(d => d.Attributes.HasFlag(FileAttributes.ReparsePoint)).ToList())
            link.Delete();
        _root.Delete(recursive: true);
    }

    private string PathOf(params string[] parts) => Path.Combine([_root.FullName, .. parts]);

    private static byte[] Concatenate(IEnumerable<string> paths)
    {
        using var output = new MemoryStream();
        foreach (var path in paths)
        {
            using var input = File.OpenRead(path);
            input.CopyTo(output);
        }
        return output.ToArray();
    }

    private string CreateSource()
    {
        var desktop = Directory.CreateDirectory(PathOf("src", "Desktop"));
        File.WriteAllText(Path.Combine(desktop.FullName, "notatka.txt"), "zażółć gęślą jaźń");
        Directory.CreateDirectory(Path.Combine(desktop.FullName, "Projekty", "Głęboki"));
        File.WriteAllBytes(Path.Combine(desktop.FullName, "Projekty", "Głęboki", "dane.bin"), [1, 2, 3, 4, 5]);
        File.WriteAllText(Path.Combine(desktop.FullName, "~$blokada.docx"), "lock");
        File.WriteAllText(Path.Combine(desktop.FullName, "plik.tmp"), "temp");
        var documents = Directory.CreateDirectory(PathOf("src", "Documents"));
        File.WriteAllText(Path.Combine(documents.FullName, "raport.txt"), "raport");
        return PathOf("src");
    }

    private static List<ProfileFolderPath> Folders(string root) =>
        [new("Desktop", Path.Combine(root, "Desktop")), new("Documents", Path.Combine(root, "Documents"))];

    [Fact]
    public void PackageRoundTripRestoresFilesSkipsExcludedFilesAndLinks()
    {
        var source = CreateSource();
        var outside = Directory.CreateDirectory(PathOf("outside"));
        File.WriteAllText(Path.Combine(outside.FullName, "poza-profilem.txt"), "nie kopiować");
        CreateJunction(Path.Combine(source, "Desktop", "Link"), outside.FullName);
        var package = PathOf("profil" + ProfilePackage.Extension);

        var estimate = ProfilePackage.Estimate(Folders(source));
        var created = ProfilePackage.Create(Folders(source), package, "PC\\jan", source);
        var verification = ProfilePackage.Verify(package);

        Assert.Equal(3, estimate.Files);
        Assert.Equal(1, estimate.SkippedLinks);
        Assert.Equal(3, created.Files);
        Assert.Contains(created.Skipped, s => s.Contains("Link"));
        Assert.True(verification.Succeeded);
        Assert.False(verification.Encrypted);
        Assert.Equal("PC\\jan", verification.Manifest.UserName);
        Assert.Equal(["Desktop", "Documents"], verification.Manifest.Folders);
        Assert.False(File.Exists(package + ".partial"));

        var target = PathOf("dst");
        var result = ProfilePackage.Restore(package, Folders(target), RestoreConflictMode.Skip, PathOf("backup"));

        Assert.Equal(3, result.Restored);
        Assert.Empty(result.Problems);
        Assert.Equal("zażółć gęślą jaźń", File.ReadAllText(Path.Combine(target, "Desktop", "notatka.txt")));
        Assert.Equal([1, 2, 3, 4, 5], File.ReadAllBytes(Path.Combine(target, "Desktop", "Projekty", "Głęboki", "dane.bin")));
        Assert.Equal("raport", File.ReadAllText(Path.Combine(target, "Documents", "raport.txt")));
        Assert.False(File.Exists(Path.Combine(target, "Desktop", "~$blokada.docx")));
        Assert.False(File.Exists(Path.Combine(target, "Desktop", "plik.tmp")));
        Assert.False(Directory.Exists(Path.Combine(target, "Desktop", "Link")));
        Assert.Empty(Directory.GetFiles(target, "*.partial", SearchOption.AllDirectories));
    }

    [Fact]
    public void RestorePreviewReportsConflictsAndRequiredBytesWithoutWritingFiles()
    {
        var source = CreateSource();
        var package = PathOf("profil" + ProfilePackage.Extension);
        ProfilePackage.Create(Folders(source), package, "PC\\jan", source);
        var verification = ProfilePackage.Verify(package);
        var target = PathOf("dst");
        var existing = Path.Combine(target, "Documents", "raport.txt");
        Directory.CreateDirectory(Path.GetDirectoryName(existing)!);
        File.WriteAllText(existing, "old");

        var preview = ProfilePackage.PreviewRestore(verification, Folders(target), RestoreConflictMode.Skip);

        Assert.Equal(1, preview.ExistingFiles);
        Assert.Equal(3, preview.ExistingBytes);
        Assert.Equal(1, preview.SkippedFiles);
        Assert.Equal(2, preview.FilesToWrite);
        Assert.Equal(verification.Manifest.TotalBytes - 6, preview.BytesToWrite);
        Assert.Equal(preview.BytesToWrite, preview.BytesByVolume.Values.Sum());
        Assert.Equal("old", File.ReadAllText(existing));
        Assert.False(File.Exists(Path.Combine(target, "Desktop", "notatka.txt")));

        var overwritePreview = ProfilePackage.PreviewRestore(verification, Folders(target), RestoreConflictMode.Overwrite);
        Assert.Equal(3, overwritePreview.FilesToWrite);
        Assert.Equal(verification.Manifest.TotalBytes, overwritePreview.BytesToWrite);
        Assert.Equal(1, overwritePreview.ExistingFiles);
        Assert.Equal(0, overwritePreview.SkippedFiles);
    }

    [Fact]
    public void EncryptedPackageRequiresCorrectPasswordAndHidesContent()
    {
        var source = CreateSource();
        var big = new byte[(int)(2.5 * 1024 * 1024)];
        RandomNumberGenerator.Fill(big);
        File.WriteAllBytes(Path.Combine(source, "Documents", "duzy.bin"), big);
        var package = PathOf("tajne" + ProfilePackage.Extension);

        ProfilePackage.Create(Folders(source), package, "jan", source, password: "Dobre hasło 123");

        Assert.True(ProfilePackage.IsEncrypted(package));
        var raw = File.ReadAllBytes(package);
        Assert.DoesNotContain("manifest.json", Encoding.ASCII.GetString(raw));
        Assert.Throws<ProfilePackageException>(() => ProfilePackage.Verify(package));
        Assert.Throws<ProfilePackageException>(() => ProfilePackage.Verify(package, "złe hasło"));

        var target = PathOf("dst");
        var result = ProfilePackage.Restore(package, Folders(target), RestoreConflictMode.Skip, PathOf("backup"), "Dobre hasło 123");

        Assert.Equal(4, result.Restored);
        Assert.Equal(big, File.ReadAllBytes(Path.Combine(target, "Documents", "duzy.bin")));
    }

    [Fact]
    public void EncryptedPackageCanBeSplitAcrossPortablePartsAndRestored()
    {
        var source = CreateSource();
        var payload = RandomNumberGenerator.GetBytes(160_000);
        File.WriteAllBytes(Path.Combine(source, "Documents", "payload.bin"), payload);
        var package = PathOf("podzielona" + ProfilePackage.Extension);

        var created = ProfilePackage.CreateCore(Folders(source), package, "jan", source, "bezpieczne-haslo",
            progress: null, cancellationToken: default, maxPartBytes: 16_384);

        Assert.True(created.Parts.Count > 2);
        Assert.All(created.Parts, part => Assert.True(new FileInfo(part).Length <= 16_384));
        Assert.Equal(created.Parts, ProfilePackage.GetPackageParts(package));
        Assert.True(ProfilePackage.IsEncrypted(package));
        Assert.True(ProfilePackage.Verify(package, "bezpieczne-haslo").Succeeded);
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(Concatenate(created.Parts))),
            ProfilePackage.ComputeSha256(package));

        var target = PathOf("dst");
        var restored = ProfilePackage.Restore(package, Folders(target), RestoreConflictMode.Skip,
            PathOf("backup"), "bezpieczne-haslo");
        Assert.Equal(payload, File.ReadAllBytes(Path.Combine(target, "Documents", "payload.bin")));
        Assert.Equal(created.Files, restored.Restored);
    }

    [Fact]
    public void OptionalLargeFileFilterIsAppliedToEstimateAndPackage()
    {
        var source = CreateSource();
        var largeFile = Path.Combine(source, "Documents", "large.bin");
        File.WriteAllBytes(largeFile, new byte[2048]);
        var folders = Folders(source);
        var estimate = ProfilePackage.Estimate(folders, maxFileSize: 1024);

        Assert.Equal(3, estimate.Files);
        Assert.Equal(1, estimate.SkippedLargeFiles);
        Assert.Equal(2048L, estimate.SkippedLargeBytes);
        Assert.Equal(1024L, estimate.MaxFileSize);

        var package = PathOf("filtered" + ProfilePackage.Extension);
        var created = ProfilePackage.Create(folders, package, "jan", source, estimate: estimate);
        var verification = ProfilePackage.Verify(package);

        Assert.Equal(3, created.Files);
        Assert.Contains(created.Skipped, item => item.Contains("large.bin"));
        Assert.DoesNotContain(verification.Manifest.Files, file => file.Path.EndsWith("large.bin", StringComparison.Ordinal));
    }

    [Fact]
    public void ModifiedOrTruncatedEncryptedPackageIsRejected()
    {
        var source = CreateSource();
        File.WriteAllBytes(Path.Combine(source, "Documents", "duzy.bin"), RandomNumberGenerator.GetBytes(1_500_000));
        var package = PathOf("tajne" + ProfilePackage.Extension);
        ProfilePackage.Create(Folders(source), package, "jan", source, password: "haslo-123");
        var original = File.ReadAllBytes(package);

        var flipped = (byte[])original.Clone();
        flipped[original.Length / 2] ^= 0x01;
        File.WriteAllBytes(package, flipped);
        Assert.Throws<ProfilePackageException>(() => ProfilePackage.Verify(package, "haslo-123"));

        File.WriteAllBytes(package, original[..(original.Length - 100)]);
        Assert.Throws<ProfilePackageException>(() => ProfilePackage.Verify(package, "haslo-123"));

        // Usunięcie ostatniej porcji (ze znacznikiem końca) – pierwsza porcja ma 1 MiB + nagłówki.
        File.WriteAllBytes(package, original[..(36 + 4 + 1024 * 1024 + 16)]);
        Assert.Throws<ProfilePackageException>(() => ProfilePackage.Verify(package, "haslo-123"));
    }

    [Fact]
    public void ModifiedFileIsDetectedAndNothingIsRestored()
    {
        var source = CreateSource();
        var package = PathOf("profil" + ProfilePackage.Extension);
        ProfilePackage.Create(Folders(source), package, "jan", source);
        using (var zip = ZipFile.Open(package, ZipArchiveMode.Update))
        {
            zip.GetEntry("files/Documents/raport.txt")!.Delete();
            using var writer = new StreamWriter(zip.CreateEntry("files/Documents/raport.txt").Open());
            writer.Write("podmieniony");
        }

        var verification = ProfilePackage.Verify(package);
        Assert.False(verification.Succeeded);
        Assert.Contains(verification.Problems, p => p.Contains("Documents/raport.txt"));

        var target = PathOf("dst");
        Assert.Throws<ProfilePackageException>(() =>
            ProfilePackage.Restore(package, Folders(target), RestoreConflictMode.Overwrite, PathOf("backup")));
        Assert.False(Directory.Exists(target));
    }

    [Theory]
    [InlineData("Desktop/../../evil.txt")]
    [InlineData("Desktop/C:/evil.txt")]
    [InlineData("Unknown/plik.txt")]
    [InlineData("Desktop/plik.txt:ukryty")]
    [InlineData("Desktop/CON.txt")]
    public void PathTraversalAndUnsafeNamesInManifestAreRejected(string path)
    {
        var package = PathOf("zly" + ProfilePackage.Extension);
        WriteCraftedPackage(package, path, "zły", includeManifestEntry: true);

        Assert.Throws<ProfilePackageException>(() => ProfilePackage.Verify(package));
        Assert.Throws<ProfilePackageException>(() =>
            ProfilePackage.Restore(package, Folders(PathOf("dst")), RestoreConflictMode.Overwrite, PathOf("backup")));
        Assert.False(File.Exists(PathOf("evil.txt")));
    }

    [Fact]
    public void EntryOutsideManifestIsRejected()
    {
        var package = PathOf("zly" + ProfilePackage.Extension);
        WriteCraftedPackage(package, "Desktop/ok.txt", "ok", includeManifestEntry: false);

        var ex = Assert.Throws<ProfilePackageException>(() => ProfilePackage.Verify(package));
        Assert.Contains("files/Desktop/ok.txt", ex.Message);
    }

    [Fact]
    public void RestoreDoesNotWriteThroughJunctionInTarget()
    {
        var source = CreateSource();
        var package = PathOf("profil" + ProfilePackage.Extension);
        ProfilePackage.Create(Folders(source), package, "jan", source);
        var target = PathOf("dst");
        var elsewhere = Directory.CreateDirectory(PathOf("elsewhere"));
        Directory.CreateDirectory(Path.Combine(target, "Desktop"));
        CreateJunction(Path.Combine(target, "Desktop", "Projekty"), elsewhere.FullName);

        var result = ProfilePackage.Restore(package, Folders(target), RestoreConflictMode.Overwrite, PathOf("backup"));

        Assert.Empty(elsewhere.GetFileSystemInfos("*", SearchOption.AllDirectories));
        Assert.Contains(result.Problems, p => p.Contains("Projekty"));
        Assert.Equal(2, result.Restored);
    }

    [Theory]
    [InlineData(RestoreConflictMode.Skip)]
    [InlineData(RestoreConflictMode.Overwrite)]
    [InlineData(RestoreConflictMode.KeepBoth)]
    public void ConflictsAreHandledAccordingToMode(RestoreConflictMode mode)
    {
        var source = CreateSource();
        var package = PathOf("profil" + ProfilePackage.Extension);
        ProfilePackage.Create(Folders(source), package, "jan", source);
        var target = PathOf("dst");
        var existing = Path.Combine(target, "Documents", "raport.txt");
        Directory.CreateDirectory(Path.GetDirectoryName(existing)!);
        File.WriteAllText(existing, "lokalna wersja");
        var backup = PathOf("backup");

        var result = ProfilePackage.Restore(package, Folders(target), mode, backup);

        switch (mode)
        {
            case RestoreConflictMode.Skip:
                Assert.Equal("lokalna wersja", File.ReadAllText(existing));
                Assert.Equal(1, result.Skipped);
                break;
            case RestoreConflictMode.Overwrite:
                Assert.Equal("raport", File.ReadAllText(existing));
                Assert.Equal("lokalna wersja", File.ReadAllText(Path.Combine(backup, "Documents", "raport.txt")));
                Assert.Equal(backup, result.BackupFolder);
                break;
            default:
                Assert.Equal("lokalna wersja", File.ReadAllText(existing));
                Assert.Equal("raport", File.ReadAllText(Path.Combine(target, "Documents", "raport (2).txt")));
                Assert.Equal(1, result.Renamed);
                break;
        }
    }

    [Fact]
    public void FailedOverwriteRestoresOriginalFileFromBackup()
    {
        var source = CreateSource();
        var package = PathOf("profil" + ProfilePackage.Extension);
        ProfilePackage.Create(Folders(source), package, "jan", source);
        var target = PathOf("dst");
        var existing = Path.Combine(target, "Documents", "raport.txt");
        Directory.CreateDirectory(Path.GetDirectoryName(existing)!);
        File.WriteAllText(existing, "lokalna wersja");
        Directory.CreateDirectory(existing + ".partial");
        var backup = PathOf("backup");

        var result = ProfilePackage.Restore(package, Folders(target), RestoreConflictMode.Overwrite, backup);

        Assert.Equal("lokalna wersja", File.ReadAllText(existing));
        Assert.Equal(0, result.BackedUp);
        Assert.Null(result.BackupFolder);
        Assert.Contains(result.Problems, problem => problem.Contains("raport.txt"));
        Assert.False(File.Exists(Path.Combine(backup, "Documents", "raport.txt")));
    }

    [Fact]
    public void CanceledRestoreReturnsPartialResultAndBackupLocation()
    {
        var source = CreateSource();
        var package = PathOf("profil" + ProfilePackage.Extension);
        ProfilePackage.Create(Folders(source), package, "jan", source);
        var verification = ProfilePackage.Verify(package);
        var firstFile = verification.Manifest.Files[0];
        var separator = firstFile.Path.IndexOf('/');
        var key = firstFile.Path[..separator];
        var relative = firstFile.Path[(separator + 1)..];
        var target = PathOf("dst");
        var existing = Path.Combine(target, key, relative.Replace('/', Path.DirectorySeparatorChar));
        Directory.CreateDirectory(Path.GetDirectoryName(existing)!);
        File.WriteAllText(existing, "old");
        var backup = PathOf("backup");
        using var cancellation = new CancellationTokenSource();

        var result = ProfilePackage.Restore(package, Folders(target), RestoreConflictMode.Overwrite, backup,
            progress: new CancelAfterFirstRestoredFile(cancellation), cancellationToken: cancellation.Token);

        Assert.True(result.Canceled);
        Assert.Equal(1, result.Restored);
        Assert.Equal(1, result.BackedUp);
        Assert.Equal(backup, result.BackupFolder);
        Assert.Equal("old", File.ReadAllText(Path.Combine(backup, key, relative.Replace('/', Path.DirectorySeparatorChar))));
        Assert.Equal(File.ReadAllBytes(Path.Combine(source, key, relative.Replace('/', Path.DirectorySeparatorChar))),
            File.ReadAllBytes(existing));
    }

    [Fact]
    public void OverwriteBackupUsesTargetVolumeWhenRequestedBackupIsOnAnotherVolume()
    {
        var targetVolume = Path.GetPathRoot(_root.FullName);
        string? alternateRoot = null;
        foreach (var drive in DriveInfo.GetDrives())
        {
            if (!drive.IsReady || drive.DriveType != DriveType.Fixed ||
                string.Equals(drive.RootDirectory.FullName, targetVolume, StringComparison.OrdinalIgnoreCase))
                continue;
            var candidate = Path.Combine(drive.RootDirectory.FullName, $"ba_profile_backup_test_{Guid.NewGuid():N}");
            try
            {
                Directory.CreateDirectory(candidate);
                alternateRoot = candidate;
                break;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
            }
        }
        if (alternateRoot is null) return;

        try
        {
            var source = CreateSource();
            var package = PathOf("profil" + ProfilePackage.Extension);
            ProfilePackage.Create(Folders(source), package, "jan", source);
            var target = PathOf("dst");
            var existing = Path.Combine(target, "Documents", "raport.txt");
            Directory.CreateDirectory(Path.GetDirectoryName(existing)!);
            File.WriteAllText(existing, "old");
            var requestedBackup = Path.Combine(alternateRoot, "backup");
            var expectedBackup = Path.Combine(target, "backup");

            var result = ProfilePackage.Restore(package, Folders(target), RestoreConflictMode.Overwrite, requestedBackup);

            Assert.Empty(result.Problems);
            Assert.Equal(expectedBackup, Assert.Single(result.BackupFolders));
            Assert.Equal("old", File.ReadAllText(Path.Combine(expectedBackup, "Documents", "raport.txt")));
            Assert.False(Directory.Exists(requestedBackup));
        }
        finally
        {
            Directory.Delete(alternateRoot, recursive: true);
        }
    }

    private sealed class CancelAfterFirstRestoredFile(CancellationTokenSource cancellation) : IProgress<ProfilePackageProgress>
    {
        private bool _verificationComplete;

        public void Report(ProfilePackageProgress progress)
        {
            if (_verificationComplete && progress.FilesDone == 1)
                cancellation.Cancel();
            if (progress.FilesDone == progress.FilesTotal)
                _verificationComplete = true;
            Thread.Sleep(210);
        }
    }

    private static void WriteCraftedPackage(string package, string path, string content, bool includeManifestEntry)
    {
        var bytes = Encoding.UTF8.GetBytes(content);
        var files = new JsonArray();
        if (includeManifestEntry)
            files.Add(new JsonObject
            {
                ["path"] = path, ["size"] = bytes.Length,
                ["sha256"] = Convert.ToHexStringLower(SHA256.HashData(bytes)), ["modifiedUtc"] = "2026-01-01T00:00:00Z",
            });
        var manifest = new JsonObject
        {
            ["format"] = "BezpiecznyAktualizator.ProfilePackage", ["formatVersion"] = 1, ["created"] = "2026-01-01T00:00:00Z",
            ["machine"] = "PC", ["userName"] = "jan", ["sourceProfile"] = @"C:\Users\jan", ["folders"] = new JsonArray("Desktop"),
            ["files"] = files,
        };
        using var zip = ZipFile.Open(package, ZipArchiveMode.Create);
        using (var stream = zip.CreateEntry("files/" + path).Open()) stream.Write(bytes);
        using (var writer = new StreamWriter(zip.CreateEntry("manifest.json").Open())) writer.Write(manifest.ToJsonString());
    }

    private static void CreateJunction(string link, string target)
    {
        using var process = Process.Start(new ProcessStartInfo("cmd.exe", $"/c mklink /J \"{link}\" \"{target}\"")
        {
            UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true,
        })!;
        process.WaitForExit();
        Assert.True(Directory.Exists(link) && new DirectoryInfo(link).Attributes.HasFlag(FileAttributes.ReparsePoint));
    }
}
