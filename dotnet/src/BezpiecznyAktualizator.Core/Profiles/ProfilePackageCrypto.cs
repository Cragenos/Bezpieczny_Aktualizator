using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using BezpiecznyAktualizator.Core.Localization;

namespace BezpiecznyAktualizator.Core.Profiles;

/// <summary>
/// Szyfrowanie paczki hasłem: PBKDF2-SHA256 → AES-256-GCM w porcjach po 1 MiB.
/// Każda porcja ma własny nonce (prefiks + numer) i jest uwierzytelniona razem z nagłówkiem,
/// numerem i znacznikiem ostatniej porcji – wykrywa to podmianę, zmianę kolejności i obcięcie pliku.
/// Format: "BAPRENC1" | iteracje (int32 LE) | sól (16 B) | prefiks nonce (8 B) | porcje: długość (int32 LE) | szyfrogram | tag (16 B).
/// </summary>
internal static class ProfilePackageCrypto
{
    internal static readonly byte[] Magic = "BAPRENC1"u8.ToArray();
    internal const int DefaultIterations = 600_000;
    internal const int ChunkSize = 1 << 20;
    private const int HeaderSize = 8 + 4 + 16 + 8;
    private const int TagSize = 16;

    public static bool IsEncrypted(string path)
    {
        using var file = File.OpenRead(path);
        Span<byte> head = stackalloc byte[8];
        return file.ReadAtLeast(head, 8, throwOnEndOfStream: false) == 8 && head.SequenceEqual(Magic);
    }

    public static Stream CreateEncryptingStream(Stream output, string password, int iterations = DefaultIterations)
    {
        var header = new byte[HeaderSize];
        Magic.CopyTo(header, 0);
        BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(8), iterations);
        RandomNumberGenerator.Fill(header.AsSpan(12, 24));
        output.Write(header);
        return new EncryptingStream(output, DeriveKey(password, header, iterations), header);
    }

    /// <summary>Odszyfrowuje całą paczkę do <paramref name="destination"/>; błędne hasło lub modyfikacja → <see cref="ProfilePackageException"/>.</summary>
    public static void Decrypt(Stream input, Stream destination, string password, CancellationToken cancellationToken)
    {
        var header = new byte[HeaderSize];
        if (input.ReadAtLeast(header, HeaderSize, throwOnEndOfStream: false) != HeaderSize || !header.AsSpan(0, 8).SequenceEqual(Magic))
            throw new ProfilePackageException(L.T("Plik nie jest zaszyfrowaną paczką profilu."));
        var iterations = BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(8));
        if (iterations is < 100_000 or > 10_000_000)
            throw new ProfilePackageException(L.T("Nieobsługiwane parametry szyfrowania paczki."));
        var key = DeriveKey(password, header, iterations);
        try
        {
            using var aes = new AesGcm(key, TagSize);
            var lengthBuffer = new byte[4];
            var cipher = new byte[ChunkSize];
            var plain = new byte[ChunkSize];
            var tag = new byte[TagSize];
            for (uint index = 0; ; index++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (input.ReadAtLeast(lengthBuffer, 4, throwOnEndOfStream: false) != 4) throw Corrupted();
                var rawLength = BinaryPrimitives.ReadInt32LittleEndian(lengthBuffer);
                var final = (rawLength & int.MinValue) != 0;
                var length = rawLength & int.MaxValue;
                if (length > ChunkSize) throw Corrupted();
                if (input.ReadAtLeast(cipher.AsSpan(0, length), length, throwOnEndOfStream: false) != length ||
                    input.ReadAtLeast(tag, TagSize, throwOnEndOfStream: false) != TagSize) throw Corrupted();
                try
                {
                    aes.Decrypt(Nonce(header, index), cipher.AsSpan(0, length), tag, plain.AsSpan(0, length), Aad(header, index, final));
                }
                catch (AuthenticationTagMismatchException)
                {
                    throw new ProfilePackageException(index == 0
                        ? L.T("Nieprawidłowe hasło albo paczka została zmodyfikowana.")
                        : L.T("Paczka została zmodyfikowana lub uszkodzona (błąd uwierzytelnienia danych)."));
                }
                destination.Write(plain, 0, length);
                if (final)
                {
                    if (input.ReadByte() != -1) throw Corrupted();
                    return;
                }
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    private static ProfilePackageException Corrupted() =>
        new(L.T("Zaszyfrowana paczka jest niekompletna lub uszkodzona."));

    private static byte[] DeriveKey(string password, byte[] header, int iterations) =>
        Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(password), header.AsSpan(12, 16), iterations, HashAlgorithmName.SHA256, 32);

    private static byte[] Nonce(byte[] header, uint index)
    {
        var nonce = new byte[12];
        header.AsSpan(28, 8).CopyTo(nonce);
        BinaryPrimitives.WriteUInt32BigEndian(nonce.AsSpan(8), index);
        return nonce;
    }

    private static byte[] Aad(byte[] header, uint index, bool final)
    {
        var aad = new byte[HeaderSize + 5];
        header.CopyTo(aad, 0);
        BinaryPrimitives.WriteUInt32BigEndian(aad.AsSpan(HeaderSize), index);
        aad[^1] = final ? (byte)1 : (byte)0;
        return aad;
    }

    /// <summary>Strumień tylko do zapisu; ostatnia porcja (oznaczona jako końcowa) jest zapisywana przy Dispose.</summary>
    private sealed class EncryptingStream(Stream output, byte[] key, byte[] header) : Stream
    {
        private readonly AesGcm _aes = new(key, TagSize);
        private readonly byte[] _buffer = new byte[ChunkSize];
        private int _count;
        private uint _index;
        private bool _disposed;

        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => !_disposed;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));

        public override void Write(ReadOnlySpan<byte> data)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            while (data.Length > 0)
            {
                if (_count == ChunkSize) WriteChunk(final: false);
                var take = Math.Min(ChunkSize - _count, data.Length);
                data[..take].CopyTo(_buffer.AsSpan(_count));
                _count += take;
                data = data[take..];
            }
        }

        private void WriteChunk(bool final)
        {
            var cipher = new byte[_count];
            var tag = new byte[TagSize];
            _aes.Encrypt(Nonce(header, _index), _buffer.AsSpan(0, _count), cipher, tag, Aad(header, _index, final));
            Span<byte> length = stackalloc byte[4];
            BinaryPrimitives.WriteInt32LittleEndian(length, _count | (final ? int.MinValue : 0));
            output.Write(length);
            output.Write(cipher);
            output.Write(tag);
            _index++;
            _count = 0;
        }

        protected override void Dispose(bool disposing)
        {
            if (!_disposed && disposing)
            {
                _disposed = true;
                WriteChunk(final: true);
                output.Flush();
                _aes.Dispose();
                CryptographicOperations.ZeroMemory(key);
                CryptographicOperations.ZeroMemory(_buffer);
            }
            base.Dispose(disposing);
        }
    }
}
