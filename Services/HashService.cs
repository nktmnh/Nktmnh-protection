using System.IO;
using System.Security.Cryptography;
using CinderellaProtection.Models;

namespace CinderellaProtection.Services;

public sealed class HashService
{
    private const int DefaultBufferSize = 1024 * 1024; // 1 MB chunks

    public async Task<HashResult> ComputeHashesAsync(
        string filePath,
        CancellationToken cancellationToken = default,
        IProgress<long>? bytesProcessed = null)
    {
        await using var stream = new FileStream(
            filePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite,
            bufferSize: DefaultBufferSize,
            useAsync: true);

        using var md5 = IncrementalHash.CreateHash(HashAlgorithmName.MD5);
        using var sha1 = IncrementalHash.CreateHash(HashAlgorithmName.SHA1);
        using var sha256 = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[DefaultBufferSize];
        long totalRead = 0;
        int bytesRead;

        while ((bytesRead = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken)) > 0)
        {
            md5.AppendData(buffer, 0, bytesRead);
            sha1.AppendData(buffer, 0, bytesRead);
            sha256.AppendData(buffer, 0, bytesRead);
            totalRead += bytesRead;
            bytesProcessed?.Report(totalRead);
        }

        return new HashResult
        {
            Md5 = ToHex(md5),
            Sha1 = ToHex(sha1),
            Sha256 = ToHex(sha256)
        };
    }

    public async Task<string> ComputeSha256Async(
        string filePath,
        CancellationToken cancellationToken = default,
        IProgress<long>? bytesProcessed = null)
    {
        await using var stream = new FileStream(
            filePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite,
            bufferSize: DefaultBufferSize,
            useAsync: true);

        using var incrementalHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[DefaultBufferSize];
        long totalRead = 0;
        int bytesRead;

        while ((bytesRead = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken)) > 0)
        {
            incrementalHash.AppendData(buffer, 0, bytesRead);
            totalRead += bytesRead;
            bytesProcessed?.Report(totalRead);
        }

        return ToHex(incrementalHash);
    }

    public string ComputeSha256(string filePath)
    {
        using var stream = new FileStream(
            filePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite,
            bufferSize: DefaultBufferSize,
            useAsync: false);

        using var incrementalHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[DefaultBufferSize];
        int bytesRead;

        while ((bytesRead = stream.Read(buffer, 0, buffer.Length)) > 0)
        {
            incrementalHash.AppendData(buffer, 0, bytesRead);
        }

        return ToHex(incrementalHash);
    }

    private static string ToHex(IncrementalHash hash)
    {
        return Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
    }
}
