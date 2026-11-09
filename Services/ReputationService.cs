using NktmnhProtection.Models;

namespace NktmnhProtection.Services;

/// <summary>
/// Simulates a Threat Intelligence API (e.g. VirusTotal) lookup by SHA-256 hash.
/// Deterministic mock: hash bytes drive Safe / Suspicious / Malicious classification.
/// </summary>
public sealed class ReputationService
{
    private static readonly TimeSpan MinApiLatency = TimeSpan.FromMilliseconds(50);
    private static readonly TimeSpan MaxApiLatency = TimeSpan.FromMilliseconds(200);

    public async Task<ReputationStatus> CheckHashAsync(string sha256Hash, CancellationToken cancellationToken = default)
    {
        var delay = Random.Shared.Next((int)MinApiLatency.TotalMilliseconds, (int)MaxApiLatency.TotalMilliseconds);
        await Task.Delay(delay, cancellationToken);

        return ClassifyHash(sha256Hash);
    }

    public ReputationStatus CheckHash(string sha256Hash) => ClassifyHash(sha256Hash);

    private static ReputationStatus ClassifyHash(string sha256Hash)
    {
        if (string.IsNullOrWhiteSpace(sha256Hash) || sha256Hash.Length < 8)
            return ReputationStatus.Error;

        var normalized = sha256Hash.ToLowerInvariant();
        var sum = 0;

        foreach (var c in normalized)
        {
            sum += c;
        }

        var lastByte = Convert.ToByte(normalized[^2..], 16);

        // ~70% Safe, ~20% Suspicious, ~10% Malicious (deterministic per hash)
        return ((sum + lastByte) % 10) switch
        {
            0 => ReputationStatus.Malicious,
            1 or 2 => ReputationStatus.Suspicious,
            _ => ReputationStatus.Safe
        };
    }
}
