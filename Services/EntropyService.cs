using System.IO;

namespace NktmnhProtection.Services;

public sealed class EntropyService
{
    private const int BufferSize = 1024 * 1024;

    public async Task<double> CalculateFileEntropyAsync(string filePath, CancellationToken cancellationToken = default)
    {
        var counts = new long[256];
        long total = 0;
        var buffer = new byte[BufferSize];

        await using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, BufferSize, true);
        int read;
        while ((read = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken)) > 0)
        {
            for (var i = 0; i < read; i++)
                counts[buffer[i]]++;

            total += read;
        }

        return Calculate(counts, total);
    }

    public static double Calculate(ReadOnlySpan<byte> data)
    {
        var counts = new long[256];
        foreach (var b in data)
            counts[b]++;

        return Calculate(counts, data.Length);
    }

    private static double Calculate(long[] counts, long total)
    {
        if (total == 0)
            return 0;

        double entropy = 0;
        foreach (var count in counts)
        {
            if (count == 0)
                continue;

            var p = (double)count / total;
            entropy -= p * Math.Log2(p);
        }

        return entropy;
    }
}
