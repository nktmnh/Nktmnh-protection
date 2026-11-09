using System.IO;

namespace NktmnhProtection.Services;

public sealed class FileTypeService
{
    private static readonly (byte[] Magic, string Name)[] Signatures =
    [
        ([0x4D, 0x5A], "Windows PE executable"),
        ([0x7F, 0x45, 0x4C, 0x46], "ELF executable"),
        ([0xCA, 0xFE, 0xBA, 0xBE], "Mach-O universal binary"),
        ([0xFE, 0xED, 0xFA, 0xCE], "Mach-O binary"),
        ([0xFE, 0xED, 0xFA, 0xCF], "Mach-O 64-bit binary"),
        ([0x50, 0x4B, 0x03, 0x04], "ZIP/JAR/APK/Office archive"),
        ([0x52, 0x61, 0x72, 0x21], "RAR archive"),
        ([0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C], "7-Zip archive"),
        ([0x25, 0x50, 0x44, 0x46], "PDF document"),
        ([0xD0, 0xCF, 0x11, 0xE0], "OLE compound document"),
        ([0x89, 0x50, 0x4E, 0x47], "PNG image"),
        ([0xFF, 0xD8, 0xFF], "JPEG image"),
        ([0x47, 0x49, 0x46, 0x38], "GIF image")
    ];

    public async Task<string> DetectAsync(string filePath, CancellationToken cancellationToken = default)
    {
        var buffer = new byte[16];
        await using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 4096, true);
        var read = await stream.ReadAsync(buffer, cancellationToken);

        foreach (var (magic, name) in Signatures)
        {
            if (read >= magic.Length && buffer.AsSpan(0, magic.Length).SequenceEqual(magic))
                return name;
        }

        return LooksText(buffer.AsSpan(0, read)) ? "Text/Script" : "Unknown binary";
    }

    private static bool LooksText(ReadOnlySpan<byte> bytes)
    {
        if (bytes.IsEmpty)
            return false;

        var printable = 0;
        foreach (var b in bytes)
        {
            if (b is 0x09 or 0x0A or 0x0D || b is >= 0x20 and <= 0x7E)
                printable++;
        }

        return printable >= bytes.Length * 0.85;
    }
}
