namespace CinderellaProtection.Models;

public sealed class PeAnalysisResult
{
    public bool IsPeFile { get; init; }
    public string Architecture { get; init; } = string.Empty;
    public DateTimeOffset? CompileTimestampUtc { get; init; }
    public string Subsystem { get; init; } = string.Empty;
    public string Characteristics { get; init; } = string.Empty;
    public uint EntryPointRva { get; init; }
    public ulong ImageBase { get; init; }
    public int SectionCount { get; init; }
    public bool HasDigitalSignature { get; init; }
    public string? SignatureSubject { get; init; }
    public string? SignatureIssuer { get; init; }
    public DateTime? SignatureNotAfter { get; init; }
    public string Imphash { get; init; } = string.Empty;
    public IReadOnlyList<PeSectionInfo> Sections { get; init; } = Array.Empty<PeSectionInfo>();
    public IReadOnlyList<string> Imports { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> Exports { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> SuspicionIndicators { get; init; } = Array.Empty<string>();

    public string Summary
    {
        get
        {
            if (!IsPeFile)
                return "Not PE";

            var signed = HasDigitalSignature ? "signed" : "unsigned";
            var timestamp = CompileTimestampUtc?.ToString("yyyy-MM-dd") ?? "unknown time";
            return $"{Architecture}, {Subsystem}, {SectionCount} sections, {signed}, {timestamp}";
        }
    }
}

public sealed class PeSectionInfo
{
    public string Name { get; init; } = string.Empty;
    public uint VirtualAddress { get; init; }
    public uint VirtualSize { get; init; }
    public uint RawSize { get; init; }
    public double Entropy { get; init; }
    public bool IsExecutable { get; init; }
    public bool IsWritable { get; init; }

    public string Summary => $"{Name} VA=0x{VirtualAddress:X8} Raw={RawSize:n0} Entropy={Entropy:F2}";
}
