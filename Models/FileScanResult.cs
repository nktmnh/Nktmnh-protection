namespace NktmnhProtection.Models;

public sealed class FileScanResult
{
    public required string FilePath { get; init; }
    public required string FileName { get; init; }
    public string Extension { get; init; } = string.Empty;
    public string FileType { get; init; } = string.Empty;
    public string? Md5Hash { get; init; }
    public string? Sha1Hash { get; init; }
    public string? Sha256Hash { get; init; }
    public ReputationStatus Status { get; init; }
    public string? ErrorMessage { get; init; }
    public long FileSizeBytes { get; init; }
    public double Entropy { get; init; }
    public TimeSpan ProcessingTime { get; init; }
    public PeAnalysisResult? PeAnalysis { get; init; }
    public IocAnalysisResult? IocAnalysis { get; init; }
    public IReadOnlyList<YaraMatchResult> YaraMatches { get; init; } = Array.Empty<YaraMatchResult>();

    public string StatusText => Status.ToString();
    public string EntropyText => Entropy <= 0 ? "-" : Entropy.ToString("F2");
    public string PeSummary => PeAnalysis?.Summary ?? "Not analyzed";
    public string IocSummary => IocAnalysis?.Summary ?? "Not analyzed";
    public string YaraSummary => YaraMatches.Count == 0
        ? "-"
        : string.Join(", ", YaraMatches.Select(match => match.Summary).Take(4));
}
