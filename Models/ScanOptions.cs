namespace NktmnhProtection.Models;

public sealed class ScanOptions
{
    public int MaxParallelism { get; init; } = 20;
    public bool AnalyzePe { get; init; } = true;
    public bool ExtractIocs { get; init; } = true;
    public string? YaraRulesDirectory { get; init; }
}
