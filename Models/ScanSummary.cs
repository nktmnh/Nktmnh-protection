namespace CinderellaProtection.Models;

public sealed class ScanSummary
{
    public int TotalFiles { get; set; }
    public int ProcessedFiles { get; set; }
    public int SafeCount { get; set; }
    public int SuspiciousCount { get; set; }
    public int MaliciousCount { get; set; }
    public int ErrorCount { get; set; }
    public int YaraMatchCount { get; set; }
    public int PeFileCount { get; set; }
}
