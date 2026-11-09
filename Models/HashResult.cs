namespace CinderellaProtection.Models;

public sealed class HashResult
{
    public string Md5 { get; init; } = string.Empty;
    public string Sha1 { get; init; } = string.Empty;
    public string Sha256 { get; init; } = string.Empty;
}
