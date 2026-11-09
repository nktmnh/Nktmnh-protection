namespace CinderellaProtection.Models;

public sealed class IocAnalysisResult
{
    public IReadOnlyList<string> Urls { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> Domains { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> IPv4Addresses { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> Emails { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> RegistryKeys { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> InterestingStrings { get; init; } = Array.Empty<string>();

    public int TotalCount => Urls.Count + Domains.Count + IPv4Addresses.Count + Emails.Count + RegistryKeys.Count + InterestingStrings.Count;

    public string Summary => TotalCount == 0
        ? "No IOC"
        : $"{Urls.Count} URLs, {Domains.Count} domains, {IPv4Addresses.Count} IPs, {RegistryKeys.Count} registry, {InterestingStrings.Count} strings";
}
