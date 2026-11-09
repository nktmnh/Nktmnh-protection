namespace CinderellaProtection.Models;

public sealed class YaraMatchResult
{
    public string RuleName { get; init; } = string.Empty;
    public string SourceFile { get; init; } = string.Empty;
    public IReadOnlyList<string> Tags { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> MatchedIdentifiers { get; init; } = Array.Empty<string>();

    public string Summary => Tags.Count == 0
        ? RuleName
        : $"{RuleName} [{string.Join(", ", Tags)}]";
}
