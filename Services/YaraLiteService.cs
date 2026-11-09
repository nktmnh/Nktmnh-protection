using System.Globalization;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using CinderellaProtection.Models;

namespace CinderellaProtection.Services;

public sealed class YaraLiteService
{
    private const long MaxYaraFileSize = 75L * 1024 * 1024;
    private static readonly Regex RuleHeaderRegex = new(@"rule\s+(?<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*(?<tags>[^{]+))?\s*\{", RegexOptions.Singleline | RegexOptions.Compiled);
    private static readonly Regex TextStringRegex = new(@"\$(?<id>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*""(?<value>(?:\\.|[^""\\])*)""(?<mods>[^\r\n]*)", RegexOptions.Compiled);
    private static readonly Regex HexStringRegex = new(@"\$(?<id>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*\{(?<value>[^}]+)\}", RegexOptions.Compiled);

    public IReadOnlyList<YaraLiteRule> LoadRules(string? rulesDirectory)
    {
        if (string.IsNullOrWhiteSpace(rulesDirectory) || !Directory.Exists(rulesDirectory))
            return Array.Empty<YaraLiteRule>();

        IReadOnlyList<string> ruleFiles;
        try
        {
            ruleFiles = Directory.EnumerateFiles(rulesDirectory, "*.*", SearchOption.AllDirectories).ToList();
        }
        catch
        {
            return Array.Empty<YaraLiteRule>();
        }

        var rules = new List<YaraLiteRule>();
        foreach (var file in ruleFiles.Where(path => path.EndsWith(".yar", StringComparison.OrdinalIgnoreCase) ||
                                                     path.EndsWith(".yara", StringComparison.OrdinalIgnoreCase)))
        {
            try
            {
                var content = File.ReadAllText(file);
                rules.AddRange(ParseRules(file, content));
            }
            catch
            {
            }
        }

        return rules;
    }

    public async Task<IReadOnlyList<YaraMatchResult>> MatchFileAsync(
        string filePath,
        IReadOnlyList<YaraLiteRule> rules,
        CancellationToken cancellationToken = default)
    {
        if (rules.Count == 0)
            return Array.Empty<YaraMatchResult>();

        var info = new FileInfo(filePath);
        if (info.Length > MaxYaraFileSize)
            return Array.Empty<YaraMatchResult>();

        var data = await File.ReadAllBytesAsync(filePath, cancellationToken);
        var latinText = Encoding.Latin1.GetString(data);
        var matches = new List<YaraMatchResult>();

        foreach (var rule in rules)
        {
            var matchedIds = new List<string>();
            foreach (var pattern in rule.Patterns)
            {
                if (pattern.IsMatch(data, latinText))
                    matchedIds.Add(pattern.Identifier);
            }

            if (RuleConditionSatisfied(rule, matchedIds))
            {
                matches.Add(new YaraMatchResult
                {
                    RuleName = rule.Name,
                    SourceFile = rule.SourceFile,
                    Tags = rule.Tags,
                    MatchedIdentifiers = matchedIds
                });
            }
        }

        return matches;
    }

    private static IEnumerable<YaraLiteRule> ParseRules(string sourceFile, string content)
    {
        foreach (Match ruleMatch in RuleHeaderRegex.Matches(content))
        {
            var name = ruleMatch.Groups["name"].Value;
            var tags = ruleMatch.Groups["tags"].Value
                .Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            var bodyStart = ruleMatch.Index + ruleMatch.Length;
            var bodyEnd = FindMatchingBrace(content, bodyStart);
            if (bodyEnd <= bodyStart)
                continue;

            var body = content[bodyStart..bodyEnd];
            var condition = ExtractSection(body, "condition");
            var stringsSection = ExtractSection(body, "strings");
            var patterns = ParsePatterns(stringsSection).ToList();

            if (patterns.Count == 0)
                continue;

            yield return new YaraLiteRule(name, sourceFile, tags, condition, patterns);
        }
    }

    private static int FindMatchingBrace(string content, int bodyStart)
    {
        var depth = 1;
        var inString = false;
        var escaped = false;

        for (var i = bodyStart; i < content.Length; i++)
        {
            var c = content[i];
            if (inString)
            {
                if (escaped)
                {
                    escaped = false;
                    continue;
                }

                if (c == '\\')
                {
                    escaped = true;
                    continue;
                }

                if (c == '"')
                    inString = false;

                continue;
            }

            if (c == '"')
            {
                inString = true;
                continue;
            }

            if (c == '{')
            {
                depth++;
                continue;
            }

            if (c == '}')
            {
                depth--;
                if (depth == 0)
                    return i;
            }
        }

        return -1;
    }

    private static IEnumerable<YaraLitePattern> ParsePatterns(string stringsSection)
    {
        foreach (Match textMatch in TextStringRegex.Matches(stringsSection))
        {
            var id = "$" + textMatch.Groups["id"].Value;
            var value = Regex.Unescape(textMatch.Groups["value"].Value);
            var mods = textMatch.Groups["mods"].Value;
            var noCase = mods.Contains("nocase", StringComparison.OrdinalIgnoreCase);
            var wide = mods.Contains("wide", StringComparison.OrdinalIgnoreCase);
            yield return YaraLitePattern.FromText(id, value, noCase, wide);
        }

        foreach (Match hexMatch in HexStringRegex.Matches(stringsSection))
        {
            var id = "$" + hexMatch.Groups["id"].Value;
            var pattern = ParseHexPattern(hexMatch.Groups["value"].Value);
            if (pattern.Length > 0)
                yield return YaraLitePattern.FromHex(id, pattern);
        }
    }

    private static byte?[] ParseHexPattern(string value)
    {
        var bytes = new List<byte?>();
        foreach (var token in value.Split([' ', '\t', '\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (token.Length != 2)
                continue;

            if (token.Contains('?', StringComparison.Ordinal))
            {
                bytes.Add(null);
                continue;
            }

            if (byte.TryParse(token, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var parsed))
                bytes.Add(parsed);
        }

        return bytes.ToArray();
    }

    private static string ExtractSection(string body, string sectionName)
    {
        var match = Regex.Match(
            body,
            $@"{sectionName}\s*:\s*(?<section>.*?)(?:\n\s*(?:strings|condition|meta)\s*:|\z)",
            RegexOptions.Singleline | RegexOptions.IgnoreCase);

        return match.Success ? match.Groups["section"].Value : string.Empty;
    }

    private static bool RuleConditionSatisfied(YaraLiteRule rule, IReadOnlyList<string> matchedIds)
    {
        if (matchedIds.Count == 0)
            return false;

        var condition = rule.Condition;
        if (condition.Contains("all of them", StringComparison.OrdinalIgnoreCase))
            return matchedIds.Count == rule.Patterns.Count;

        if (condition.Contains("any of them", StringComparison.OrdinalIgnoreCase))
            return true;

        var referenced = rule.Patterns
            .Select(pattern => pattern.Identifier)
            .Where(id => condition.Contains(id, StringComparison.Ordinal))
            .ToList();

        if (referenced.Count == 0)
            return true;

        if (condition.Contains(" and ", StringComparison.OrdinalIgnoreCase))
            return referenced.All(matchedIds.Contains);

        return referenced.Any(matchedIds.Contains);
    }
}

public sealed record YaraLiteRule(
    string Name,
    string SourceFile,
    IReadOnlyList<string> Tags,
    string Condition,
    IReadOnlyList<YaraLitePattern> Patterns);

public sealed class YaraLitePattern
{
    private readonly string? _text;
    private readonly byte[]? _bytes;
    private readonly byte?[]? _hexPattern;
    private readonly bool _noCase;

    private YaraLitePattern(string identifier, string? text, byte[]? bytes, byte?[]? hexPattern, bool noCase)
    {
        Identifier = identifier;
        _text = text;
        _bytes = bytes;
        _hexPattern = hexPattern;
        _noCase = noCase;
    }

    public string Identifier { get; }

    public static YaraLitePattern FromText(string identifier, string value, bool noCase, bool wide)
    {
        return wide
            ? new YaraLitePattern(identifier, null, Encoding.Unicode.GetBytes(value), null, noCase)
            : new YaraLitePattern(identifier, value, null, null, noCase);
    }

    public static YaraLitePattern FromHex(string identifier, byte?[] pattern)
    {
        return new YaraLitePattern(identifier, null, null, pattern, false);
    }

    public bool IsMatch(byte[] data, string latinText)
    {
        if (_text is not null)
        {
            return latinText.Contains(
                _text,
                _noCase ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);
        }

        if (_bytes is not null)
            return IndexOf(data, _bytes) >= 0;

        if (_hexPattern is not null)
            return IndexOf(data, _hexPattern) >= 0;

        return false;
    }

    private static int IndexOf(byte[] data, byte[] pattern)
    {
        if (pattern.Length == 0 || data.Length < pattern.Length)
            return -1;

        for (var i = 0; i <= data.Length - pattern.Length; i++)
        {
            if (data.AsSpan(i, pattern.Length).SequenceEqual(pattern))
                return i;
        }

        return -1;
    }

    private static int IndexOf(byte[] data, byte?[] pattern)
    {
        if (pattern.Length == 0 || data.Length < pattern.Length)
            return -1;

        for (var i = 0; i <= data.Length - pattern.Length; i++)
        {
            var matched = true;
            for (var j = 0; j < pattern.Length; j++)
            {
                if (pattern[j].HasValue && data[i + j] != pattern[j])
                {
                    matched = false;
                    break;
                }
            }

            if (matched)
                return i;
        }

        return -1;
    }
}
