using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using CinderellaProtection.Models;

namespace CinderellaProtection.Services;

public sealed class IocExtractorService
{
    private const long MaxIocFileSize = 75L * 1024 * 1024;
    private const int MaxItemsPerGroup = 200;

    private static readonly Regex UrlRegex = new(@"https?://[^\s""'<>)]{4,}", RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex EmailRegex = new(@"\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b", RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex IPv4Regex = new(@"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b", RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex DomainRegex = new(@"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|ru|cn|vn|xyz|top|info|biz|co|me|dev|site|online)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex RegistryRegex = new(@"\bHKEY_(?:CLASSES_ROOT|CURRENT_USER|LOCAL_MACHINE|USERS|CURRENT_CONFIG)\\[^\r\n\0]{3,160}", RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly string[] InterestingNeedles =
    [
        "powershell", "cmd.exe", "rundll32", "regsvr32", "mshta", "wscript", "cscript",
        "schtasks", "taskkill", "vssadmin", "bcdedit", "certutil", "bitsadmin",
        "VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread", "LoadLibrary",
        "GetProcAddress", "IsDebuggerPresent", "URLDownloadToFile", "WinHttpOpen",
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    ];

    public async Task<IocAnalysisResult> ExtractAsync(string filePath, CancellationToken cancellationToken = default)
    {
        var info = new FileInfo(filePath);
        if (info.Length > MaxIocFileSize)
        {
            return new IocAnalysisResult
            {
                InterestingStrings = [$"IOC extraction skipped: file is larger than {MaxIocFileSize / 1024 / 1024} MB"]
            };
        }

        var data = await File.ReadAllBytesAsync(filePath, cancellationToken);
        var text = string.Join('\n', ExtractAsciiStrings(data).Concat(ExtractUnicodeStrings(data)).Take(20_000));

        return new IocAnalysisResult
        {
            Urls = MatchDistinct(UrlRegex, text),
            Emails = MatchDistinct(EmailRegex, text),
            IPv4Addresses = MatchDistinct(IPv4Regex, text).Where(IsPublicOrInterestingIp).Take(MaxItemsPerGroup).ToList(),
            Domains = MatchDistinct(DomainRegex, text),
            RegistryKeys = MatchDistinct(RegistryRegex, text),
            InterestingStrings = InterestingNeedles
                .Where(needle => text.Contains(needle, StringComparison.OrdinalIgnoreCase))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Take(MaxItemsPerGroup)
                .ToList()
        };
    }

    private static IReadOnlyList<string> MatchDistinct(Regex regex, string text)
    {
        return regex.Matches(text)
            .Select(match => match.Value.Trim().TrimEnd('.', ',', ';'))
            .Where(value => value.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(MaxItemsPerGroup)
            .ToList();
    }

    private static IEnumerable<string> ExtractAsciiStrings(byte[] data)
    {
        var builder = new StringBuilder();
        foreach (var b in data)
        {
            if (b is >= 0x20 and <= 0x7E)
            {
                builder.Append((char)b);
                continue;
            }

            if (builder.Length >= 4)
                yield return builder.ToString();

            builder.Clear();
        }

        if (builder.Length >= 4)
            yield return builder.ToString();
    }

    private static IEnumerable<string> ExtractUnicodeStrings(byte[] data)
    {
        var builder = new StringBuilder();
        for (var i = 0; i + 1 < data.Length; i += 2)
        {
            var value = BitConverter.ToUInt16(data, i);
            if (value is >= 0x20 and <= 0x7E)
            {
                builder.Append((char)value);
                continue;
            }

            if (builder.Length >= 4)
                yield return builder.ToString();

            builder.Clear();
        }

        if (builder.Length >= 4)
            yield return builder.ToString();
    }

    private static bool IsPublicOrInterestingIp(string ip)
    {
        return !(ip.StartsWith("127.", StringComparison.Ordinal) ||
                 ip.StartsWith("0.", StringComparison.Ordinal) ||
                 ip.StartsWith("255.", StringComparison.Ordinal));
    }
}
