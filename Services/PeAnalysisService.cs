using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using NktmnhProtection.Models;

namespace NktmnhProtection.Services;

public sealed class PeAnalysisService
{
    private const long MaxPeAnalysisFileSize = 200L * 1024 * 1024;
    private const int MaxImportNames = 5000;
    private const int MaxExportNames = 1000;

    private static readonly string[] SuspiciousImportNames =
    [
        "virtualalloc", "virtualallocex", "writeprocessmemory", "createremotethread",
        "createprocess", "winexec", "shellexecute", "urldownloadtofile", "internetopen",
        "internetconnect", "httpopenrequest", "wsastartup", "connect", "send", "recv",
        "regsetvalue", "regcreatekey", "isdebuggerpresent", "checkremotedebuggerpresent",
        "ntunmapviewofsection", "loadlibrary", "getprocaddress", "setwindowshookex"
    ];

    public async Task<PeAnalysisResult> AnalyzeAsync(string filePath, CancellationToken cancellationToken = default)
    {
        try
        {
            var fileInfo = new FileInfo(filePath);
            if (fileInfo.Length > MaxPeAnalysisFileSize)
                return new PeAnalysisResult { IsPeFile = false };

            var data = await File.ReadAllBytesAsync(filePath, cancellationToken);
            return AnalyzeBytes(filePath, data);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            return new PeAnalysisResult { IsPeFile = false };
        }
    }

    private static PeAnalysisResult AnalyzeBytes(string filePath, byte[] data)
    {
        try
        {
        if (data.Length < 0x40 || data[0] != 'M' || data[1] != 'Z')
            return new PeAnalysisResult { IsPeFile = false };

        var peOffset = ReadInt32(data, 0x3C);
        if (peOffset <= 0 || peOffset + 0x18 >= data.Length)
            return new PeAnalysisResult { IsPeFile = false };

        if (ReadUInt32(data, peOffset) != 0x00004550)
            return new PeAnalysisResult { IsPeFile = false };

        var coffOffset = peOffset + 4;
        var machine = ReadUInt16(data, coffOffset);
        var sectionCount = ReadUInt16(data, coffOffset + 2);
        var timestamp = ReadUInt32(data, coffOffset + 4);
        var optionalHeaderSize = ReadUInt16(data, coffOffset + 16);
        var characteristics = ReadUInt16(data, coffOffset + 18);
        var optionalOffset = coffOffset + 20;
        var magic = ReadUInt16(data, optionalOffset);
        var is64Bit = magic == 0x20B;

        if (magic is not (0x10B or 0x20B) || optionalOffset + optionalHeaderSize > data.Length)
            return new PeAnalysisResult { IsPeFile = false };

        var entryPointRva = ReadUInt32(data, optionalOffset + 16);
        var imageBase = is64Bit
            ? ReadUInt64(data, optionalOffset + 24)
            : ReadUInt32(data, optionalOffset + 28);
        var subsystem = ReadUInt16(data, optionalOffset + 68);
        var numberOfRvaAndSizes = ReadUInt32(data, optionalOffset + (is64Bit ? 108 : 92));
        var dataDirectoryOffset = optionalOffset + (is64Bit ? 112 : 96);

        var exportDirectory = ReadDirectory(data, dataDirectoryOffset, numberOfRvaAndSizes, 0);
        var importDirectory = ReadDirectory(data, dataDirectoryOffset, numberOfRvaAndSizes, 1);
        var certificateDirectory = ReadDirectory(data, dataDirectoryOffset, numberOfRvaAndSizes, 4);
        var sectionTableOffset = optionalOffset + optionalHeaderSize;
        var sections = ReadSections(data, sectionTableOffset, sectionCount);
        var imports = ReadImports(data, sections, importDirectory.Rva, importDirectory.Size, is64Bit);
        var exports = ReadExports(data, sections, exportDirectory.Rva, exportDirectory.Size);
        var signature = ReadSignature(filePath, certificateDirectory.Size > 0);
        var indicators = BuildIndicators(sections, imports, signature.HasSignature);

        return new PeAnalysisResult
        {
            IsPeFile = true,
            Architecture = DecodeMachine(machine),
            CompileTimestampUtc = timestamp == 0
                ? null
                : DateTimeOffset.FromUnixTimeSeconds(timestamp).ToUniversalTime(),
            Subsystem = DecodeSubsystem(subsystem),
            Characteristics = DecodeCharacteristics(characteristics),
            EntryPointRva = entryPointRva,
            ImageBase = imageBase,
            SectionCount = sectionCount,
            Sections = sections.Select(section => section.Info).ToList(),
            Imports = imports,
            Exports = exports,
            HasDigitalSignature = signature.HasSignature,
            SignatureSubject = signature.Subject,
            SignatureIssuer = signature.Issuer,
            SignatureNotAfter = signature.NotAfter,
            Imphash = CalculateImphash(imports),
            SuspicionIndicators = indicators
        };
        }
        catch
        {
            return new PeAnalysisResult { IsPeFile = false };
        }
    }

    private static IReadOnlyList<SectionRecord> ReadSections(byte[] data, int offset, int sectionCount)
    {
        var sections = new List<SectionRecord>();
        for (var i = 0; i < sectionCount; i++)
        {
            var current = offset + i * 40;
            if (current + 40 > data.Length)
                break;

            var name = ReadFixedAscii(data, current, 8);
            var virtualSize = ReadUInt32(data, current + 8);
            var virtualAddress = ReadUInt32(data, current + 12);
            var rawSize = ReadUInt32(data, current + 16);
            var rawPointer = ReadUInt32(data, current + 20);
            var characteristics = ReadUInt32(data, current + 36);
            var entropy = 0d;

            if (rawPointer < data.Length && rawSize > 0)
            {
                var available = (int)Math.Min(rawSize, data.Length - rawPointer);
                entropy = EntropyService.Calculate(data.AsSpan((int)rawPointer, available));
            }

            sections.Add(new SectionRecord(
                new PeSectionInfo
                {
                    Name = string.IsNullOrWhiteSpace(name) ? $"section{i}" : name,
                    VirtualAddress = virtualAddress,
                    VirtualSize = virtualSize,
                    RawSize = rawSize,
                    Entropy = entropy,
                    IsExecutable = (characteristics & 0x20000000) != 0,
                    IsWritable = (characteristics & 0x80000000) != 0
                },
                rawPointer,
                rawSize));
        }

        return sections;
    }

    private static IReadOnlyList<string> ReadImports(byte[] data, IReadOnlyList<SectionRecord> sections, uint importRva, uint importSize, bool is64Bit)
    {
        var imports = new List<string>();
        if (importRva == 0 || importSize == 0)
            return imports;

        var descriptorOffset = RvaToOffset(sections, importRva);
        if (descriptorOffset is null)
            return imports;

        for (var descriptor = descriptorOffset.Value; descriptor + 20 <= data.Length; descriptor += 20)
        {
            var originalFirstThunk = ReadUInt32(data, descriptor);
            var nameRva = ReadUInt32(data, descriptor + 12);
            var firstThunk = ReadUInt32(data, descriptor + 16);

            if (originalFirstThunk == 0 && nameRva == 0 && firstThunk == 0)
                break;

            var dllOffset = RvaToOffset(sections, nameRva);
            var dllName = dllOffset is null ? "unknown.dll" : ReadNullTerminatedAscii(data, dllOffset.Value, 256);
            var thunkRva = originalFirstThunk != 0 ? originalFirstThunk : firstThunk;
            var thunkOffset = RvaToOffset(sections, thunkRva);
            if (thunkOffset is null)
                continue;

            var thunkSize = is64Bit ? 8 : 4;
            for (var thunk = thunkOffset.Value; thunk + thunkSize <= data.Length; thunk += thunkSize)
            {
                var thunkValue = is64Bit ? ReadUInt64(data, thunk) : ReadUInt32(data, thunk);
                if (thunkValue == 0)
                    break;

                var ordinalFlag = is64Bit ? 0x8000000000000000UL : 0x80000000UL;
                if ((thunkValue & ordinalFlag) != 0)
                {
                    imports.Add($"{dllName}.ordinal_{thunkValue & 0xFFFF}");
                }
                else
                {
                    var hintNameOffset = RvaToOffset(sections, (uint)thunkValue);
                    if (hintNameOffset is null || hintNameOffset.Value + 2 >= data.Length)
                        continue;

                    var importName = ReadNullTerminatedAscii(data, hintNameOffset.Value + 2, 512);
                    if (!string.IsNullOrWhiteSpace(importName))
                        imports.Add($"{dllName}.{importName}");
                }

                if (imports.Count >= MaxImportNames)
                    return imports;
            }
        }

        return imports;
    }

    private static IReadOnlyList<string> ReadExports(byte[] data, IReadOnlyList<SectionRecord> sections, uint exportRva, uint exportSize)
    {
        var exports = new List<string>();
        if (exportRva == 0 || exportSize == 0)
            return exports;

        var exportOffset = RvaToOffset(sections, exportRva);
        if (exportOffset is null || exportOffset.Value + 40 > data.Length)
            return exports;

        var numberOfNames = ReadUInt32(data, exportOffset.Value + 24);
        var addressOfNamesRva = ReadUInt32(data, exportOffset.Value + 32);
        var addressOfNamesOffset = RvaToOffset(sections, addressOfNamesRva);
        if (addressOfNamesOffset is null)
            return exports;

        var count = Math.Min(numberOfNames, MaxExportNames);
        for (var i = 0; i < count; i++)
        {
            var nameRvaOffset = addressOfNamesOffset.Value + i * 4;
            if (nameRvaOffset + 4 > data.Length)
                break;

            var nameOffset = RvaToOffset(sections, ReadUInt32(data, nameRvaOffset));
            if (nameOffset is null)
                continue;

            var name = ReadNullTerminatedAscii(data, nameOffset.Value, 512);
            if (!string.IsNullOrWhiteSpace(name))
                exports.Add(name);
        }

        return exports;
    }

    private static IReadOnlyList<string> BuildIndicators(IReadOnlyList<SectionRecord> sections, IReadOnlyList<string> imports, bool hasSignature)
    {
        var indicators = new List<string>();
        if (!hasSignature)
            indicators.Add("Unsigned PE file");

        foreach (var section in sections.Select(s => s.Info))
        {
            if (section.Entropy >= 7.2)
                indicators.Add($"High entropy section: {section.Name} ({section.Entropy:F2})");

            if (section.IsExecutable && section.IsWritable)
                indicators.Add($"Writable executable section: {section.Name}");
        }

        var lowerImports = imports.Select(import => import.ToLowerInvariant()).ToList();
        foreach (var suspicious in SuspiciousImportNames)
        {
            if (lowerImports.Any(import => import.Contains($".{suspicious}", StringComparison.Ordinal)))
                indicators.Add($"Suspicious import: {suspicious}");
        }

        return indicators.Distinct(StringComparer.OrdinalIgnoreCase).Take(40).ToList();
    }

    private static string CalculateImphash(IReadOnlyList<string> imports)
    {
        if (imports.Count == 0)
            return string.Empty;

        var normalized = imports.Select(import =>
        {
            var parts = import.Split('.', 2);
            if (parts.Length != 2)
                return import.ToLowerInvariant();

            var dll = Path.GetFileNameWithoutExtension(parts[0]).ToLowerInvariant();
            var function = parts[1].ToLowerInvariant();
            return $"{dll}.{function}";
        });

        var bytes = Encoding.ASCII.GetBytes(string.Join(",", normalized));
        return Convert.ToHexString(MD5.HashData(bytes)).ToLowerInvariant();
    }

    private static SignatureInfo ReadSignature(string filePath, bool certificateDirectoryPresent)
    {
        if (!certificateDirectoryPresent)
            return new SignatureInfo(false, null, null, null);

        try
        {
            using var cert = X509Certificate.CreateFromSignedFile(filePath);
            var cert2 = new X509Certificate2(cert);
            return new SignatureInfo(true, cert2.Subject, cert2.Issuer, cert2.NotAfter);
        }
        catch
        {
            return new SignatureInfo(true, "Certificate present but unreadable", null, null);
        }
    }

    private static DataDirectory ReadDirectory(byte[] data, int dataDirectoryOffset, uint numberOfRvaAndSizes, int index)
    {
        if (numberOfRvaAndSizes <= index)
            return new DataDirectory(0, 0);

        var offset = dataDirectoryOffset + index * 8;
        if (offset + 8 > data.Length)
            return new DataDirectory(0, 0);

        return new DataDirectory(ReadUInt32(data, offset), ReadUInt32(data, offset + 4));
    }

    private static int? RvaToOffset(IReadOnlyList<SectionRecord> sections, uint rva)
    {
        foreach (var section in sections)
        {
            var start = section.Info.VirtualAddress;
            var size = Math.Max(section.Info.VirtualSize, section.RawSize);
            var end = start + size;
            if (rva >= start && rva < end)
                return checked((int)(section.RawPointer + (rva - start)));
        }

        return rva < 0x1000 ? (int)rva : null;
    }

    private static string ReadFixedAscii(byte[] data, int offset, int length)
    {
        if (offset < 0 || offset >= data.Length)
            return string.Empty;

        var count = Math.Min(length, data.Length - offset);
        var end = Array.IndexOf(data, (byte)0, offset, count);
        if (end < 0)
            end = offset + count;

        return Encoding.ASCII.GetString(data, offset, end - offset).Trim();
    }

    private static string ReadNullTerminatedAscii(byte[] data, int offset, int maxLength)
    {
        if (offset < 0 || offset >= data.Length)
            return string.Empty;

        var count = Math.Min(maxLength, data.Length - offset);
        var end = Array.IndexOf(data, (byte)0, offset, count);
        if (end < 0)
            end = offset + count;

        return Encoding.ASCII.GetString(data, offset, Math.Max(0, end - offset)).Trim();
    }

    private static ushort ReadUInt16(byte[] data, int offset) => BitConverter.ToUInt16(data, offset);
    private static uint ReadUInt32(byte[] data, int offset) => BitConverter.ToUInt32(data, offset);
    private static ulong ReadUInt64(byte[] data, int offset) => BitConverter.ToUInt64(data, offset);
    private static int ReadInt32(byte[] data, int offset) => BitConverter.ToInt32(data, offset);

    private static string DecodeMachine(ushort machine) => machine switch
    {
        0x014C => "x86",
        0x8664 => "x64",
        0x01C0 => "ARM",
        0xAA64 => "ARM64",
        _ => $"0x{machine:X4}"
    };

    private static string DecodeSubsystem(ushort subsystem) => subsystem switch
    {
        2 => "Windows GUI",
        3 => "Windows Console",
        9 => "Windows CE",
        10 => "EFI application",
        14 => "Xbox",
        _ => $"Subsystem {subsystem}"
    };

    private static string DecodeCharacteristics(ushort characteristics)
    {
        var flags = new List<string>();
        if ((characteristics & 0x0002) != 0) flags.Add("Executable");
        if ((characteristics & 0x2000) != 0) flags.Add("DLL");
        if ((characteristics & 0x0020) != 0) flags.Add("LargeAddressAware");
        if ((characteristics & 0x0100) != 0) flags.Add("32BitMachine");
        return flags.Count == 0 ? $"0x{characteristics.ToString("X4", CultureInfo.InvariantCulture)}" : string.Join(", ", flags);
    }

    private sealed record SectionRecord(PeSectionInfo Info, uint RawPointer, uint RawSize);
    private sealed record DataDirectory(uint Rva, uint Size);
    private sealed record SignatureInfo(bool HasSignature, string? Subject, string? Issuer, DateTime? NotAfter);
}
