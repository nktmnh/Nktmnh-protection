using System.IO;
using System.Threading.Tasks.Dataflow;
using CinderellaProtection.Models;

namespace CinderellaProtection.Services;

public sealed class FileScannerService
{
    public const int MaxParallelism = 20;

    private readonly HashService _hashService;
    private readonly ReputationService _reputationService;
    private readonly LogService _logService;
    private readonly FileTypeService _fileTypeService;
    private readonly EntropyService _entropyService;
    private readonly PeAnalysisService _peAnalysisService;
    private readonly IocExtractorService _iocExtractorService;
    private readonly YaraLiteService _yaraLiteService;

    public FileScannerService(
        HashService hashService,
        ReputationService reputationService,
        LogService logService,
        FileTypeService fileTypeService,
        EntropyService entropyService,
        PeAnalysisService peAnalysisService,
        IocExtractorService iocExtractorService,
        YaraLiteService yaraLiteService)
    {
        _hashService = hashService;
        _reputationService = reputationService;
        _logService = logService;
        _fileTypeService = fileTypeService;
        _entropyService = entropyService;
        _peAnalysisService = peAnalysisService;
        _iocExtractorService = iocExtractorService;
        _yaraLiteService = yaraLiteService;
    }

    public IReadOnlyList<string> CollectFilePaths(IEnumerable<string> droppedPaths)
    {
        var files = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var path in droppedPaths)
        {
            if (File.Exists(path))
            {
                files.Add(path);
            }
            else if (Directory.Exists(path))
            {
                foreach (var file in EnumerateFilesSafely(path))
                    files.Add(file);
            }
        }

        return files.OrderBy(f => f, StringComparer.OrdinalIgnoreCase).ToList();
    }

    public async Task<IReadOnlyList<FileScanResult>> ScanFilesAsync(
        IEnumerable<string> filePaths,
        ScanOptions? options = null,
        IProgress<FileScanResult>? resultProgress = null,
        IProgress<ScanSummary>? summaryProgress = null,
        CancellationToken cancellationToken = default)
    {
        options ??= new ScanOptions();
        var paths = filePaths.ToList();
        var results = new List<FileScanResult>(paths.Count);
        var summary = new ScanSummary { TotalFiles = paths.Count };
        var resultsLock = new object();
        var rules = _yaraLiteService.LoadRules(options.YaraRulesDirectory);

        _logService.Info("Log_ScanStarted", paths.Count);
        _logService.Info("Log_ParallelWorkers", options.MaxParallelism);
        if (rules.Count > 0)
            _logService.Info("Log_YaraRulesLoaded", rules.Count);

        var processingBlock = new ActionBlock<string>(
            async filePath =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                var result = await ProcessSingleFileAsync(filePath, options, rules, cancellationToken);

                lock (resultsLock)
                {
                    results.Add(result);
                    UpdateSummary(summary, result);
                    resultProgress?.Report(result);
                    summaryProgress?.Report(CloneSummary(summary));
                }
            },
            new ExecutionDataflowBlockOptions
            {
                MaxDegreeOfParallelism = Math.Clamp(options.MaxParallelism, 1, 64),
                CancellationToken = cancellationToken
            });

        foreach (var path in paths)
        {
            await processingBlock.SendAsync(path, cancellationToken);
        }

        processingBlock.Complete();
        await processingBlock.Completion;

        _logService.Success("Log_ScanComplete", summary.ProcessedFiles, summary.SafeCount, summary.SuspiciousCount, summary.MaliciousCount);

        return results
            .OrderBy(r => r.FilePath, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private async Task<FileScanResult> ProcessSingleFileAsync(
        string filePath,
        ScanOptions options,
        IReadOnlyList<YaraLiteRule> yaraRules,
        CancellationToken cancellationToken)
    {
        var fileName = Path.GetFileName(filePath);
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();

        try
        {
            var fileInfo = new FileInfo(filePath);
            _logService.Info("Log_HashingFile", fileName);

            var hashes = await _hashService.ComputeHashesAsync(filePath, cancellationToken);
            _logService.Info("Log_HashComplete", fileName, hashes.Sha256[..16] + "...");

            var status = await _reputationService.CheckHashAsync(hashes.Sha256, cancellationToken);
            var fileType = await _fileTypeService.DetectAsync(filePath, cancellationToken);
            var entropy = await _entropyService.CalculateFileEntropyAsync(filePath, cancellationToken);
            var peAnalysis = options.AnalyzePe ? await _peAnalysisService.AnalyzeAsync(filePath, cancellationToken) : null;
            var iocAnalysis = options.ExtractIocs ? await _iocExtractorService.ExtractAsync(filePath, cancellationToken) : null;
            var yaraMatches = await _yaraLiteService.MatchFileAsync(filePath, yaraRules, cancellationToken);
            status = UpgradeStatus(status, peAnalysis, iocAnalysis, yaraMatches);
            LogStatus(fileName, status);

            stopwatch.Stop();

            return new FileScanResult
            {
                FilePath = filePath,
                FileName = fileName,
                Extension = Path.GetExtension(filePath),
                FileType = fileType,
                Md5Hash = hashes.Md5,
                Sha1Hash = hashes.Sha1,
                Sha256Hash = hashes.Sha256,
                Status = status,
                FileSizeBytes = fileInfo.Length,
                Entropy = entropy,
                ProcessingTime = stopwatch.Elapsed,
                PeAnalysis = peAnalysis,
                IocAnalysis = iocAnalysis,
                YaraMatches = yaraMatches
            };
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            stopwatch.Stop();
            _logService.Error("Log_FileError", fileName, ex.Message);

            return new FileScanResult
            {
                FilePath = filePath,
                FileName = fileName,
                Extension = Path.GetExtension(filePath),
                Status = ReputationStatus.Error,
                ErrorMessage = ex.Message,
                ProcessingTime = stopwatch.Elapsed
            };
        }
    }

    private void LogStatus(string fileName, ReputationStatus status)
    {
        switch (status)
        {
            case ReputationStatus.Safe:
                _logService.Success("Log_StatusSafe", fileName);
                break;
            case ReputationStatus.Suspicious:
                _logService.Warning("Log_StatusSuspicious", fileName);
                break;
            case ReputationStatus.Malicious:
                _logService.Error("Log_StatusMalicious", fileName);
                break;
            default:
                _logService.Warning("Log_StatusUnknown", fileName);
                break;
        }
    }

    private static void UpdateSummary(ScanSummary summary, FileScanResult result)
    {
        summary.ProcessedFiles++;
        if (result.YaraMatches.Count > 0)
            summary.YaraMatchCount++;

        if (result.PeAnalysis?.IsPeFile == true)
            summary.PeFileCount++;

        switch (result.Status)
        {
            case ReputationStatus.Safe:
                summary.SafeCount++;
                break;
            case ReputationStatus.Suspicious:
                summary.SuspiciousCount++;
                break;
            case ReputationStatus.Malicious:
                summary.MaliciousCount++;
                break;
            default:
                summary.ErrorCount++;
                break;
        }
    }

    private static ScanSummary CloneSummary(ScanSummary source) => new()
    {
        TotalFiles = source.TotalFiles,
        ProcessedFiles = source.ProcessedFiles,
        SafeCount = source.SafeCount,
        SuspiciousCount = source.SuspiciousCount,
        MaliciousCount = source.MaliciousCount,
        ErrorCount = source.ErrorCount,
        YaraMatchCount = source.YaraMatchCount,
        PeFileCount = source.PeFileCount
    };

    private static ReputationStatus UpgradeStatus(
        ReputationStatus current,
        PeAnalysisResult? peAnalysis,
        IocAnalysisResult? iocAnalysis,
        IReadOnlyList<YaraMatchResult> yaraMatches)
    {
        if (current is ReputationStatus.Malicious or ReputationStatus.Error)
            return current;

        if (yaraMatches.Count > 0)
            return ReputationStatus.Malicious;

        var indicatorCount = peAnalysis?.SuspicionIndicators.Count ?? 0;
        var iocCount = iocAnalysis?.TotalCount ?? 0;

        if (indicatorCount >= 3 || iocCount >= 10)
            return ReputationStatus.Suspicious;

        return current;
    }

    private IEnumerable<string> EnumerateFilesSafely(string root)
    {
        var pending = new Stack<string>();
        pending.Push(root);

        while (pending.Count > 0)
        {
            var directory = pending.Pop();
            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(directory);
            }
            catch (Exception ex)
            {
                _logService.Warning("Log_FileError", directory, ex.Message);
                continue;
            }

            foreach (var file in files)
                yield return file;

            IEnumerable<string> subdirectories;
            try
            {
                subdirectories = Directory.EnumerateDirectories(directory);
            }
            catch (Exception ex)
            {
                _logService.Warning("Log_FileError", directory, ex.Message);
                continue;
            }

            foreach (var subdirectory in subdirectories)
            {
                try
                {
                    var attributes = File.GetAttributes(subdirectory);
                    if ((attributes & FileAttributes.ReparsePoint) == 0)
                        pending.Push(subdirectory);
                }
                catch (Exception ex)
                {
                    _logService.Warning("Log_FileError", subdirectory, ex.Message);
                }
            }
        }
    }
}
