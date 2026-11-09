using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using CinderellaProtection.Helpers;
using CinderellaProtection.Localization;
using CinderellaProtection.Models;
using CinderellaProtection.Services;
using Microsoft.Win32;

namespace CinderellaProtection;

public partial class MainWindow : Window
{
    private readonly ObservableCollection<FileScanResult> _results = [];
    private LogService? _logService;
    private FileScannerService? _fileScannerService;
    private CancellationTokenSource? _scanCts;
    private ICollectionView? _resultsView;
    private string? _yaraRulesDirectory;
    private bool _isScanning;
    private bool _isFullScreen;
    private Rect? _restoreBounds;
    private ResizeMode _restoreResizeMode = ResizeMode.CanResize;

    public MainWindow()
    {
        InitializeComponent();
        InitializeApplication();
    }

    private void InitializeApplication()
    {
        IconHelper.ApplyWindowIcon(this);
        AppLogoImage.Source = IconHelper.LoadImageSource();
        TitleIconImage.Source = AppLogoImage.Source;

        _resultsView = CollectionViewSource.GetDefaultView(_results);
        _resultsView.Filter = FilterResult;
        ResultsDataGrid.ItemsSource = _resultsView;

        _logService = new LogService(LogConsole);
        _fileScannerService = new FileScannerService(
            new HashService(),
            new ReputationService(),
            _logService,
            new FileTypeService(),
            new EntropyService(),
            new PeAnalysisService(),
            new IocExtractorService(),
            new YaraLiteService());

        LocalizationManager.LanguageChanged += OnLanguageChanged;
        _logService.Info("Log_Ready");
    }

    private void OnLanguageChanged(object? sender, EventArgs e)
    {
        ResultsDataGrid.Items.Refresh();
        _resultsView?.Refresh();
        _logService?.Info("Log_LanguageChanged");
    }

    private bool FilterResult(object item)
    {
        if (item is not FileScanResult result)
            return false;

        var statusIndex = StatusFilterComboBox?.SelectedIndex ?? 0;
        if (statusIndex > 0 &&
            StatusFilterComboBox?.SelectedItem is ComboBoxItem statusItem &&
            !string.Equals(result.StatusText, statusItem.Content?.ToString(), StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var query = SearchFilterTextBox?.Text?.Trim();
        if (string.IsNullOrWhiteSpace(query))
            return true;

        return Contains(result.FileName, query) ||
               Contains(result.FilePath, query) ||
               Contains(result.FileType, query) ||
               Contains(result.Sha256Hash, query) ||
               Contains(result.Md5Hash, query) ||
               Contains(result.Sha1Hash, query) ||
               Contains(result.PeSummary, query) ||
               Contains(result.IocSummary, query) ||
               Contains(result.YaraSummary, query);
    }

    private static bool Contains(string? value, string query)
    {
        return value?.Contains(query, StringComparison.OrdinalIgnoreCase) == true;
    }

    #region Drag & Drop

    private void Window_DragOver(object sender, DragEventArgs e)
    {
        e.Effects = HasFileDrop(e) ? DragDropEffects.Copy : DragDropEffects.None;
        e.Handled = true;
    }

    private void Window_Drop(object sender, DragEventArgs e)
    {
        StartDropScan(e);
    }

    private void DropZone_DragOver(object sender, DragEventArgs e)
    {
        e.Effects = HasFileDrop(e) ? DragDropEffects.Copy : DragDropEffects.None;
        e.Handled = true;
    }

    private void DropZone_DragEnter(object sender, DragEventArgs e)
    {
        if (HasFileDrop(e))
            DropZoneBorder.BorderBrush = (Brush)FindResource("DropZoneHoverBrush");
    }

    private void DropZone_DragLeave(object sender, DragEventArgs e)
    {
        DropZoneBorder.BorderBrush = (Brush)FindResource("DropZoneBorderBrush");
    }

    private void DropZone_Drop(object sender, DragEventArgs e)
    {
        DropZoneBorder.BorderBrush = (Brush)FindResource("DropZoneBorderBrush");
        StartDropScan(e);
    }

    private void StartDropScan(DragEventArgs e)
    {
        try
        {
            e.Handled = true;

            if (!HasFileDrop(e))
                return;

            var paths = ExtractDroppedPaths(e);
            if (paths.Length == 0)
                return;

            _ = StartScanAsync(paths);
        }
        catch (Exception ex)
        {
            _logService?.Error("Log_FileError", "drop", ex.Message);
            MessageBox.Show(
                ex.Message,
                "Cinderella Protection",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
        }
    }

    private static bool HasFileDrop(DragEventArgs e)
    {
        try
        {
            return e.Data.GetDataPresent(DataFormats.FileDrop);
        }
        catch
        {
            return false;
        }
    }

    private static string[] ExtractDroppedPaths(DragEventArgs e)
    {
        try
        {
            return e.Data.GetData(DataFormats.FileDrop) as string[] ?? [];
        }
        catch
        {
            return [];
        }
    }

    #endregion

    #region Window Chrome

    private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ClickCount == 2)
        {
            ToggleMaximize();
            return;
        }

        if (_isFullScreen)
            return;

        try
        {
            DragMove();
        }
        catch
        {
        }
    }

    private void MinimizeButton_Click(object sender, RoutedEventArgs e)
    {
        WindowState = WindowState.Minimized;
    }

    private void MaximizeButton_Click(object sender, RoutedEventArgs e)
    {
        ToggleMaximize();
    }

    private void CloseButton_Click(object sender, RoutedEventArgs e)
    {
        Close();
    }

    private void ToggleMaximize()
    {
        if (_isFullScreen)
            RestoreFromFullScreen();
        else
            EnterFullScreen();
    }

    private void EnterFullScreen()
    {
        if (!_isFullScreen)
        {
            _restoreBounds = new Rect(Left, Top, Width, Height);
            _restoreResizeMode = ResizeMode;
        }

        WindowState = WindowState.Normal;
        ResizeMode = ResizeMode.NoResize;

        var bounds = GetCurrentMonitorBounds();
        Left = bounds.Left;
        Top = bounds.Top;
        Width = bounds.Width;
        Height = bounds.Height;

        _isFullScreen = true;
        MaximizeButton.Content = "[]";
    }

    private void RestoreFromFullScreen()
    {
        _isFullScreen = false;
        WindowState = WindowState.Normal;
        ResizeMode = _restoreResizeMode;

        if (_restoreBounds is { Width: > 0, Height: > 0 } bounds)
        {
            Left = bounds.Left;
            Top = bounds.Top;
            Width = bounds.Width;
            Height = bounds.Height;
        }

        MaximizeButton.Content = "[]";
    }

    private Rect GetCurrentMonitorBounds()
    {
        var handle = new WindowInteropHelper(this).Handle;
        if (handle != IntPtr.Zero)
        {
            var monitor = MonitorFromWindow(handle, MonitorDefaultToNearest);
            if (monitor != IntPtr.Zero)
            {
                var info = new MonitorInfo
                {
                    Size = Marshal.SizeOf<MonitorInfo>()
                };

                if (GetMonitorInfo(monitor, ref info))
                    return ToDeviceIndependentRect(info.Monitor);
            }
        }

        return new Rect(0, 0, SystemParameters.PrimaryScreenWidth, SystemParameters.PrimaryScreenHeight);
    }

    private Rect ToDeviceIndependentRect(NativeRect rect)
    {
        var topLeft = new Point(rect.Left, rect.Top);
        var bottomRight = new Point(rect.Right, rect.Bottom);
        var source = PresentationSource.FromVisual(this);

        if (source?.CompositionTarget is not null)
        {
            topLeft = source.CompositionTarget.TransformFromDevice.Transform(topLeft);
            bottomRight = source.CompositionTarget.TransformFromDevice.Transform(bottomRight);
        }

        return new Rect(topLeft, bottomRight);
    }

    private const uint MonitorDefaultToNearest = 2;

    [DllImport("user32.dll")]
    private static extern IntPtr MonitorFromWindow(IntPtr hwnd, uint flags);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool GetMonitorInfo(IntPtr monitor, ref MonitorInfo monitorInfo);

    [StructLayout(LayoutKind.Sequential)]
    private struct MonitorInfo
    {
        public int Size;
        public NativeRect Monitor;
        public NativeRect WorkArea;
        public uint Flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeRect
    {
        public int Left;
        public int Top;
        public int Right;
        public int Bottom;
    }

    #endregion

    #region Browse

    private void BrowseFilesButton_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Multiselect = true,
            Title = LocalizationManager.GetString("BrowseFiles")
        };

        if (dialog.ShowDialog() == true)
            _ = StartScanAsync(dialog.FileNames);
    }

    private void BrowseFolderButton_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFolderDialog
        {
            Title = LocalizationManager.GetString("BrowseFolder")
        };

        if (dialog.ShowDialog() == true)
            _ = StartScanAsync([dialog.FolderName]);
    }

    #endregion

    #region Scanning

    private async Task StartScanAsync(IEnumerable<string> droppedPaths)
    {
        if (_fileScannerService is null || _logService is null)
            return;

        if (_isScanning)
        {
            _scanCts?.Cancel();
            await Task.Delay(100);
        }

        _scanCts?.Dispose();
        _scanCts = new CancellationTokenSource();
        var token = _scanCts.Token;

        _isScanning = true;
        SetScanningState(true);
        ResetSummary();
        _results.Clear();

        try
        {
            _logService.Info("Log_DropReceived");

            var filePaths = _fileScannerService.CollectFilePaths(droppedPaths);

            if (filePaths.Count == 0)
            {
                _logService.Warning("Log_NoFiles");
                return;
            }

            _logService.Info("Log_FoundFiles", filePaths.Count);
            TotalFilesText.Text = filePaths.Count.ToString(CultureInfo.InvariantCulture);
            ScanProgressBar.Visibility = Visibility.Visible;
            ScanProgressBar.Maximum = filePaths.Count;
            ScanProgressBar.Value = 0;

            var scanOptions = new ScanOptions
            {
                MaxParallelism = GetSelectedWorkerCount(),
                AnalyzePe = true,
                ExtractIocs = true,
                YaraRulesDirectory = _yaraRulesDirectory
            };

            var resultProgress = new Progress<FileScanResult>(result =>
            {
                Dispatcher.Invoke(() =>
                {
                    _results.Add(result);
                    ScanProgressBar.Value = _results.Count;
                    UpdateResultActionButtons();
                });
            });

            var summaryProgress = new Progress<ScanSummary>(summary =>
            {
                Dispatcher.Invoke(() => UpdateSummaryUI(summary));
            });

            await _fileScannerService.ScanFilesAsync(
                filePaths,
                scanOptions,
                resultProgress,
                summaryProgress,
                token);
        }
        catch (OperationCanceledException)
        {
            _logService.Warning("Log_ScanCancelled");
        }
        catch (Exception ex)
        {
            _logService.Error("Log_FileError", "scan", ex.Message);
        }
        finally
        {
            _isScanning = false;
            SetScanningState(false);
            UpdateResultActionButtons();
            ScanProgressBar.Visibility = Visibility.Collapsed;
        }
    }

    private void SetScanningState(bool isScanning)
    {
        CancelScanButton.IsEnabled = isScanning;
        ClearLogButton.IsEnabled = !isScanning;
        LanguageToggleButton.IsEnabled = !isScanning;
        RulesFolderButton.IsEnabled = !isScanning;
        WorkerComboBox.IsEnabled = !isScanning;
        ExportJsonButton.IsEnabled = !isScanning && _results.Count > 0;
        ExportCsvButton.IsEnabled = !isScanning && _results.Count > 0;
    }

    private void ResetSummary()
    {
        TotalFilesText.Text = "0";
        ProcessedText.Text = "0";
        SafeCountText.Text = "0";
        SuspiciousCountText.Text = "0";
        MaliciousCountText.Text = "0";
        ErrorCountText.Text = "0";
        UpdateResultActionButtons();
    }

    private void UpdateSummaryUI(ScanSummary summary)
    {
        TotalFilesText.Text = summary.TotalFiles.ToString(CultureInfo.InvariantCulture);
        ProcessedText.Text = summary.ProcessedFiles.ToString(CultureInfo.InvariantCulture);
        SafeCountText.Text = summary.SafeCount.ToString(CultureInfo.InvariantCulture);
        SuspiciousCountText.Text = summary.SuspiciousCount.ToString(CultureInfo.InvariantCulture);
        MaliciousCountText.Text = summary.MaliciousCount.ToString(CultureInfo.InvariantCulture);
        ErrorCountText.Text = summary.ErrorCount.ToString(CultureInfo.InvariantCulture);
    }

    private int GetSelectedWorkerCount()
    {
        if (WorkerComboBox.SelectedItem is ComboBoxItem item &&
            int.TryParse(item.Content?.ToString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var workers))
        {
            return Math.Clamp(workers, 1, 64);
        }

        return FileScannerService.MaxParallelism;
    }

    #endregion

    #region UI Actions

    private void LanguageToggleButton_Click(object sender, RoutedEventArgs e)
    {
        LocalizationManager.ToggleLanguage();
    }

    private void ClearLogButton_Click(object sender, RoutedEventArgs e)
    {
        _logService?.Clear();
        _logService?.Info("Log_Ready");
    }

    private void CancelScanButton_Click(object sender, RoutedEventArgs e)
    {
        _scanCts?.Cancel();
    }

    private void RulesFolderButton_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFolderDialog
        {
            Title = LocalizationManager.GetString("RulesFolder")
        };

        if (dialog.ShowDialog() == true)
        {
            _yaraRulesDirectory = dialog.FolderName;
            _logService?.Info("Log_RulesFolderSelected", _yaraRulesDirectory);
        }
    }

    private void SearchFilterTextBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        _resultsView?.Refresh();
    }

    private void StatusFilterComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        _resultsView?.Refresh();
    }

    private void ResultsDataGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        UpdateResultActionButtons();
    }

    private void CopyHashButton_Click(object sender, RoutedEventArgs e)
    {
        if (ResultsDataGrid.SelectedItem is FileScanResult result && !string.IsNullOrWhiteSpace(result.Sha256Hash))
        {
            Clipboard.SetText(result.Sha256Hash);
            _logService?.Info("Log_CopiedSha256", result.FileName);
        }
    }

    private void OpenFolderButton_Click(object sender, RoutedEventArgs e)
    {
        if (ResultsDataGrid.SelectedItem is not FileScanResult result || !File.Exists(result.FilePath))
            return;

        Process.Start(new ProcessStartInfo
        {
            FileName = "explorer.exe",
            Arguments = $"/select,\"{result.FilePath}\"",
            UseShellExecute = true
        });
    }

    private void ExportJsonButton_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new SaveFileDialog
        {
            Title = LocalizationManager.GetString("ExportJson"),
            Filter = "JSON report (*.json)|*.json",
            FileName = $"cinderella-report-{DateTime.Now:yyyyMMdd-HHmmss}.json"
        };

        if (dialog.ShowDialog() != true)
            return;

        var payload = new
        {
            generatedAt = DateTimeOffset.Now,
            rulesDirectory = _yaraRulesDirectory,
            results = _results
        };
        var json = JsonSerializer.Serialize(payload, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(dialog.FileName, json, Encoding.UTF8);
        _logService?.Success("Log_ExportComplete", dialog.FileName);
    }

    private void ExportCsvButton_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new SaveFileDialog
        {
            Title = LocalizationManager.GetString("ExportCsv"),
            Filter = "CSV report (*.csv)|*.csv",
            FileName = $"cinderella-report-{DateTime.Now:yyyyMMdd-HHmmss}.csv"
        };

        if (dialog.ShowDialog() != true)
            return;

        File.WriteAllText(dialog.FileName, BuildCsv(_results), Encoding.UTF8);
        _logService?.Success("Log_ExportComplete", dialog.FileName);
    }

    private void UpdateResultActionButtons()
    {
        var hasSelection = ResultsDataGrid?.SelectedItem is FileScanResult;
        if (CopyHashButton is not null)
            CopyHashButton.IsEnabled = !_isScanning && hasSelection;
        if (OpenFolderButton is not null)
            OpenFolderButton.IsEnabled = !_isScanning && hasSelection;
        if (ExportJsonButton is not null)
            ExportJsonButton.IsEnabled = !_isScanning && _results.Count > 0;
        if (ExportCsvButton is not null)
            ExportCsvButton.IsEnabled = !_isScanning && _results.Count > 0;
    }

    private static string BuildCsv(IEnumerable<FileScanResult> results)
    {
        var builder = new StringBuilder();
        builder.AppendLine("FileName,FilePath,Status,FileType,SizeBytes,Entropy,MD5,SHA1,SHA256,PE,YARA,IOC,Error");

        foreach (var result in results)
        {
            var values = new[]
            {
                result.FileName,
                result.FilePath,
                result.StatusText,
                result.FileType,
                result.FileSizeBytes.ToString(CultureInfo.InvariantCulture),
                result.Entropy.ToString("F2", CultureInfo.InvariantCulture),
                result.Md5Hash ?? string.Empty,
                result.Sha1Hash ?? string.Empty,
                result.Sha256Hash ?? string.Empty,
                result.PeSummary,
                result.YaraSummary,
                result.IocSummary,
                result.ErrorMessage ?? string.Empty
            };
            builder.AppendLine(string.Join(",", values.Select(EscapeCsv)));
        }

        return builder.ToString();
    }

    private static string EscapeCsv(string value)
    {
        return "\"" + value.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";
    }

    #endregion
}
