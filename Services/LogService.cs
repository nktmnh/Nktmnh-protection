using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Media;
using System.Windows.Threading;
using CinderellaProtection.Localization;

namespace CinderellaProtection.Services;

public sealed class LogService
{
    private readonly RichTextBox _logConsole;
    private readonly Dispatcher _dispatcher;
    private readonly object _lock = new();

    public LogService(RichTextBox logConsole)
    {
        _logConsole = logConsole;
        _dispatcher = logConsole.Dispatcher;
    }

    public void Info(string messageKey, params object[] args)
    {
        WriteLog(LogLevel.Info, messageKey, args);
    }

    public void Success(string messageKey, params object[] args)
    {
        WriteLog(LogLevel.Success, messageKey, args);
    }

    public void Warning(string messageKey, params object[] args)
    {
        WriteLog(LogLevel.Warning, messageKey, args);
    }

    public void Error(string messageKey, params object[] args)
    {
        WriteLog(LogLevel.Error, messageKey, args);
    }

    public void Clear()
    {
        RunOnUiThread(() => _logConsole.Document.Blocks.Clear());
    }

    private void WriteLog(LogLevel level, string messageKey, params object[] args)
    {
        RunOnUiThread(() =>
        {
            var timestamp = DateTime.Now.ToString("HH:mm:ss");
            var message = LocalizationManager.GetString(messageKey, args);
            var brush = GetBrushForLevel(level);
            var timestampBrush = new SolidColorBrush(Color.FromRgb(120, 120, 130));

            lock (_lock)
            {
                var paragraph = new Paragraph { Margin = new Thickness(0, 0, 0, 2) };

                paragraph.Inlines.Add(new Run($"[{timestamp}] ")
                {
                    Foreground = timestampBrush
                });

                paragraph.Inlines.Add(new Run(message)
                {
                    Foreground = brush
                });

                _logConsole.Document.Blocks.Add(paragraph);
                _logConsole.ScrollToEnd();
            }
        });
    }

    private void RunOnUiThread(Action action)
    {
        if (_dispatcher.HasShutdownStarted || _dispatcher.HasShutdownFinished)
            return;

        if (_dispatcher.CheckAccess())
        {
            TryRun(action);
            return;
        }

        try
        {
            _dispatcher.BeginInvoke(() => TryRun(action), DispatcherPriority.Background);
        }
        catch
        {
        }
    }

    private static void TryRun(Action action)
    {
        try
        {
            action();
        }
        catch
        {
        }
    }

    private static SolidColorBrush GetBrushForLevel(LogLevel level) => level switch
    {
        LogLevel.Success => new SolidColorBrush(Color.FromRgb(76, 175, 80)),
        LogLevel.Warning => new SolidColorBrush(Color.FromRgb(255, 193, 7)),
        LogLevel.Error => new SolidColorBrush(Color.FromRgb(244, 67, 54)),
        _ => new SolidColorBrush(Color.FromRgb(200, 200, 210))
    };

    private enum LogLevel
    {
        Info,
        Success,
        Warning,
        Error
    }
}
