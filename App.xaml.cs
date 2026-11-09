using System.Windows;
using System.Windows.Threading;

namespace NktmnhProtection;

public partial class App : Application
{
    private static int _uiErrorShown;

    protected override void OnStartup(StartupEventArgs e)
    {
        DispatcherUnhandledException += OnDispatcherUnhandledException;
        TaskScheduler.UnobservedTaskException += OnUnobservedTaskException;
        AppDomain.CurrentDomain.UnhandledException += OnUnhandledException;

        base.OnStartup(e);
    }

    private static void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        e.Handled = true;
        if (Interlocked.Exchange(ref _uiErrorShown, 1) != 0)
            return;

        MessageBox.Show(
            $"The app caught an unexpected UI error and stayed open:\n\n{e.Exception.Message}",
            "nktmnhprotection",
            MessageBoxButton.OK,
            MessageBoxImage.Warning);
    }

    private static void OnUnobservedTaskException(object? sender, UnobservedTaskExceptionEventArgs e)
    {
        e.SetObserved();
    }

    private static void OnUnhandledException(object sender, UnhandledExceptionEventArgs e)
    {
        if (e.ExceptionObject is not Exception ex)
            return;

        MessageBox.Show(
            $"Unexpected error:\n\n{ex.Message}",
            "nktmnhprotection",
            MessageBoxButton.OK,
            MessageBoxImage.Error);
    }
}
