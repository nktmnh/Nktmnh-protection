using System.IO;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace NktmnhProtection.Helpers;

public static class IconHelper
{
    private const string IconFileName = "app.jpg";

    public static string ResolveIconPath()
    {
        var localIcon = Path.Combine(AppContext.BaseDirectory, IconFileName);
        if (File.Exists(localIcon))
            return localIcon;

        var projectRootIcon = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "app.jpg"));
        if (File.Exists(projectRootIcon))
            return projectRootIcon;

        return localIcon;
    }

    public static void ApplyWindowIcon(Window window, string? iconPath = null)
    {
        var path = iconPath ?? ResolveIconPath();

        if (!File.Exists(path))
            return;

        try
        {
            var bitmap = new BitmapImage();
            bitmap.BeginInit();
            bitmap.CacheOption = BitmapCacheOption.OnLoad;
            bitmap.UriSource = new Uri(path, UriKind.Absolute);
            bitmap.EndInit();
            bitmap.Freeze();

            window.Icon = bitmap;
        }
        catch
        {
            // Fallback: ignore icon load failures
        }
    }

    public static ImageSource? LoadImageSource(string? path = null)
    {
        var imagePath = path ?? ResolveIconPath();

        if (!File.Exists(imagePath))
            return null;

        try
        {
            var bitmap = new BitmapImage();
            bitmap.BeginInit();
            bitmap.CacheOption = BitmapCacheOption.OnLoad;
            bitmap.UriSource = new Uri(imagePath, UriKind.Absolute);
            bitmap.EndInit();
            bitmap.Freeze();
            return bitmap;
        }
        catch
        {
            return null;
        }
    }
}
