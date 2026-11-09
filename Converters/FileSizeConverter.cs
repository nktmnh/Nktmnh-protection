using System.Globalization;
using System.Windows.Data;

namespace CinderellaProtection.Converters;

public sealed class FileSizeConverter : IValueConverter
{
    private static readonly string[] Units = ["B", "KB", "MB", "GB", "TB"];

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is not long bytes)
            return "—";

        if (bytes == 0)
            return "0 B";

        var order = (int)Math.Floor(Math.Log(bytes, 1024));
        order = Math.Clamp(order, 0, Units.Length - 1);
        var size = bytes / Math.Pow(1024, order);

        return $"{size:0.##} {Units[order]}";
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
