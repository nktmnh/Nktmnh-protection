using System.Globalization;
using System.Windows.Data;
using NktmnhProtection.Models;

namespace NktmnhProtection.Converters;

public sealed class StatusToBrushConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is not ReputationStatus status)
            return "#B0B0B0";

        return status switch
        {
            ReputationStatus.Safe => "#4CAF50",
            ReputationStatus.Suspicious => "#FFC107",
            ReputationStatus.Malicious => "#F44336",
            _ => "#9E9E9E"
        };
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
