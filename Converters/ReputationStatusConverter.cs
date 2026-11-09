using System.Globalization;
using System.Windows.Data;
using NktmnhProtection.Localization;
using NktmnhProtection.Models;

namespace NktmnhProtection.Converters;

public sealed class ReputationStatusConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is not ReputationStatus status)
            return string.Empty;

        var key = status switch
        {
            ReputationStatus.Safe => "Status_Safe",
            ReputationStatus.Suspicious => "Status_Suspicious",
            ReputationStatus.Malicious => "Status_Malicious",
            _ => "Status_Error"
        };

        return LocalizationManager.GetString(key);
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
