using System.Windows;

namespace CinderellaProtection.Localization;

public static class LocalizationManager
{
    public const string EnglishCulture = "en";
    public const string VietnameseCulture = "vi";

    private static string _currentCulture = EnglishCulture;

    public static event EventHandler? LanguageChanged;

    public static string CurrentCulture => _currentCulture;

    public static bool IsVietnamese => _currentCulture == VietnameseCulture;

    public static void SetLanguage(string culture)
    {
        if (_currentCulture == culture)
            return;

        _currentCulture = culture;

        var app = Application.Current;
        if (app is null)
            return;

        var dictionaries = app.Resources.MergedDictionaries;
        var existing = dictionaries.FirstOrDefault(d =>
            d.Source?.OriginalString.Contains("Strings.", StringComparison.OrdinalIgnoreCase) == true);

        if (existing is not null)
            dictionaries.Remove(existing);

        var uri = new Uri($"Localization/Strings.{culture}.xaml", UriKind.Relative);
        dictionaries.Add(new ResourceDictionary { Source = uri });

        LanguageChanged?.Invoke(null, EventArgs.Empty);
    }

    public static void ToggleLanguage()
    {
        SetLanguage(IsVietnamese ? EnglishCulture : VietnameseCulture);
    }

    public static string GetString(string key)
    {
        if (Application.Current?.TryFindResource(key) is string value)
            return value;

        return key;
    }

    public static string GetString(string key, params object[] args)
    {
        var format = GetString(key);
        return args.Length > 0 ? string.Format(format, args) : format;
    }
}
