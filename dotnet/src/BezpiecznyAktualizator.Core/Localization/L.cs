using System.Collections.Concurrent;
using System.Globalization;
using System.Text.Json;

namespace BezpiecznyAktualizator.Core.Localization;

public sealed record LanguageInfo(string Code, string NativeName, string EnglishName)
{
    public override string ToString() => NativeName;
}

/// <summary>
/// Tłumaczenia interfejsu. Kluczem jest polski tekst źródłowy; tłumaczenia są w osadzonych plikach
/// Localization/Strings/&lt;kod&gt;.json. Brakujące tłumaczenie → angielski → tekst polski.
/// Nowe teksty dodaje się przez L.T / L.F / L.Txt / L.N (z literałem) lub {l:Tr '...'} w XAML,
/// a pliki językowe aktualizuje skrypt tools\Update-Translations.ps1.
/// </summary>
public static class L
{
    public const string SourceLanguage = "pl";
    public const string FallbackLanguage = "en";

    public static IReadOnlyList<LanguageInfo> Languages { get; } =
    [
        new("pl", "Polski", "Polish"),
        new("en", "English", "English"),
        new("de", "Deutsch", "German"),
        new("fr", "Français", "French"),
        new("es", "Español", "Spanish"),
        new("it", "Italiano", "Italian"),
        new("pt", "Português (Brasil)", "Portuguese (Brazil)"),
        new("ru", "Русский", "Russian"),
        new("uk", "Українська", "Ukrainian"),
        new("tr", "Türkçe", "Turkish"),
        new("zh", "中文（简体）", "Chinese (Simplified)"),
        new("ja", "日本語", "Japanese"),
        new("ko", "한국어", "Korean"),
    ];

    private static readonly ConcurrentDictionary<string, IReadOnlyDictionary<string, string>> Tables = new();
    private static volatile string _language = SourceLanguage;

    /// <summary>Wywoływane po zmianie języka (w wątku, który zmienił język).</summary>
    public static event Action? LanguageChanged;

    public static string Language
    {
        get => _language;
        set
        {
            var code = Normalize(value) ?? FallbackLanguage;
            if (code == _language) return;
            _language = code;
            LanguageChanged?.Invoke();
        }
    }

    /// <summary>Zwraca kod obsługiwanego języka ("pt-BR" → "pt", "zh-Hans" → "zh") lub null.</summary>
    public static string? Normalize(string? code)
    {
        if (string.IsNullOrWhiteSpace(code)) return null;
        var two = code.Trim().Split('-', '_')[0].ToLowerInvariant();
        return Languages.Any(l => l.Code == two) ? two : null;
    }

    /// <summary>Język interfejsu systemu Windows, jeśli jest obsługiwany; w przeciwnym razie angielski.</summary>
    public static string SystemLanguage() => Normalize(CultureInfo.CurrentUICulture.Name) ?? FallbackLanguage;

    /// <summary>Tłumaczy tekst źródłowy na bieżący język.</summary>
    public static string T(string text) => Translate(text, _language);

    /// <summary>Tłumaczy wzorzec formatu ({0}, {1}...) i wstawia argumenty.</summary>
    public static string F(string format, params object?[] args) =>
        string.Format(CultureInfo.CurrentCulture, T(format), args);

    /// <summary>Tekst tłumaczony dopiero przy wyświetleniu (raporty pokazywane także po zmianie języka).</summary>
    public static LocText Txt(string format, params object?[] args) => new(format, args);

    /// <summary>Oznacza literał do tłumaczenia bez tłumaczenia go teraz (wartości przechowywane w danych).</summary>
    public static string N(string text) => text;

    public static string Translate(string text, string language)
    {
        if (text.Length == 0 || language == SourceLanguage) return text;
        if (Table(language).TryGetValue(text, out var value) && value.Length > 0) return value;
        if (language != FallbackLanguage && Table(FallbackLanguage).TryGetValue(text, out var en) && en.Length > 0) return en;
        return text;
    }

    public static IReadOnlyDictionary<string, string> Table(string language) => Tables.GetOrAdd(language, Load);

    private static IReadOnlyDictionary<string, string> Load(string language)
    {
        using var stream = typeof(L).Assembly.GetManifestResourceStream($"Strings.{language}.json");
        if (stream is null) return new Dictionary<string, string>();
        return JsonSerializer.Deserialize<Dictionary<string, string>>(stream) ?? [];
    }
}

/// <summary>Tekst z argumentami tłumaczony przy każdym ToString(); zwykły string jest przekazywany bez tłumaczenia.</summary>
public sealed class LocText
{
    private readonly Func<string> _render;

    internal LocText(string format, object?[] args) =>
        _render = args.Length == 0 ? () => L.T(format) : () => L.F(format, args);

    private LocText(Func<string> render) => _render = render;

    public static LocText Raw(string text) => new(() => text);

    public static implicit operator LocText(string text) => Raw(text);

    public static LocText operator +(LocText a, LocText b) => new(() => a.ToString() + b.ToString());

    public int Length => ToString().Length;

    public override string ToString() => _render();
}
