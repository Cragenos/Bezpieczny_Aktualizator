using System.Text.RegularExpressions;
using BezpiecznyAktualizator.Core.Localization;
using BezpiecznyAktualizator.Core.Security;

namespace BezpiecznyAktualizator.Tests;

/// <summary>
/// Spójność tłumaczeń: każdy tekst użyty w kodzie (L.T/F/Txt/N, {l:Tr '...'}) ma tłumaczenie
/// w każdym języku, a symbole zastępcze {n} są zachowane. Testy nie zmieniają globalnego L.Language.
/// </summary>
public partial class LocalizationTests
{
    private static readonly Lazy<string> SourceDir = new(() =>
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            var src = Path.Combine(dir.FullName, "src");
            if (Directory.Exists(Path.Combine(src, "BezpiecznyAktualizator.Core"))) return src;
        }
        throw new DirectoryNotFoundException("Nie znaleziono katalogu src.");
    });

    private static IEnumerable<FileInfo> SourceFiles(string pattern) =>
        new DirectoryInfo(SourceDir.Value).EnumerateFiles(pattern, SearchOption.AllDirectories)
            .Where(f => !Regex.IsMatch(f.FullName, @"[\\/](obj|bin)[\\/]"));

    private static string Unescape(string s) => Regex.Unescape(s);

    private static readonly Lazy<HashSet<string>> SourceKeys = new(() =>
    {
        var keys = new HashSet<string>(StringComparer.Ordinal);
        foreach (var f in SourceFiles("*.cs"))
            foreach (Match m in CsKey().Matches(File.ReadAllText(f.FullName)))
                keys.Add(Unescape(m.Groups[1].Value));
        foreach (var f in SourceFiles("*.xaml"))
            foreach (Match m in XamlKey().Matches(File.ReadAllText(f.FullName)))
                keys.Add(System.Net.WebUtility.HtmlDecode(m.Groups[1].Value));
        keys.Remove("");
        return keys;
    });

    public static TheoryData<string> TranslatedLanguages() =>
        new(L.Languages.Select(l => l.Code).Where(c => c != L.SourceLanguage));

    [Fact]
    public void SourceContainsTranslatableTexts() => Assert.True(SourceKeys.Value.Count > 200);

    [Theory]
    [MemberData(nameof(TranslatedLanguages))]
    public void LanguageFileMatchesSourceKeys(string language)
    {
        var table = L.Table(language);
        var missing = SourceKeys.Value.Where(k => !table.ContainsKey(k)).ToList();
        var obsolete = table.Keys.Where(k => !SourceKeys.Value.Contains(k)).ToList();
        Assert.True(missing.Count == 0, $"{language}: brak kluczy (uruchom tools\\Update-Translations.ps1): " + string.Join(" | ", missing));
        Assert.True(obsolete.Count == 0, $"{language}: nieużywane klucze: " + string.Join(" | ", obsolete));
    }

    [Theory]
    [MemberData(nameof(TranslatedLanguages))]
    public void TranslationsAreCompleteAndKeepPlaceholders(string language)
    {
        static List<string> Placeholders(string s) =>
            Placeholder().Matches(s).Select(m => m.Value).Order(StringComparer.Ordinal).ToList();
        var problems = L.Table(language)
            .Where(kv => kv.Value.Trim().Length == 0 || !Placeholders(kv.Key).SequenceEqual(Placeholders(kv.Value)))
            .Select(kv => kv.Key).ToList();
        Assert.True(problems.Count == 0, $"{language}: puste lub błędne tłumaczenia: " + string.Join(" | ", problems));
        foreach (var (key, value) in L.Table(language))
            _ = string.Format(value, Enumerable.Range(0, 10).Select(i => (object)i).ToArray()); // poprawny format
    }

    /// <summary>Polskie literały w kodzie muszą przechodzić przez L.T/F/Txt/N (wykrywa nieprzetłumaczone teksty).</summary>
    [Fact]
    public void PolishLiteralsAreTranslatable()
    {
        var untranslated = new List<string>();
        foreach (var f in SourceFiles("*.cs"))
        {
            var lines = File.ReadAllLines(f.FullName);
            for (var i = 0; i < lines.Length; i++)
            {
                if (lines[i].TrimStart().StartsWith("//", StringComparison.Ordinal)) continue;
                foreach (Match m in Literal().Matches(lines[i]))
                {
                    var text = Unescape(m.Groups[1].Value);
                    if (PolishText().IsMatch(text) && !SourceKeys.Value.Contains(text))
                        untranslated.Add($"{f.Name}:{i + 1} {text}");
                }
            }
        }
        foreach (var f in SourceFiles("*.xaml"))
            foreach (Match m in XamlLiteral().Matches(File.ReadAllText(f.FullName)))
                untranslated.Add($"{f.Name}: {m.Value}");
        Assert.True(untranslated.Count == 0, "Teksty bez tłumaczenia:\n" + string.Join("\n", untranslated));
    }

    [Fact]
    public void TranslateFallsBackToEnglishThenPolish()
    {
        Assert.Equal("Gotowy.", L.Translate("Gotowy.", "pl"));
        Assert.NotEqual("Gotowy.", L.Translate("Gotowy.", "de"));
        Assert.Equal("tekst spoza tabeli", L.Translate("tekst spoza tabeli", "ja"));
        Assert.Equal(L.Translate(Levels.High, "en"), L.Translate(Levels.High, "xx"));
    }

    [Theory]
    [InlineData("pt-BR", "pt")]
    [InlineData("zh-Hans", "zh")]
    [InlineData("zh_CN", "zh")]
    [InlineData("EN-us", "en")]
    [InlineData("xx", null)]
    [InlineData("", null)]
    public void NormalizesLanguageCodes(string input, string? expected) => Assert.Equal(expected, L.Normalize(input));

    [GeneratedRegex("""L\.(?:T|F|Txt|N)\(\s*"((?:[^"\\]|\\.)*)"(?=\s*[,)])""")]
    private static partial Regex CsKey();

    [GeneratedRegex(@"\{l:Tr '([^']*)'\}")]
    private static partial Regex XamlKey();

    [GeneratedRegex("""(?<![@$])"((?:[^"\\]|\\.)*)"(?!")""")]
    private static partial Regex Literal();

    /// <summary>Atrybuty tekstowe XAML z polskim tekstem wpisanym bezpośrednio, zamiast przez {l:Tr '...'}.</summary>
    [GeneratedRegex(@"\b(?:Content|Header|Text|Title|ToolTip)=""[^""{]*[ąćęłńóśźżĄĆĘŁŃÓŚŹŻ„][^""]*""")]
    private static partial Regex XamlLiteral();

    [GeneratedRegex(@"\{\d+(?::[^}]*)?\}")]
    private static partial Regex Placeholder();

    [GeneratedRegex("[ąćęłńóśźżĄĆĘŁŃÓŚŹŻ„”]")]
    private static partial Regex PolishText();
}
