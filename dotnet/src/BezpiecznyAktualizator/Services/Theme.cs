using System.Windows;

namespace BezpiecznyAktualizator.Services;

public enum AppTheme { System, Light, Dark }

/// <summary>Przełącza wbudowany motyw Fluent WPF (jasny / ciemny / zgodny z ustawieniami Windows).</summary>
public static class Theme
{
#pragma warning disable WPF0001 // ThemeMode jest w .NET 9/10 oznaczony jako eksperymentalny
    public static void Apply(AppTheme theme)
    {
        if (Application.Current is not { } app) return;
        app.ThemeMode = theme switch
        {
            AppTheme.Light => ThemeMode.Light,
            AppTheme.Dark => ThemeMode.Dark,
            _ => ThemeMode.System,
        };
    }
#pragma warning restore WPF0001
}
