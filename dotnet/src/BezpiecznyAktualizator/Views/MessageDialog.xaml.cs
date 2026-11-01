using System.Windows;
using System.Windows.Controls;
using BezpiecznyAktualizator.Core.Localization;

namespace BezpiecznyAktualizator.Views;

/// <summary>Okno komunikatu zgodne z motywem aplikacji (jasnym/ciemnym) – zamiennik systemowego MessageBox.</summary>
public partial class MessageDialog : Window
{
    private MessageBoxResult _result;

    private MessageDialog(string text, string title, MessageBoxButton buttons, MessageBoxImage image, bool defaultNo)
    {
        InitializeComponent();
        Title = title;
        MessageText.Text = text;
        var (glyph, brush) = image switch
        {
            MessageBoxImage.Error => ("\uEA39", "SystemFillColorCriticalBrush"),
            MessageBoxImage.Warning => ("\uE7BA", "SystemFillColorCautionBrush"),
            MessageBoxImage.Question => ("\uE9CE", "AccentFillColorDefaultBrush"),
            _ => ("\uE946", "AccentFillColorDefaultBrush"),
        };
        IconText.Text = glyph;
        IconText.SetResourceReference(TextBlock.ForegroundProperty, brush);

        switch (buttons)
        {
            case MessageBoxButton.YesNo:
                AddButton(L.T("Tak"), MessageBoxResult.Yes, accent: true, isDefault: !defaultNo, isCancel: false);
                AddButton(L.T("Nie"), MessageBoxResult.No, accent: false, isDefault: defaultNo, isCancel: true);
                _result = MessageBoxResult.No;
                break;
            case MessageBoxButton.YesNoCancel:
                AddButton(L.T("Tak"), MessageBoxResult.Yes, accent: true, isDefault: !defaultNo, isCancel: false);
                AddButton(L.T("Nie"), MessageBoxResult.No, accent: false, isDefault: defaultNo, isCancel: false);
                AddButton(L.T("Anuluj"), MessageBoxResult.Cancel, accent: false, isDefault: false, isCancel: true);
                _result = MessageBoxResult.Cancel;
                break;
            default:
                AddButton("OK", MessageBoxResult.OK, accent: true, isDefault: true, isCancel: true);
                _result = MessageBoxResult.OK;
                break;
        }
    }

    private void AddButton(string text, MessageBoxResult result, bool accent, bool isDefault, bool isCancel)
    {
        var button = new Button
        {
            Content = text, MinWidth = 96, Padding = new Thickness(16, 6, 16, 6), Margin = new Thickness(8, 0, 0, 0),
            IsDefault = isDefault, IsCancel = isCancel,
        };
        if (accent) button.SetResourceReference(StyleProperty, "AccentButtonStyle");
        button.Click += (_, _) =>
        {
            _result = result;
            DialogResult = true;
        };
        Buttons.Children.Add(button);
        if (isDefault) Loaded += (_, _) => button.Focus();
    }

    /// <summary>Pokazuje komunikat modalnie; zamknięcie okna (Esc/✕) daje wynik „Nie”/„Anuluj”/„OK”.</summary>
    public static MessageBoxResult Show(Window? owner, string text, string title, MessageBoxButton buttons,
                                        MessageBoxImage image, bool defaultNo = false)
    {
        var dialog = new MessageDialog(text, title, buttons, image, defaultNo);
        if (owner is { IsVisible: true }) dialog.Owner = owner;
        else dialog.WindowStartupLocation = WindowStartupLocation.CenterScreen;
        dialog.ShowDialog();
        return dialog._result;
    }
}
