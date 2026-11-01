using System.Drawing;
using BezpiecznyAktualizator.Core.Localization;
using Forms = System.Windows.Forms;
using Application = System.Windows.Application;

namespace BezpiecznyAktualizator.Services;

internal sealed class ApplicationTray : IDisposable
{
    private readonly Action _showWindow;
    private readonly Action _exit;
    private readonly Action _checkUpdate;
    private readonly Forms.NotifyIcon _icon;
    private readonly Forms.ToolStripMenuItem _openItem;
    private readonly Forms.ToolStripMenuItem _checkUpdateItem;
    private readonly Forms.ToolStripMenuItem _exitItem;
    private bool _disposed;

    public ApplicationTray(Action showWindow, Action exit, Action checkUpdate)
    {
        _showWindow = showWindow;
        _exit = exit;
        _checkUpdate = checkUpdate;
        _openItem = new Forms.ToolStripMenuItem();
        _checkUpdateItem = new Forms.ToolStripMenuItem();
        _exitItem = new Forms.ToolStripMenuItem();

        var menu = new Forms.ContextMenuStrip();
        menu.Items.AddRange([_openItem, _checkUpdateItem, new Forms.ToolStripSeparator(), _exitItem]);
        _openItem.Click += (_, _) => _showWindow();
        _checkUpdateItem.Click += (_, _) => _checkUpdate();
        _exitItem.Click += (_, _) => _exit();

        _icon = new Forms.NotifyIcon
        {
            Icon = SystemIcons.Shield,
            Text = "Bezpieczny Aktualizator",
            ContextMenuStrip = menu,
            Visible = true,
        };
        _icon.DoubleClick += (_, _) => _showWindow();
        L.LanguageChanged += UpdateLabels;
        UpdateLabels();
    }

    public void ShowBalloon(string title, string message, Forms.ToolTipIcon icon = Forms.ToolTipIcon.Info)
    {
        if (_disposed) return;
        _icon.BalloonTipTitle = Shorten(title, 63);
        _icon.BalloonTipText = Shorten(message, 255);
        _icon.BalloonTipIcon = icon;
        _icon.ShowBalloonTip(5000);
    }

    private void UpdateLabels()
    {
        if (Application.Current?.Dispatcher is { } dispatcher && !dispatcher.CheckAccess())
        {
            dispatcher.BeginInvoke(UpdateLabels);
            return;
        }

        _openItem.Text = L.T("Otwórz Bezpieczny Aktualizator");
        _checkUpdateItem.Text = L.T("Sprawdź aktualizację programu");
        _exitItem.Text = L.T("Zakończ program");
    }

    private static string Shorten(string text, int maxLength) =>
        text.Length <= maxLength ? text : text[..(maxLength - 1)] + "…";

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        L.LanguageChanged -= UpdateLabels;
        _icon.Visible = false;
        _icon.Dispose();
    }
}
