using System.Drawing.Drawing2D;
using System.ComponentModel;

namespace Cascade.Win;

static class Theme
{
    public static readonly Color Background = Color.FromArgb(15, 19, 23), Panel = Color.FromArgb(26, 32, 36), Field = Color.FromArgb(36, 43, 48), Mint = Color.FromArgb(130, 240, 198), Text = Color.FromArgb(232, 238, 239), Muted = Color.FromArgb(151, 164, 170);
    public static Font Font(float size = 10, bool bold = false) => new("Segoe UI", size, bold ? FontStyle.Bold : FontStyle.Regular);
    public static Label Label(string text, float size = 10, bool bold = false, Color? color = null) => new() { Text = text, AutoSize = true, Font = Font(size, bold), ForeColor = color ?? Text, Margin = new Padding(0, 0, 0, 7) };
    public static Button Button(string text, bool primary = false) => new() { Text = text, AutoSize = true, MinimumSize = new Size(100, 36), Font = Font(9.5f, true), FlatStyle = FlatStyle.Flat, BackColor = primary ? Mint : Field, ForeColor = primary ? Background : Text, Padding = new Padding(8, 2, 8, 2), Margin = new Padding(0, 0, 10, 8), Cursor = Cursors.Hand, UseVisualStyleBackColor = false };
    public static TextBox Input(string value = "", bool password = false) => new() { Text = value, Font = Font(11), BackColor = Field, ForeColor = Text, BorderStyle = BorderStyle.FixedSingle, UseSystemPasswordChar = password, Dock = DockStyle.Top, Margin = new Padding(0, 0, 0, 10) };
    public static GraphicsPath Rounded(Rectangle r, int radius = 14)
    {
        var path = new GraphicsPath(); var d = radius * 2;
        path.AddArc(r.Left, r.Top, d, d, 180, 90); path.AddArc(r.Right - d, r.Top, d, d, 270, 90);
        path.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90); path.AddArc(r.Left, r.Bottom - d, d, d, 90, 90); path.CloseFigure(); return path;
    }
}

class RoundPanel : Panel
{
    public RoundPanel() { DoubleBuffered = true; Padding = new Padding(18); BackColor = Theme.Panel; }
    protected override void OnPaint(PaintEventArgs e)
    {
        e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
        using var path = Theme.Rounded(new Rectangle(0, 0, Width - 1, Height - 1));
        using var fill = new SolidBrush(Theme.Panel); e.Graphics.FillPath(fill, path);
        using var border = new Pen(Color.FromArgb(49, 60, 65)); e.Graphics.DrawPath(border, path);
    }
}

enum Phase { Idle, Checking, Passed, Failed }

sealed class MapView : Control
{
    public Phase[] Servers { get; } = [Phase.Idle, Phase.Idle];
    [Browsable(false), DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
    public Phase Link { get; set; }
    [Browsable(false), DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
    public string Detail { get; set; } = "Проверьте SSH-доступ к обоим VPS";
    readonly System.Windows.Forms.Timer timer = new() { Interval = 40 };
    public MapView() { DoubleBuffered = true; Height = 170; BackColor = Theme.Panel; timer.Tick += (_, _) => { if (Visible && (Link is Phase.Passed or Phase.Checking || Servers.Contains(Phase.Checking))) Invalidate(); }; timer.Start(); }
    protected override void Dispose(bool disposing) { if (disposing) timer.Dispose(); base.Dispose(disposing); }
    static Color ColorFor(Phase phase) => phase switch { Phase.Passed => Theme.Mint, Phase.Checking => Color.Orange, Phase.Failed => Color.Salmon, _ => Color.FromArgb(83, 97, 104) };
    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics; g.SmoothingMode = SmoothingMode.AntiAlias;
        using var label = Theme.Font(9); using var subtitle = Theme.Font(8); using var muted = new SolidBrush(Theme.Muted);
        g.DrawString("СВЯЗЬ СЕРВЕРОВ", label, muted, 18, 13);
        var left = 96; var right = Width - 96; const int y = 75;
        using var line = new Pen(ColorFor(Link), Link == Phase.Passed ? 2.5f : 1.4f);
        if (Link is Phase.Idle or Phase.Failed) line.DashPattern = [4, 6];
        g.DrawLine(line, left + 48, y, right - 48, y);
        if (Link is Phase.Passed or Phase.Checking)
        {
            using var bead = new SolidBrush(ColorFor(Link)); var fraction = (Environment.TickCount64 % 2400) / 2400f;
            for (var i = 0; i < 3; i++) { var x = left + 48 + ((fraction + i / 3f) % 1f) * (right - left - 96); g.FillEllipse(bead, x - 3, y - 3, 6, 6); }
        }
        for (var i = 0; i < 2; i++)
        {
            var x = i == 0 ? left : right; var color = ColorFor(Servers[i]);
            using var pen = new Pen(color, 2); using var dot = new SolidBrush(color);
            for (var row = 0; row < 3; row++) { g.DrawRectangle(pen, x - 23, y - 24 + row * 16, 46, 12); g.FillEllipse(dot, x + 13, y - 20 + row * 16, 4, 4); }
            var text = i == 0 ? "Входной VPS" : "Выходной VPS"; var size = g.MeasureString(text, label); g.DrawString(text, label, muted, x - size.Width / 2, 109);
        }
        var detail = g.MeasureString(Detail, subtitle); g.DrawString(Detail, subtitle, muted, Math.Max(15, (Width - detail.Width) / 2), 143);
    }
}
