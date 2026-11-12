using Cascade.Core;

namespace Cascade.Win;

sealed class ServerCard : RoundPanel
{
    readonly TextBox v4 = Theme.Input(), v6 = Theme.Input(), host = Theme.Input(), user = Theme.Input("root"), port = Theme.Input("22"), secret = Theme.Input("", true), key = Theme.Input();
    readonly ComboBox auth = new() { DropDownStyle = ComboBoxStyle.DropDownList, Dock = DockStyle.Top, BackColor = Theme.Field, ForeColor = Theme.Text, Font = Theme.Font(10) };
    readonly FlowLayoutPanel keyRow = new() { Dock = DockStyle.Top, AutoSize = true, WrapContents = false };
    readonly ComboBox addressMode = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 300, BackColor = Theme.Field, ForeColor = Theme.Text };
    public readonly Button Check = Theme.Button("Проверить подключение");
    public readonly Label Status = Theme.Label("SSH ещё не проверен", 9, false, Theme.Muted);
    public event Action? Edited;
    public ServerCard(int index)
    {
        Height = 600; Dock = DockStyle.Fill;
        var layout = new TableLayoutPanel { ColumnCount = 1, Dock = DockStyle.Fill, Padding = new Padding(0), BackColor = Theme.Panel, RowCount = 0 };
        void Add(Control c) { layout.RowCount++; layout.RowStyles.Add(new RowStyle(SizeType.AutoSize)); c.Margin = new Padding(0, 0, 0, 8); layout.Controls.Add(c, 0, layout.RowCount - 1); }
        Add(Theme.Label($"0{index + 1}   " + (index == 0 ? "Входной сервер" : "Выходной сервер"), 15, true, Theme.Mint));
        Add(Theme.Label("SSH · IPv4 или IPv6", 9, false, Theme.Muted)); host.PlaceholderText = "203.0.113.10 / 2001:db8::1"; Add(host);
        addressMode.Items.AddRange(["Авто · IPv4 / IPv6", "Только IPv4", "Только IPv6"]); addressMode.SelectedIndex = 0; Add(addressMode);
        v4.PlaceholderText = "Дополнительный IPv4 этого VPS"; Add(v4); v6.PlaceholderText = "Дополнительный IPv6 этого VPS"; Add(v6);
        addressMode.SelectedIndexChanged += (_, _) => Edited?.Invoke();
        var pair = new TableLayoutPanel { ColumnCount = 2, Dock = DockStyle.Top, Height = 65, BackColor = Theme.Panel };
        pair.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 74)); pair.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 26));
        pair.Controls.Add(Theme.Label("Логин", 9, false, Theme.Muted), 0, 0); pair.Controls.Add(Theme.Label("SSH-порт", 9, false, Theme.Muted), 1, 0);
        pair.Controls.Add(user, 0, 1); pair.Controls.Add(port, 1, 1); Add(pair);
        auth.Items.AddRange(["Пароль SSH", "Приватный SSH-ключ"]); auth.SelectedIndex = 0; Add(auth);
        key.Width = 200; key.ReadOnly = true; var pick = Theme.Button("Ключ…"); pick.MinimumSize = new Size(55, 28); pick.Click += (_, _) => { using var dialog = new OpenFileDialog { Title = "Приватный SSH-ключ", Filter = "Все файлы|*.*" }; if (dialog.ShowDialog() == DialogResult.OK) key.Text = dialog.FileName; };
        keyRow.Controls.Add(key); keyRow.Controls.Add(pick); keyRow.Visible = false; Add(keyRow);
        secret.PlaceholderText = "Пароль SSH / пароль ключа"; Add(secret); Check.Dock = DockStyle.Top; Add(Check); Add(Status);
        Controls.Add(layout);
        foreach (var field in new[] { host, user, port, secret, key, v4, v6 }) field.TextChanged += (_, _) => Edited?.Invoke();
        auth.SelectedIndexChanged += (_, _) => { keyRow.Visible = auth.SelectedIndex == 1; secret.Clear(); Edited?.Invoke(); };
    }
    public Server Read() => new(host.Text.Trim(), int.TryParse(port.Text, out var n) ? n : 0, user.Text.Trim(), secret.Text, auth.SelectedIndex == 1 ? key.Text : "", v4.Text.Trim(), v6.Text.Trim(), (AddressMode)addressMode.SelectedIndex);
}
