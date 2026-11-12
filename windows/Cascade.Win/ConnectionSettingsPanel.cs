using Cascade.Core;

namespace Cascade.Win;

sealed class ConnectionSettingsPanel : RoundPanel
{
    readonly ComboBox scheme = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 330, BackColor = Theme.Field, ForeColor = Theme.Text, Font = Theme.Font(10) };
    readonly TextBox domain = Theme.Input(), path = Theme.Input("/cascade"), service = Theme.Input("cascade");
    readonly Button cert = Theme.Button("Сертификат PEM…"), key = Theme.Button("Ключ PEM…");
    readonly Label note = Theme.Label("REALITY работает без своего домена. Внешний TLS-сайт задаётся ниже.", 9, false, Theme.Muted);
    string certificate = "", privateKey = "";
    public event Action? Edited;
    public ConnectionSettingsPanel(string title)
    {
        Height = 330; Dock = DockStyle.Fill;
        var layout = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoScroll = true, BackColor = Theme.Panel };
        layout.Controls.Add(Theme.Label(title, 11, true));
        scheme.Items.AddRange(Enum.GetValues<ConnectionScheme>().Select(s => (object)new ConnectionSettings { Scheme = s }).ToArray()); scheme.SelectedIndex = 0;
        layout.Controls.Add(scheme); domain.PlaceholderText = "Свой домен: vpn.example.com"; domain.Width = path.Width = service.Width = 330;
        layout.Controls.Add(domain); layout.Controls.Add(cert); layout.Controls.Add(key); layout.Controls.Add(path); layout.Controls.Add(service); layout.Controls.Add(note); Controls.Add(layout);
        scheme.SelectedIndexChanged += (_, _) => { UpdateFields(); Edited?.Invoke(); };
        foreach (var t in new[] { domain, path, service }) t.TextChanged += (_, _) => Edited?.Invoke();
        cert.Click += (_, _) => Pick(false); key.Click += (_, _) => Pick(true); UpdateFields();
    }
    void Pick(bool isKey)
    {
        using var dialog = new OpenFileDialog { Title = isKey ? "PEM-ключ без пароля" : "PEM-сертификат с полной цепочкой", Filter = "PEM-файлы|*.pem;*.crt;*.key|Все файлы|*.*" };
        if (dialog.ShowDialog(this) != DialogResult.OK) return;
        try {
            if (new FileInfo(dialog.FileName).Length >= 100000) throw new IOException("PEM-файл должен быть меньше 100 КБ.");
            var text = File.ReadAllText(dialog.FileName); if (isKey) { privateKey = text; key.Text = "Ключ выбран"; } else { certificate = text; cert.Text = "Сертификат выбран"; } Edited?.Invoke();
        } catch (Exception e) { MessageBox.Show(this, e.Message); }
    }
    void UpdateFields()
    {
        var s = Read(); domain.Visible = cert.Visible = key.Visible = !s.Reality;
        path.Visible = s.TransportType is "ws" or "http" or "httpupgrade"; service.Visible = s.TransportType == "grpc";
        note.Text = s.Reality ? "Без своего домена. TLS-сайт REALITY задаётся ниже." : "Нужны свой домен и доверенный PEM-сертификат с ключом. Проверим имя, срок и соответствие ключа до установки.";
    }
    public ConnectionSettings Read() => new() { Scheme = ((ConnectionSettings?)scheme.SelectedItem)?.Scheme ?? ConnectionScheme.RealityVision, ServerName = domain.Text.Trim(), Path = path.Text, ServiceName = service.Text.Trim(), Certificate = certificate, Key = privateKey };
    public void LoadSettings(ConnectionSettings s) { scheme.SelectedIndex = (int)s.Scheme; domain.Text = s.ServerName; path.Text = s.Path; service.Text = s.ServiceName; certificate = s.Certificate; privateKey = s.Key; cert.Text = certificate.Length > 0 ? "Сертификат выбран" : "Сертификат PEM…"; key.Text = privateKey.Length > 0 ? "Ключ выбран" : "Ключ PEM…"; UpdateFields(); }
}
