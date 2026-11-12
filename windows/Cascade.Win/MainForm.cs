using System.Diagnostics;
using System.Text;
using Cascade.Core;

namespace Cascade.Win;

sealed class MainForm : Form
{
    readonly Workflow flow = new();
    readonly ServerCard[] servers = [new(0), new(1)];
    readonly ConnectionSettingsPanel entryScheme = new("Устройство → входной VPS"), exitScheme = new("Входной → выходной VPS");
    readonly MapView map = new();
    readonly FlowLayoutPanel content = new() { Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoScroll = true, Padding = new Padding(26) };
    readonly TextBox sni = Theme.Input("www.microsoft.com"), deviceName = Theme.Input("Телефон");
    readonly ComboBox devices = new() { DropDownStyle = ComboBoxStyle.DropDownList, Font = Theme.Font(11), BackColor = Theme.Field, ForeColor = Theme.Text, Width = 340 };
    readonly TextBox journal = new() { Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical, Height = 145, BackColor = Theme.Panel, ForeColor = Theme.Muted, BorderStyle = BorderStyle.None, Font = Theme.Font(9) };
    readonly Label activity = Theme.Label("", 10, false, Theme.Mint), result = Theme.Label("Профили появятся после установки или загрузки каскада.", 10, false, Theme.Muted);
    readonly Button prepare = Theme.Button("Проверить и подготовить", true), install = Theme.Button("Установить каскад", true), load = Theme.Button("Получить конфиги"), link = Theme.Button("Проверить связь между VPS"), tls = Theme.Button("Проверить TLS-сайт"), verify = Theme.Button("Сквозной тест"), rollback = Theme.Button("Откатить…"), add = Theme.Button("Создать профиль"), json = Theme.Button("JSON"), bpf = Theme.Button("BPF для iOS / SFM"), qr = Theme.Button("QR-код"), client = Theme.Button("Установить sing-box для Windows");
    bool busy;
    public MainForm()
    {
        Text = "Cascade · Windows 0.4"; ClientSize = new Size(1150, 980); MinimumSize = new Size(1040, 740); StartPosition = FormStartPosition.CenterScreen;
        BackColor = Theme.Background; ForeColor = Theme.Text; Font = Theme.Font(); AutoScaleMode = AutoScaleMode.Dpi;
        try { Icon = Icon.ExtractAssociatedIcon(Environment.ProcessPath!); } catch { }
        var sidebar = new Panel { Dock = DockStyle.Left, Width = 205, BackColor = Color.FromArgb(10, 14, 17), Padding = new Padding(24, 35, 18, 25) };
        var brand = Theme.Label("CASCADE", 21, true, Theme.Mint); brand.Dock = DockStyle.Top;
        var info = Theme.Label("by BadPaand\n\nДва сервера\nПроверка\nУстановка\nПрофили\n\nIPv4 / IPv6 · VLESS · AnyTLS · Naive\n\nWindows · 0.4.0", 10, false, Theme.Muted); info.Dock = DockStyle.Fill; info.Padding = new Padding(0, 55, 0, 0);
        sidebar.Controls.Add(info); sidebar.Controls.Add(brand); Controls.Add(content); Controls.Add(sidebar);
        content.Controls.Add(Theme.Label("Два сервера. Готовое подключение.", 25, true));
        content.Controls.Add(Theme.Label("Настройка собственных VPS, отдельные профили устройств и QR · IPv4 / IPv6, VLESS, AnyTLS, NaiveProxy.", 10, false, Theme.Muted));
        content.Controls.Add(map);
        var cards = new TableLayoutPanel { ColumnCount = 2, Height = 610, BackColor = Theme.Background, Margin = new Padding(0, 15, 0, 12) };
        cards.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50)); cards.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        cards.Controls.Add(servers[0], 0, 0); cards.Controls.Add(servers[1], 1, 0); servers[0].Margin = new Padding(0, 0, 8, 0); servers[1].Margin = new Padding(8, 0, 0, 0); content.Controls.Add(cards);
        content.Controls.Add(Row(link, Theme.Label("До установки: TCP. После установки: сквозной VPN-тест.", 9, false, Theme.Muted)));
        var schemes = new TableLayoutPanel { ColumnCount = 2, Height = 345, BackColor = Theme.Background };
        schemes.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50)); schemes.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50)); schemes.Controls.Add(entryScheme, 0, 0); schemes.Controls.Add(exitScheme, 1, 0); content.Controls.Add(schemes);
        foreach (var panel in new[] { entryScheme, exitScheme }) panel.Edited += () => { if (!busy) { flow.ConfigurationChanged(); UpdateDevices(); RefreshState(); } };
        var advanced = new RoundPanel { Height = 130, Margin = new Padding(0, 10, 0, 10) };
        var adv = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, BackColor = Theme.Panel };
        adv.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 65)); adv.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 35));
        adv.Controls.Add(Theme.Label("Дополнительные настройки · внешний TLS-сайт", 11, true), 0, 0); adv.SetColumnSpan(adv.GetControlFromPosition(0, 0)!, 2);
        adv.Controls.Add(sni, 0, 1); adv.Controls.Add(tls, 1, 1); var note = Theme.Label("Проверка имени, доверенного сертификата и TLS 1.3 с обоих VPS. Владеть доменом не нужно.", 9, false, Theme.Muted); adv.Controls.Add(note, 0, 2); adv.SetColumnSpan(note, 2); advanced.Controls.Add(adv); content.Controls.Add(advanced);
        content.Controls.Add(Theme.Label("Ubuntu 22.04 / 24.04 / 26.04 или Debian 12 / 13; root либо sudo без пароля. Нужен свободный TCP 443.", 9, false, Theme.Muted));
        content.Controls.Add(Row(prepare, load, install)); content.Controls.Add(activity);
        content.Controls.Add(Row(client));
        content.Controls.Add(Theme.Label("Официальный SFW 1.14.4 скачивается с проверкой SHA-256. Установку и разрешения подтверждает Windows.", 9, false, Theme.Muted));
        content.Controls.Add(Theme.Label("Подключение и устройства", 17, true)); content.Controls.Add(result);
        content.Controls.Add(Row(devices, json, bpf, qr)); deviceName.Width = 230; content.Controls.Add(Row(deviceName, add));
        content.Controls.Add(Theme.Label("Новому устройству выдаётся отдельный UUID. Входной сервис кратко перезапускается; старые профили сохраняются.", 9, false, Theme.Muted));
        content.Controls.Add(Row(verify, rollback)); content.Controls.Add(journal);
        content.Controls.Add(Theme.Label("SSH-доступы хранятся в памяти. Нет регистрации, телеметрии и облачного хранения конфигов.", 9, false, Theme.Muted));
        content.SizeChanged += (_, _) => ResizeContent(); Shown += (_, _) => ResizeContent();
        flow.Log = text => { if (InvokeRequired) BeginInvoke(() => Log(text)); else Log(text); };
        for (var i = 0; i < 2; i++)
        {
            var index = i;
            servers[i].Edited += () => { if (busy) return; flow.Invalidate(index); map.Servers[index] = Phase.Idle; map.Link = Phase.Idle; map.Detail = "Доступы изменились — нужна новая проверка"; servers[index].Status.Text = "SSH ещё не проверен"; UpdateDevices(); RefreshState(); };
            servers[i].Check.Click += async (_, _) => await Perform(() => Check(index));
        }
        sni.TextChanged += (_, _) => { if (busy) return; flow.ConfigurationChanged(); map.Link = Phase.Idle; map.Detail = "TLS-имя изменилось — подготовьте или загрузите каскад заново"; UpdateDevices(); RefreshState(); };
        link.Click += async (_, _) => await Perform(async () => { SyncInputs(); map.Link = Phase.Checking; map.Detail = "Проверяем TCP с входного VPS…"; try { map.Detail = await flow.CheckLink(); map.Link = Phase.Passed; } catch { map.Link = Phase.Failed; throw; } });
        tls.Click += async (_, _) => await Perform(async () => { SyncInputs(); await flow.CheckTls(); MessageBox.Show(this, "TLS 1.3 и сертификат подтверждены с обоих VPS.", "TLS-сайт"); });
        prepare.Click += async (_, _) => await Perform(async () => { SyncInputs(); for (var i = 0; i < 2; i++) if (map.Servers[i] != Phase.Passed) await Check(i); await flow.Prepare(false); Log("Все конфиги проверены. Можно установить каскад."); });
        load.Click += async (_, _) => await Perform(async () => { SyncInputs(); await flow.Prepare(true); entryScheme.LoadSettings(flow.EntrySettings); exitScheme.LoadSettings(flow.ExitSettings); sni.Text = flow.Sni; UpdateDevices(); await Verify(); });
        install.Click += async (_, _) => await Perform(async () => { SyncInputs(); await flow.Install(); UpdateDevices(); await Verify(); });
        verify.Click += async (_, _) => await Perform(Verify);
        rollback.Click += async (_, _) => { if (MessageBox.Show(this, "Восстановить предыдущую настройку обоих VPS? Выданные профили могут перестать работать.", "Откат", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) == DialogResult.Yes) await Perform(async () => { await flow.Rollback(); map.Link = Phase.Idle; map.Detail = "Настройка отменена"; UpdateDevices(); }); };
        add.Click += async (_, _) => await Perform(async () => { var id = await flow.AddDevice(deviceName.Text); UpdateDevices(id); deviceName.Text = $"Устройство {flow.Devices.Count + 1}"; });
        json.Click += async (_, _) => await Perform(() => Save(false)); bpf.Click += async (_, _) => await Perform(() => Save(true));
        qr.Click += (_, _) => { if (devices.SelectedItem is DeviceProfile profile) new QrForm(profile).ShowDialog(this); };
        client.Click += async (_, _) => await Perform(async () =>
        {
            Log("Загружаем официальный установщик SFW; проверяем SHA-256…"); var file = await CoreRuntime.DownloadClient();
            if (MessageBox.Show(this, "SHA-256 официального SFW совпал. Открыть установщик sing-box?", "Установка sing-box", MessageBoxButtons.YesNo, MessageBoxIcon.Information) == DialogResult.Yes)
                Process.Start(new ProcessStartInfo(file) { UseShellExecute = true });
        });
        FormClosing += (_, e) => { if (busy) { e.Cancel = true; MessageBox.Show(this, "Дождитесь завершения операции, чтобы подтвердить результат и возможный откат.", "Операция выполняется"); } };
        RefreshState();
    }
    static FlowLayoutPanel Row(params Control[] controls)
    {
        var row = new FlowLayoutPanel { AutoSize = true, WrapContents = true, Margin = new Padding(0, 5, 0, 5), BackColor = Theme.Background };
        foreach (var c in controls) row.Controls.Add(c); return row;
    }
    void ResizeContent() { foreach (Control c in content.Controls) c.Width = Math.Max(650, content.ClientSize.Width - 65); }
    void SyncInputs() { for (var i = 0; i < 2; i++) flow.SetServer(i, servers[i].Read()); flow.SetSni(sni.Text.Trim()); flow.SetSettings(entryScheme.Read(), exitScheme.Read()); }
    async Task Check(int i)
    {
        flow.SetServer(i, servers[i].Read()); map.Servers[i] = Phase.Checking; servers[i].Status.Text = "Проверяем SSH…";
        try
        {
            await flow.CheckServer(i, pin => MessageBox.Show(this, $"Сервер {i + 1}\n{pin.Algorithm}\n{pin.Fingerprint}\n\nСверьте ключ с консолью хостинга. Доверять и проверить?", "SSH-отпечаток", MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes);
            map.Servers[i] = Phase.Passed; servers[i].Status.Text = "SSH подтверждён · " + DateTime.Now.ToString("HH:mm");
        }
        catch { map.Servers[i] = Phase.Failed; servers[i].Status.Text = "SSH не подтверждён"; throw; }
    }
    async Task Verify()
    {
        map.Link = Phase.Checking;
        try { var ip = await flow.Verify(); map.Link = Phase.Passed; map.Detail = "VPN-каскад проверен · " + DateTime.Now.ToString("HH:mm"); result.Text = "Сквозной тест пройден. Выходной IP: " + ip; }
        catch { map.Link = Phase.Failed; map.Detail = "Сквозной VPN-тест не подтверждён"; result.Text = "Сервисы установлены. Профили доступны; подключение требует проверки."; throw; }
    }
    void UpdateDevices(string? id = null)
    {
        var previous = id ?? (devices.SelectedItem as DeviceProfile)?.Id; devices.DataSource = null; devices.DataSource = flow.Devices.ToList();
        if (previous is not null) for (var i = 0; i < devices.Items.Count; i++) if (((DeviceProfile)devices.Items[i]!).Id == previous) devices.SelectedIndex = i;
    }
    async Task Save(bool portable)
    {
        if (devices.SelectedItem is not DeviceProfile profile) return;
        using var dialog = new SaveFileDialog { Title = "Сохранить профиль — файл содержит ключ доступа", FileName = "Cascade-" + string.Concat(profile.Name.Select(c => Path.GetInvalidFileNameChars().Contains(c) ? '-' : c)) + (portable ? ".bpf" : ".json"), Filter = portable ? "sing-box Profile|*.bpf" : "JSON sing-box|*.json", InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments) };
        if (dialog.ShowDialog(this) != DialogResult.OK) return;
        await Files.AtomicWrite(dialog.FileName, portable ? profile.Bpf() : Encoding.UTF8.GetBytes(profile.Json)); Log("Профиль сохранён. Храните файл как пароль.");
    }
    async Task Perform(Func<Task> action)
    {
        if (busy) return; busy = true; activity.Text = "Выполняется проверка или настройка…"; RefreshState();
        try { await action(); }
        catch (Exception e) { var message = flow.SafeError(e); Log(message); MessageBox.Show(this, message, "Cascade", MessageBoxButtons.OK, e is OperationCanceledException ? MessageBoxIcon.Information : MessageBoxIcon.Warning); }
        finally { busy = false; activity.Text = ""; RefreshState(); map.Invalidate(); }
    }
    void Log(string text) { journal.AppendText($"{DateTime.Now:HH:mm:ss}  {text}{Environment.NewLine}"); activity.Text = text; }
    void RefreshState()
    {
        entryScheme.Enabled = exitScheme.Enabled = !busy; foreach (var card in servers) card.Enabled = !busy; sni.Enabled = !busy; deviceName.Enabled = !busy; devices.Enabled = !busy;
        prepare.Enabled = !busy; prepare.Text = flow.BothChecked ? "Подготовить установку" : "Проверить и подготовить";
        link.Enabled = tls.Enabled = load.Enabled = !busy && flow.BothChecked;
        install.Enabled = !busy && flow.Prepared && !flow.Installed; verify.Enabled = add.Enabled = !busy && flow.Installed;
        json.Enabled = bpf.Enabled = qr.Enabled = !busy && devices.Items.Count > 0; rollback.Enabled = !busy && flow.CanRollback; client.Enabled = !busy;
        map.Invalidate();
    }
}

sealed class QrForm : Form
{
    readonly DeviceProfile profile;
    readonly PictureBox picture = new() { Dock = DockStyle.Fill, SizeMode = PictureBoxSizeMode.Zoom, BackColor = Color.White };
    readonly ComboBox format = new() { DropDownStyle = ComboBoxStyle.DropDownList, Dock = DockStyle.Top };
    public QrForm(DeviceProfile profile)
    {
        this.profile = profile; Text = "QR · " + profile.Name; ClientSize = new Size(490, 570); BackColor = Theme.Background; ForeColor = Theme.Text; Padding = new Padding(20); StartPosition = FormStartPosition.CenterParent;
        format.Items.AddRange(["Ссылка", "Полный JSON sing-box"]); format.SelectedIndex = 0;
        var footer = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 96, FlowDirection = FlowDirection.TopDown };
        footer.Controls.Add(Theme.Label("QR содержит ключ доступа. Для официального SFI/SFM используйте BPF/JSON-файл.", 8.5f, false, Theme.Muted));
        var save = Theme.Button("Сохранить PNG"); var copy = Theme.Button("Скопировать содержимое"); var row = new FlowLayoutPanel { AutoSize = true }; row.Controls.Add(save); row.Controls.Add(copy); footer.Controls.Add(row);
        Controls.Add(picture); Controls.Add(footer); Controls.Add(format);
        format.SelectedIndexChanged += (_, _) => Draw(); Shown += (_, _) => Draw();
        save.Click += async (_, _) => { try { using var dialog = new SaveFileDialog { FileName = "Cascade-QR.png", Filter = "PNG|*.png" }; if (dialog.ShowDialog(this) == DialogResult.OK) await Files.AtomicWrite(dialog.FileName, profile.Qr(format.SelectedIndex == 1)); } catch (Exception e) { MessageBox.Show(this, e.Message); } };
        copy.Click += (_, _) => Clipboard.SetText(format.SelectedIndex == 0 ? profile.Link : System.Text.Json.Nodes.JsonNode.Parse(profile.Json)!.ToJsonString());
    }
    void Draw() { try { using var stream = new MemoryStream(profile.Qr(format.SelectedIndex == 1)); using var image = Image.FromStream(stream); var old = picture.Image; picture.Image = new Bitmap(image); old?.Dispose(); } catch (Exception e) { MessageBox.Show(this, "QR не создан: " + e.Message); } }
}
