using System.Diagnostics;
using System.Reflection;
using Cascade.Distribution;

internal static class Program
{
    [STAThread]
    static void Main()
    {
        Application.SetHighDpiMode(HighDpiMode.PerMonitorV2);
        Application.EnableVisualStyles(); Application.SetCompatibleTextRenderingDefault(false);
        Application.Run(new SetupForm());
    }
}

sealed class SetupForm : Form
{
    readonly Button install = new() { Text = "Установить Cascade", Width = 185, Height = 42, FlatStyle = FlatStyle.Flat, BackColor = Color.FromArgb(130, 240, 198), ForeColor = Color.FromArgb(15, 20, 24) };
    readonly CheckBox desktop = new() { Text = "Создать ярлык на рабочем столе", Checked = true, AutoSize = true, ForeColor = Color.Gainsboro };
    readonly Label status = new() { AutoSize = false, Height = 65, ForeColor = Color.Silver };
    bool busy, complete;
    public SetupForm()
    {
        Text = "Установка Cascade · 0.4.0"; ClientSize = new Size(620, 390); FormBorderStyle = FormBorderStyle.FixedDialog; MaximizeBox = false; StartPosition = FormStartPosition.CenterScreen;
        BackColor = Color.FromArgb(15, 20, 24); ForeColor = Color.Gainsboro; Font = new Font("Segoe UI", 10); Padding = new Padding(30);
        try { Icon = Icon.ExtractAssociatedIcon(Environment.ProcessPath!); } catch { }
        var layout = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown, WrapContents = false };
        layout.Controls.Add(new Label { Text = "CASCADE", Font = new Font("Segoe UI", 27, FontStyle.Bold), ForeColor = Color.FromArgb(130, 240, 198), AutoSize = true, Margin = new Padding(0, 0, 0, 15) });
        layout.Controls.Add(new Label { Text = "Два VPS. Проверка. Готовые профили подключения.", AutoSize = true, Margin = new Padding(0, 0, 0, 15) });
        layout.Controls.Add(new Label { Text = "Приложение установится только для текущего пользователя:\n" + Installation.Target + "\n\n.NET включён в установщик; отдельно устанавливать его не нужно.", Width = 545, Height = 100, ForeColor = Color.Silver });
        layout.Controls.Add(desktop); layout.Controls.Add(status); layout.Controls.Add(install); Controls.Add(layout);
        install.Click += async (_, _) =>
        {
            if (complete) { Process.Start(new ProcessStartInfo(Path.Combine(Installation.Target, "Cascade.exe")) { UseShellExecute = true }); Close(); return; }
            busy = true; install.Enabled = desktop.Enabled = false; status.Text = "Распаковываем приложение и создаём ярлыки…";
            try
            {
                using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("Cascade.Payload.zip")!;
                using var hashReader = new StreamReader(Assembly.GetExecutingAssembly().GetManifestResourceStream("Cascade.Payload.sha256")!);
                var hash = (await hashReader.ReadToEndAsync()).Trim(); var shortcut = desktop.Checked;
                await Sta(() => Installation.Install(stream, hash, shortcut));
                complete = true; status.Text = "Cascade установлен. Доступен ярлык в меню «Пуск» и удаление в настройках Windows."; install.Text = "Запустить Cascade";
            }
            catch (Exception e) { status.Text = "Установка не завершена."; MessageBox.Show(this, e.Message, "Установка Cascade", MessageBoxButtons.OK, MessageBoxIcon.Warning); }
            finally { busy = false; install.Enabled = desktop.Enabled = true; }
        };
        FormClosing += (_, e) => { if (busy) e.Cancel = true; };
    }
    static Task Sta(Action action)
    {
        var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var thread = new Thread(() => { try { action(); completion.SetResult(); } catch (Exception e) { completion.SetException(e); } }) { IsBackground = true };
        thread.SetApartmentState(ApartmentState.STA); thread.Start(); return completion.Task;
    }
}
