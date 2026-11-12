using Cascade.Win;
using Cascade.Distribution;

internal static class Program
{
    [STAThread]
    static void Main(string[] args)
    {
        Application.SetHighDpiMode(HighDpiMode.PerMonitorV2);
        Application.EnableVisualStyles(); Application.SetCompatibleTextRenderingDefault(false);
        if (args.Contains("--uninstall", StringComparer.OrdinalIgnoreCase)) { Installation.Uninstall(); return; }
        Application.Run(new MainForm());
    }
}
