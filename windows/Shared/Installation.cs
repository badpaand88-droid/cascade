using System.Diagnostics;
using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Win32;

namespace Cascade.Distribution;

internal sealed record InstallManifest(string Product, string Version, string[] Files);

internal static class Installation
{
    const string Product = "BadPaand.Cascade";
    const string RegistryPath = @"Software\Microsoft\Windows\CurrentVersion\Uninstall\BadPaand.Cascade";
    public static string Target => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "Cascade");
    static string ShortcutDirectory => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Programs), "Cascade");
    public static void Install(Stream payload, string expectedHash, bool desktop)
    {
        var parent = Path.GetDirectoryName(Target)!; Directory.CreateDirectory(parent);
        var staging = Path.Combine(parent, "Cascade.install-" + Guid.NewGuid().ToString("N"));
        var zipPath = staging + ".zip"; var backup = Target + ".previous-" + Guid.NewGuid().ToString("N");
        bool moved = false;
        try
        {
            using (var file = File.Create(zipPath)) payload.CopyTo(file);
            using (var file = File.OpenRead(zipPath))
                if (!Convert.ToHexString(SHA256.HashData(file)).Equals(expectedHash.Trim(), StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("Контрольная сумма встроенного пакета не совпала.");
            Directory.CreateDirectory(staging); var owned = new List<string>();
            using (var zip = ZipFile.OpenRead(zipPath))
            {
                foreach (var entry in zip.Entries)
                {
                    var relative = entry.FullName.Replace('/', Path.DirectorySeparatorChar);
                    var path = Path.GetFullPath(Path.Combine(staging, relative));
                    if (!path.StartsWith(staging + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("Некорректный путь в пакете.");
                    if (entry.Name.Length == 0) { Directory.CreateDirectory(path); continue; }
                    Directory.CreateDirectory(Path.GetDirectoryName(path)!); entry.ExtractToFile(path); owned.Add(relative);
                }
            }
            if (!File.Exists(Path.Combine(staging, "Cascade.exe"))) throw new InvalidDataException("Пакет не содержит Cascade.exe.");
            owned.Add("cascade.install.json");
            File.WriteAllText(Path.Combine(staging, "cascade.install.json"), JsonSerializer.Serialize(new InstallManifest(Product, "0.4.0", owned.ToArray())));
            if (Directory.Exists(Target))
            {
                var manifestFile = Path.Combine(Target, "cascade.install.json");
                if (!File.Exists(manifestFile) || JsonSerializer.Deserialize<InstallManifest>(File.ReadAllText(manifestFile))?.Product != Product)
                    throw new IOException("Папка установки уже занята неизвестными файлами. Переместите её и повторите установку.");
                var running = Process.GetProcessesByName("Cascade").Any(p => { try { return string.Equals(p.MainModule?.FileName, Path.Combine(Target, "Cascade.exe"), StringComparison.OrdinalIgnoreCase); } catch { return false; } });
                if (running) throw new IOException("Закройте установленный Cascade и повторите установку. Введённые SSH-пароли хранятся только в его памяти.");
                // Preserve user-added files that are not owned by the prior installation.
                var old = JsonSerializer.Deserialize<InstallManifest>(File.ReadAllText(manifestFile))!;
                foreach (var file in Directory.EnumerateFiles(Target, "*", SearchOption.AllDirectories))
                {
                    var relative = Path.GetRelativePath(Target, file);
                    if (old.Files.Contains(relative, StringComparer.OrdinalIgnoreCase)) continue;
                    var destination = Path.Combine(staging, relative); Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
                    if (!File.Exists(destination)) File.Copy(file, destination);
                }
                Directory.Move(Target, backup); moved = true;
            }
            Directory.Move(staging, Target);
            Directory.CreateDirectory(ShortcutDirectory); MakeShortcut(Path.Combine(ShortcutDirectory, "Cascade.lnk"), Path.Combine(Target, "Cascade.exe"));
            if (desktop) MakeShortcut(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), "Cascade.lnk"), Path.Combine(Target, "Cascade.exe"));
            using var key = Registry.CurrentUser.CreateSubKey(RegistryPath);
            key.SetValue("DisplayName", "Cascade"); key.SetValue("DisplayVersion", "0.4.0"); key.SetValue("Publisher", "BadPaand");
            key.SetValue("InstallLocation", Target); key.SetValue("DisplayIcon", Path.Combine(Target, "Cascade.exe"));
            key.SetValue("UninstallString", "\"" + Path.Combine(Target, "Cascade.exe") + "\" --uninstall");
            key.SetValue("NoModify", 1); key.SetValue("NoRepair", 1);
            if (moved) Directory.Delete(backup, true);
        }
        catch
        {
            if (moved && Directory.Exists(backup)) { if (Directory.Exists(Target)) Directory.Delete(Target, true); Directory.Move(backup, Target); }
            throw;
        }
        finally { if (Directory.Exists(staging)) Directory.Delete(staging, true); if (File.Exists(zipPath)) File.Delete(zipPath); }
    }
    static void MakeShortcut(string path, string target)
    {
        var type = Type.GetTypeFromProgID("WScript.Shell") ?? throw new IOException("Windows Script Host недоступен для создания ярлыка.");
        dynamic shell = Activator.CreateInstance(type)!; dynamic shortcut = shell.CreateShortcut(path);
        try { shortcut.TargetPath = target; shortcut.WorkingDirectory = Path.GetDirectoryName(target); shortcut.IconLocation = target + ",0"; shortcut.Description = "Cascade · настройка двух VPS"; shortcut.Save(); }
        finally { Marshal.FinalReleaseComObject(shortcut); Marshal.FinalReleaseComObject(shell); }
    }
    public static void Uninstall()
    {
        try
        {
            var executable = Path.GetFullPath(Environment.ProcessPath!);
            if (!executable.Equals(Path.Combine(Target, "Cascade.exe"), StringComparison.OrdinalIgnoreCase)) throw new IOException("Удаление доступно только из установленной версии Cascade.");
            var file = Path.Combine(Target, "cascade.install.json"); var manifest = JsonSerializer.Deserialize<InstallManifest>(File.ReadAllText(file));
            if (manifest?.Product != Product) throw new IOException("Не найдена корректная запись установки.");
            var otherInstance = Process.GetProcessesByName("Cascade").Any(p => { try { return p.Id != Environment.ProcessId && string.Equals(p.MainModule?.FileName, executable, StringComparison.OrdinalIgnoreCase); } catch { return false; } });
            if (otherInstance) throw new IOException("Сначала закройте открытый Cascade и повторите удаление. Введённые SSH-доступы хранятся только в его памяти.");
            if (MessageBox.Show("Удалить Cascade? Экспортированные профили и настройки серверов сохранятся.", "Удаление Cascade", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
            Registry.CurrentUser.DeleteSubKeyTree(RegistryPath, false);
            foreach (var shortcut in new[] { Path.Combine(ShortcutDirectory, "Cascade.lnk"), Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), "Cascade.lnk") }) if (File.Exists(shortcut)) File.Delete(shortcut);
            if (Directory.Exists(ShortcutDirectory) && !Directory.EnumerateFileSystemEntries(ShortcutDirectory).Any()) Directory.Delete(ShortcutDirectory);
            var paths = manifest.Files.Select(relative => Path.GetFullPath(Path.Combine(Target, relative))).ToArray();
            if (paths.Any(p => !p.StartsWith(Target + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))) throw new IOException("Недопустимые пути в записи установки.");
            static string Quote(string p) => "\"" + p.Replace("%", "%%") + "\"";
            var script = new StringBuilder("@echo off\r\nchcp 65001 >nul\r\nfor /L %%i in (1,1,10) do (\r\n timeout /t 1 /nobreak >nul\r\n");
            foreach (var p in paths) script.Append(" del /f /q ").Append(Quote(p)).Append(" >nul 2>&1\r\n");
            script.Append(")\r\n");
            foreach (var dir in paths.Select(p => Path.GetDirectoryName(p)!).Distinct().OrderByDescending(p => p.Length)) script.Append("rd ").Append(Quote(dir)).Append(" >nul 2>&1\r\n");
            script.Append("del \"%~f0\"\r\n");
            var cmd = Path.Combine(Path.GetTempPath(), "Cascade-uninstall-" + Guid.NewGuid().ToString("N") + ".cmd"); File.WriteAllText(cmd, script.ToString(), new UTF8Encoding(false));
            var info = new ProcessStartInfo("cmd.exe") { UseShellExecute = false, CreateNoWindow = true }; info.ArgumentList.Add("/c"); info.ArgumentList.Add(cmd); Process.Start(info);
        }
        catch (Exception e) { MessageBox.Show(e.Message, "Удаление Cascade", MessageBoxButtons.OK, MessageBoxIcon.Warning); }
    }
}
