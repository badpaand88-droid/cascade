using System.Diagnostics;
using System.IO.Compression;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace Cascade.Core;

public static class Files
{
    public static string Root => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "BadPaand", "Cascade");
    public static string TempDirectory()
    {
        var path = Path.Combine(Root, "temporary", Guid.NewGuid().ToString("N")); Directory.CreateDirectory(path);
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        return path;
    }
    public static async Task AtomicWrite(string path, byte[] data)
    {
        var temp = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            await using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(temp, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                await stream.WriteAsync(data);
            }
            File.Move(temp, path, true);
        }
        finally { if (File.Exists(temp)) File.Delete(temp); }
    }
}

public static class NativeProcess
{
    public static async Task<Result> Run(string file, IEnumerable<string> args, int timeout = 30)
    {
        var info = new ProcessStartInfo(file) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var arg in args) info.ArgumentList.Add(arg);
        using var process = Process.Start(info) ?? throw new IOException("Не удалось запустить проверку sing-box.");
        var output = process.StandardOutput.ReadToEndAsync(); var error = process.StandardError.ReadToEndAsync();
        using var timer = new CancellationTokenSource(TimeSpan.FromSeconds(timeout));
        try { await process.WaitForExitAsync(timer.Token); }
        catch (OperationCanceledException) { if (!process.HasExited) process.Kill(true); throw new TimeoutException("Проверка превысила время ожидания."); }
        return new(process.ExitCode, await output, await error);
    }
}

public sealed class CoreRuntime
{
    public string? Binary { get; private set; }
    readonly bool customBinary;
    public CoreRuntime(string? testBinary = null) { Binary = testBinary; customBinary = testBinary is not null; }
    static readonly Dictionary<string, string> CoreHashes = new()
    {
        ["amd64"] = "99185d75d314a07dbba4a130c8ad986cbeb629a07927975636b341ca61f991df",
        ["arm64"] = "8cd0a4d0cd8cd480be5731ac31f17038969a42d12add9feb6e031fd43d85bbae"
    };
    static readonly Dictionary<string, string> ClientHashes = new()
    {
        ["x64"] = "9720433083bb00cacbc439cad79b89d337814fe8af31a8ff6f8dc5b807782446",
        ["arm64"] = "65f2813f83616c9e43625873fcc80fdf522aca66d560600d6edb721366efb781"
    };
    public async Task Ensure()
    {
        if (customBinary) return;
        var arch = RuntimeInformation.ProcessArchitecture == Architecture.Arm64 ? "arm64" : "amd64";
        var name = $"sing-box-{Profiles.Version}-windows-{arch}";
        var archive = await Download(name + ".zip", CoreHashes[arch]);
        var directory = Path.Combine(Files.Root, "core", name);
        if (Directory.Exists(directory)) Directory.Delete(directory, true);
        Directory.CreateDirectory(directory); ZipFile.ExtractToDirectory(archive, directory);
        Binary = Path.Combine(directory, name, "sing-box.exe");
        if (!File.Exists(Binary)) throw new InvalidDataException("В официальном архиве не найден sing-box.exe.");
    }
    public static Task<string> DownloadClient()
    {
        var arch = RuntimeInformation.ProcessArchitecture == Architecture.Arm64 ? "arm64" : "x64";
        return Download($"SFW-{Profiles.Version}-{arch}.exe", ClientHashes[arch]);
    }
    public static async Task<string> Download(string name, string digest)
    {
        var dir = Path.Combine(Files.Root, "downloads"); Directory.CreateDirectory(dir);
        var destination = Path.Combine(dir, name);
        if (File.Exists(destination) && await CheckHash(destination, digest)) return destination;
        var temporary = destination + "." + Guid.NewGuid().ToString("N") + ".download";
        try
        {
            using var client = new HttpClient { Timeout = TimeSpan.FromMinutes(6) };
            using var response = await client.GetAsync($"https://github.com/SagerNet/sing-box/releases/download/v{Profiles.Version}/{name}", HttpCompletionOption.ResponseHeadersRead);
            response.EnsureSuccessStatusCode();
            await using (var stream = File.Create(temporary)) await response.Content.CopyToAsync(stream);
            if (!await CheckHash(temporary, digest)) throw new InvalidDataException("SHA-256 загрузки не совпал. Запуск запрещён.");
            File.Move(temporary, destination, true); return destination;
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }
    static async Task<bool> CheckHash(string path, string expected)
    {
        await using var stream = File.OpenRead(path);
        return Convert.ToHexString(await SHA256.HashDataAsync(stream)).Equals(expected, StringComparison.OrdinalIgnoreCase);
    }
    public async Task Validate(string config)
    {
        if (Binary is null) throw new InvalidOperationException("Ядро sing-box ещё не подготовлено.");
        var dir = Files.TempDirectory();
        try
        {
            var path = Path.Combine(dir, "config.json"); await Files.AtomicWrite(path, Encoding.UTF8.GetBytes(config));
            var result = await NativeProcess.Run(Binary, ["check", "-c", path]);
            if (result.Code != 0) throw new InvalidDataException("sing-box отклонил конфиг: " + result.Error[..Math.Min(result.Error.Length, 500)]);
        }
        finally { Directory.Delete(dir, true); }
    }
    public Task<string> Probe(string host, Credentials credentials, string sni) => ProbeClient(Profiles.Client(host, credentials, sni));
    public async Task<string> ProbeClient(string clientConfig)
    {
        if (Binary is null) throw new InvalidOperationException("Ядро sing-box ещё не подготовлено.");
        var dir = Files.TempDirectory(); Process? process = null;
        try
        {
            var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port; listener.Stop();
            var config = System.Text.Json.Nodes.JsonNode.Parse(clientConfig)!;
            config["inbounds"] = new System.Text.Json.Nodes.JsonArray(new System.Text.Json.Nodes.JsonObject { ["type"] = "mixed", ["listen"] = "127.0.0.1", ["listen_port"] = port });
            config["route"] = new System.Text.Json.Nodes.JsonObject { ["final"] = "cascade" };
            var path = Path.Combine(dir, "probe.json"); await Files.AtomicWrite(path, Encoding.UTF8.GetBytes(config.ToJsonString()));
            var info = new ProcessStartInfo(Binary) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
            foreach (var a in new[] { "run", "-c", path }) info.ArgumentList.Add(a);
            process = Process.Start(info)!;
            var output = process.StandardOutput.ReadToEndAsync(); var error = process.StandardError.ReadToEndAsync();
            await Task.Delay(600);
            if (process.HasExited) throw new IOException("Локальная проверка не запустилась.");
            using var handler = new SocketsHttpHandler { Proxy = new WebProxy($"socks5://127.0.0.1:{port}"), UseProxy = true, ConnectTimeout = TimeSpan.FromSeconds(12) };
            using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(25) };
            var ip = (await client.GetStringAsync("https://api64.ipify.org")).Trim();
            if (!IPAddress.TryParse(ip, out _)) throw new InvalidDataException("Проверка не вернула внешний IP.");
            using var check = await client.GetAsync("https://www.cloudflare.com/cdn-cgi/trace"); check.EnsureSuccessStatusCode();
            return ip;
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException)
        { throw new IOException("Сквозной тест не подтверждён. Проверьте TCP 443 в панели хостинга и доступность узлов у оператора.", e); }
        finally
        {
            if (process is not null) { if (!process.HasExited) { process.Kill(true); await process.WaitForExitAsync(); } process.Dispose(); }
            Directory.Delete(dir, true);
        }
    }
}
