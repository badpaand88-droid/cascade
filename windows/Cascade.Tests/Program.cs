using System.Diagnostics;
using System.IO.Compression;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json.Nodes;
using Cascade.Core;

var directory = Path.GetFullPath(args.FirstOrDefault() ?? "artifacts"); Directory.CreateDirectory(directory);
var tests = 0;
void Check(bool condition, string message) { if (!condition) throw new Exception(message); }
async Task Test(string name, Func<Task> action) { await action(); tests++; Console.WriteLine("PASS " + name); }
await Test("validation blocks shell/SSH option injection", () =>
{
    foreach (var host in new[] { "-oProxyCommand=x", "1.2.3.4;id", "001.2.3.4", "example.com", "1.2.3.256" })
    {
        bool blocked = false; try { new Server(host, 22, "root", "test").Validate(); } catch { blocked = true; } Check(blocked, host);
    }
    foreach (var sni in new[] { "https://example.com", "example.com;id" }) { bool blocked = false; try { Profiles.ValidateSni(sni); } catch { blocked = true; } Check(blocked, sni); }
    new Server("203.0.113.1", 22, "root", "test").Validate(); return Task.CompletedTask;
});
var entryKey = Credentials.Create(); var exitKey = Credentials.Create();
var exitConfig = Profiles.Server(exitKey, "www.microsoft.com");
var entryConfig = Profiles.Server(entryKey, "www.microsoft.com", Profiles.Outbound("198.51.100.2", exitKey, "www.microsoft.com"));
await Test("X25519 credentials round trip and per-device profiles preserve users and routing", () =>
{
    var restored = Credentials.From(JsonNode.Parse(entryConfig)!.AsObject()); Check(restored == entryKey, "Key mismatch");
    var (updated, id) = Profiles.Add(entryConfig, "iPhone / работа");
    var profiles = Profiles.List(updated, "203.0.113.1", "www.microsoft.com");
    Check(profiles.Count == 2 && profiles[0].Id == entryKey.Uuid && profiles[1].Id == id, "Users not preserved");
    Check(!profiles[1].Json.Contains(entryKey.PrivateKey) && !profiles[1].Link.Contains(exitKey.Uuid), "Secret leak");
    Check(JsonNode.Parse(updated)!["outbounds"]!.ToJsonString() == JsonNode.Parse(entryConfig)!["outbounds"]!.ToJsonString(), "Route changed");
    Check(Uri.UnescapeDataString(new Uri(profiles[1].Link).Fragment[1..]) == profiles[1].Name, "URI label mismatch");
    bool duplicate = false; try { Profiles.Add(updated, "iPhone / работа"); } catch { duplicate = true; } Check(duplicate, "Duplicate allowed");
    return Task.CompletedTask;
});
var sample = Profiles.List(entryConfig, "203.0.113.1", "www.microsoft.com")[0];
await Test("BPF and QR artifacts contain only the selected client profile", async () =>
{
    var portable = sample.Bpf(); Check(portable[0] == 3 && portable[1] == 1, "BPF header");
    using var gzip = new GZipStream(new MemoryStream(portable[2..]), CompressionMode.Decompress);
    using var data = new MemoryStream(); await gzip.CopyToAsync(data); var decoded = Encoding.UTF8.GetString(data.ToArray());
    Check(decoded.Contains(sample.Json) && !decoded.Contains(entryKey.PrivateKey), "BPF content");
    await File.WriteAllBytesAsync(Path.Combine(directory, "sample.bpf"), portable);
    await File.WriteAllTextAsync(Path.Combine(directory, "client.json"), sample.Json);
    await File.WriteAllTextAsync(Path.Combine(directory, "link.txt"), sample.Link);
    await File.WriteAllBytesAsync(Path.Combine(directory, "qr-vless.png"), sample.Qr());
    await File.WriteAllBytesAsync(Path.Combine(directory, "qr-json.png"), sample.Qr(true));
    const string appStore = "https://apps.apple.com/us/app/sing-box-mt/id6785326793";
    using var qrData = QRCoder.QRCodeGenerator.GenerateQrCode(appStore, QRCoder.QRCodeGenerator.ECCLevel.M);
    await File.WriteAllBytesAsync(Path.Combine(directory, "app-store-qr.png"), new QRCoder.PngByteQRCode(qrData).GetGraphic(8));
});
await Test("workflow cannot bypass server checks or accept identical VPS", async () =>
{
    var flow = new Workflow(); var s = new Server("203.0.113.1", 22, "root", "test"); flow.SetServer(0, s); flow.SetServer(1, s);
    Check(!flow.BothChecked && !flow.CanRollback, "Trust inferred without authentication");
    bool blocked = false; try { await flow.Prepare(true); } catch { blocked = true; } Check(blocked, "Identical VPS accepted");
});
await Test("shared deployment templates are fully substituted and Bash-valid", async () =>
{
    var tx = Guid.NewGuid().ToString("N");
    foreach (var name in new[] { "ssh", "link", "tls", "preflight", "install", "rollback", "readClients", "updateClients", "updateStatus" })
    {
        var script = Scripts.Get(name, peer: "198.51.100.2", tx: tx, config: entryConfig); Check(!script.Contains("@@"), "Unresolved placeholder");
        var path = Path.Combine(directory, name + ".sh"); await File.WriteAllTextAsync(path, script);
        if (!OperatingSystem.IsWindows()) { var syntax = await NativeProcess.Run("/bin/bash", ["-n", path]); Check(syntax.Code == 0, syntax.Error); }
    }
    bool blocked = false; try { Scripts.Get("install", tx: "x;id"); } catch { blocked = true; } Check(blocked, "Transaction injection");
});
await Test("security payload, generated administrator key and workflow gates", async () =>
{
    var keyPath=Path.Combine(directory,"test-admin-"+Guid.NewGuid().ToString("N")+".pem");
    try {
        SecurityKeys.Create(keyPath);
        using var key=new Renci.SshNet.PrivateKeyFile(keyPath);
        Check(key.HostKeyAlgorithms.Any(x=>x.Name=="ssh-ed25519"),"Generated key incompatible with SSH.NET");
        bool blocked=false;try { SecurityKeys.Create(keyPath); } catch(IOException) { blocked=true; } Check(blocked,"Existing key overwritten");
        if(!OperatingSystem.IsWindows()) { var openssh=await NativeProcess.Run("/usr/bin/ssh-keygen",["-y","-f",keyPath]);Check(openssh.Code==0 && openssh.Output.StartsWith("ssh-ed25519 "),"Generated key incompatible with OpenSSH: "+openssh.Error); }
        var q=ServerSecurity.Request("audit",new Server("2001:db8::1",2222,"admin","test"),"entry",["203.0.113.1"]);
        q["publicKey"]="x'\n$(id)";
        var script=ServerSecurity.Script(q);Check(!script.Contains("x'\n$(id)"),"Payload escaped into shell");
        if(!OperatingSystem.IsWindows()) { var path=Path.Combine(directory,"security.sh");await File.WriteAllTextAsync(path,script);var syntax=await NativeProcess.Run("/bin/bash",["-n",path]);Check(syntax.Code==0,syntax.Error); }
        var flow=new Workflow();blocked=false;try { await flow.SecurityRun("apply",0); } catch(InvalidOperationException) { blocked=true; }Check(blocked,"Security allowed before install");
    } finally { File.Delete(keyPath); }
});
var binary = Environment.GetEnvironmentVariable("CASCADE_TEST_CORE");
if (!string.IsNullOrEmpty(binary))
{
    await Test("all generated configs validate with official sing-box", async () =>
    {
        var runtime = new CoreRuntime(binary); await runtime.Ensure();
        var (updated, _) = Profiles.Add(entryConfig, "Телефон");
        foreach (var json in new[] { exitConfig, entryConfig, updated, sample.Json, Profiles.Probe("203.0.113.1", entryKey, "www.microsoft.com", 19080) }) await runtime.Validate(json);
    });
    await Test("IPv6 modes, 16 schemes, device export and all mixed cascade configs", async () =>
    {
        foreach (var host in new[] { "2001:db8::1", "::1", "2001:0DB8:0000::1" }) new Server(host,22,"root","test").Validate();
        var dual = new Server("203.0.113.1",22,"root","test",TunnelIPv6:"2001:db8::1");
        Check(Addresses.Endpoints(dual).Length == 2, "Dual-stack endpoints missing");
        Check(Addresses.Endpoints(dual with { AddressMode = AddressMode.IPv6 }).SequenceEqual(new[] { "2001:db8::1" }), "IPv6 mode");
        bool bad6 = false; try { new Server("fe80::1%eth0",22,"root","test").Validate(); } catch { bad6 = true; } Check(bad6,"Scoped address accepted");
        var fixture = Environment.GetEnvironmentVariable("CASCADE_MATRIX_OUTPUT") ?? throw new Exception("Set CASCADE_MATRIX_OUTPUT to Swift fixture directory");
        var cert = await File.ReadAllTextAsync(Path.Combine(fixture,"cert.pem")); var key = await File.ReadAllTextAsync(Path.Combine(fixture,"key.pem"));
        var runtime = new CoreRuntime(binary);
        var variants = Enum.GetValues<ConnectionScheme>().Select(scheme => (Settings:new ConnectionSettings { Scheme=scheme,ServerName="cascade.test",Certificate=cert,Key=key },Credentials:Credentials.Create())).ToArray();
        foreach (var (settings, credentials) in variants) {
            settings.Validate("www.microsoft.com");
            var config = ProtocolConfig.Server(credentials,settings,"www.microsoft.com"); await runtime.Validate(config);
            Check(ConnectionSettings.From(JsonNode.Parse(config)!.AsObject()).Scheme == settings.Scheme,"Scheme round trip");
            var (added,id) = Profiles.Add(config,"iPhone"); var profiles = Profiles.List(added,"2001:db8::1","www.microsoft.com",new[] {"203.0.113.1","2001:db8::1"});
            Check(profiles.Count == 2 && profiles[1].Id == id,"Device list");
            foreach (var profile in profiles) { await runtime.Validate(profile.Json); Check(!profile.Json.Contains(key),"TLS private key leak"); Check(profile.Bpf().Length > 0,"No BPF"); }
            var single = Profiles.List(config,"2001:db8::1","www.microsoft.com")[0]; Check(single.Link.Contains("@[2001:db8::1]:443"),"IPv6 URI");
            var script = Scripts.Get("install",peer:"2001:db8::2",config:config,settings:settings,sources:new[] { "203.0.113.1", "2001:db8::1" });
            var scriptPath=Path.Combine(directory,"install-"+settings.Scheme+".sh"); await File.WriteAllTextAsync(scriptPath,script);
            var syntax=await NativeProcess.Run("/bin/bash",new[] { "-n",scriptPath }); Check(syntax.Code == 0,syntax.Error);
        }
        foreach (var (a,ca) in variants) foreach (var (b,cb) in variants) await runtime.Validate(ProtocolConfig.Server(ca,a,"www.microsoft.com",ProtocolConfig.Outbounds(new[] {"198.51.100.2","2001:db8::2"},cb,b,"www.microsoft.com")));
    });
    if (Environment.GetEnvironmentVariable("CASCADE_NETWORK_TEST") == "1")
    {
        await Test("real two-hop REALITY with .NET-generated X25519 keys; exit failure has no direct fallback", async () =>
        {
            static int Port() { var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start(); var p = ((IPEndPoint)listener.LocalEndpoint).Port; listener.Stop(); return p; }
            var exitPort = Port(); var entryPort = Port(); var proxyPort = Port();
            var exit = JsonNode.Parse(exitConfig)!; exit["inbounds"]![0]!["listen"] = "127.0.0.1"; exit["inbounds"]![0]!["listen_port"] = exitPort;
            var entry = JsonNode.Parse(entryConfig)!; entry["inbounds"]![0]!["listen"] = "127.0.0.1"; entry["inbounds"]![0]!["listen_port"] = entryPort;
            entry["outbounds"]![0]!["server"] = "127.0.0.1"; entry["outbounds"]![0]!["server_port"] = exitPort;
            var proxy = JsonNode.Parse(Profiles.Probe("127.0.0.1", entryKey, "www.microsoft.com", proxyPort))!; proxy["outbounds"]![0]!["server_port"] = entryPort;
            var children = new List<Process>();
            try
            {
                foreach (var config in new[] { exit, entry, proxy })
                {
                    var path = Path.Combine(directory, "live-" + children.Count + ".json"); await File.WriteAllTextAsync(path, config.ToJsonString());
                    var info = new ProcessStartInfo(binary) { UseShellExecute = false, RedirectStandardError = true, RedirectStandardOutput = true }; foreach (var a in new[] { "run", "-c", path }) info.ArgumentList.Add(a);
                    var process = Process.Start(info)!; _ = process.StandardError.ReadToEndAsync(); _ = process.StandardOutput.ReadToEndAsync(); children.Add(process);
                }
                await Task.Delay(800);
                async Task<string> Fetch()
                {
                    using var handler = new SocketsHttpHandler { Proxy = new WebProxy($"socks5://127.0.0.1:{proxyPort}"), UseProxy = true };
                    using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(15) }; return (await client.GetStringAsync("https://api.ipify.org")).Trim();
                }
                Check(IPAddress.TryParse(await Fetch(), out _), "No exit IP");
                children[0].Kill(true); await children[0].WaitForExitAsync();
                bool failed = false; try { await Fetch(); } catch { failed = true; } Check(failed, "Direct fallback detected");
            }
            finally { foreach (var p in children) { if (!p.HasExited) { p.Kill(true); await p.WaitForExitAsync(); } p.Dispose(); } }
        });
    }
}
Console.WriteLine($"{tests} checks passed.");
