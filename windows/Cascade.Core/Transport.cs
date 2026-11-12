using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Renci.SshNet;

namespace Cascade.Core;

public sealed record HostPin(string Fingerprint, string Algorithm);
public sealed record Result(int Code, string Output, string Error)
{
    public void Require(string marker)
    {
        if (Code != 0 || !Output.Contains(marker, StringComparison.Ordinal))
            throw new InvalidOperationException(string.IsNullOrWhiteSpace(Error) ? "Сервер не подтвердил этап: " + marker : Error[^Math.Min(Error.Length, 900)..]);
    }
}

public static class Transport
{
    static SshClient Client(Server server, bool probe = false)
    {
        server.Validate();
        AuthenticationMethod auth = probe ? new PasswordAuthenticationMethod("cascade-key-probe", Guid.NewGuid().ToString()) :
            server.KeyPath.Length > 0 ? new PrivateKeyAuthenticationMethod(server.User,
                server.Secret.Length > 0 ? new PrivateKeyFile(server.KeyPath, server.Secret) : new PrivateKeyFile(server.KeyPath)) :
            new PasswordAuthenticationMethod(server.User, server.Secret);
        var info = new ConnectionInfo(server.Host, server.Port, probe ? "cascade-key-probe" : server.User, auth) { Timeout = TimeSpan.FromSeconds(12) };
        return new SshClient(info) { KeepAliveInterval = TimeSpan.FromSeconds(10) };
    }
    public static Task<HostPin> Scan(Server server) => Task.Run(() =>
    {
        using var client = Client(server, true); HostPin? pin = null;
        client.HostKeyReceived += (_, e) => { pin = new("SHA256:" + Convert.ToBase64String(SHA256.HashData(e.HostKey)).TrimEnd('='), e.HostKeyName); e.CanTrust = false; };
        try { client.Connect(); } catch when (pin is not null) { }
        return pin ?? throw new InvalidOperationException("Не удалось получить SSH-ключ. Проверьте IP, порт и firewall.");
    });
    public static Task<Result> Run(Server server, HostPin pin, string script, bool root = true, int timeout = 60) => Task.Run(() =>
    {
        using var client = Client(server);
        client.HostKeyReceived += (_, e) =>
        {
            var actual = "SHA256:" + Convert.ToBase64String(SHA256.HashData(e.HostKey)).TrimEnd('=');
            e.CanTrust = e.HostKeyName == pin.Algorithm && CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(actual), Encoding.UTF8.GetBytes(pin.Fingerprint));
        };
        client.Connect();
        var delimiter = "CASCADE_" + Guid.NewGuid().ToString("N");
        var shell = root && server.User != "root" ? "sudo -n /bin/bash" : "/bin/bash";
        using var command = client.CreateCommand(shell + " <<'" + delimiter + "'\n" + script + "\n" + delimiter + "\n");
        command.CommandTimeout = TimeSpan.FromSeconds(timeout);
        var output = command.Execute();
        return new Result(command.ExitStatus ?? -1, output, command.Error);
    });
}

public static class Scripts
{
    static readonly Dictionary<string, string> Templates = Load();
    static Dictionary<string, string> Load()
    {
        using var resource = Assembly.GetExecutingAssembly().GetManifestResourceStream("Cascade.RemoteScripts.json")!;
        return JsonSerializer.Deserialize<Dictionary<string, string>>(resource)!;
    }
    public static string Get(string name, string sni = "www.microsoft.com", string peer = "198.51.100.2", string role = "entry", string tx = "none", string digest = "none", string? config = null, int sshPort = 22)
    {
        Profiles.ValidateSni(sni);
        if (!System.Net.IPAddress.TryParse(peer, out var ip) || ip.ToString() != peer || peer.Contains(':')) throw new InvalidOperationException("Некорректный адрес второго VPS.");
        if (role is not ("entry" or "exit") || !Regex.IsMatch(tx, "^[a-zA-Z0-9]+$") || !(digest == "none" || Regex.IsMatch(digest, "^[0-9a-f]{64}$")) || sshPort is < 1 or > 65535)
            throw new InvalidOperationException("Некорректные параметры установки.");
        var text = Templates[name].Replace("@@SNI@@", sni).Replace("@@PEER@@", peer).Replace("@@ROLE@@", role).Replace("@@TX@@", tx).Replace("@@EXPECTED_DIGEST@@", digest)
            .Replace("@@SSH_PORT@@", sshPort.ToString()).Replace("@@CONFIG_BASE64@@", Convert.ToBase64String(Encoding.UTF8.GetBytes(config ?? "{}")));
        if (text.Contains("@@", StringComparison.Ordinal)) throw new InvalidOperationException("Не заполнен шаблон установки.");
        return text;
    }
}
