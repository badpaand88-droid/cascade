using System.IO.Compression;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using QRCoder;

namespace Cascade.Core;

public sealed record Server(string Host, int Port, string User, string Secret, string KeyPath = "", string TunnelIPv4 = "", string TunnelIPv6 = "", AddressMode AddressMode = AddressMode.Auto)
{
    public void Validate()
    {
        _ = Addresses.Endpoints(this);
        if (Port is < 1 or > 65535 || !Regex.IsMatch(User, "^[a-z_][a-z0-9_-]{0,31}$")) throw new InvalidOperationException("Проверьте порт и SSH-логин.");
        if (KeyPath.Length > 0) { if (!File.Exists(KeyPath)) throw new InvalidOperationException("SSH-ключ не найден."); }
        else if (Secret.Length == 0) throw new InvalidOperationException("Введите пароль SSH.");
    }
}

public sealed record Credentials(string Uuid, string PrivateKey, string PublicKey, string ShortId)
{
    public static Credentials Create()
    {
        var key = new X25519PrivateKeyParameters(new SecureRandom());
        return new(Guid.NewGuid().ToString(), B64(key.GetEncoded()), B64(key.GeneratePublicKey().GetEncoded()), Convert.ToHexString(RandomNumberGenerator.GetBytes(4)).ToLowerInvariant());
    }
    public static Credentials From(JsonObject config)
    {
        var inbound = config["inbounds"]![0]!;
        var user = inbound["users"]![0]!;
        var uuid = (user["uuid"] ?? user["password"])!.GetValue<string>();
        if (!Guid.TryParse(uuid, out _)) throw new InvalidDataException("Некорректный ключ на сервере.");
        var reality = inbound["tls"]?["reality"];
        if (reality is null) return new(uuid, "", "", "");
        var secret = reality["private_key"]!.GetValue<string>();
        var raw = Convert.FromBase64String(secret.Replace('-', '+').Replace('_', '/') + new string('=', (4 - secret.Length % 4) % 4));
        var key = new X25519PrivateKeyParameters(raw, 0);
        return new(uuid, secret, B64(key.GeneratePublicKey().GetEncoded()), reality["short_id"]![0]!.GetValue<string>());
    }
    static string B64(byte[] b) => Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}

public sealed record DeviceProfile(string Id, string Name, string Json, string Link)
{
    public override string ToString() => Name;
    public byte[] Qr(bool json = false)
    {
        var payload = json ? JsonNode.Parse(Json)!.ToJsonString() : Link;
        using var data = QRCodeGenerator.GenerateQrCode(payload, QRCodeGenerator.ECCLevel.M);
        return new PngByteQRCode(data).GetGraphic(8);
    }
    public byte[] Bpf()
    {
        using var payload = new MemoryStream();
        WriteString(payload, "Cascade · " + Name);
        payload.Write([0, 0, 0, 0]); WriteString(payload, Json);
        using var result = new MemoryStream(); result.Write([3, 1]);
        using (var gzip = new GZipStream(result, CompressionLevel.SmallestSize, true)) gzip.Write(payload.ToArray());
        return result.ToArray();
    }
    static void WriteString(Stream stream, string value)
    {
        var data = Encoding.UTF8.GetBytes(value); var n = (uint)data.Length;
        while (n >= 128) { stream.WriteByte((byte)((n & 127) | 128)); n >>= 7; }
        stream.WriteByte((byte)n); stream.Write(data);
    }
}

public static class Profiles
{
    public const string Version = "1.14.4";
    public static readonly JsonSerializerOptions Pretty = new() { WriteIndented = true };
    public static string Digest(string text) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text))).ToLowerInvariant();
    public static void ValidateSni(string name)
    {
        if (name.Length > 253 || !Regex.IsMatch(name, "^([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\\.)+[A-Za-z]{2,63}$"))
            throw new InvalidOperationException("Укажите имя TLS-сайта без https:// и пути.");
    }
    public static JsonObject Outbound(string host, Credentials c, string sni) => new()
    {
        ["type"] = "vless", ["tag"] = "cascade", ["server"] = host, ["server_port"] = 443,
        ["uuid"] = c.Uuid, ["flow"] = "xtls-rprx-vision",
        ["tls"] = new JsonObject { ["enabled"] = true, ["server_name"] = sni,
            ["utls"] = new JsonObject { ["enabled"] = true, ["fingerprint"] = "chrome" },
            ["reality"] = new JsonObject { ["enabled"] = true, ["public_key"] = c.PublicKey, ["short_id"] = c.ShortId } }
    };
    public static string Server(Credentials c, string sni, JsonObject? next = null) => new JsonObject
    {
        ["log"] = new JsonObject { ["level"] = "warn", ["timestamp"] = true },
        ["inbounds"] = new JsonArray(new JsonObject { ["type"] = "vless", ["tag"] = "entry", ["listen"] = "0.0.0.0", ["listen_port"] = 443,
            ["users"] = new JsonArray(new JsonObject { ["uuid"] = c.Uuid, ["flow"] = "xtls-rprx-vision" }),
            ["tls"] = new JsonObject { ["enabled"] = true, ["server_name"] = sni,
                ["reality"] = new JsonObject { ["enabled"] = true, ["handshake"] = new JsonObject { ["server"] = sni, ["server_port"] = 443 },
                    ["private_key"] = c.PrivateKey, ["short_id"] = new JsonArray(c.ShortId) } } }),
        ["outbounds"] = new JsonArray(next?.DeepClone() ?? new JsonObject { ["type"] = "direct", ["tag"] = "internet" }),
        ["route"] = new JsonObject { ["final"] = next is null ? "internet" : "cascade" }
    }.ToJsonString(Pretty);
    public static string Client(string host, Credentials c, string sni) => new JsonObject
    {
        ["log"] = new JsonObject { ["level"] = "warn", ["timestamp"] = true },
        ["dns"] = new JsonObject { ["servers"] = new JsonArray(new JsonObject { ["type"] = "https", ["tag"] = "secure-dns", ["server"] = "1.1.1.1", ["server_port"] = 443,
            ["tls"] = new JsonObject { ["enabled"] = true, ["server_name"] = "cloudflare-dns.com" }, ["detour"] = "cascade" }), ["final"] = "secure-dns", ["strategy"] = "ipv4_only" },
        ["inbounds"] = new JsonArray(new JsonObject { ["type"] = "tun", ["tag"] = "tun-in", ["address"] = new JsonArray("172.28.0.1/30", "fdfe:dcba:9876::1/126"),
            ["auto_route"] = true, ["strict_route"] = true, ["stack"] = "mixed", ["mtu"] = 1400 }),
        ["outbounds"] = new JsonArray(Outbound(host, c, sni)),
        ["route"] = new JsonObject { ["auto_detect_interface"] = true, ["rules"] = new JsonArray(new JsonObject { ["action"] = "sniff" }, new JsonObject { ["protocol"] = "dns", ["action"] = "hijack-dns" }), ["final"] = "cascade" }
    }.ToJsonString(Pretty);
    public static string Probe(string host, Credentials c, string sni, int port) => new JsonObject
    {
        ["log"] = new JsonObject { ["level"] = "error" },
        ["inbounds"] = new JsonArray(new JsonObject { ["type"] = "mixed", ["listen"] = "127.0.0.1", ["listen_port"] = port }),
        ["outbounds"] = new JsonArray(Outbound(host, c, sni)), ["route"] = new JsonObject { ["final"] = "cascade" }
    }.ToJsonString();
    public static List<DeviceProfile> List(string configText, string host, string sni, string[]? hosts = null, bool ipv6Dns = false)
    {
        var config = JsonNode.Parse(configText)!.AsObject(); var inbound = config["inbounds"]![0]!;
        var settings = ConnectionSettings.From(config);
        if (settings.Reality && settings.ServerName != sni) throw new InvalidDataException("Укажите прежнее имя REALITY установленного каскада.");
        var c = Credentials.From(config); var index = 0;
        hosts ??= [host];
        return inbound["users"]!.AsArray().Select(user =>
        {
            var id = (user!["uuid"] ?? user["password"])!.GetValue<string>(); if (!Guid.TryParse(id, out _)) throw new InvalidDataException("Повреждён список устройств.");
            var name = user["name"]?.GetValue<string>() ?? (index == 0 ? "Основной профиль" : $"Устройство {index + 1}"); index++;
            var device = c with { Uuid = id };
            var query = new Dictionary<string, string> { ["sni"] = settings.ServerName };
            if (settings.Vless) {
                query["encryption"] = "none"; query["security"] = settings.Reality ? "reality" : "tls"; query["type"] = settings.TransportType ?? "tcp";
                if (settings.Vision) query["flow"] = "xtls-rprx-vision";
                if (settings.Reality) { query["fp"] = "chrome"; query["pbk"] = c.PublicKey; query["sid"] = c.ShortId; }
                if (settings.TransportType is "ws" or "http" or "httpupgrade") query["path"] = settings.Path;
                if (settings.TransportType is "http" or "httpupgrade") query["host"] = settings.ServerName;
                if (settings.TransportType == "grpc") query["serviceName"] = settings.ServiceName;
            }
            if (settings.Scheme == ConnectionScheme.NaiveQuic) query["quic"] = "1";
            var scheme = settings.Vless ? "vless" : settings.Naive ? "naive+https" : "anytls";
            var auth = settings.Vless ? id : settings.Naive ? id + ":" + id : id;
            var link = $"{scheme}://{auth}@{Addresses.Authority(hosts[0])}:443?" + string.Join("&", query.Select(kv => kv.Key + "=" + Uri.EscapeDataString(kv.Value))) + "#" + Uri.EscapeDataString(name);
            return new DeviceProfile(id, name, ProtocolConfig.Client(hosts, device, settings, settings.ServerName, ipv6Dns), link);
        }).ToList();
    }
    public static (string Json, string Id) Add(string configText, string name)
    {
        name = name.Trim();
        if (name.Length is < 1 or > 60 || name.Any(char.IsControl)) throw new InvalidOperationException("Имя устройства: 1–60 символов, без управляющих знаков.");
        var config = JsonNode.Parse(configText)!.AsObject(); var users = config["inbounds"]![0]!["users"]!.AsArray();
        if (users.Any(u => string.Equals(u!["name"]?.GetValue<string>(), name, StringComparison.OrdinalIgnoreCase))) throw new InvalidOperationException("Такое имя уже используется.");
        var settings = ConnectionSettings.From(config);
        var id = Guid.NewGuid().ToString(); var user = new JsonObject { ["name"] = name, [settings.Vless ? "uuid" : "password"] = id };
        if (settings.Vision) user["flow"] = "xtls-rprx-vision"; if (settings.Naive) user["username"] = id; users.Add(user);
        return (config.ToJsonString(Pretty), id);
    }
}
