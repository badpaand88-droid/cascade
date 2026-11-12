using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Cascade.Core;

public enum AddressMode { Auto, IPv4, IPv6 }
public static class Addresses
{
    public static string? Canonical(string value)
    {
        if (value.Any(c => !char.IsAsciiHexDigit(c) && c is not (':' or '.')) || value.Contains('%') || value.Contains('[') || value.Contains(']') || !IPAddress.TryParse(value, out var ip)) return null;
        if (ip.AddressFamily == AddressFamily.InterNetwork && ip.ToString() != value) return null;
        return ip.ToString();
    }
    public static bool V6(string ip) => ip.Contains(':') && Canonical(ip) is not null;
    public static string Authority(string ip) => V6(ip) ? $"[{ip}]" : ip;
    public static string[] Endpoints(Server s)
    {
        if (Canonical(s.Host) is null) throw new InvalidOperationException("Укажите IPv4 или IPv6 без квадратных скобок.");
        foreach (var (ip, v6) in new[] { (s.TunnelIPv4, false), (s.TunnelIPv6, true) })
            if (ip.Length > 0 && (Canonical(ip) is null || V6(ip) != v6)) throw new InvalidOperationException("Проверьте дополнительные IPv4/IPv6 адреса этого VPS.");
        var endpoints = new[] { s.Host, s.TunnelIPv4, s.TunnelIPv6 }.Where(x => x.Length > 0).Select(x => Canonical(x)!)
            .Where(x => s.AddressMode == AddressMode.Auto || V6(x) == (s.AddressMode == AddressMode.IPv6)).Distinct().ToArray();
        if (endpoints.Length == 0) throw new InvalidOperationException("Для выбранного режима нет адреса VPS.");
        return endpoints;
    }
    public static string[] Sources(Server s) => new[] { s.Host, s.TunnelIPv4, s.TunnelIPv6 }.Where(x => Canonical(x) is not null).Select(x => Canonical(x)!).Distinct().Order().ToArray();
}
public enum ConnectionScheme { RealityVision, Reality, RealityWebSocket, RealityHttp, RealityGrpc, RealityHttpUpgrade, TlsVision, Tls, WebSocket, Http, Grpc, HttpUpgrade, Quic, AnyTls, Naive, NaiveQuic }
public sealed record ConnectionSettings
{
    public ConnectionScheme Scheme { get; init; } = ConnectionScheme.RealityVision;
    public string ServerName { get; init; } = "";
    public string Path { get; init; } = "/cascade";
    public string ServiceName { get; init; } = "cascade";
    public string Certificate { get; init; } = "";
    public string Key { get; init; } = "";
    public bool Reality => Scheme is ConnectionScheme.Reality or ConnectionScheme.RealityVision or ConnectionScheme.RealityWebSocket or ConnectionScheme.RealityHttp or ConnectionScheme.RealityGrpc or ConnectionScheme.RealityHttpUpgrade;
    public bool Naive => Scheme is ConnectionScheme.Naive or ConnectionScheme.NaiveQuic;
    public bool Vless => !Naive && Scheme != ConnectionScheme.AnyTls;
    public bool Vision => Scheme is ConnectionScheme.RealityVision or ConnectionScheme.TlsVision;
    public bool Udp => Scheme is ConnectionScheme.Quic or ConnectionScheme.NaiveQuic;
    public string? TransportType => Scheme switch { ConnectionScheme.WebSocket or ConnectionScheme.RealityWebSocket => "ws", ConnectionScheme.Http or ConnectionScheme.RealityHttp => "http", ConnectionScheme.Grpc or ConnectionScheme.RealityGrpc => "grpc", ConnectionScheme.HttpUpgrade or ConnectionScheme.RealityHttpUpgrade => "httpupgrade", ConnectionScheme.Quic => "quic", _ => null };
    public string Title => Scheme switch {
        ConnectionScheme.RealityVision => "VLESS · REALITY · Vision", ConnectionScheme.Reality => "VLESS · REALITY · TCP", ConnectionScheme.RealityWebSocket => "VLESS · REALITY · WebSocket", ConnectionScheme.RealityHttp => "VLESS · REALITY · HTTP/2", ConnectionScheme.RealityGrpc => "VLESS · REALITY · gRPC", ConnectionScheme.RealityHttpUpgrade => "VLESS · REALITY · HTTPUpgrade", ConnectionScheme.TlsVision => "VLESS · TLS · Vision", ConnectionScheme.Tls => "VLESS · TLS · TCP",
        ConnectionScheme.WebSocket => "VLESS · WebSocket · TLS", ConnectionScheme.Http => "VLESS · HTTP/2 · TLS", ConnectionScheme.Grpc => "VLESS · gRPC · TLS", ConnectionScheme.HttpUpgrade => "VLESS · HTTPUpgrade · TLS", ConnectionScheme.Quic => "VLESS · QUIC · TLS",
        ConnectionScheme.AnyTls => "AnyTLS", ConnectionScheme.Naive => "NaiveProxy · HTTPS / HTTP2", _ => "NaiveProxy · HTTP3 / QUIC" };
    public override string ToString() => Title;
    public void Validate(string realityName)
    {
        Profiles.ValidateSni(Reality ? realityName : ServerName);
        if (!Reality && (!Certificate.Contains("-----BEGIN CERTIFICATE-----") || !Key.Contains("PRIVATE KEY-----") || Encoding.UTF8.GetByteCount(Certificate) > 100000 || Encoding.UTF8.GetByteCount(Key) > 100000))
            throw new InvalidOperationException("Выберите PEM-сертификат с полной цепочкой и приватный ключ своего домена.");
        if (!Path.StartsWith('/') || Path.Length > 512 || Path.Contains('?') || Path.Any(char.IsControl) || !Regex.IsMatch(ServiceName, "^[A-Za-z0-9._-]{1,100}$")) throw new InvalidOperationException("Проверьте путь /cascade и имя gRPC.");
    }
    public JsonObject Tls(Credentials c, string realityName, bool inbound)
    {
        var t = new JsonObject { ["enabled"] = true, ["server_name"] = Reality ? realityName : ServerName };
        if (Reality) {
            t["reality"] = inbound ? new JsonObject { ["enabled"] = true, ["private_key"] = c.PrivateKey, ["short_id"] = new JsonArray(c.ShortId), ["handshake"] = new JsonObject { ["server"] = realityName, ["server_port"] = 443 } } : new JsonObject { ["enabled"] = true, ["public_key"] = c.PublicKey, ["short_id"] = c.ShortId };
            if (!inbound) t["utls"] = new JsonObject { ["enabled"] = true, ["fingerprint"] = "chrome" };
        } else if (inbound) { t["certificate"] = Certificate; t["key"] = Key; if (Naive || Scheme is ConnectionScheme.Http or ConnectionScheme.Grpc) t["alpn"] = new JsonArray(Scheme == ConnectionScheme.NaiveQuic ? "h3" : "h2"); }
        return t;
    }
    public JsonObject? Transport(string? host = null) => TransportType is null ? null : Scheme switch {
        ConnectionScheme.Grpc or ConnectionScheme.RealityGrpc => new() { ["type"] = "grpc", ["service_name"] = ServiceName },
        ConnectionScheme.Http or ConnectionScheme.RealityHttp => new() { ["type"] = "http", ["path"] = Path, ["host"] = new JsonArray(host ?? ServerName) },
        ConnectionScheme.HttpUpgrade or ConnectionScheme.RealityHttpUpgrade => new() { ["type"] = "httpupgrade", ["path"] = Path, ["host"] = host ?? ServerName },
        ConnectionScheme.WebSocket or ConnectionScheme.RealityWebSocket => new() { ["type"] = "ws", ["path"] = Path }, _ => new() { ["type"] = "quic" } };
    static string Pem(JsonNode? node) => node is JsonArray a ? string.Join("\n", a.Select(x => x!.GetValue<string>())) : node?.GetValue<string>() ?? "";
    public static ConnectionSettings From(JsonObject config)
    {
        var i = config["inbounds"]?[0] ?? throw new InvalidDataException("Нет входящего конфига.");
        var t = i["tls"] ?? throw new InvalidDataException("Нет TLS-конфига."); var u = i["users"]![0]!;
        var type = i["type"]!.GetValue<string>(); var transport = i["transport"]?["type"]?.GetValue<string>(); var vision = u["flow"]?.GetValue<string>() == "xtls-rprx-vision";
        var scheme = type switch {
            "anytls" => ConnectionScheme.AnyTls, "naive" => i["network"]?.GetValue<string>() == "udp" ? ConnectionScheme.NaiveQuic : ConnectionScheme.Naive,
            "vless" when t["reality"]?["enabled"]?.GetValue<bool>() == true => transport switch { null => vision ? ConnectionScheme.RealityVision : ConnectionScheme.Reality, "ws" => ConnectionScheme.RealityWebSocket, "http" => ConnectionScheme.RealityHttp, "grpc" => ConnectionScheme.RealityGrpc, "httpupgrade" => ConnectionScheme.RealityHttpUpgrade, _ => throw new InvalidDataException("Неизвестный транспорт REALITY.") },
            "vless" => transport switch { null => vision ? ConnectionScheme.TlsVision : ConnectionScheme.Tls, "ws" => ConnectionScheme.WebSocket, "http" => ConnectionScheme.Http, "grpc" => ConnectionScheme.Grpc, "httpupgrade" => ConnectionScheme.HttpUpgrade, "quic" => ConnectionScheme.Quic, _ => throw new InvalidDataException("Неизвестный транспорт VLESS.") },
            _ => throw new InvalidDataException("Неизвестный протокол Cascade.") };
        return new() { Scheme = scheme, ServerName = t["server_name"]!.GetValue<string>(), Path = i["transport"]?["path"]?.GetValue<string>() ?? "/cascade", ServiceName = i["transport"]?["service_name"]?.GetValue<string>() ?? "cascade", Certificate = Pem(t["certificate"]), Key = Pem(t["key"]) };
    }
    public string TlsCheck(string realityName)
    {
        if (Reality) return Scripts.TlsTemplate(realityName);
        static string B(string text) => Convert.ToBase64String(Encoding.UTF8.GetBytes(text));
        return $"""
        cert_tmp="$(mktemp -d)"
        trap 'rm -rf "$cert_tmp"' EXIT
        printf '%s' '{B(Certificate)}' | base64 -d > "$cert_tmp/cert.pem"
        printf '%s' '{B(Key)}' | base64 -d > "$cert_tmp/key.pem"
        openssl x509 -in "$cert_tmp/cert.pem" -noout -checkend 604800 >/dev/null || fail 'Сертификат истёк или истекает менее чем через 7 дней.'
        openssl verify -verify_hostname '{ServerName}' -untrusted "$cert_tmp/cert.pem" -CAfile /etc/ssl/certs/ca-certificates.crt "$cert_tmp/cert.pem" >/dev/null 2>&1 || fail 'Не подтверждены имя домена и доверенная полная цепочка сертификата.'
        cert_pub="$(openssl x509 -in "$cert_tmp/cert.pem" -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum | cut -d ' ' -f1)"
        key_pub="$(openssl pkey -in "$cert_tmp/key.pem" -passin pass: -pubout -outform DER 2>/dev/null | sha256sum | cut -d ' ' -f1)"
        test "$cert_pub" = "$key_pub" || fail 'Приватный ключ не соответствует сертификату.'
        rm -rf "$cert_tmp"
        trap - EXIT
        echo TLS_OK
        """;
    }
}
public static class ProtocolConfig
{
    public static JsonObject Outbound(string host, Credentials c, ConnectionSettings s, string realityName, string tag = "cascade")
    {
        var o = new JsonObject { ["type"] = s.Vless ? "vless" : s.Naive ? "naive" : "anytls", ["tag"] = tag, ["server"] = host, ["server_port"] = 443, ["tls"] = s.Tls(c, realityName, false) };
        if (s.Vless) { o["uuid"] = c.Uuid; if (s.Vision) o["flow"] = "xtls-rprx-vision"; if (s.Transport(s.Reality ? realityName : s.ServerName) is {} t) o["transport"] = t; }
        else { o["password"] = c.Uuid; if (s.Naive) { o["username"] = c.Uuid; o["quic"] = s.Scheme == ConnectionScheme.NaiveQuic; o["udp_over_tcp"] = true; } }
        return o;
    }
    public static JsonArray Outbounds(string[] hosts, Credentials c, ConnectionSettings s, string realityName)
    {
        var list = new JsonArray();
        if (hosts.Length == 1) { list.Add(Outbound(hosts[0], c, s, realityName)); return list; }
        for (var i = 0; i < hosts.Length; i++) list.Add(Outbound(hosts[i], c, s, realityName, $"cascade-{i}"));
        list.Add(new JsonObject { ["type"] = "urltest", ["tag"] = "cascade", ["outbounds"] = new JsonArray(hosts.Select((_, i) => JsonValue.Create($"cascade-{i}")).ToArray()), ["url"] = "https://www.gstatic.com/generate_204", ["interval"] = "1m", ["tolerance"] = 100, ["interrupt_exist_connections"] = false }); return list;
    }
    public static string Server(Credentials c, ConnectionSettings s, string realityName, JsonArray? next = null, string listen = "::")
    {
        var user = new JsonObject { [s.Vless ? "uuid" : "password"] = c.Uuid }; if (s.Vision) user["flow"] = "xtls-rprx-vision"; if (s.Naive) user["username"] = c.Uuid;
        var inbound = new JsonObject { ["type"] = s.Vless ? "vless" : s.Naive ? "naive" : "anytls", ["tag"] = "entry", ["listen"] = listen, ["listen_port"] = 443, ["users"] = new JsonArray(user), ["tls"] = s.Tls(c, realityName, true) };
        if (s.Transport(s.Reality ? realityName : s.ServerName) is {} t) inbound["transport"] = t; if (s.Naive) inbound["network"] = s.Udp ? "udp" : "tcp";
        return new JsonObject { ["log"] = new JsonObject { ["level"] = "warn", ["timestamp"] = true }, ["inbounds"] = new JsonArray(inbound), ["outbounds"] = next?.DeepClone() ?? new JsonArray(new JsonObject { ["type"] = "direct", ["tag"] = "internet" }), ["route"] = new JsonObject { ["final"] = next is null ? "internet" : "cascade" } }.ToJsonString(Profiles.Pretty);
    }
    public static string Client(string[] hosts, Credentials c, ConnectionSettings s, string realityName, bool ipv6Dns = false)
    {
        var config = JsonNode.Parse(Profiles.Client(hosts[0], c, realityName))!;
        config["outbounds"] = Outbounds(hosts, c, s, realityName);
        config["dns"]!["strategy"] = ipv6Dns ? "prefer_ipv6" : "prefer_ipv4"; config["dns"]!["servers"]![0]!["server"] = ipv6Dns ? "2606:4700:4700::1111" : "1.1.1.1";
        return config.ToJsonString(Profiles.Pretty);
    }
}
