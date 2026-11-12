import Foundation
import Darwin

public enum AddressMode: String, CaseIterable, Sendable {
    case auto, ipv4, ipv6
    public var title: String { switch self { case .auto: "Авто · IPv4 / IPv6"; case .ipv4: "Только IPv4"; case .ipv6: "Только IPv6" } }
}
public enum IPAddress {
    public static func canonical(_ value: String) -> String? {
        guard value.utf8.allSatisfy({ (48...57).contains($0) || (65...70).contains($0) || (97...102).contains($0) || $0 == 46 || $0 == 58 }), (value.contains(":") || Server.isIPv4(value)), !value.contains("%"), !value.contains("["), !value.contains("]") else { return nil }
        for family in [AF_INET, AF_INET6] {
            var bytes = [UInt8](repeating: 0, count: 16)
            if inet_pton(family, value, &bytes) == 1 {
                var output = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
                guard inet_ntop(family, &bytes, &output, socklen_t(output.count)) != nil else { return nil }
                return String(decoding: output.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
            }
        }
        return nil
    }
    public static func isValid(_ value: String) -> Bool { canonical(value) != nil }
    public static func isIPv6(_ value: String) -> Bool { value.contains(":") && isValid(value) }
    public static func authority(_ value: String) -> String { isIPv6(value) ? "[\(value)]" : value }
}

public enum ConnectionScheme: String, CaseIterable, Sendable {
    case realityVision, reality, realityWebSocket, realityHTTP, realityGRPC, realityHTTPUpgrade, tlsVision, tls, websocket, http, grpc, httpUpgrade, quic, anytls, naive, naiveQUIC
    public var title: String {
        switch self {
        case .realityVision: "VLESS · REALITY · Vision"
        case .reality: "VLESS · REALITY · TCP"
        case .realityWebSocket: "VLESS · REALITY · WebSocket"
        case .realityHTTP: "VLESS · REALITY · HTTP/2"
        case .realityGRPC: "VLESS · REALITY · gRPC"
        case .realityHTTPUpgrade: "VLESS · REALITY · HTTPUpgrade"
        case .tlsVision: "VLESS · TLS · Vision"
        case .tls: "VLESS · TLS · TCP"
        case .websocket: "VLESS · WebSocket · TLS"
        case .http: "VLESS · HTTP/2 · TLS"
        case .grpc: "VLESS · gRPC · TLS"
        case .httpUpgrade: "VLESS · HTTPUpgrade · TLS"
        case .quic: "VLESS · QUIC · TLS"
        case .anytls: "AnyTLS"
        case .naive: "NaiveProxy · HTTPS / HTTP2"
        case .naiveQUIC: "NaiveProxy · HTTP3 / QUIC"
        }
    }
    public var isReality: Bool { [.realityVision, .reality, .realityWebSocket, .realityHTTP, .realityGRPC, .realityHTTPUpgrade].contains(self) }
    public var isNaive: Bool { self == .naive || self == .naiveQUIC }
    public var isVless: Bool { self != .anytls && !isNaive }
    public var vision: Bool { self == .realityVision || self == .tlsVision }
    public var udp: Bool { self == .quic || self == .naiveQUIC }
    public var transport: String? { switch self { case .websocket, .realityWebSocket: "ws"; case .http, .realityHTTP: "http"; case .grpc, .realityGRPC: "grpc"; case .httpUpgrade, .realityHTTPUpgrade: "httpupgrade"; case .quic: "quic"; default: nil } }
}

public struct ConnectionSettings: Sendable, Equatable {
    public var scheme: ConnectionScheme = .realityVision
    public var serverName = ""
    public var path = "/cascade"
    public var serviceName = "cascade"
    public var certificate = ""
    public var key = ""
    public init() {}
    public func validate(realityName: String) throws {
        try Config.validateSNI(scheme.isReality ? realityName : serverName)
        if !scheme.isReality {
            guard certificate.contains("-----BEGIN CERTIFICATE-----"), key.contains("PRIVATE KEY-----"), certificate.utf8.count < 100_000, key.utf8.count < 100_000 else {
                throw CascadeError("Для \(scheme.title) выберите PEM-сертификат (полную цепочку) и приватный ключ для своего домена.")
            }
        }
        guard path.hasPrefix("/"), path.utf8.count <= 512, !path.contains("?"), !path.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }),
              !serviceName.isEmpty, serviceName.range(of: "^[A-Za-z0-9._-]{1,100}$", options: .regularExpression) != nil else { throw CascadeError("Путь должен начинаться с / и не содержать параметров или управляющих символов; имя gRPC — буквы, цифры, . _ -.") }
    }
    public func tls(realityName: String, credentials: Credentials, inbound: Bool) -> [String: Any] {
        var tls: [String: Any] = ["enabled": true, "server_name": scheme.isReality ? realityName : serverName]
        if scheme.isReality {
            if inbound { tls["reality"] = ["enabled": true, "handshake": ["server": realityName, "server_port": 443], "private_key": credentials.privateKey, "short_id": [credentials.shortID]] as [String: Any] }
            else { tls["utls"] = ["enabled": true, "fingerprint": "chrome"]; tls["reality"] = ["enabled": true, "public_key": credentials.publicKey, "short_id": credentials.shortID] as [String: Any] }
        } else if inbound {
            tls["certificate"] = certificate; tls["key"] = key
            if scheme.isNaive || scheme == .http || scheme == .grpc { tls["alpn"] = scheme == .naiveQUIC ? ["h3"] : ["h2"] }
        }
        return tls
    }
    public func transport(host: String? = nil) -> [String: Any]? {
        let host = host ?? serverName
        guard let type = scheme.transport else { return nil }
        switch scheme { case .grpc, .realityGRPC: return ["type": type, "service_name": serviceName]
        case .http, .realityHTTP: return ["type": type, "path": path, "host": [host]]
        case .httpUpgrade, .realityHTTPUpgrade: return ["type": type, "path": path, "host": host]
        case .websocket, .realityWebSocket: return ["type": type, "path": path]
        default: return ["type": type] }
    }
    public static func read(_ config: [String: Any]) throws -> ConnectionSettings {
        guard let inbound = (config["inbounds"] as? [[String: Any]])?.first, let type = inbound["type"] as? String,
              let tls = inbound["tls"] as? [String: Any], let name = tls["server_name"] as? String else { throw CascadeError("Неизвестная конфигурация Cascade.") }
        let user = (inbound["users"] as? [[String: Any]])?.first ?? [:]
        let transport = inbound["transport"] as? [String: Any] ?? [:]
        var s = ConnectionSettings(); s.serverName = name
        if type == "anytls" { s.scheme = .anytls }
        else if type == "naive" { s.scheme = inbound["network"] as? String == "udp" ? .naiveQUIC : .naive }
        else if type == "vless" {
            if (tls["reality"] as? [String: Any])?["enabled"] as? Bool == true {
                switch transport["type"] as? String {
                case "ws": s.scheme = .realityWebSocket; case "http": s.scheme = .realityHTTP; case "grpc": s.scheme = .realityGRPC; case "httpupgrade": s.scheme = .realityHTTPUpgrade
                case nil: s.scheme = user["flow"] as? String == "xtls-rprx-vision" ? .realityVision : .reality
                default: throw CascadeError("Этот транспорт REALITY не поддерживается.")
                }
            }
            else {
                switch transport["type"] as? String {
                case "ws": s.scheme = .websocket; case "http": s.scheme = .http; case "grpc": s.scheme = .grpc
                case "httpupgrade": s.scheme = .httpUpgrade; case "quic": s.scheme = .quic
                case nil: s.scheme = user["flow"] as? String == "xtls-rprx-vision" ? .tlsVision : .tls
                default: throw CascadeError("Транспорт существующего VLESS не поддерживается.")
                }
            }
        } else { throw CascadeError("Этот протокол не поддерживается Cascade.") }
        s.path = transport["path"] as? String ?? "/cascade"; s.serviceName = transport["service_name"] as? String ?? "cascade"
        s.certificate = tls["certificate"] as? String ?? (tls["certificate"] as? [String])?.joined(separator: "\n") ?? ""
        s.key = tls["key"] as? String ?? (tls["key"] as? [String])?.joined(separator: "\n") ?? ""
        return s
    }
}

public extension Server {
    func endpoints() throws -> [String] {
        guard IPAddress.isValid(host) else { throw CascadeError("Укажите IPv4 или IPv6 без квадратных скобок.") }
        var addresses = [host]
        for (value, ipv6) in [(tunnelIPv4, false), (tunnelIPv6, true)] where !value.isEmpty {
            guard IPAddress.isValid(value), IPAddress.isIPv6(value) == ipv6 else { throw CascadeError("Проверьте дополнительные IPv4/IPv6 адреса сервера.") }
            addresses.append(value)
        }
        var seen = Set<String>()
        let result = addresses.compactMap(IPAddress.canonical).filter { value in
            (addressMode == .auto || IPAddress.isIPv6(value) == (addressMode == .ipv6)) && seen.insert(value).inserted
        }
        guard !result.isEmpty else { throw CascadeError("Для выбранного режима нет адреса сервера. Введите IPv4/IPv6.") }
        return result
    }
    var sourceAddresses: [String] { Array(Set(([host, tunnelIPv4, tunnelIPv6]).filter(IPAddress.isValid).compactMap(IPAddress.canonical))).sorted() }
}

public enum ProtocolConfig {
    public static func outbound(host: String, credentials c: Credentials, settings s: ConnectionSettings, realityName: String, tag: String = "cascade") -> [String: Any] {
        var o: [String: Any] = ["type": s.scheme.isVless ? "vless" : s.scheme.isNaive ? "naive" : "anytls", "tag": tag, "server": host, "server_port": Config.port, "tls": s.tls(realityName: realityName, credentials: c, inbound: false)]
        if s.scheme.isVless { o["uuid"] = c.uuid; if s.scheme.vision { o["flow"] = "xtls-rprx-vision" }; if let t = s.transport(host: s.scheme.isReality ? realityName : s.serverName) { o["transport"] = t } }
        else { o["password"] = c.uuid; if s.scheme.isNaive { o["username"] = c.uuid; o["quic"] = s.scheme == .naiveQUIC; o["udp_over_tcp"] = true } }
        return o
    }
    public static func outbounds(hosts: [String], credentials: Credentials, settings: ConnectionSettings, realityName: String) -> [[String: Any]] {
        if hosts.count == 1 { return [outbound(host: hosts[0], credentials: credentials, settings: settings, realityName: realityName)] }
        let tags = hosts.indices.map { "cascade-\($0)" }
        var list = hosts.enumerated().map { outbound(host: $0.element, credentials: credentials, settings: settings, realityName: realityName, tag: tags[$0.offset]) }
        list.append(["type": "urltest", "tag": "cascade", "outbounds": tags, "url": "https://www.gstatic.com/generate_204", "interval": "1m", "tolerance": 100, "interrupt_exist_connections": false])
        return list
    }
    public static func server(credentials c: Credentials, settings s: ConnectionSettings, realityName: String, next: [[String: Any]]? = nil) -> [String: Any] {
        var user: [String: Any] = s.scheme.isVless ? ["uuid": c.uuid] : ["password": c.uuid]
        if s.scheme.vision { user["flow"] = "xtls-rprx-vision" }
        if s.scheme.isNaive { user["username"] = c.uuid }
        var inbound: [String: Any] = ["type": s.scheme.isVless ? "vless" : s.scheme.isNaive ? "naive" : "anytls", "tag": "entry", "listen": "::", "listen_port": Config.port, "users": [user], "tls": s.tls(realityName: realityName, credentials: c, inbound: true)]
        if let transport = s.transport(host: s.scheme.isReality ? realityName : s.serverName) { inbound["transport"] = transport }
        if s.scheme.isNaive { inbound["network"] = s.scheme == .naiveQUIC ? "udp" : "tcp" }
        return ["log": ["level": "warn", "timestamp": true], "inbounds": [inbound], "outbounds": next ?? [["type": "direct", "tag": "internet"]], "route": ["final": next == nil ? "internet" : "cascade"]]
    }
    public static func client(hosts: [String], credentials: Credentials, settings: ConnectionSettings, realityName: String, ipv6DNS: Bool = false) -> [String: Any] {
        var c = Config.client(host: hosts[0], credentials: credentials, sni: realityName)
        c["outbounds"] = outbounds(hosts: hosts, credentials: credentials, settings: settings, realityName: realityName)
        c["dns"] = ["servers": [["type": "https", "tag": "secure-dns", "server": ipv6DNS ? "2606:4700:4700::1111" : "1.1.1.1", "server_port": 443, "tls": ["enabled": true, "server_name": "cloudflare-dns.com"], "detour": "cascade"]], "final": "secure-dns", "strategy": ipv6DNS ? "prefer_ipv6" : "prefer_ipv4"] as [String: Any]
        return c
    }
}
