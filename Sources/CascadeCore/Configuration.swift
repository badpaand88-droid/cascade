import Foundation
import CryptoKit

public struct CascadeError: LocalizedError, Sendable {
    public let message: String
    public init(_ message: String) { self.message = message }
    public var errorDescription: String? { message }
}

public struct Server: Sendable, Equatable {
    public var host = ""
    public var port = "22"
    public var user = "root"
    public var secret = ""
    public var keyPath = ""
    public var useKey = false
    public init() {}
    public func validate() throws {
        guard Self.isIPv4(host) else { throw CascadeError("Укажите IPv4-адрес сервера, например 203.0.113.10.") }
        guard let p = Int(port), (1...65535).contains(p) else { throw CascadeError("SSH-порт должен быть от 1 до 65535.") }
        guard user.range(of: "^[a-z_][a-z0-9_-]{0,31}$", options: .regularExpression) != nil else { throw CascadeError("Некорректное имя SSH-пользователя.") }
        if useKey {
            guard keyPath.hasPrefix("/"), FileManager.default.fileExists(atPath: keyPath) else { throw CascadeError("Выберите существующий файл приватного SSH-ключа.") }
        } else if secret.isEmpty { throw CascadeError("Введите SSH-пароль.") }
    }
    public static func isIPv4(_ value: String) -> Bool {
        let parts = value.split(separator: ".", omittingEmptySubsequences: false)
        return parts.count == 4 && parts.allSatisfy { p in
            !p.isEmpty && p.allSatisfy { $0.isASCII && $0.isNumber } && (p.count == 1 || p.first != "0") && UInt8(p) != nil
        }
    }
}

public struct Credentials: Sendable {
    public let uuid: String
    public let privateKey: String
    public let publicKey: String
    public let shortID: String
    public init() {
        let key = Curve25519.KeyAgreement.PrivateKey()
        uuid = UUID().uuidString.lowercased()
        privateKey = Self.encode(key.rawRepresentation)
        publicKey = Self.encode(key.publicKey.rawRepresentation)
        shortID = UUID().uuidString.replacingOccurrences(of: "-", with: "").prefix(8).lowercased()
    }
    public init(server: Credentials, userID: String) throws {
        guard UUID(uuidString: userID) != nil else { throw CascadeError("Некорректный идентификатор устройства.") }
        uuid = userID.lowercased(); privateKey = server.privateKey; publicKey = server.publicKey; shortID = server.shortID
    }
    public init(config: [String: Any]) throws {
        guard let inbound = (config["inbounds"] as? [[String: Any]])?.first,
              let user = (inbound["users"] as? [[String: Any]])?.first,
              let uuid = user["uuid"] as? String, UUID(uuidString: uuid) != nil,
              let tls = inbound["tls"] as? [String: Any], let reality = tls["reality"] as? [String: Any],
              let secret = reality["private_key"] as? String,
              let short = (reality["short_id"] as? [String])?.first,
              let raw = Self.decode(secret) else { throw CascadeError("Существующая конфигурация Cascade повреждена. Автоматическая перезапись остановлена.") }
        let key = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: raw)
        self.uuid = uuid; privateKey = secret; publicKey = Self.encode(key.publicKey.rawRepresentation); shortID = short
    }
    private static func encode(_ data: Data) -> String { data.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "") }
    private static func decode(_ s: String) -> Data? {
        let normal = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        return Data(base64Encoded: normal + String(repeating: "=", count: (4 - normal.count % 4) % 4))
    }
}

public enum Config {
    public static let version = "1.14.4"
    public static let port = 443
    public static func validateSNI(_ sni: String) throws {
        guard sni.count <= 253, sni.range(of: "^(?=.{1,253}$)([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\\.)+[A-Za-z]{2,63}$", options: .regularExpression) != nil else { throw CascadeError("Укажите имя TLS-сайта без https:// и пути.") }
    }
    public static func outbound(host: String, credentials c: Credentials, sni: String, tag: String = "cascade") -> [String: Any] {
        ["type": "vless", "tag": tag, "server": host, "server_port": port,
         "uuid": c.uuid, "flow": "xtls-rprx-vision", "tls": ["enabled": true, "server_name": sni,
         "utls": ["enabled": true, "fingerprint": "chrome"],
         "reality": ["enabled": true, "public_key": c.publicKey, "short_id": c.shortID]]]
    }
    public static func server(credentials c: Credentials, sni: String, next: [String: Any]? = nil) -> [String: Any] {
        let inbound: [String: Any] = ["type": "vless", "tag": "entry", "listen": "0.0.0.0", "listen_port": port,
            "users": [["uuid": c.uuid, "flow": "xtls-rprx-vision"]],
            "tls": ["enabled": true, "server_name": sni, "reality": ["enabled": true,
            "handshake": ["server": sni, "server_port": 443], "private_key": c.privateKey, "short_id": [c.shortID]]]]
        return ["log": ["level": "warn", "timestamp": true], "inbounds": [inbound],
                "outbounds": [next ?? ["type": "direct", "tag": "internet"]],
                "route": ["final": next == nil ? "internet" : "cascade"]]
    }
    public static func client(host: String, credentials: Credentials, sni: String) -> [String: Any] {
        ["log": ["level": "warn", "timestamp": true],
         "dns": ["servers": [["type": "https", "tag": "secure-dns", "server": "1.1.1.1", "server_port": 443,
                               "tls": ["enabled": true, "server_name": "cloudflare-dns.com"], "detour": "cascade"]],
                 "final": "secure-dns", "strategy": "ipv4_only"],
         "inbounds": [["type": "tun", "tag": "tun-in", "address": ["172.28.0.1/30", "fdfe:dcba:9876::1/126"],
                       "auto_route": true, "strict_route": true, "stack": "mixed", "mtu": 1400]],
         "outbounds": [outbound(host: host, credentials: credentials, sni: sni)],
         "route": ["auto_detect_interface": true, "rules": [["action": "sniff"], ["protocol": "dns", "action": "hijack-dns"]], "final": "cascade"]]
    }
    public static func probe(host: String, credentials: Credentials, sni: String, localPort: Int) -> [String: Any] {
        ["log": ["level": "error"], "inbounds": [["type": "mixed", "listen": "127.0.0.1", "listen_port": localPort]],
         "outbounds": [outbound(host: host, credentials: credentials, sni: sni)], "route": ["final": "cascade"]]
    }
    public static func json(_ config: [String: Any]) throws -> Data {
        try JSONSerialization.data(withJSONObject: config, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes])
    }
}

public enum Releases {
    public static let hashes: [String: String] = [
        "linux-amd64": "699a1b510aa4396b2176d32d1181920399ebf1e267835da6f3b598d0f7c24968",
        "linux-arm64": "436441f76ee2f7fe21b5b2d426d3cb261a480455a704865789ad533e4273ec26",
        "darwin-arm64": "0d8c7f5ed5d587b0f1a5e9772a708ec3bfa4ac4c9329604b01d8d9c2ba406838",
        "darwin-amd64": "eae86b9b033bba50b7c44ab719e4bfac0aca05efd28483390ed3aa510f32db25"
    ]
    public static func url(_ platform: String) -> URL {
        URL(string: "https://github.com/SagerNet/sing-box/releases/download/v\(Config.version)/sing-box-\(Config.version)-\(platform).tar.gz")!
    }
}
