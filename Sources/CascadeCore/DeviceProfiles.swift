import Foundation
import CryptoKit

public struct DeviceProfile: Identifiable, Sendable {
    public let id: String
    public let name: String
    public let config: Data
    public let link: String
}

public enum DeviceProfiles {
    public static func list(serverConfig: Data, host: String, sni: String, hosts: [String]? = nil, ipv6DNS: Bool = false) throws -> [DeviceProfile] {
        guard let config = try JSONSerialization.jsonObject(with: serverConfig) as? [String: Any],
              let inbound = (config["inbounds"] as? [[String: Any]])?.first,
              let users = inbound["users"] as? [[String: Any]] else { throw CascadeError("Не найден конфиг Cascade.") }
        let settings = try ConnectionSettings.read(config), server = try Credentials(config: config)
        if settings.scheme.isReality && settings.serverName != sni { throw CascadeError("Укажите прежнее имя REALITY установленного каскада.") }
        return try users.enumerated().map { index, user in
            guard let uuid = (user["uuid"] ?? user["password"]) as? String else { throw CascadeError("Повреждён список устройств.") }
            let credential = try Credentials(server: server, userID: uuid)
            let name = user["name"] as? String ?? (index == 0 ? "Основной профиль" : "Устройство \(index + 1)")
            return try profile(hosts: hosts ?? [host], credentials: credential, sni: settings.serverName, name: name, settings: settings, ipv6DNS: ipv6DNS)
        }
    }
    public static func profile(host: String, credentials: Credentials, sni: String, name: String) throws -> DeviceProfile {
        try profile(hosts: [host], credentials: credentials, sni: sni, name: name, settings: ConnectionSettings())
    }
    public static func profile(hosts: [String], credentials: Credentials, sni: String, name: String, settings: ConnectionSettings, ipv6DNS: Bool = false) throws -> DeviceProfile {
        guard !hosts.isEmpty, hosts.allSatisfy(IPAddress.isValid) else { throw CascadeError("Некорректный адрес входного сервера.") }
        try Config.validateSNI(sni)
        var url = URLComponents(); let scheme = settings.scheme
        url.scheme = scheme.isVless ? "vless" : scheme.isNaive ? "naive+https" : "anytls"
        url.host = IPAddress.isIPv6(hosts[0]) ? "[" + hosts[0] + "]" : hosts[0]; url.port = Config.port
        if scheme.isVless { url.user = credentials.uuid }
        else if scheme.isNaive { url.user = credentials.uuid; url.password = credentials.uuid }
        else { url.user = credentials.uuid }
        var q = [URLQueryItem(name: "sni", value: sni)]
        if scheme.isVless {
            q += [URLQueryItem(name: "encryption", value: "none"), URLQueryItem(name: "security", value: scheme.isReality ? "reality" : "tls"), URLQueryItem(name: "type", value: scheme.transport ?? "tcp")]
            if scheme.vision { q.append(URLQueryItem(name: "flow", value: "xtls-rprx-vision")) }
            if scheme.isReality { q += [URLQueryItem(name: "fp", value: "chrome"), URLQueryItem(name: "pbk", value: credentials.publicKey), URLQueryItem(name: "sid", value: credentials.shortID)] }
            if ["ws", "http", "httpupgrade"].contains(scheme.transport ?? "") { q.append(URLQueryItem(name: "path", value: settings.path)) }
            if scheme.transport == "grpc" { q.append(URLQueryItem(name: "serviceName", value: settings.serviceName)) }
            if ["http", "httpupgrade"].contains(scheme.transport ?? "") { q.append(URLQueryItem(name: "host", value: sni)) }
        }
        if scheme == .naiveQUIC { q.append(URLQueryItem(name: "quic", value: "1")) }
        url.queryItems = q; url.fragment = name
        guard let link = url.string else { throw CascadeError("Не удалось сформировать ссылку профиля.") }
        return DeviceProfile(id: credentials.uuid, name: name, config: try Config.json(ProtocolConfig.client(hosts: hosts, credentials: credentials, settings: settings, realityName: sni, ipv6DNS: ipv6DNS)), link: link)
    }
    public static func add(to serverConfig: Data, name: String, userID: String = UUID().uuidString.lowercased()) throws -> Data {
        let name = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty, name.count <= 60, !name.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else { throw CascadeError("Имя устройства: от 1 до 60 символов, без управляющих знаков.") }
        guard UUID(uuidString: userID) != nil,
              var config = try JSONSerialization.jsonObject(with: serverConfig) as? [String: Any],
              var inbounds = config["inbounds"] as? [[String: Any]], inbounds.count == 1,
              var users = inbounds[0]["users"] as? [[String: Any]] else { throw CascadeError("Не удалось прочитать список устройств Cascade.") }
        let settings = try ConnectionSettings.read(config)
        guard !users.contains(where: { (($0["uuid"] ?? $0["password"]) as? String)?.lowercased() == userID.lowercased() }) else { throw CascadeError("Такой ключ устройства уже существует.") }
        guard !users.contains(where: { ($0["name"] as? String)?.caseInsensitiveCompare(name) == .orderedSame }) else { throw CascadeError("Устройство с таким именем уже есть. Выберите другое имя.") }
        var user = ["name": name, settings.scheme.isVless ? "uuid" : "password": userID.lowercased()]
        if settings.scheme.vision { user["flow"] = "xtls-rprx-vision" }
        if settings.scheme.isNaive { user["username"] = userID.lowercased() }
        users.append(user); inbounds[0]["users"] = users; config["inbounds"] = inbounds
        return try Config.json(config)
    }
    public static func digest(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
}
