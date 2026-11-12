import Foundation
import CryptoKit

public struct DeviceProfile: Identifiable, Sendable {
    public let id: String
    public let name: String
    public let config: Data
    public let link: String
}

public enum DeviceProfiles {
    public static func list(serverConfig: Data, host: String, sni: String) throws -> [DeviceProfile] {
        guard let config = try JSONSerialization.jsonObject(with: serverConfig) as? [String: Any],
              let inbound = (config["inbounds"] as? [[String: Any]])?.first,
              inbound["type"] as? String == "vless",
              let tls = inbound["tls"] as? [String: Any], tls["server_name"] as? String == sni,
              let users = inbound["users"] as? [[String: Any]] else { throw CascadeError("Не найден входящий VLESS-конфиг Cascade.") }
        let server = try Credentials(config: config)
        return try users.enumerated().map { index, user in
            guard let uuid = user["uuid"] as? String else { throw CascadeError("Повреждён список устройств.") }
            let credential = try Credentials(server: server, userID: uuid)
            let name = user["name"] as? String ?? (index == 0 ? "Основной профиль" : "Устройство \(index + 1)")
            return try profile(host: host, credentials: credential, sni: sni, name: name)
        }
    }
    public static func profile(host: String, credentials: Credentials, sni: String, name: String) throws -> DeviceProfile {
        guard Server.isIPv4(host) else { throw CascadeError("Некорректный адрес входного сервера.") }
        try Config.validateSNI(sni)
        var url = URLComponents()
        url.scheme = "vless"; url.user = credentials.uuid; url.host = host; url.port = Config.port
        url.queryItems = [URLQueryItem(name: "encryption", value: "none"), URLQueryItem(name: "security", value: "reality"),
            URLQueryItem(name: "sni", value: sni), URLQueryItem(name: "fp", value: "chrome"),
            URLQueryItem(name: "pbk", value: credentials.publicKey), URLQueryItem(name: "sid", value: credentials.shortID),
            URLQueryItem(name: "type", value: "tcp"), URLQueryItem(name: "flow", value: "xtls-rprx-vision")]
        url.fragment = name
        guard let link = url.string else { throw CascadeError("Не удалось сформировать ссылку профиля.") }
        return DeviceProfile(id: credentials.uuid, name: name,
            config: try Config.json(Config.client(host: host, credentials: credentials, sni: sni)), link: link)
    }
    public static func add(to serverConfig: Data, name: String, userID: String = UUID().uuidString.lowercased()) throws -> Data {
        let name = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty, name.count <= 60, !name.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else { throw CascadeError("Имя устройства: от 1 до 60 символов, без управляющих знаков.") }
        guard UUID(uuidString: userID) != nil,
              var config = try JSONSerialization.jsonObject(with: serverConfig) as? [String: Any],
              var inbounds = config["inbounds"] as? [[String: Any]], inbounds.count == 1,
              inbounds[0]["type"] as? String == "vless",
              var users = inbounds[0]["users"] as? [[String: Any]] else { throw CascadeError("Не удалось прочитать список устройств Cascade.") }
        guard !users.contains(where: { ($0["uuid"] as? String)?.lowercased() == userID.lowercased() }) else { throw CascadeError("Такой ключ устройства уже существует.") }
        guard !users.contains(where: { ($0["name"] as? String)?.caseInsensitiveCompare(name) == .orderedSame }) else { throw CascadeError("Устройство с таким именем уже есть. Выберите другое имя.") }
        users.append(["name": name, "uuid": userID.lowercased(), "flow": "xtls-rprx-vision"])
        inbounds[0]["users"] = users; config["inbounds"] = inbounds
        return try Config.json(config)
    }
    public static func digest(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
}
