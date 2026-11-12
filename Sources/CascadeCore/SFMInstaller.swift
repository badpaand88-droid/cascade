import Foundation
import CryptoKit

public enum SFMInstaller {
    public static let packageHashes = [
        "Apple": "6eb140750dfdc386ebb5da3957e8d8024fee8f2316318b7b7b79e015a088274c",
        "Intel": "27de3ca781aa4e93ded22d76b65abee12b6778226c1fbee1218719dcd6beb29e"
    ]
    public static func download(cacheDirectory: URL? = nil) async throws -> URL {
        #if arch(arm64)
        let arch = "Apple"
        #else
        let arch = "Intel"
        #endif
        let name = "SFM-\(Config.version)-\(arch).pkg"
        let root = cacheDirectory ?? FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("ru.badpaand.Cascade/installers")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let package = root.appendingPathComponent(name)
        if !FileManager.default.fileExists(atPath: package.path) {
            let settings = URLSessionConfiguration.ephemeral
            settings.timeoutIntervalForResource = 360
            let session = URLSession(configuration: settings); defer { session.invalidateAndCancel() }
            let url = URL(string: "https://github.com/SagerNet/sing-box/releases/download/v\(Config.version)/" + name)!
            let (temp, response) = try await session.download(from: url)
            guard (response as? HTTPURLResponse)?.statusCode == 200 else { throw CascadeError("GitHub не отдал установщик SFM.") }
            try FileManager.default.moveItem(at: temp, to: package)
        }
        let digest = SHA256.hash(data: try Data(contentsOf: package)).map { String(format: "%02x", $0) }.joined()
        guard digest == packageHashes[arch] else {
            try? FileManager.default.removeItem(at: package)
            throw CascadeError("SHA-256 установщика SFM не совпал. Файл удалён, установка запрещена.")
        }
        let signature = try await Commands.run("/usr/sbin/pkgutil", ["--check-signature", package.path])
        guard signature.status == 0, signature.output.contains("Developer ID Installer:") else { throw CascadeError("Не подтверждена подпись официального установщика SFM.") }
        let assessment = try await Commands.run("/usr/sbin/spctl", ["--assess", "--type", "install", "--verbose=2", package.path], timeout: 90)
        guard assessment.status == 0 else { throw CascadeError("macOS не подтвердила доверие к установщику SFM. Проверка безопасности не отключалась.") }
        return package
    }
}
