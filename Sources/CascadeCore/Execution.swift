import Foundation
import CryptoKit
import Darwin

public struct CommandResult: Sendable {
    public init(status: Int32, output: String, error: String) { self.status = status; self.output = output; self.error = error }
    public let status: Int32
    public let output: String
    public let error: String
}

public enum Commands {
    /// Some proxy cores wait for active connections during graceful shutdown.
    /// Never let that block the installer or leave the loopback proxy running.
    public static func stop(_ process: Process) {
        guard process.isRunning else { return }
        process.terminate()
        for _ in 0..<20 { if !process.isRunning { break }; Thread.sleep(forTimeInterval: 0.05) }
        if process.isRunning { Darwin.kill(process.processIdentifier, SIGKILL) }
        process.waitUntilExit()
    }
    public static func run(_ executable: String, _ arguments: [String], input: String? = nil,
                           environment: [String: String] = [:], timeout: TimeInterval = 60) async throws -> CommandResult {
        try await Task.detached { try execute(executable, arguments, input: input, environment: environment, timeout: timeout) }.value
    }
    public static func execute(_ executable: String, _ arguments: [String], input: String? = nil,
                               environment: [String: String] = [:], timeout: TimeInterval = 60) throws -> CommandResult {
        let dir = try PrivateFiles.directory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let outURL = dir.appendingPathComponent("out"), errURL = dir.appendingPathComponent("err")
        try PrivateFiles.write(Data(), to: outURL); try PrivateFiles.write(Data(), to: errURL)
        let out = try FileHandle(forWritingTo: outURL), err = try FileHandle(forWritingTo: errURL)
        defer { try? out.close(); try? err.close() }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable); process.arguments = arguments
        process.environment = ProcessInfo.processInfo.environment.merging(environment) { _, new in new }
        process.standardOutput = out; process.standardError = err
        if let input {
            let inputURL = dir.appendingPathComponent("input")
            try PrivateFiles.write(Data(input.utf8), to: inputURL)
            process.standardInput = try FileHandle(forReadingFrom: inputURL)
        } else { process.standardInput = FileHandle.nullDevice }
        try process.run()
        let deadline = Date().addingTimeInterval(timeout)
        while process.isRunning && Date() < deadline { Thread.sleep(forTimeInterval: 0.05) }
        if process.isRunning {
            stop(process)
            throw CascadeError("Операция превысила время ожидания. Проверьте связь с сервером; при установке могла потребоваться проверка отката.")
        }
        process.waitUntilExit()
        return CommandResult(status: process.terminationStatus,
                             output: String(decoding: try Data(contentsOf: outURL), as: UTF8.self),
                             error: String(decoding: try Data(contentsOf: errURL), as: UTF8.self))
    }
}

public enum PrivateFiles {
    public static func directory() throws -> URL {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("bp-cascade-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        return dir
    }
    public static func write(_ data: Data, to url: URL) throws {
        // Create private from the outset; do not briefly create a world-readable secret.
        guard FileManager.default.createFile(atPath: url.path, contents: nil, attributes: [.posixPermissions: 0o600]) else { throw CascadeError("Не удалось создать защищённый временный файл.") }
        let h = try FileHandle(forWritingTo: url)
        defer { try? h.close() }
        try h.write(contentsOf: data)
    }
}

public struct HostIdentity: Sendable {
    public init(server: Server, knownHosts: String, fingerprint: String) { self.server=server; self.knownHosts=knownHosts; self.fingerprint=fingerprint }
    public let server: Server
    public let knownHosts: String
    public let fingerprint: String
}

public enum SSH {
    public static func scan(_ server: Server) async throws -> HostIdentity {
        try server.validate()
        let r = try await Commands.run("/usr/bin/ssh-keyscan", ["-T", "8", "-p", server.port, "-t", "ed25519", server.host], timeout: 15)
        let keys = r.output.split(separator: "\n").filter { !$0.hasPrefix("#") && $0.contains("ssh-ed25519 ") }.map(String.init)
        guard r.status == 0, !keys.isEmpty else { throw CascadeError("Не удалось получить SSH-ключ \(server.host):\(server.port). Проверьте адрес, порт и сетевой firewall.") }
        let dir = try PrivateFiles.directory(); defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appendingPathComponent("known_hosts")
        try PrivateFiles.write(Data((keys.joined(separator: "\n") + "\n").utf8), to: url)
        let f = try await Commands.run("/usr/bin/ssh-keygen", ["-lf", url.path, "-E", "sha256"])
        guard f.status == 0 else { throw CascadeError("Не удалось вычислить SSH-отпечаток.") }
        return HostIdentity(server: server, knownHosts: keys.joined(separator: "\n") + "\n", fingerprint: f.output.trimmingCharacters(in: .whitespacesAndNewlines))
    }
    public static func run(_ identity: HostIdentity, script: String, askpass: String, timeout: TimeInterval = 60, privileged: Bool = true) async throws -> CommandResult {
        let s = identity.server
        let dir = try PrivateFiles.directory(); defer { try? FileManager.default.removeItem(at: dir) }
        let known = dir.appendingPathComponent("known_hosts")
        try PrivateFiles.write(Data(identity.knownHosts.utf8), to: known)
        var args = ["-F", "/dev/null", "-T", "-p", s.port, "-l", s.user,
                    "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=\(known.path)", "-o", "GlobalKnownHostsFile=/dev/null",
                    "-o", "HostKeyAlgorithms=ssh-ed25519", "-o", "ConnectTimeout=12", "-o", "ServerAliveInterval=10",
                    "-o", "ServerAliveCountMax=3", "-o", "NumberOfPasswordPrompts=1", "-o", "ForwardAgent=no",
                    "-o", "ClearAllForwardings=yes", "-o", "ControlMaster=no", "-o", "ControlPath=none"]
        if s.useKey { args += ["-i", s.keyPath, "-o", "IdentitiesOnly=yes", "-o", "PreferredAuthentications=publickey"] }
        else { args += ["-o", "PubkeyAuthentication=no", "-o", "PreferredAuthentications=password,keyboard-interactive"] }
        args += [s.host, s.user == "root" || !privileged ? "exec env CASCADE_CONNECTION=\"$SSH_CONNECTION\" /bin/bash -s" : "exec sudo -n env CASCADE_CONNECTION=\"$SSH_CONNECTION\" /bin/bash -s"]
        return try await Commands.run("/usr/bin/ssh", args, input: script,
            environment: ["SSH_ASKPASS": askpass, "SSH_ASKPASS_REQUIRE": "force", "DISPLAY": "cascade:0", "CASCADE_SSH_SECRET": s.secret], timeout: timeout)
    }
}

public enum CoreDownload {
    public static func obtain() async throws -> URL {
        #if arch(arm64)
        let platform = "darwin-arm64"
        #else
        let platform = "darwin-amd64"
        #endif
        let root = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0].appendingPathComponent("ru.badpaand.Cascade/\(Config.version)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let archive = root.appendingPathComponent("\(platform).tar.gz")
        if !FileManager.default.fileExists(atPath: archive.path) {
            let config = URLSessionConfiguration.ephemeral
            config.timeoutIntervalForResource = 300
            let session = URLSession(configuration: config); defer { session.invalidateAndCancel() }
            let (file, response) = try await session.download(from: Releases.url(platform))
            guard (response as? HTTPURLResponse)?.statusCode == 200 else { throw CascadeError("GitHub не отдал официальный sing-box. Проверьте доступ к GitHub и повторите.") }
            try FileManager.default.moveItem(at: file, to: archive)
        }
        let hash = SHA256.hash(data: try Data(contentsOf: archive)).map { String(format: "%02x", $0) }.joined()
        guard hash == Releases.hashes[platform] else {
            try? FileManager.default.removeItem(at: archive)
            throw CascadeError("SHA-256 загруженного sing-box не совпал. Файл удалён; запуск запрещён.")
        }
        // Always extract from the verified archive; do not trust a previously modified executable.
        let extracted = root.appendingPathComponent("sing-box-\(Config.version)-\(platform)")
        if FileManager.default.fileExists(atPath: extracted.path) { try FileManager.default.removeItem(at: extracted) }
        let r = try await Commands.run("/usr/bin/tar", ["-xzf", archive.path, "-C", root.path])
        guard r.status == 0 else { throw CascadeError("Не удалось распаковать sing-box.") }
        return extracted.appendingPathComponent("sing-box")
    }
}

public enum Probe {
    public static func validate(_ config: Data, core: URL) async throws {
        let dir = try PrivateFiles.directory(); defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appendingPathComponent("config.json"); try PrivateFiles.write(config, to: url)
        let r = try await Commands.run(core.path, ["check", "-c", url.path])
        guard r.status == 0 else { throw CascadeError("sing-box отклонил конфигурацию. Экспорт остановлен. " + r.error.prefix(300)) }
    }
    public static func test(core: URL, host: String, credentials: Credentials, sni: String) async throws -> String {
        try await Task.detached { try testSynchronously(core: core, host: host, credentials: credentials, sni: sni) }.value
    }
    public static func test(core: URL, client: Data) async throws -> String {
        try await Task.detached { try testSynchronously(core: core, client: client) }.value
    }
    private static func testSynchronously(core: URL, host: String, credentials: Credentials, sni: String) throws -> String {
        try testSynchronously(core: core, client: Config.json(Config.client(host: host, credentials: credentials, sni: sni)))
    }
    private static func testSynchronously(core: URL, client: Data) throws -> String {
        let dir = try PrivateFiles.directory(); defer { try? FileManager.default.removeItem(at: dir) }
        // Reserve an available loopback port. Close immediately before the child binds it.
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { throw CascadeError("Не удалось выделить порт проверки.") }
        var addr = sockaddr_in(); addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size); addr.sin_family = sa_family_t(AF_INET)
        addr.sin_addr.s_addr = inet_addr("127.0.0.1"); addr.sin_port = 0
        let bound = withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        guard bound == 0 else { close(fd); throw CascadeError("Не удалось занять порт проверки.") }
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &length) } }
        let port = Int(UInt16(bigEndian: addr.sin_port)); close(fd)
        let url = dir.appendingPathComponent("probe.json")
        var config = try JSONSerialization.jsonObject(with: client) as! [String: Any]
        config["inbounds"] = [["type": "mixed", "listen": "127.0.0.1", "listen_port": port]]
        config["route"] = ["final": "cascade"]
        try PrivateFiles.write(try Config.json(config), to: url)
        let p = Process(); p.executableURL = core; p.arguments = ["run", "-c", url.path]
        p.standardOutput = FileHandle.nullDevice; p.standardError = FileHandle.nullDevice; p.standardInput = FileHandle.nullDevice
        try p.run()
        defer { Commands.stop(p) }
        Thread.sleep(forTimeInterval: 0.5)
        guard p.isRunning else { throw CascadeError("Локальный процесс проверки sing-box не запустился.") }
        let proxy = "socks5h://127.0.0.1:\(port)"
        let ip = try Commands.execute("/usr/bin/curl", ["--silent", "--show-error", "--fail", "--proxy", proxy, "--noproxy", "", "--connect-timeout", "12", "--max-time", "25", "https://api64.ipify.org"], timeout: 30)
        let value = ip.output.trimmingCharacters(in: .whitespacesAndNewlines)
        guard ip.status == 0, IPAddress.isValid(value) else { throw CascadeError("Сервисы установлены, но тест Mac → сервер 1 → сервер 2 не прошёл. Проверьте порт 443 в панели хостинга и доступность серверов у оператора. Другой включённый VPN тоже может влиять на тест.") }
        let https = try Commands.execute("/usr/bin/curl", ["--silent", "--show-error", "--fail", "--proxy", proxy, "--noproxy", "", "--connect-timeout", "12", "--max-time", "25", "-o", "/dev/null", "https://www.cloudflare.com/cdn-cgi/trace"], timeout: 30)
        guard https.status == 0 else { throw CascadeError("Выходной IP получен, но второй HTTPS-тест не прошёл. Конфиг можно сохранить для диагностики.") }
        return value
    }
}
