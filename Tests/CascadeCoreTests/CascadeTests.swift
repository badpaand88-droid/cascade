import XCTest
import Foundation
import Darwin
@testable import CascadeCore

final class CascadeTests: XCTestCase {
    func testInputValidationRejectsSSHAndShellInjection() throws {
        for host in ["-oProxyCommand=touch /tmp/x", "1.2.3.4;id", "001.2.3.4", "1.2.3.256", "1.2.3", "example.com"] {
            var s = Server(); s.host = host; s.secret = "test"
            XCTAssertThrowsError(try s.validate(), host)
        }
        var s = Server(); s.host = "203.0.113.1"; s.secret = "test"
        XCTAssertNoThrow(try s.validate())
        s.user = "root;id"; XCTAssertThrowsError(try s.validate())
        XCTAssertThrowsError(try Config.validateSNI("example.com;id"))
        XCTAssertThrowsError(try Config.validateSNI("https://example.com"))
        XCTAssertNoThrow(try Config.validateSNI("www.microsoft.com"))
    }

    func testServerChainAndCredentialReuse() throws {
        let entry = Credentials(), exit = Credentials()
        let outbound = Config.outbound(host: "198.51.100.2", credentials: exit, sni: "www.microsoft.com")
        let config = Config.server(credentials: entry, sni: "www.microsoft.com", next: outbound)
        XCTAssertEqual((config["route"] as? [String: Any])?["final"] as? String, "cascade")
        XCTAssertEqual((config["outbounds"] as? [[String: Any]])?.count, 1, "Entry has no direct fallback")
        let restored = try Credentials(config: config)
        XCTAssertEqual(restored.publicKey, entry.publicKey)
        XCTAssertEqual(restored.uuid, entry.uuid)
        XCTAssertEqual(restored.shortID, entry.shortID)
        let client = try Config.json(Config.client(host: "203.0.113.1", credentials: entry, sni: "www.microsoft.com"))
        let text = String(decoding: client, as: UTF8.self)
        XCTAssertFalse(text.contains(entry.privateKey))
        XCTAssertFalse(text.contains(exit.privateKey))
        XCTAssertFalse(text.contains(exit.uuid))
        XCTAssertFalse(text.contains("198.51.100.2"), "Client knows only entry")
        XCTAssertFalse(text.contains("insecure"))
    }

    func testPrivateFiles() throws {
        let dir = try PrivateFiles.directory(); defer { try? FileManager.default.removeItem(at: dir) }
        let file = dir.appendingPathComponent("secret")
        try PrivateFiles.write(Data("secret".utf8), to: file)
        let perms = try FileManager.default.attributesOfItem(atPath: file.path)[.posixPermissions] as? NSNumber
        XCTAssertEqual(perms?.intValue, 0o600)
        let dirPerms = try FileManager.default.attributesOfItem(atPath: dir.path)[.posixPermissions] as? NSNumber
        XCTAssertEqual(dirPerms?.intValue, 0o700)
    }

    func testShellQuotingAndScriptsParse() throws {
        let dir = try PrivateFiles.directory(); defer { try? FileManager.default.removeItem(at: dir) }
        let quoted = RemoteScripts.quote("password ' \n $(touch /tmp/never-cascade-test) `id`")
        let r = try Commands.execute("/bin/bash", ["-c", "printf %s " + quoted])
        XCTAssertEqual(r.output, "password ' \n $(touch /tmp/never-cascade-test) `id`")
        let config = try Config.json(Config.server(credentials: Credentials(), sni: "www.microsoft.com"))
        let scripts = [RemoteScripts.preflight(sni: "www.microsoft.com", peer: "203.0.113.1", role: "exit"),
            RemoteScripts.install(config: config, role: "exit", peer: "203.0.113.1", sni: "www.microsoft.com", transaction: "fixture", expectedDigest: nil),
            RemoteScripts.rollback(transaction: "fixture")]
        for (i, script) in scripts.enumerated() {
            let path = dir.appendingPathComponent("\(i).sh"); try PrivateFiles.write(Data(script.utf8), to: path)
            let r = try Commands.execute("/bin/bash", ["-n", path.path])
            XCTAssertEqual(r.status, 0, r.error)
        }
        XCTAssertTrue(scripts[1].contains("sha256sum -c"))
        XCTAssertFalse(scripts[1].contains("ufw reset"))
        XCTAssertFalse(scripts[1].contains("sshd_config"))
    }

    func testDiagnosticScriptsAreReadOnlyAndValidateTargets() throws {
        let link = try Diagnostics.link(host: "198.51.100.2", sshPort: "2222")
        let tls = try Diagnostics.tls(host: "www.microsoft.com")
        for script in [Diagnostics.ssh, link, tls] {
            let result = try Commands.execute("/bin/bash", ["-n"], input: script)
            XCTAssertEqual(result.status, 0, result.error)
            XCTAssertFalse(script.contains("apt-get"))
            XCTAssertFalse(script.contains("systemctl"))
            XCTAssertFalse(script.contains("ufw "))
        }
        XCTAssertTrue(link.contains("/2222"))
        XCTAssertTrue(link.contains("/443"))
        XCTAssertTrue(tls.contains("-verify_hostname 'www.microsoft.com'"))
        XCTAssertTrue(tls.contains("-verify_return_error"))
        XCTAssertThrowsError(try Diagnostics.link(host: "1.2.3.4;id", sshPort: "22"))
        XCTAssertThrowsError(try Diagnostics.link(host: "198.51.100.2", sshPort: "22;id"))
        XCTAssertThrowsError(try Diagnostics.tls(host: "example.com;id"))
    }

    func testLocalTLS13WithSystemTrust() async throws {
        guard ProcessInfo.processInfo.environment["CASCADE_NETWORK_TEST"] == "1" else { throw XCTSkip("Opt-in TLS network test") }
        try await Diagnostics.localTLS(host: "www.microsoft.com")
    }

    func testInterServerDiagnosticAgainstRealLoopbackSocket() throws {
        guard ProcessInfo.processInfo.environment["CASCADE_NETWORK_TEST"] == "1" else { throw XCTSkip("Opt-in TCP network test") }
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        XCTAssertGreaterThanOrEqual(fd, 0)
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET); address.sin_addr.s_addr = inet_addr("127.0.0.1")
        let status = withUnsafePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        guard status == 0, listen(fd, 4) == 0 else { close(fd); throw CascadeError("Loopback fixture failed") }
        var size = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &size) } }
        let port = String(UInt16(bigEndian: address.sin_port))
        // macOS lacks GNU timeout; the enclosing runner bounds the localhost-only test.
        let script = "timeout() { shift; \"$@\"; }\n" + (try Diagnostics.link(host: "127.0.0.1", sshPort: port))
            .replacingOccurrences(of: "/443'", with: "/" + port + "'")
        let open: CommandResult
        do { open = try Commands.execute("/bin/bash", ["-s"], input: script, timeout: 10) }
        catch { close(fd); throw error }
        close(fd)
        XCTAssertEqual(open.status, 0, open.error)
        XCTAssertTrue(open.output.contains("TCP_SSH_OK"))
        let closed = try Commands.execute("/bin/bash", ["-s"], input: script, timeout: 10)
        XCTAssertNotEqual(closed.status, 0)
        XCTAssertFalse(closed.output.contains("LINK_OK"))
    }

    func testProcessInputAndTimeout() throws {
        let r = try Commands.execute("/bin/cat", [], input: "private input")
        XCTAssertEqual(r.output, "private input")
        XCTAssertThrowsError(try Commands.execute("/bin/sleep", ["5"], timeout: 0.1))
    }

    func testProxyShutdownIsBoundedWhenTermIsIgnored() throws {
        let p = Process(); p.executableURL = URL(fileURLWithPath: "/bin/bash")
        p.arguments = ["-c", "trap '' TERM; exec /bin/sleep 30"]
        p.standardInput = FileHandle.nullDevice; p.standardOutput = FileHandle.nullDevice; p.standardError = FileHandle.nullDevice
        try p.run(); Thread.sleep(forTimeInterval: 0.1)
        let start = Date(); Commands.stop(p)
        XCTAssertFalse(p.isRunning)
        XCTAssertLessThan(Date().timeIntervalSince(start), 3)
    }

    func testGeneratedConfigurationsWithRealCore() async throws {
        guard let path = ProcessInfo.processInfo.environment["CASCADE_TEST_CORE"] else { throw XCTSkip("Set CASCADE_TEST_CORE to the verified official sing-box binary") }
        let core = URL(fileURLWithPath: path)
        let a = Credentials(), b = Credentials()
        let configs = [Config.server(credentials: b, sni: "www.microsoft.com"),
            Config.server(credentials: a, sni: "www.microsoft.com", next: Config.outbound(host: "198.51.100.2", credentials: b, sni: "www.microsoft.com")),
            Config.client(host: "203.0.113.1", credentials: a, sni: "www.microsoft.com"),
            Config.probe(host: "203.0.113.1", credentials: a, sni: "www.microsoft.com", localPort: 18080)]
        for config in configs { try await Probe.validate(Config.json(config), core: core) }
    }

    func testLocalRealityCascadeEndToEnd() throws {
        guard ProcessInfo.processInfo.environment["CASCADE_NETWORK_TEST"] == "1",
              let path = ProcessInfo.processInfo.environment["CASCADE_TEST_CORE"] else { throw XCTSkip("Opt-in network integration test") }
        let results = try Self.localChain(path: path)
        XCTAssertEqual(results.0.status, 0, results.0.error)
        XCTAssertTrue(Server.isIPv4(results.0.output.trimmingCharacters(in: .whitespacesAndNewlines)))
        XCTAssertNotEqual(results.1.status, 0)
    }

    private static func localChain(path: String) throws -> (CommandResult, CommandResult) {
        let dir = try PrivateFiles.directory(); defer { try? FileManager.default.removeItem(at: dir) }
        let a = Credentials(), b = Credentials(), core = URL(fileURLWithPath: path)
        let sni = "www.microsoft.com"
        var next = Config.outbound(host: "127.0.0.1", credentials: b, sni: sni); next["server_port"] = 32444
        var exit = Config.server(credentials: b, sni: sni), entry = Config.server(credentials: a, sni: sni, next: next)
        for (port, name) in [(32444, "exit"), (32443, "entry")] {
            var config = name == "exit" ? exit : entry
            var inbound = (config["inbounds"] as! [[String: Any]])[0]
            inbound["listen"] = "127.0.0.1"; inbound["listen_port"] = port
            config["inbounds"] = [inbound]
            if name == "exit" { exit = config } else { entry = config }
        }
        var probe = Config.probe(host: "127.0.0.1", credentials: a, sni: sni, localPort: 32445)
        var out = (probe["outbounds"] as! [[String: Any]])[0]; out["server_port"] = 32443; probe["outbounds"] = [out]
        var children: [Process] = []
        defer { for p in children.reversed() { Commands.stop(p) } }
        for (i, config) in [exit, entry, probe].enumerated() {
            let url = dir.appendingPathComponent("\(i).json"); try PrivateFiles.write(Config.json(config), to: url)
            let p = Process(); p.executableURL = core; p.arguments = ["run", "-c", url.path]
            p.standardInput = FileHandle.nullDevice; p.standardOutput = FileHandle.nullDevice; p.standardError = FileHandle.nullDevice
            try p.run(); children.append(p)
        }
        Thread.sleep(forTimeInterval: 1)
        guard children.allSatisfy(\.isRunning) else { throw CascadeError("Test core failed to start") }
        let r = try Commands.execute("/usr/bin/curl", ["--fail", "--silent", "--show-error", "--proxy", "socks5h://127.0.0.1:32445", "--noproxy", "", "--max-time", "30", "https://api.ipify.org"], timeout: 35)
        // Breaking the exit must break the chain: no fallback to direct Internet.
        Commands.stop(children[0])
        let broken = try Commands.execute("/usr/bin/curl", ["--fail", "--silent", "--proxy", "socks5h://127.0.0.1:32445", "--noproxy", "", "--max-time", "5", "https://api.ipify.org"], timeout: 8)
        return (r, broken)
    }
}
