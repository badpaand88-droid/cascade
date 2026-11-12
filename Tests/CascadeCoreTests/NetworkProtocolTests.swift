import XCTest
import Foundation
@testable import CascadeCore

final class NetworkProtocolTests: XCTestCase {
    func testAddressFamiliesCanonicalizationAndStrictInput() throws {
        for host in ["203.0.113.10", "2001:db8::1", "::1", "2001:0DB8:0000::1"] {
            var s = Server(); s.host = host; s.secret = "test"; try s.validate()
        }
        for host in ["[::1]", "fe80::1%en0", "::1;id", "001.2.3.4", "-oProxyCommand=id", "2001:db8::1\n", "example.com"] {
            var s = Server(); s.host = host; s.secret = "test"; XCTAssertThrowsError(try s.validate(), host)
        }
        XCTAssertEqual(IPAddress.canonical("2001:0DB8:0000::1"), "2001:db8::1")
        var s = Server(); s.host = "203.0.113.10"; s.tunnelIPv6 = "2001:db8::1"
        XCTAssertEqual(try s.endpoints(), ["203.0.113.10", "2001:db8::1"])
        s.addressMode = .ipv6; XCTAssertEqual(try s.endpoints(), ["2001:db8::1"])
        s.tunnelIPv6 = ""; XCTAssertThrowsError(try s.endpoints())
        XCTAssertTrue(try Diagnostics.link(host: "2001:db8::1", sshPort: "22").contains("/dev/tcp/2001:db8::1/443"))
    }
    func testProtocolRoundTripAndCoreMatrix() async throws {
        guard let binary = ProcessInfo.processInfo.environment["CASCADE_TEST_CORE"] else { throw XCTSkip("Official core required") }
        let dir = try PrivateFiles.directory(); defer { try? FileManager.default.removeItem(at: dir) }
        let conf = dir.appendingPathComponent("openssl.cnf")
        try PrivateFiles.write(Data("[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n[dn]\nCN=cascade.test\n[ext]\nsubjectAltName=DNS:cascade.test\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,digitalSignature,keyEncipherment,keyCertSign\n".utf8), to: conf)
        let cert = dir.appendingPathComponent("cert.pem"), key = dir.appendingPathComponent("key.pem")
        let r = try await Commands.run("/usr/bin/openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "30", "-config", conf.path, "-keyout", key.path, "-out", cert.path])
        XCTAssertEqual(r.status, 0, r.error)
        let pem = try String(contentsOf: cert, encoding: .utf8), secret = try String(contentsOf: key, encoding: .utf8)
        let export = ProcessInfo.processInfo.environment["CASCADE_MATRIX_OUTPUT"].map { URL(fileURLWithPath: $0) }
        if let export { try FileManager.default.createDirectory(at: export, withIntermediateDirectories: true); try PrivateFiles.write(Data(pem.utf8), to: export.appendingPathComponent("cert.pem")); try PrivateFiles.write(Data(secret.utf8), to: export.appendingPathComponent("key.pem")) }
        var all: [(ConnectionSettings, Credentials)] = []
        for scheme in ConnectionScheme.allCases {
            var s = ConnectionSettings(); s.scheme = scheme; s.serverName = "cascade.test"; s.certificate = pem; s.key = secret
            try s.validate(realityName: "www.microsoft.com")
            let c = Credentials(); all.append((s,c))
            let config = ProtocolConfig.server(credentials: c, settings: s, realityName: "www.microsoft.com")
            let data = try Config.json(config)
            try await Probe.validate(data, core: URL(fileURLWithPath: binary))
            XCTAssertEqual(try ConnectionSettings.read(config).scheme, scheme)
            XCTAssertEqual(try Credentials(config: config).uuid, c.uuid)
            let updated = try DeviceProfiles.add(to: data, name: "iPhone")
            let profiles = try DeviceProfiles.list(serverConfig: updated, host: "2001:db8::1", sni: "www.microsoft.com", hosts: ["203.0.113.1", "2001:db8::1"])
            XCTAssertEqual(profiles.count, 2)
            for p in profiles {
                XCTAssertFalse(String(decoding: p.config, as: UTF8.self).contains(secret))
                try await Probe.validate(p.config, core: URL(fileURLWithPath: binary))
            }
            let single = try DeviceProfiles.profile(hosts: ["2001:db8::1"], credentials: c, sni: s.scheme.isReality ? "www.microsoft.com" : "cascade.test", name: "IPv6", settings: s)
            XCTAssertTrue(single.link.contains("@[2001:db8::1]:443"))
            if let export {
                try PrivateFiles.write(data, to: export.appendingPathComponent(scheme.rawValue + "-server.json"))
                let client = ProtocolConfig.client(hosts: ["::1"], credentials: c, settings: s, realityName: "www.microsoft.com")
                try PrivateFiles.write(Config.json(client), to: export.appendingPathComponent(scheme.rawValue + "-client.json"))
            }
        }
        // Every supported entry can use every supported inter-server scheme.
        for (a, ca) in all { for (b, cb) in all {
            let config = ProtocolConfig.server(credentials: ca, settings: a, realityName: "www.microsoft.com", next: ProtocolConfig.outbounds(hosts: ["198.51.100.2", "2001:db8::2"], credentials: cb, settings: b, realityName: "www.microsoft.com"))
            try await Probe.validate(Config.json(config), core: URL(fileURLWithPath: binary))
        } }
    }
}
