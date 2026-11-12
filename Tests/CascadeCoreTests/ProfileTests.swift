import XCTest
import Foundation
@testable import CascadeCore

final class ProfileTests: XCTestCase {
    func testAdditionalDeviceHasSeparateIDAndPreservesServerAndOtherUsers() throws {
        let server = Credentials()
        let original = try Config.json(Config.server(credentials: server, sni: "www.microsoft.com"))
        let updated = try DeviceProfiles.add(to: original, name: "iPhone / работа")
        let profiles = try DeviceProfiles.list(serverConfig: updated, host: "203.0.113.1", sni: "www.microsoft.com")
        XCTAssertEqual(profiles.count, 2)
        XCTAssertEqual(profiles[0].id, server.uuid)
        XCTAssertNotEqual(profiles[0].id, profiles[1].id)
        let url = try XCTUnwrap(URLComponents(string: profiles[1].link))
        XCTAssertEqual(url.scheme, "vless"); XCTAssertEqual(url.host, "203.0.113.1")
        XCTAssertEqual(url.user, profiles[1].id)
        XCTAssertEqual(url.fragment, "iPhone / работа")
        XCTAssertEqual(url.queryItems?.first(where: { $0.name == "pbk" })?.value, server.publicKey)
        XCTAssertFalse(profiles[1].link.contains(server.privateKey))
        XCTAssertFalse(String(decoding: profiles[1].config, as: UTF8.self).contains(server.privateKey))
        let oldConfig = try JSONSerialization.jsonObject(with: original) as! [String: Any]
        let newConfig = try JSONSerialization.jsonObject(with: updated) as! [String: Any]
        XCTAssertEqual(try Credentials(config: newConfig).privateKey, server.privateKey)
        XCTAssertEqual(try Config.json(["outbounds": oldConfig["outbounds"]!]), try Config.json(["outbounds": newConfig["outbounds"]!]))
        XCTAssertThrowsError(try DeviceProfiles.add(to: updated, name: "iPhone / работа"))
        XCTAssertThrowsError(try DeviceProfiles.add(to: updated, name: "New", userID: server.uuid))
        XCTAssertThrowsError(try DeviceProfiles.add(to: updated, name: "\n"))
        XCTAssertThrowsError(try DeviceProfiles.list(serverConfig: updated, host: "203.0.113.1", sni: "wrong.example.com"))
    }

    func testBPFMatchesOfficialLibboxWireFormat() throws {
        let dir = try PrivateFiles.directory(); defer { try? FileManager.default.removeItem(at: dir) }
        let config = try Config.json(Config.client(host: "203.0.113.1", credentials: Credentials(), sni: "www.microsoft.com"))
        let bpf = try PortableProfile.encode(name: "Cascade · Телефон", config: config)
        XCTAssertEqual(Array(bpf.prefix(2)), [3, 1])
        let file = dir.appendingPathComponent("profile.bpf"); try PrivateFiles.write(bpf, to: file)
        let decoder = """
        import gzip,sys,json,hashlib
        raw=open(sys.argv[1],'rb').read()
        assert raw[:2] == bytes([3,1])
        d=gzip.decompress(raw[2:]); pos=0
        def string():
            global pos
            size=shift=0
            while True:
                b=d[pos];pos+=1;size|=(b&127)<<shift
                if b<128:break
                shift+=7
            value=d[pos:pos+size];pos+=size
            return value
        name=string().decode();kind=int.from_bytes(d[pos:pos+4],'big');pos+=4
        config=string()
        assert pos==len(d) and kind==0
        json.loads(config)
        print(name)
        print(hashlib.sha256(config).hexdigest())
        """
        let result = try Commands.execute("/usr/bin/python3", ["-c", decoder, file.path])
        XCTAssertEqual(result.status, 0, result.error)
        XCTAssertEqual(result.output, "Cascade · Телефон\n" + DeviceProfiles.digest(config) + "\n")
    }

    func testAdditionalUserAndClientValidateWithRealCore() async throws {
        guard let path = ProcessInfo.processInfo.environment["CASCADE_TEST_CORE"] else { throw XCTSkip("Official test core required") }
        let server = try Config.json(Config.server(credentials: Credentials(), sni: "www.microsoft.com"))
        let updated = try DeviceProfiles.add(to: server, name: "Тест")
        let core = URL(fileURLWithPath: path)
        try await Probe.validate(updated, core: core)
        for profile in try DeviceProfiles.list(serverConfig: updated, host: "203.0.113.1", sni: "www.microsoft.com") { try await Probe.validate(profile.config, core: core) }
    }

    func testSFMInstallerDownloadVerification() async throws {
        guard ProcessInfo.processInfo.environment["CASCADE_SFM_PACKAGE_TEST"] == "1" else { throw XCTSkip("Opt-in official package download test") }
        let dir = try PrivateFiles.directory(); defer { try? FileManager.default.removeItem(at: dir) }
        let url = try await SFMInstaller.download(cacheDirectory: dir)
        XCTAssertTrue(FileManager.default.fileExists(atPath: url.path))
    }
}
