import XCTest
import Foundation
@testable import CascadeCore

/// Exercises the actual deployment/rollback shell, with filesystem paths redirected
/// to a private fixture and host commands replaced. No VPS or system service is touched.
final class DeploymentTests: XCTestCase {
    func testDeployReuseRollbackAndFailureRecovery() throws {
        try exerciseDeployment(version: "24.04")
    }

    func testUbuntu2604DeployReuseRollbackAndFailureRecovery() throws {
        try exerciseDeployment(version: "26.04")
    }

    func testUnlistedUbuntuVersionRemainsBlocked() throws {
        let f = try Fixture(version: "26.10"); defer { f.cleanup() }
        let r = try f.run(RemoteScripts.preflight(sni: "www.microsoft.com", peer: "198.51.100.2", role: "entry"))
        XCTAssertNotEqual(r.status, 0)
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.config.path))
    }

    func testDetachedDeviceRegistrationPreservesUsersAndRecoversFromRestartFailure() throws {
        let f = try Fixture(version: "26.04"); defer { f.cleanup() }
        let original = try Config.json(Config.server(credentials: Credentials(), sni: "www.microsoft.com"))
        let installed = try f.run(RemoteScripts.install(config: original, role: "entry", peer: "198.51.100.2", sni: "www.microsoft.com", transaction: "base", expectedDigest: nil))
        XCTAssertEqual(installed.status, 0, installed.error)
        let candidate = try DeviceProfiles.add(to: original, name: "Телефон")
        let queued = try f.run(RemoteScripts.updateClients(config: candidate, expectedDigest: DeviceProfiles.digest(original), peer: "198.51.100.2", transaction: "device1"))
        XCTAssertEqual(queued.status, 0, queued.error)
        XCTAssertTrue(queued.output.contains("CLIENT_UPDATE_STARTED"))
        let completed = try waitForDevice(f, transaction: "device1")
        XCTAssertTrue(completed.output.contains("CLIENT_UPDATE_SUCCESS"), completed.error)
        XCTAssertEqual(try Data(contentsOf: f.config), candidate)
        XCTAssertEqual(try DeviceProfiles.list(serverConfig: candidate, host: "203.0.113.1", sni: "www.microsoft.com").count, 2)
        XCTAssertFalse(f.exists("etc/bp-cascade/device-job.device1/worker.sh"), "Worker removes its embedded secrets after completion")

        let next = try DeviceProfiles.add(to: candidate, name: "Планшет")
        try Data().write(to: f.root.appendingPathComponent("fail-restart"))
        _ = try f.run(RemoteScripts.updateClients(config: next, expectedDigest: DeviceProfiles.digest(candidate), peer: "198.51.100.2", transaction: "device2"))
        let failed = try waitForDevice(f, transaction: "device2")
        XCTAssertTrue(failed.output.contains("CLIENT_UPDATE_FAILED"))
        XCTAssertEqual(try Data(contentsOf: f.config), candidate)
        XCTAssertTrue(f.exists("active"), "Previously working config is restarted on failure")

        _ = try f.run(RemoteScripts.updateClients(config: next, expectedDigest: DeviceProfiles.digest(original), peer: "198.51.100.2", transaction: "staleDevice"))
        let stale = try waitForDevice(f, transaction: "staleDevice")
        XCTAssertTrue(stale.output.contains("CLIENT_UPDATE_FAILED"))
        XCTAssertEqual(try Data(contentsOf: f.config), candidate)
    }

    private func waitForDevice(_ fixture: Fixture, transaction: String) throws -> CommandResult {
        let end = Date().addingTimeInterval(12)
        while Date() < end {
            let status = try fixture.run(RemoteScripts.clientUpdateStatus(transaction: transaction))
            if status.output.contains("CLIENT_UPDATE_SUCCESS") || status.output.contains("CLIENT_UPDATE_FAILED") { return status }
            Thread.sleep(forTimeInterval: 0.15)
        }
        throw CascadeError("Device update fixture timed out")
    }

    private func exerciseDeployment(version: String) throws {
        let f = try Fixture(version: version); defer { f.cleanup() }
        let credentials = Credentials()
        let config = try Config.json(Config.server(credentials: credentials, sni: "www.microsoft.com"))
        let first = try f.run(RemoteScripts.install(config: config, role: "exit", peer: "203.0.113.1", sni: "www.microsoft.com", transaction: "first", expectedDigest: nil))
        XCTAssertEqual(first.status, 0, first.error)
        XCTAssertTrue(first.output.contains("INSTALL_OK"))
        XCTAssertEqual(try Data(contentsOf: f.config), config)
        XCTAssertTrue(f.exists("active"))
        let digest = try f.digest()
        let second = try f.run(RemoteScripts.install(config: config, role: "exit", peer: "203.0.113.1", sni: "www.microsoft.com", transaction: "second", expectedDigest: digest))
        XCTAssertEqual(second.status, 0, second.error)
        let rollbackSecond = try f.run(RemoteScripts.rollback(transaction: "second"))
        XCTAssertEqual(rollbackSecond.status, 0, rollbackSecond.error)
        XCTAssertEqual(try Data(contentsOf: f.config), config)
        XCTAssertTrue(f.exists("active"), "Rollback of an update restores active service")
        XCTAssertTrue(f.exists("ufw-rule"), "Rollback must preserve a pre-existing firewall rule")
        let rollbackFirst = try f.run(RemoteScripts.rollback(transaction: "first"))
        XCTAssertEqual(rollbackFirst.status, 0, rollbackFirst.error)
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.config.path))
        XCTAssertFalse(f.exists("active"))
        XCTAssertFalse(f.exists("ufw-rule"))
        // Retained history/ownership markers must not prevent a fresh attempt.
        try Data().write(to: f.root.appendingPathComponent("fail-restart"))
        let failed = try f.run(RemoteScripts.install(config: config, role: "exit", peer: "203.0.113.1", sni: "www.microsoft.com", transaction: "failed", expectedDigest: nil))
        XCTAssertNotEqual(failed.status, 0)
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.config.path), "Failure trap rolls back new config")
        XCTAssertFalse(f.exists("active"))
        XCTAssertTrue(failed.error.contains("ROLLBACK_OK"))
        let retry = try f.run(RemoteScripts.install(config: config, role: "exit", peer: "203.0.113.1", sni: "www.microsoft.com", transaction: "retry", expectedDigest: nil))
        XCTAssertEqual(retry.status, 0, retry.error)
    }

    func testConcurrentConfigChangeStopsBeforeMutation() throws {
        let f = try Fixture(); defer { f.cleanup() }
        let config = try Config.json(Config.server(credentials: Credentials(), sni: "www.microsoft.com"))
        let r = try f.run(RemoteScripts.install(config: config, role: "entry", peer: "198.51.100.2", sni: "www.microsoft.com", transaction: "base", expectedDigest: nil))
        XCTAssertEqual(r.status, 0, r.error)
        let before = try Data(contentsOf: f.config)
        let stale = try f.run(RemoteScripts.install(config: config, role: "entry", peer: "198.51.100.2", sni: "www.microsoft.com", transaction: "stale", expectedDigest: String(repeating: "0", count: 64)))
        XCTAssertNotEqual(stale.status, 0)
        XCTAssertEqual(try Data(contentsOf: f.config), before)
        XCTAssertTrue(f.exists("active"))
        let unrelated = try f.run(RemoteScripts.rollback(transaction: "stale"))
        XCTAssertEqual(unrelated.status, 0)
        XCTAssertTrue(unrelated.output.contains("ROLLBACK_NOT_NEEDED"))
        XCTAssertTrue(f.exists("active"), "A failed new transaction must never roll back an earlier successful transaction")
    }

    func testOccupiedPortAndWrongPeerAreRejected() throws {
        let f = try Fixture(); defer { f.cleanup() }
        try Data().write(to: f.root.appendingPathComponent("port-busy"))
        let r = try f.run(RemoteScripts.preflight(sni: "www.microsoft.com", peer: "198.51.100.2", role: "entry"))
        XCTAssertNotEqual(r.status, 0)
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.config.path))
        try FileManager.default.removeItem(at: f.root.appendingPathComponent("port-busy"))
        let config = try Config.json(Config.server(credentials: Credentials(), sni: "www.microsoft.com"))
        XCTAssertEqual(try f.run(RemoteScripts.install(config: config, role: "entry", peer: "198.51.100.2", sni: "www.microsoft.com", transaction: "base", expectedDigest: nil)).status, 0)
        let wrong = try f.run(RemoteScripts.preflight(sni: "www.microsoft.com", peer: "198.51.100.99", role: "entry"))
        XCTAssertNotEqual(wrong.status, 0)
        XCTAssertTrue(f.exists("active"))
    }
}

private final class Fixture {
    let root: URL
    var config: URL { root.appendingPathComponent("etc/bp-cascade/config.json") }
    init(version: String = "24.04") throws {
        root = try PrivateFiles.directory()
        for path in ["bin", "etc/systemd/system", "run/systemd/system", "run/lock", "opt", "etc/ssl/certs"] {
            try FileManager.default.createDirectory(at: root.appendingPathComponent(path), withIntermediateDirectories: true)
        }
        try Data("ID=ubuntu\nVERSION_ID=\(version)\n".utf8).write(to: root.appendingPathComponent("etc/os-release"))
        try Data().write(to: root.appendingPathComponent("etc/ssl/certs/ca-certificates.crt"))
        let common = "#!/bin/bash\nset -eu\n"
        let mocks: [String: String] = [
            "id": "if test \"${1:-}\" = -u; then echo 0; fi",
            "uname": "echo x86_64",
            "getent": "exit 0", "chown": "exit 0", "flock": "exit 0",
            "timeout": "shift; exec \"$@\"", "openssl": "echo 'New, TLSv1.3, Cipher is TLS_AES_128_GCM_SHA256'",
            "base64": "if test \"${1:-}\" = -w0; then shift; /usr/bin/base64 \"$@\" | tr -d '\\n'; else /usr/bin/base64 \"$@\"; fi",
            "sha256sum": "if test \"${1:-}\" = -c; then cat >/dev/null; exit 0; fi; exec /usr/bin/shasum -a 256 \"$@\"",
            "ss": "if test -f \"$FAKE_ROOT/port-busy\"; then echo 'LISTEN 0 4096 0.0.0.0:443 users:((\"other\",pid=999,fd=1))'; elif test -f \"$FAKE_ROOT/active\"; then echo 'LISTEN 0 4096 0.0.0.0:443 users:((\"sing-box\",pid=101,fd=1))'; fi",
            "curl": "while test $# -gt 0; do if test \"$1\" = -o; then shift; touch \"$1\"; fi; shift; done",
            "tar": "while test $# -gt 0; do if test \"$1\" = -C; then shift; dest=$1; fi; shift; done; mkdir -p \"$dest/sing-box-1.14.4-linux-amd64\"; printf '#!/bin/sh\\nexit 0\\n' > \"$dest/sing-box-1.14.4-linux-amd64/sing-box\"; chmod 755 \"$dest/sing-box-1.14.4-linux-amd64/sing-box\"",
            "install": "args=(); while test $# -gt 0; do case \"$1\" in -o|-g) shift 2 ;; *) args+=(\"$1\"); shift ;; esac; done; exec /usr/bin/install \"${args[@]}\"",
            "systemctl": """
            case "$1" in
              show) if test -f "$FAKE_ROOT/active"; then echo 101; else echo 0; fi ;;
              is-active) test -f "$FAKE_ROOT/active" ;;
              is-enabled) test -f "$FAKE_ROOT/enabled" ;;
              enable) touch "$FAKE_ROOT/enabled" ;;
              disable) rm -f "$FAKE_ROOT/enabled" ;;
              start) touch "$FAKE_ROOT/active" ;;
              restart) if test -f "$FAKE_ROOT/fail-restart"; then rm "$FAKE_ROOT/fail-restart"; exit 1; fi; touch "$FAKE_ROOT/active" ;;
              stop) rm -f "$FAKE_ROOT/active" ;;
              daemon-reload) exit 0 ;;
              *) exit 1 ;;
            esac
            """,
            "ufw": """
            if test "$1" = status; then echo 'Status: active';
            elif test "$1" = --force; then rm -f "$FAKE_ROOT/ufw-rule";
            elif test -f "$FAKE_ROOT/ufw-rule"; then echo 'Skipping adding existing rule';
            else touch "$FAKE_ROOT/ufw-rule"; echo 'Rule added'; fi
            """
        ]
        for (name, body) in mocks {
            let path = root.appendingPathComponent("bin/" + name)
            try PrivateFiles.write(Data((common + body + "\n").utf8), to: path)
            try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: path.path)
        }
    }
    func exists(_ name: String) -> Bool { FileManager.default.fileExists(atPath: root.appendingPathComponent(name).path) }
    func digest() throws -> String {
        let r = try Commands.execute("/usr/bin/shasum", ["-a", "256", config.path])
        return String(r.output.split(separator: " ")[0])
    }
    func run(_ script: String) throws -> CommandResult {
        var remapped = script
        for path in ["/etc/bp-cascade", "/etc/systemd/system", "/etc/os-release", "/opt/bp-cascade", "/run/lock", "/run/systemd/system", "/etc/ssl/certs/ca-certificates.crt"] {
            remapped = remapped.replacingOccurrences(of: path, with: root.path + path)
        }
        return try Commands.execute("/bin/bash", ["-s"], input: remapped,
            environment: ["FAKE_ROOT": root.path, "PATH": root.appendingPathComponent("bin").path + ":/usr/bin:/bin:/usr/sbin:/sbin"], timeout: 30)
    }
    func cleanup() { try? FileManager.default.removeItem(at: root) }
}
