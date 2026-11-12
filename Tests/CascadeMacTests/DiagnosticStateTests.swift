import XCTest
@testable import CascadeMac

final class DiagnosticStateTests: XCTestCase {
    @MainActor
    func testLinkRequiresBothSuccessfulSSHChecksAndNoOperation() {
        let model = InstallerModel()
        XCTAssertFalse(model.canCheckLink)
        model.serverPhases = [.passed, .idle]
        XCTAssertFalse(model.canCheckLink)
        model.serverPhases = [.passed, .passed]
        XCTAssertTrue(model.canCheckLink)
        model.busy = true
        XCTAssertFalse(model.canCheckLink)
    }
    @MainActor
    func testEditingAccessInvalidatesConnectionAndDependentChecks() {
        let model = InstallerModel()
        model.serverPhases = [.passed, .passed]; model.linkPhase = .passed; model.tlsPhase = .passed
        model.first.port = "2222"
        XCTAssertEqual(model.serverPhases, [.idle, .passed])
        XCTAssertEqual(model.linkPhase, .idle)
        XCTAssertEqual(model.tlsPhase, .idle)
        XCTAssertFalse(model.canCheckLink)
        model.serverPhases = [.passed, .passed]
        model.second.secret = "new-test-password"
        XCTAssertEqual(model.serverPhases, [.passed, .idle])
    }
    @MainActor
    func testTLSNameChangeClearsOnlyTLSResult() {
        let model = InstallerModel()
        model.serverPhases = [.passed, .passed]; model.linkPhase = .passed; model.tlsPhase = .passed
        model.sni = "example.org"
        XCTAssertEqual(model.tlsPhase, .idle)
        XCTAssertEqual(model.linkPhase, .passed)
        XCTAssertEqual(model.serverPhases, [.passed, .passed])
    }
    @MainActor
    func testServerCanBeCheckedIndependentlyWithoutOtherAccess() async throws {
        let model = InstallerModel()
        model.checkServer(0)
        for _ in 0..<50 {
            if !model.busy { break }
            try await Task.sleep(for: .milliseconds(10))
        }
        XCTAssertEqual(model.serverPhases[0], .failed)
        XCTAssertEqual(model.serverPhases[1], .idle)
        XCTAssertFalse(model.busy)
        XCTAssertNotNil(model.error)
    }
}
