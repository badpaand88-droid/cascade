import XCTest
import AppKit
import Vision
import CascadeCore
@testable import CascadeMac

final class ProfileQRTests: XCTestCase {
    func testVLESSAndJSONQRCodeRoundTripWithAppleVision() throws {
        let credentials = Credentials()
        let profile = try DeviceProfiles.profile(host: "203.0.113.1", credentials: credentials, sni: "www.microsoft.com", name: "Телефон")
        for payload in [profile.link, try ProfileQR.compactJSON(profile.config)] {
            let image = try ProfileQR.image(payload: payload)
            var rect = CGRect(origin: .zero, size: image.size)
            let cgImage = try XCTUnwrap(image.cgImage(forProposedRect: &rect, context: nil, hints: nil))
            let request = VNDetectBarcodesRequest()
            request.symbologies = [.qr]
            try VNImageRequestHandler(cgImage: cgImage).perform([request])
            XCTAssertEqual(request.results?.first?.payloadStringValue, payload)
        }
    }
    @MainActor
    func testVisualStatusesAloneCannotSkipFingerprintTrust() {
        let model = InstallerModel()
        model.serverPhases = [.passed, .passed]
        XCTAssertFalse(model.canSkipFingerprints, "Only previously pinned matching SSH identities may bypass the trust step")
    }
    @MainActor
    func testSameServerIsRejectedBeforeAutonomousPreparation() {
        let model = InstallerModel()
        model.first.host = "203.0.113.1"; model.first.secret = "test"
        model.second.host = "203.0.113.1"; model.second.secret = "test"
        model.scan()
        XCTAssertNotNil(model.error)
        XCTAssertFalse(model.busy)
    }
}
