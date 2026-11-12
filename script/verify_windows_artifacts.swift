import Foundation
import AppKit
import Vision
let root = URL(fileURLWithPath: CommandLine.arguments[1])
for (file, expectedFile) in [("qr-vless.png","link.txt"),("qr-json.png","client.json")] {
    let image = NSImage(contentsOf: root.appendingPathComponent(file))!
    var rect = CGRect(origin: .zero, size: image.size)
    let cg = image.cgImage(forProposedRect: &rect, context: nil, hints: nil)!
    let request = VNDetectBarcodesRequest(); request.symbologies = [.qr]
    try VNImageRequestHandler(cgImage: cg).perform([request])
    guard let payload = request.results?.first?.payloadStringValue else { fatalError("QR not decoded: \(file)") }
    let expected = try Data(contentsOf: root.appendingPathComponent(expectedFile))
    if file == "qr-vless.png" { guard payload == String(decoding: expected, as: UTF8.self) else { fatalError("URI mismatch") } }
    else {
        let actual = try JSONSerialization.jsonObject(with: Data(payload.utf8)) as! NSDictionary
        let wanted = try JSONSerialization.jsonObject(with: expected) as! NSDictionary
        guard actual.isEqual(to: wanted as! [AnyHashable:Any]) else { fatalError("JSON mismatch") }
    }
    print("PASS Apple Vision decoded \(file)")
}
