import AppKit
import CoreImage
import CoreImage.CIFilterBuiltins
import CascadeCore
import SwiftUI

enum ProfileQR {
    static func image(payload: String) throws -> NSImage {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(payload.utf8); filter.correctionLevel = "M"
        guard let code = filter.outputImage else { throw CascadeError("Конфиг слишком велик для QR. Используйте файл JSON или BPF.") }
        let bordered = code.extent.insetBy(dx: -4, dy: -4)
        let white = CIImage(color: CIColor.white).cropped(to: bordered)
        let composed = code.composited(over: white).transformed(by: CGAffineTransform(scaleX: 8, y: 8))
        let context = CIContext(options: [.useSoftwareRenderer: true])
        guard let image = context.createCGImage(composed, from: composed.extent) else { throw CascadeError("Не удалось нарисовать QR.") }
        return NSImage(cgImage: image, size: NSSize(width: image.width, height: image.height))
    }
    static func compactJSON(_ data: Data) throws -> String {
        let object = try JSONSerialization.jsonObject(with: data)
        return String(decoding: try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes]), as: UTF8.self)
    }
}

struct ProfileQRSheet: View {
    let profile: DeviceProfile
    @Environment(\.dismiss) private var dismiss
    @State private var format = 0
    @State private var error: String?
    var payload: String { format == 0 ? profile.link : (try? ProfileQR.compactJSON(profile.config)) ?? "" }
    var body: some View {
        VStack(spacing: 18) {
            HStack { VStack(alignment: .leading, spacing: 5) { Text(profile.name).font(.title2.bold()); Text("Профиль подключения").font(.caption).foregroundStyle(.secondary) }; Spacer(); Button("Готово") { dismiss() } }
            Picker("Формат", selection: $format) { Text("Ссылка").tag(0); Text("JSON sing-box").tag(1) }.pickerStyle(.segmented)
            if let image = try? ProfileQR.image(payload: payload) {
                Image(nsImage: image).interpolation(.none).resizable().aspectRatio(contentMode: .fit).frame(width: 320, height: 320).background(.white)
            } else { Text("Профиль не помещается в QR. Сохраните JSON-файл.").foregroundStyle(.orange) }
            Text(format == 0 ? "Для совместимых клиентов. Ссылка содержит один адрес; для IPv4/IPv6 Авто используйте JSON/BPF. В SFM используйте импорт BPF или JSON-файла." : "Полный конфиг JSON. Поддержка сканирования зависит от клиента; для SFM надёжнее файл BPF.")
                .font(.caption).foregroundStyle(.secondary).multilineTextAlignment(.center)
            Text("QR содержит ключ доступа. Передавайте его только владельцу устройства.").font(.caption).foregroundStyle(.orange)
            HStack {
                Button("Скопировать") { NSPasteboard.general.clearContents(); NSPasteboard.general.setString(payload, forType: .string) }
                Button("Сохранить QR PNG") { save() }
            }
            if let error { Text(error).font(.caption).foregroundStyle(.orange) }
        }.padding(28).frame(width: 460).preferredColorScheme(.dark)
    }
    func save() {
        do {
            let image = try ProfileQR.image(payload: payload)
            let panel = NSSavePanel(); panel.nameFieldStringValue = "Cascade-QR.png"; panel.allowedContentTypes = [.png]
            guard panel.runModal() == .OK, let url = panel.url,
                  let tiff = image.tiffRepresentation, let bitmap = NSBitmapImageRep(data: tiff),
                  let data = bitmap.representation(using: .png, properties: [:]) else { return }
            let temporary = url.deletingLastPathComponent().appendingPathComponent(".cascade-qr-" + UUID().uuidString)
            defer { try? FileManager.default.removeItem(at: temporary) }
            try PrivateFiles.write(data, to: temporary)
            if FileManager.default.fileExists(atPath: url.path) { _ = try FileManager.default.replaceItemAt(url, withItemAt: temporary) }
            else { try FileManager.default.moveItem(at: temporary, to: url) }
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        } catch { self.error = error.localizedDescription }
    }
}
