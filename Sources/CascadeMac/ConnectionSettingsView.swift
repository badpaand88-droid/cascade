import SwiftUI
import AppKit
import CascadeCore

struct ConnectionSettingsView: View {
    @Binding var settings: ConnectionSettings
    let title: String
    @State private var fileError: String?
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(title).font(.system(size: 12, weight: .semibold))
            Picker("Схема", selection: $settings.scheme) {
                ForEach(ConnectionScheme.allCases, id: \.self) { Text($0.title).tag($0) }
            }.labelsHidden()
            if settings.scheme.isReality {
                Text("Без собственного домена. Внешний TLS-сайт задаётся ниже.").font(.caption).foregroundStyle(.secondary)
            } else {
                TextField("Домен этого VPS, например vpn.example.com", text: $settings.serverName).textFieldStyle(.roundedBorder)
                Text("Нужны ваш домен, действующая полная цепочка PEM и соответствующий незашифрованный ключ. Проверим имя, доверие и срок сертификата до установки.").font(.caption).foregroundStyle(.secondary)
                HStack {
                    Button(settings.certificate.isEmpty ? "Сертификат PEM…" : "Сертификат выбран") { choose(key: false) }
                    Button(settings.key.isEmpty ? "Приватный ключ…" : "Ключ выбран") { choose(key: true) }
                }.buttonStyle(.bordered)
            }
            if ["ws", "http", "httpupgrade"].contains(settings.scheme.transport ?? "") {
                TextField("Путь /cascade", text: $settings.path).textFieldStyle(.roundedBorder)
            }
            if settings.scheme.transport == "grpc" { TextField("Имя сервиса gRPC", text: $settings.serviceName).textFieldStyle(.roundedBorder) }
            if settings.scheme.udp { Text("Требуется доступный UDP 443.").font(.caption).foregroundStyle(.secondary) }
            if let fileError { Text(fileError).font(.caption).foregroundStyle(.orange) }
        }.padding(16).frame(maxWidth: .infinity, alignment: .topLeading)
            .background(Color.white.opacity(0.035), in: RoundedRectangle(cornerRadius: 12))
    }
    private func choose(key: Bool) {
        let panel = NSOpenPanel(); panel.canChooseFiles = true; panel.canChooseDirectories = false
        panel.message = key ? "PEM-ключ сертификата этого VPS, без пароля" : "PEM-сертификат с полной цепочкой"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            let data = try Data(contentsOf: url)
            guard data.count < 100_000, let text = String(data: data, encoding: .utf8) else { throw CascadeError("Ожидается PEM-файл до 100 КБ.") }
            if key { settings.key = text } else { settings.certificate = text }
            fileError = nil
        } catch { fileError = "Не удалось прочитать PEM-файл." }
    }
}
