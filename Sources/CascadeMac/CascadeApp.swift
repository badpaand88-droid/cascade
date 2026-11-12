import SwiftUI
import AppKit
import CascadeCore
import CryptoKit

@main
struct CascadeApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var delegate
    var body: some Scene {
        WindowGroup("Cascade") { ContentView().preferredColorScheme(.dark) }
            .defaultSize(width: 1100, height: 1000)
            .windowStyle(.hiddenTitleBar)
            .commands { CommandGroup(replacing: .newItem) {} }
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
    }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        if InstallerModel.operationInProgress {
            let alert = NSAlert()
            alert.messageText = "Дождитесь завершения операции"
            alert.informativeText = "Закрытие во время установки может оставить серверы настроенными частично. Приложение проверяет результат и при ошибке пытается выполнить откат."
            alert.addButton(withTitle: "Продолжить работу")
            alert.runModal()
            return .terminateCancel
        }
        return .terminateNow
    }
}

@MainActor
final class InstallerModel: ObservableObject {
    static var operationInProgress = false
    enum Stage { case editing, trust, ready, installed, recovery }
    @Published var first = Server() { didSet { if first != oldValue { invalidateServer(0) } } }
    @Published var second = Server() { didSet { if second != oldValue { invalidateServer(1) } } }
    @Published var sni = "www.microsoft.com" { didSet { if sni != oldValue { tlsPhase = .idle; tlsDetail = "Имя ещё не проверено" } } }
    @Published var entrySettings = ConnectionSettings() { didSet { if entrySettings != oldValue { invalidateConfiguration() } } }
    @Published var exitSettings = ConnectionSettings() { didSet { if exitSettings != oldValue { invalidateConfiguration() } } }
    private func invalidateConfiguration() {
        guard !busy else { return }
        stage = .editing; verified = false; profiles = []; client = nil; credentials = []; serverConfigs = []; digests = []
        linkPhase = .idle; linkDetail = "Схема изменена — подготовьте конфигурацию заново"
    }
    private var ipv6DNS: Bool { second.addressMode == .ipv6 || (try? second.endpoints().allSatisfy(IPAddress.isIPv6)) == true }
    private func settings(_ i: Int) -> ConnectionSettings { i == 0 ? entrySettings : exitSettings }
    private func tlsCheck(_ i: Int) -> String { ProtocolScripts.tls(settings(i), realityName: sni) }
    @Published var serverPhases: [CheckPhase] = [.idle, .idle]
    @Published var serverDetails = ["SSH ещё не проверен", "SSH ещё не проверен"]
    @Published var linkPhase: CheckPhase = .idle
    @Published var linkDetail = "Проверьте SSH-доступ к обоим VPS"
    @Published var tlsPhase: CheckPhase = .idle
    @Published var tlsDetail = "Имя ещё не проверено"
    private var diagnosticIdentities: [Int: HostIdentity] = [:]
    @Published var stage: Stage = .editing
    @Published var busy = false
    @Published var busyText = ""
    @Published var trusted = false
    @Published var fingerprints: [String] = []
    @Published var events: [String] = []
    @Published var error: String?
    @Published var verified = false
    @Published var exitIP = ""
    @Published var exportedPath: String?
    @Published var existing = false
    @Published var profiles: [DeviceProfile] = []
    @Published var selectedProfileID = ""
    @Published var deviceName = "Телефон"
    @Published var qrVisible = false
    @Published var sfmURL: URL?
    @Published var sfmStatus = "Проверяем наличие sing-box…"
    private var serverConfigs: [Data?] = []
    private var identities: [HostIdentity] = []
    private var credentials: [Credentials] = []
    private var core: URL?
    private var client: Data?
    private var changed: [HostIdentity] = []
    private var digests: [String?] = []
    private var transaction = ""
    private var askpass: String {
        if let resources = Bundle.main.resourceURL,
           let bundle = Bundle(url: resources.appendingPathComponent("Cascade_CascadeMac.bundle")),
           let script = bundle.url(forResource: "askpass", withExtension: "sh") { return script.path }
        return Bundle.module.url(forResource: "askpass", withExtension: "sh")!.path
    }

    var step: Int { switch stage { case .editing: 1; case .trust: 2; case .ready, .recovery: 3; case .installed: 4 } }
    var canSkipFingerprints: Bool {
        serverPhases.allSatisfy { $0 == .passed } && diagnosticIdentities[0]?.server == first && diagnosticIdentities[1]?.server == second
    }
    var selectedProfile: DeviceProfile? { profiles.first { $0.id == selectedProfileID } ?? profiles.first }
    var canRollback: Bool { !transaction.isEmpty }
    func refreshSFM() {
        sfmURL = NSWorkspace.shared.urlForApplication(withBundleIdentifier: "io.nekohasekai.sfamt.standalone")
        if sfmURL == nil, FileManager.default.fileExists(atPath: "/Applications/SFM.app") { sfmURL = URL(fileURLWithPath: "/Applications/SFM.app") }
        if let sfmURL {
            let version = Bundle(url: sfmURL)?.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? ""
            sfmStatus = "sing-box установлен" + (version.isEmpty ? "" : " · \(version)")
        } else { sfmStatus = "sing-box ещё не установлен" }
    }
    func installSFM() {
        refreshSFM()
        if let sfmURL { NSWorkspace.shared.open(sfmURL); return }
        start("Загружаем официальный установщик SFM \(Config.version)…")
        Task {
            defer { finish(); refreshSFM() }
            do {
                let package = try await SFMInstaller.download()
                guard NSWorkspace.shared.open(package) else { throw CascadeError("Не удалось открыть системный установщик.") }
                log("SHA-256, подпись и доверие macOS к SFM подтверждены. Завершите установку в системном окне и разрешите сетевое расширение.")
            } catch { self.error = safeError(error) }
        }
    }
    func importSelected() {
        refreshSFM()
        guard let sfmURL else { error = "Сначала установите sing-box для Mac."; return }
        guard let profile = selectedProfile else { return }
        do {
            let dir = try PrivateFiles.directory()
            let file = dir.appendingPathComponent("Cascade-" + profile.id + ".bpf")
            try PrivateFiles.write(PortableProfile.encode(name: "Cascade · " + profile.name, config: profile.config), to: file)
            NSWorkspace.shared.open([file], withApplicationAt: sfmURL, configuration: NSWorkspace.OpenConfiguration()) { _, error in
                if let error { Task { @MainActor in self.error = self.safeError(error) } }
            }
            log("Профиль передан в SFM через локальный BPF-файл. Подтвердите импорт в окне sing-box; действующий VPN автоматически не переключается Cascade.")
            Task { try? await Task.sleep(for: .seconds(300)); try? FileManager.default.removeItem(at: dir) }
        } catch { self.error = safeError(error) }
    }
    private func configForServer(_ index: Int) throws -> Data {
        if serverConfigs.indices.contains(index), let data = serverConfigs[index] {
            var config = try JSONSerialization.jsonObject(with: data) as! [String: Any]
            var inbound = config["inbounds"] as! [[String: Any]]
            inbound[0]["listen"] = (index == 0 ? first : second).sourceAddresses.contains(where: IPAddress.isIPv6) ? "::" : "0.0.0.0"
            config["inbounds"] = inbound
            if index == 0, credentials.count == 2 { config["outbounds"] = ProtocolConfig.outbounds(hosts: try second.endpoints(), credentials: credentials[1], settings: exitSettings, realityName: sni) }
            return try Config.json(config)
        }
        var config = ProtocolConfig.server(credentials: credentials[index], settings: settings(index), realityName: sni,
            next: index == 0 ? ProtocolConfig.outbounds(hosts: try second.endpoints(), credentials: credentials[1], settings: exitSettings, realityName: sni) : nil)
        var inbounds = config["inbounds"] as! [[String: Any]]
        inbounds[0]["listen"] = (index == 0 ? first : second).sourceAddresses.contains(where: IPAddress.isIPv6) ? "::" : "0.0.0.0"
        config["inbounds"] = inbounds
        return try Config.json(config)
    }
    private func refreshProfilesFromMemory() throws {
        profiles = try DeviceProfiles.list(serverConfig: configForServer(0), host: first.host, sni: sni, hosts: try first.endpoints(), ipv6DNS: ipv6DNS)
        if !profiles.contains(where: { $0.id == selectedProfileID }) { selectedProfileID = profiles.first?.id ?? "" }
        client = selectedProfile?.config
    }
    func createDevice() {
        guard !busy, stage == .installed, identities.count == 2, serverConfigs.count == 2, digests.count == 2, let core else { return }
        start("Добавляем устройство на входном VPS…")
        Task {
            defer { finish() }
            do {
                let read = try await SSH.run(identities[0], script: RemoteScripts.readClients(peer: second.host), askpass: askpass)
                guard read.status == 0, let current = Data(base64Encoded: read.output.trimmingCharacters(in: .whitespacesAndNewlines)) else { throw CascadeError("Не удалось прочитать текущие профили. " + read.error) }
                let id = UUID().uuidString.lowercased()
                let candidate = try DeviceProfiles.add(to: current, name: deviceName, userID: id)
                try await Probe.validate(candidate, core: core)
                let candidateProfiles = try DeviceProfiles.list(serverConfig: candidate, host: first.host, sni: sni, hosts: try first.endpoints(), ipv6DNS: ipv6DNS)
                guard let newProfile = candidateProfiles.first(where: { $0.id == id }) else { throw CascadeError("Не удалось создать профиль устройства.") }
                try await Probe.validate(newProfile.config, core: core)
                let tx = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
                let update = try await SSH.run(identities[0], script: RemoteScripts.updateClients(config: candidate, expectedDigest: DeviceProfiles.digest(current), peer: second.host, transaction: tx), askpass: askpass, timeout: 50)
                try require(update, marker: "CLIENT_UPDATE_STARTED")
                busyText = "Входной сервис обновляется. Ждём восстановления SSH…"
                let deadline = Date().addingTimeInterval(65)
                var confirmed = false
                while Date() < deadline {
                    try await Task.sleep(for: .seconds(1))
                    let status: CommandResult
                    do { status = try await SSH.run(identities[0], script: RemoteScripts.clientUpdateStatus(transaction: tx), askpass: askpass, timeout: 15) }
                    catch { continue }
                    if status.output.contains("CLIENT_UPDATE_FAILED") { throw CascadeError("Сервер не подтвердил добавление устройства. " + status.error) }
                    if status.status == 0 && status.output.contains("CLIENT_UPDATE_SUCCESS") { confirmed = true; break }
                }
                guard confirmed else { throw CascadeError("Обновление не подтверждено. Дождитесь восстановления сети и обновите список профилей; не создавайте дубликат вслепую.") }
                serverConfigs[0] = candidate; digests[0] = DeviceProfiles.digest(candidate)
                selectedProfileID = id; try refreshProfilesFromMemory()
                deviceName = "Устройство \(profiles.count + 1)"
                log("Новое устройство добавлено с отдельным UUID. Прежние профили сохранены.")
            } catch { self.error = safeError(error) + "\nЕсли SSH-связь прервалась, обновите список профилей перед повторной попыткой." }
        }
    }
    func loadExisting() {
        guard canSkipFingerprints, let a = diagnosticIdentities[0], let b = diagnosticIdentities[1] else { return }
        identities = [a, b]; trusted = true; prepare(loadOnly: true)
    }
    func start(_ text: String) { busy = true; Self.operationInProgress = true; busyText = text; error = nil }
    func finish() { busy = false; Self.operationInProgress = false; busyText = "" }
    func log(_ text: String) { events.append(text) }
    var canCheckLink: Bool { serverPhases.allSatisfy { $0 == .passed } && !busy }
    func invalidateServer(_ index: Int) {
        serverPhases[index] = .idle; serverDetails[index] = "SSH ещё не проверен"
        diagnosticIdentities[index] = nil
        linkPhase = .idle; linkDetail = "Проверьте SSH-доступ к обоим VPS"
        tlsPhase = .idle; tlsDetail = "Имя ещё не проверено"
    }
    private var checkedTime: String { Date().formatted(.dateTime.hour(.twoDigits(amPM: .omitted)).minute(.twoDigits)) }
    func checkServer(_ index: Int) {
        guard !busy else { return }
        let server = index == 0 ? first : second
        start("Проверяем SSH сервера \(index + 1)…")
        serverPhases[index] = .checking; serverDetails[index] = "Устанавливаем SSH-соединение…"
        linkPhase = .idle; linkDetail = "Связь между VPS ещё не проверена"
        Task {
            defer { finish() }
            do {
                try server.validate()
                let identity: HostIdentity
                if let pinned = diagnosticIdentities[index], pinned.server == server { identity = pinned }
                else {
                    identity = try await SSH.scan(server)
                    let alert = NSAlert()
                    alert.messageText = "SSH-ключ сервера \(index + 1)"
                    alert.informativeText = "\(server.host):\(server.port)\n\n\(identity.fingerprint)\n\nСверьте отпечаток с консолью хостинга. Пароль будет передан только после подтверждения."
                    alert.addButton(withTitle: "Доверять и проверить")
                    alert.addButton(withTitle: "Отмена")
                    guard alert.runModal() == .alertFirstButtonReturn else {
                        serverPhases[index] = .idle; serverDetails[index] = "Проверка отменена"; return
                    }
                    diagnosticIdentities[index] = identity
                }
                let r = try await SSH.run(identity, script: Diagnostics.ssh, askpass: askpass, timeout: 25, privileged: false)
                try require(r, marker: "SSH_CONNECTED")
                serverPhases[index] = .passed; serverDetails[index] = "SSH подтверждён · \(checkedTime)"
                log("Сервер \(index + 1): SSH-аутентификация подтверждена. Настройки не изменялись.")
                if serverPhases.allSatisfy({ $0 == .passed }) { linkDetail = "Оба VPS доступны · можно проверить связь" }
            } catch {
                serverPhases[index] = .failed; serverDetails[index] = "SSH не подтверждён"
                self.error = safeError(error)
            }
        }
    }
    func checkLink() {
        guard canCheckLink, let entry = diagnosticIdentities[0], let exit = diagnosticIdentities[1] else { return }
        start("Проверяем TCP-связь сервер 1 → сервер 2…")
        linkPhase = .checking; linkDetail = "Открываем TCP-соединения с входного VPS…"
        Task {
            defer { finish() }
            do {
                guard entry.server.host != exit.server.host else { throw CascadeError("Нужны два разных VPS.") }
                var all = ""
                for host in try second.endpoints() {
                    let script = try Diagnostics.link(host: host, sshPort: exit.server.port)
                    let check = try await SSH.run(entry, script: script, askpass: askpass, timeout: 30, privileged: false)
                    all += host + ": " + check.output + "\n"
                    if check.status != 0 { log("Маршрут к " + host + " пока недоступен.") }
                }
                let r = CommandResult(status: all.contains("LINK_OK") ? 0 : 1, output: all, error: "Между VPS не найден доступный маршрут.")
                try require(r, marker: "LINK_OK")
                linkPhase = .passed
                let ports = [r.output.contains("TCP_SSH_OK") ? "SSH \(exit.server.port)" : nil, r.output.contains("TCP_443_OK") ? "443" : nil].compactMap { $0 }.joined(separator: ", ")
                linkDetail = "TCP доступен: \(ports) · \(checkedTime)"
                log("Сервер 1 → сервер 2: TCP-проверка пройдена (\(ports)). VPN-туннель проверяется после установки.")
            } catch { linkPhase = .failed; linkDetail = "TCP-связь не подтверждена"; self.error = safeError(error) }
        }
    }
    func checkTLS() {
        guard !busy else { return }
        start("Проверяем TLS-сайт…")
        tlsPhase = .checking; tlsDetail = "Проверяем имя, сертификат и TLS 1.3…"
        let host = sni
        let targets = (0..<2).compactMap { i -> (Int, HostIdentity)? in
            guard serverPhases[i] == .passed, let identity = diagnosticIdentities[i] else { return nil }
            return (i, identity)
        }
        Task {
            defer { finish() }
            do {
                try Config.validateSNI(host)
                if targets.isEmpty {
                    try await Diagnostics.localTLS(host: host)
                    tlsDetail = "TLS 1.3 и сертификат подтверждены на Mac. Проверка с VPS — после проверки SSH."
                } else {
                    for (i, identity) in targets {
                        busyText = "Проверяем TLS-сайт с сервера \(i + 1)…"
                        let r = try await SSH.run(identity, script: Diagnostics.tls(host: host), askpass: askpass, timeout: 22, privileged: false)
                        try require(r, marker: "TLS_OK")
                    }
                    let names = targets.map { String($0.0 + 1) }.joined(separator: ", ")
                    tlsDetail = "TLS 1.3 и сертификат подтверждены с VPS \(names) · \(checkedTime). Это не гарантия доступности VPN у оператора."
                }
                tlsPhase = .passed; log("TLS-сайт \(host): " + tlsDetail)
            } catch { tlsPhase = .failed; tlsDetail = safeError(error); self.error = safeError(error) }
        }
    }
    func safeError(_ error: Error) -> String {
        var text = error.localizedDescription
        for s in [first.secret, second.secret, entrySettings.key, exitSettings.key] + credentials.flatMap({ [$0.privateKey, $0.uuid] }) + profiles.map(\.id) where !s.isEmpty { text = text.replacingOccurrences(of: s, with: "[скрыто]") }
        return String(text.prefix(1400))
    }
    func require(_ r: CommandResult, marker: String) throws {
        guard r.status == 0 && r.output.contains(marker) else {
            let message = r.error.trimmingCharacters(in: .whitespacesAndNewlines)
            throw CascadeError(message.isEmpty ? "Сервер не подтвердил этап \(marker)." : String(message.suffix(1000)))
        }
    }
    func scan() {
        do {
            try first.validate(); try second.validate(); try entrySettings.validate(realityName: sni); try exitSettings.validate(realityName: sni)
            guard IPAddress.canonical(first.host) != IPAddress.canonical(second.host) else { throw CascadeError("Для каскада нужны два разных сервера.") }
        } catch { self.error = safeError(error); return }
        if canSkipFingerprints, let a = diagnosticIdentities[0], let b = diagnosticIdentities[1] {
            identities = [a, b]; trusted = true; check(); return
        }
        start("Получаем SSH-отпечатки…")
        Task {
            defer { finish() }
            do {
                try first.validate(); try second.validate(); try entrySettings.validate(realityName: sni); try exitSettings.validate(realityName: sni)
                guard IPAddress.canonical(first.host) != IPAddress.canonical(second.host) else { throw CascadeError("Для каскада нужны два разных сервера.") }
                let a: HostIdentity
                if let pinned = diagnosticIdentities[0] { a = pinned } else { a = try await SSH.scan(first) }
                let b: HostIdentity
                if let pinned = diagnosticIdentities[1] { b = pinned } else { b = try await SSH.scan(second) }
                identities = [a, b]; fingerprints = [a.fingerprint, b.fingerprint]
                trusted = serverPhases.allSatisfy { $0 == .passed }
                stage = .trust
                log("SSH-ключи получены. Сверьте отпечатки перед передачей доступов.")
            } catch { self.error = safeError(error) }
        }
    }
    func check() { prepare(loadOnly: false) }
    private func prepare(loadOnly: Bool) {
        guard trusted, identities.count == 2 else { return }
        start("Проверяем серверы…")
        Task {
            defer { finish() }
            do {
                guard IPAddress.canonical(first.host) != IPAddress.canonical(second.host) else { throw CascadeError("Для каскада нужны два разных сервера.") }
                credentials = []; digests = []; serverConfigs = []; existing = false
                for i in 0..<2 {
                    busyText = "Проверяем сервер \(i + 1) из 2…"
                    let r = try await SSH.run(identities[i], script: RemoteScripts.preflight(sni: sni, peer: identities[1-i].server.host, role: i == 0 ? "entry" : "exit", tlsCheck: loadOnly ? "true" : tlsCheck(i)), askpass: askpass)
                    try require(r, marker: "PREFLIGHT_OK")
                    serverPhases[i] = .passed; serverDetails[i] = "SSH подтверждён · \(checkedTime)"
                    diagnosticIdentities[i] = identities[i]
                    if let start = r.output.range(of: "CONFIG_BEGIN\n"), let end = r.output.range(of: "\nCONFIG_END"), start.upperBound < end.lowerBound {
                        guard let data = Data(base64Encoded: String(r.output[start.upperBound..<end.lowerBound])),
                              let config = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw CascadeError("Не удалось прочитать существующий конфиг. Перезапись остановлена.") }
                        let found = try ConnectionSettings.read(config)
                        if !loadOnly, found.scheme != settings(i).scheme { throw CascadeError("На сервере \(i+1) уже установлен \(found.scheme.title). Загрузите его профили; смена протокола требует отдельной миграции, чтобы не отключить прежние устройства.") }
                        if !loadOnly, found.serverName != (found.scheme.isReality ? sni : settings(i).serverName) { throw CascadeError("Имя TLS установленного каскада отличается. Укажите прежнее имя или загрузите существующие профили.") }
                        if i == 0 { entrySettings = found; if loadOnly && found.scheme.isReality { sni = found.serverName } } else { exitSettings = found }
                        digests.append(SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined())
                        serverConfigs.append(data)
                        credentials.append(try Credentials(config: config)); existing = true
                        log("Сервер \(i+1): найдена установка Cascade, ключи будут сохранены.")
                    } else {
                        if loadOnly { throw CascadeError("На сервере \(i+1) не найдена установка Cascade. Сначала установите каскад.") }
                        credentials.append(Credentials()); digests.append(nil); serverConfigs.append(nil)
                        log("Сервер \(i+1): ОС, права, порт 443 и TLS-сайт проверены.")
                    }
                }
                busyText = "Загружаем проверенный sing-box для локального теста…"
                core = try await CoreDownload.obtain()
                client = try Config.json(ProtocolConfig.client(hosts: first.endpoints(), credentials: credentials[0], settings: entrySettings, realityName: sni, ipv6DNS: ipv6DNS))
                try await Probe.validate(client!, core: core!)
                for i in 0..<2 {
                    try await Probe.validate(configForServer(i), core: core!)
                }
                log("SHA-256 sing-box \(Config.version) совпал. Все три конфига прошли sing-box check.")
                if loadOnly { try refreshProfilesFromMemory(); stage = .installed; await verifyInternal() }
                else { stage = .ready }
            } catch {
                self.error = safeError(error); credentials = []; client = nil
                if loadOnly { stage = .editing; profiles = []; serverConfigs = []; digests = [] }
            }
        }
    }
    func install() {
        guard credentials.count == 2, core != nil else { return }
        start("Настраиваем каскад…")
        Task {
            defer { finish() }
            changed = []
            transaction = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
            do {
                for i in [1, 0] {
                    busyText = "Устанавливаем \(i == 1 ? "выходной" : "входной") сервер…"
                    let config = try configForServer(i)
                    let r = try await SSH.run(identities[i], script: RemoteScripts.install(config: config, role: i == 0 ? "entry" : "exit", peer: identities[1-i].server.host, sni: sni, transaction: transaction, expectedDigest: digests[i], tlsCheck: tlsCheck(i), network: settings(i).scheme.udp ? "udp" : "tcp", sources: first.sourceAddresses), askpass: askpass, timeout: 780)
                    try require(r, marker: "INSTALL_OK")
                    changed.append(identities[i]); serverConfigs[i] = config; digests[i] = DeviceProfiles.digest(config)
                    log("Сервер \(i+1): сервис запущен, порт 443 слушает. Точка отката сохранена.")
                }
                stage = .installed
                try refreshProfilesFromMemory()
            } catch {
                let original = safeError(error)
                log("Установка не завершена. Проверяем откат обоих серверов.")
                // A disconnected SSH session may have committed without returning its marker.
                var rollbackFailures: [String] = []
                for identity in identities {
                    do {
                        let r = try await SSH.run(identity, script: RemoteScripts.rollback(transaction: transaction), askpass: askpass)
                        if r.status == 0 && (r.output.contains("ROLLBACK_OK") || r.output.contains("ROLLBACK_NOT_NEEDED")) { log("\(identity.server.host): откат подтверждён либо изменений ещё не было.") }
                        else { rollbackFailures.append(identity.server.host) }
                    } catch { rollbackFailures.append(identity.server.host) }
                }
                self.error = original + (rollbackFailures.isEmpty ? "\nОткат подтверждён." : "\nОткат не подтверждён для: " + rollbackFailures.joined(separator: ", ") + ". Проверьте серверы; журнал сохранённых откатов: /etc/bp-cascade/backup.*/rollback.sh.")
                // Recheck credentials/state before any retry after rollback.
                stage = rollbackFailures.isEmpty ? .trust : .recovery
                trusted = true; credentials = []; client = nil; changed = []
                return
            }
            await verifyInternal()
        }
    }
    private func verifyInternal() async {
        guard let core, credentials.count == 2 else { return }
        busyText = "Проверяем всю цепочку с этого Mac…"
        verified = false
        do {
            guard let client else { throw CascadeError("Нет профиля для проверки.") }
            exitIP = try await Probe.test(core: core, client: client)
            verified = true
            linkPhase = .passed; linkDetail = "VPN-каскад проверен · \(checkedTime)"
            log("Проверка через оба сервера: два HTTPS-ресурса доступны. Выходной IP: \(exitIP).")
            if exitIP != second.host { log("Выходной IP отличается от адреса VPS — возможно, у хостинга используется NAT. Проверьте его в панели.") }
        } catch {
            linkPhase = .failed; linkDetail = "VPN-каскад не подтверждён"
            self.error = safeError(error)
            log("Сервисы установлены. Сквозной тест не подтверждён; конфиг доступен для диагностики.")
        }
    }
    func verify() {
        start("Повторяем проверку…")
        Task { defer { finish() }; await verifyInternal() }
    }
    func export() {
        guard let client = selectedProfile?.config ?? client else { return }
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "Cascade-" + (selectedProfile?.name ?? "sing-box").replacingOccurrences(of: "/", with: "-") + ".json"
        panel.title = "Сохранить профиль sing-box"
        panel.message = "Файл содержит ключ доступа к VPN. Храните его как пароль."
        panel.allowedContentTypes = [.json]
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            // Atomic replacement avoids following an existing symlink or weakening permissions.
            let tmp = url.deletingLastPathComponent().appendingPathComponent(".cascade-" + UUID().uuidString)
            defer { try? FileManager.default.removeItem(at: tmp) }
            try PrivateFiles.write(client, to: tmp)
            if FileManager.default.fileExists(atPath: url.path) { _ = try FileManager.default.replaceItemAt(url, withItemAt: tmp) }
            else { try FileManager.default.moveItem(at: tmp, to: url) }
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
            exportedPath = url.path
            log("Профиль сохранён. Импортируйте его как локальный профиль в sing-box \(Config.version).")
        } catch { self.error = safeError(error) }
    }
    func rollback() {
        start("Откатываем настройку…")
        Task {
            defer { finish() }
            var failures: [String] = []
            for identity in identities {
                do {
                    let r = try await SSH.run(identity, script: RemoteScripts.rollback(transaction: transaction), askpass: askpass)
                    try require(r, marker: "ROLLBACK_OK")
                    log("\(identity.server.host): предыдущая настройка восстановлена.")
                } catch { failures.append(identity.server.host) }
            }
            if failures.isEmpty {
                stage = .trust; client = nil; credentials = []; verified = false; exportedPath = nil
                linkPhase = .idle; linkDetail = "Настройка отменена · нужна новая проверка связи"
                log("Установка отменена. Сохранённый профиль может больше не работать.")
            }
            else { error = "Не удалось подтвердить откат: " + failures.joined(separator: ", ") + ". Не закрывайте доступы до проверки серверов." }
        }
    }
    func reset() {
        identities = []; credentials = []; client = nil; core = nil; trusted = false; fingerprints = []
        first.secret = ""; second.secret = ""; stage = .editing; error = nil; events = []; verified = false; exportedPath = nil
        invalidateServer(0); invalidateServer(1)
        profiles = []; selectedProfileID = ""; serverConfigs = []
        transaction = ""
    }
}

let mint = Color(red: 0.51, green: 0.94, blue: 0.77)
let panelColor = Color.white.opacity(0.045)

struct ContentView: View {
    @StateObject private var model = InstallerModel()
    @State private var advanced = false
    @State private var confirmRollback = false
    var body: some View {
        HStack(spacing: 0) {
            sidebar
            ScrollView {
                VStack(alignment: .leading, spacing: 24) {
                    header
                    ConnectionMap(phases: model.serverPhases, hosts: [model.first.host, model.second.host], linkPhase: model.linkPhase, detail: model.linkDetail)
                    if model.stage == .editing { servers }
                    if model.stage == .trust { trust }
                    if model.stage == .ready { ready }
                    if model.stage == .installed { result }
                    macClient
                    if model.stage == .recovery {
                        Label("Установка не завершена. Нужна проверка отката.", systemImage: "exclamationmark.arrow.trianglehead.2.clockwise.rotate.90")
                            .font(.system(size: 16)).foregroundStyle(.orange)
                        Text("Не все серверы подтвердили восстановление. Проверьте SSH-связь и повторите откат; текущие доступы сохранены в памяти приложения.")
                            .font(.system(size: 12)).foregroundStyle(.secondary)
                    }
                    if let error = model.error {
                        Label(error, systemImage: "exclamationmark.triangle")
                            .font(.system(size: 13)).foregroundStyle(.orange).textSelection(.enabled)
                            .padding(16).frame(maxWidth: .infinity, alignment: .leading)
                            .background(.orange.opacity(0.08), in: RoundedRectangle(cornerRadius: 12))
                    }
                    if model.busy { HStack(spacing: 12) { ProgressView().controlSize(.small); Text(model.busyText).font(.system(size: 13)) }.foregroundStyle(mint) }
                    actions
                    if !model.events.isEmpty { journal }
                    HStack(spacing: 6) {
                        Image(systemName: "lock.shield")
                        Text("SSH-доступы остаются на Mac. Телеметрии и регистрации нет.")
                    }.font(.system(size: 11)).foregroundStyle(.secondary)
                }.padding(.horizontal, 36).padding(.vertical, 34).frame(maxWidth: 900)
            }
        }.frame(minWidth: 1020, minHeight: 760)
            .background(Color(red: 0.055, green: 0.067, blue: 0.075))
            .tint(mint)
            .confirmationDialog("Откатить последнюю установку на обоих серверах?", isPresented: $confirmRollback, titleVisibility: .visible) {
                Button("Откатить установку", role: .destructive) { model.rollback() }
            } message: { Text("Будет восстановлена предыдущая настройка Cascade. Выданный профиль может перестать работать.") }
            .sheet(isPresented: $model.qrVisible) {
                if let profile = model.selectedProfile { ProfileQRSheet(profile: profile) }
            }
            .onAppear { model.refreshSFM() }
            .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in model.refreshSFM() }
    }
    var sidebar: some View {
        VStack(alignment: .leading, spacing: 0) {
            Image(systemName: "point.3.connected.trianglepath.dotted").font(.system(size: 34)).foregroundStyle(mint).padding(.bottom, 14)
            Text("CASCADE").font(.system(size: 21, weight: .bold, design: .rounded)).tracking(2)
            Text("by BadPaand").font(.system(size: 11)).foregroundStyle(.secondary).padding(.top, 6)
            VStack(alignment: .leading, spacing: 24) {
                step(1, "Два сервера", "SSH-доступы")
                step(2, "Проверка", "Ключи и совместимость")
                step(3, "Установка", "Настройка каскада")
                step(4, "Подключение", "Профиль sing-box")
            }.padding(.top, 48)
            Spacer()
            VStack(alignment: .leading, spacing: 8) {
                Text("IPv4 / IPv6 · VLESS · TLS").font(.system(size: 9, weight: .semibold)).tracking(0.5).foregroundStyle(mint)
                Text("Два VPS. Один профиль.\nВыберите свою схему.").font(.system(size: 12)).foregroundStyle(.secondary).lineSpacing(4)
                Text("v0.4 · sing-box \(Config.version)").font(.system(size: 10)).foregroundStyle(.tertiary).padding(.top, 14)
            }
        }.padding(.horizontal, 26).padding(.top, 44).padding(.bottom, 28).frame(width: 228)
            .background(Color.black.opacity(0.20))
    }
    func step(_ n: Int, _ title: String, _ subtitle: String) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Text(n < model.step ? "✓" : "\(n)").font(.system(size: 12, weight: .semibold))
                .frame(width: 26, height: 26).background(n == model.step ? mint : .white.opacity(0.06), in: Circle())
                .foregroundStyle(n == model.step ? .black : n < model.step ? mint : .gray)
            VStack(alignment: .leading, spacing: 5) {
                Text(title).font(.system(size: 13, weight: .medium)).foregroundStyle(n == model.step ? .white : .secondary)
                Text(subtitle).font(.system(size: 10)).foregroundStyle(.secondary)
            }
        }
    }
    var header: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("СВОЯ ИНФРАСТРУКТУРА").font(.system(size: 10, weight: .semibold)).tracking(2).foregroundStyle(mint)
            Text(model.stage == .installed ? "Ваш каскад настроен" : "Два сервера.\nГотовое подключение.")
                .font(.system(size: 35, weight: .semibold, design: .rounded)).lineSpacing(1)
            Text("Установщик соединит ваши VPS в цепочку и подготовит профиль для sing-box.")
                .font(.system(size: 13)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
        }
    }
    var servers: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack(spacing: 16) {
                ServerCard(server: $model.first, number: "01", title: "Входной сервер", subtitle: "Например, VPS в России", phase: model.serverPhases[0], detail: model.serverDetails[0]) { model.checkServer(0) }
                ServerCard(server: $model.second, number: "02", title: "Выходной сервер", subtitle: "VPS за рубежом", phase: model.serverPhases[1], detail: model.serverDetails[1]) { model.checkServer(1) }
            }.disabled(model.busy)
            HStack(alignment: .center, spacing: 16) {
                Button(action: model.checkLink) {
                    Label("Проверить связь между VPS", systemImage: "arrow.left.arrow.right")
                        .font(.system(size: 12, weight: .medium)).padding(.horizontal, 14).padding(.vertical, 11)
                        .background(model.canCheckLink ? mint.opacity(0.12) : .white.opacity(0.035), in: RoundedRectangle(cornerRadius: 9))
                        .overlay(RoundedRectangle(cornerRadius: 9).stroke(model.canCheckLink ? mint.opacity(0.35) : .white.opacity(0.08)))
                }.buttonStyle(.plain).foregroundStyle(model.canCheckLink ? mint : .secondary).disabled(!model.canCheckLink)
                Text("Сначала SSH обоих VPS. До установки проверяется TCP; после — VPN-каскад.")
                    .font(.system(size: 10)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            HStack(alignment: .top, spacing: 16) {
                ConnectionSettingsView(settings: $model.entrySettings, title: "Устройство → входной VPS")
                ConnectionSettingsView(settings: $model.exitSettings, title: "Входной → выходной VPS")
            }.disabled(model.busy)
            VStack(alignment: .leading, spacing: 0) {
                Button {
                    withAnimation(.easeInOut(duration: 0.2)) { advanced.toggle() }
                } label: {
                    HStack(spacing: 10) {
                        Image(systemName: "slider.horizontal.3").foregroundStyle(mint)
                        Text("Дополнительные настройки").font(.system(size: 12, weight: .medium))
                        Spacer()
                        Text("REALITY / TLS").font(.system(size: 9, design: .monospaced)).foregroundStyle(.secondary)
                        Image(systemName: "chevron.down").font(.system(size: 10)).rotationEffect(.degrees(advanced ? 180 : 0))
                    }.padding(16).contentShape(Rectangle())
                }.buttonStyle(.plain).accessibilityValue(advanced ? "Развёрнуто" : "Свёрнуто")
                if advanced {
                    VStack(alignment: .leading, spacing: 12) {
                        Divider()
                        Text("Внешний TLS-сайт REALITY").font(.system(size: 11, weight: .medium))
                        HStack(spacing: 12) {
                            TextField("www.microsoft.com", text: $model.sni).textFieldStyle(.roundedBorder)
                            Button(action: model.checkTLS) { Label("Проверить TLS-сайт", systemImage: "checkmark.shield") }
                                .buttonStyle(.bordered).controlSize(.large)
                        }
                        Text("Владеть доменом не нужно. Проверим сертификат имени и TLS 1.3 с доступных по SSH серверов; если их ещё нет — только с Mac.")
                            .font(.system(size: 11)).foregroundStyle(.secondary).lineSpacing(3)
                        Label(model.tlsDetail, systemImage: model.tlsPhase.symbol).font(.system(size: 11))
                            .foregroundStyle(model.tlsPhase == .idle ? .secondary : model.tlsPhase.color)
                            .textSelection(.enabled)
                    }.padding(.horizontal, 16).padding(.bottom, 16).transition(.opacity.combined(with: .move(edge: .top)))
                }
            }.background(panelColor, in: RoundedRectangle(cornerRadius: 12))
                .overlay(RoundedRectangle(cornerRadius: 12).stroke(.white.opacity(0.07))).disabled(model.busy)
            Text("Нужны чистые Ubuntu 22.04 / 24.04 / 26.04 или Debian 12 / 13, root либо sudo без пароля. Порт 443 выбранного TCP/UDP транспорта должен быть свободен и доступен в firewall хостинга.")
                .font(.system(size: 11)).foregroundStyle(.secondary).lineSpacing(3)
        }
    }
    var trust: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Проверьте SSH-отпечатки").font(.system(size: 20, weight: .medium))
            Text("Сравните ключи с данными панели или консоли хостинга. Доступы передаются только после подтверждения ключей. Само получение ключа по сети не подтверждает подлинность сервера.")
                .font(.system(size: 12)).foregroundStyle(.secondary)
            ForEach(Array(model.fingerprints.enumerated()), id: \.offset) { i, f in
                VStack(alignment: .leading, spacing: 8) {
                    Text("СЕРВЕР \(i+1) · \(i == 0 ? model.first.host : model.second.host)").font(.system(size: 10, weight: .semibold)).foregroundStyle(mint)
                    Text(f).font(.system(size: 11, design: .monospaced)).textSelection(.enabled)
                }.padding(16).frame(maxWidth: .infinity, alignment: .leading).background(panelColor, in: RoundedRectangle(cornerRadius: 12))
            }
            Toggle("Я сверил отпечатки и доверяю этим серверам", isOn: $model.trusted).toggleStyle(.checkbox).font(.system(size: 12)).disabled(model.busy)
            Text("Далее — проверка ОС, прав, портов и TLS. На Mac загрузится официальный sing-box с проверкой SHA-256; серверы пока не изменяются.")
                .font(.system(size: 11)).foregroundStyle(.secondary)
        }
    }
    var ready: some View {
        VStack(alignment: .leading, spacing: 18) {
            Label("Серверы готовы к установке", systemImage: "checkmark.shield").font(.system(size: 20, weight: .medium)).foregroundStyle(mint)
            summaryRow("Вход", "\(model.first.host):443")
            summaryRow("Выход", "\(model.second.host):443")
            summaryRow("Вход", model.entrySettings.scheme.title)
            summaryRow("Между VPS", model.exitSettings.scheme.title)
            summaryRow("Профиль", "sing-box \(Config.version)")
            Divider()
            Text("Установщик создаст отдельный сервис bp-cascade, добавит правила в активный UFW и включит автозапуск. Перед заменой настройки Cascade сохранится точка отката. Firewall панели хостинга настраивается отдельно.")
                .font(.system(size: 12)).foregroundStyle(.secondary).lineSpacing(4)
            if model.existing { Label("Существующие ключи доступа Cascade сохраняются.", systemImage: "key").font(.system(size: 12)).foregroundStyle(mint) }
            Text("Другие сервисы и настройки SSH установщик не останавливает. Пакеты curl и ca-certificates будут установлены при необходимости.")
                .font(.system(size: 11)).foregroundStyle(.secondary)
        }.padding(22).background(panelColor, in: RoundedRectangle(cornerRadius: 16))
    }
    var result: some View {
        VStack(alignment: .leading, spacing: 18) {
            Label(model.verified ? "Сквозной тест пройден" : "Ожидает проверки подключения", systemImage: model.verified ? "checkmark.circle.fill" : "clock")
                .font(.system(size: 20, weight: .medium)).foregroundStyle(model.verified ? mint : .orange)
            if model.verified { summaryRow("Выходной IP", model.exitIP) }
            if !model.profiles.isEmpty {
                Divider()
                HStack { Text("Профиль устройства").font(.system(size: 12, weight: .medium)); Spacer(); Text("\(model.profiles.count) профилей").font(.caption).foregroundStyle(.secondary) }
                Picker("Устройство", selection: $model.selectedProfileID) {
                    ForEach(model.profiles) { profile in Text(profile.name).tag(profile.id) }
                }.labelsHidden().frame(maxWidth: .infinity)
                HStack(spacing: 12) {
                    Button(action: model.importSelected) { Label("Импортировать в sing-box", systemImage: "arrow.up.forward.app") }.disabled(model.sfmURL == nil)
                    Button { model.qrVisible = true } label: { Label("Показать QR", systemImage: "qrcode") }
                }.buttonStyle(.bordered).controlSize(.large).disabled(model.busy)
                Text("SFM откроет подтверждение локального импорта BPF. JSON можно сохранить отдельно; QR доступен как ссылка и полный JSON; автоматический выбор адресов сохраняется в JSON/BPF.")
                    .font(.system(size: 11)).foregroundStyle(.secondary)
                Divider()
                Text("Добавить устройство").font(.system(size: 12, weight: .medium))
                HStack {
                    TextField("Название, например iPhone", text: $model.deviceName).textFieldStyle(.roundedBorder)
                    Button("Создать профиль", action: model.createDevice).buttonStyle(.bordered)
                }.disabled(model.busy)
                Text("Каждое устройство получит отдельный UUID. Входной сервис кратко перезапустится; прежние ключи сохранятся.")
                    .font(.system(size: 11)).foregroundStyle(.secondary)
            }
            Text("Тест использует временный локальный прокси, не меняя системный VPN. Он проверяет два HTTPS-ресурса из сети этого Mac; мобильную сеть нужно проверить отдельно.")
                .font(.system(size: 11)).foregroundStyle(.secondary)
            if let path = model.exportedPath {
                Button { NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)]) } label: { Label("Показать сохранённый профиль", systemImage: "doc.text") }
                .buttonStyle(.link)
            }
        }.padding(22).background(panelColor, in: RoundedRectangle(cornerRadius: 16))
    }
    var macClient: some View {
        HStack(alignment: .center, spacing: 14) {
            Image(systemName: "laptopcomputer.and.arrow.down").font(.system(size: 24)).foregroundStyle(mint)
            VStack(alignment: .leading, spacing: 6) {
                Text("sing-box для Mac").font(.system(size: 13, weight: .medium))
                Text(model.sfmStatus).font(.system(size: 11)).foregroundStyle(.secondary)
                if model.sfmURL == nil {
                    Text("Официальный SFM \(Config.version). Загрузка и проверка — здесь; установка и разрешение расширения — в macOS.")
                        .font(.system(size: 10)).foregroundStyle(.secondary)
                }
            }
            Spacer()
            Button(model.sfmURL == nil ? "Установить sing-box" : "Открыть sing-box", action: model.installSFM)
                .buttonStyle(.bordered).controlSize(.large).disabled(model.busy)
        }.padding(18).background(panelColor, in: RoundedRectangle(cornerRadius: 12))
    }
    func summaryRow(_ label: String, _ value: String) -> some View {
        HStack { Text(label).foregroundStyle(.secondary).frame(width: 80, alignment: .leading); Text(value).textSelection(.enabled); Spacer() }.font(.system(size: 12))
    }
    var actions: some View {
        HStack(spacing: 12) {
            switch model.stage {
            case .editing:
                primary(model.canSkipFingerprints ? "Подготовить установку" : "Получить SSH-отпечатки", "arrow.right", action: model.scan)
                if model.canSkipFingerprints { Button("Получить конфиги", action: model.loadExisting).buttonStyle(.bordered) }
            case .trust: primary("Проверить серверы", "checkmark.shield", action: model.check).disabled(!model.trusted)
            case .ready: primary("Установить на оба сервера", "arrow.triangle.branch", action: model.install)
            case .recovery: primary("Повторить откат", "arrow.uturn.backward", action: model.rollback)
            case .installed:
                primary(model.verified ? "Сохранить конфиг" : "Сохранить непроверенный конфиг", "square.and.arrow.down", action: model.export)
                Button("Повторить тест", action: model.verify).buttonStyle(.bordered)
                Button("Обновить профили", action: model.loadExisting).buttonStyle(.borderless)
            }
            Spacer()
            if model.stage == .installed && model.canRollback { Button("Откатить…") { confirmRollback = true }.buttonStyle(.borderless).foregroundStyle(.secondary) }
            else if model.stage != .editing && model.stage != .recovery { Button("Изменить доступы", action: model.reset).buttonStyle(.borderless).foregroundStyle(.secondary) }
        }.disabled(model.busy)
    }
    func primary(_ text: String, _ icon: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Label(text, systemImage: icon).font(.system(size: 12, weight: .semibold))
                .foregroundStyle(.black).padding(.horizontal, 20).padding(.vertical, 13)
                .background(mint.opacity(model.busy ? 0.45 : 1), in: RoundedRectangle(cornerRadius: 10))
        }.buttonStyle(.plain)
    }
    var journal: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("ЖУРНАЛ").font(.system(size: 9, weight: .semibold)).tracking(2).foregroundStyle(.secondary)
            ForEach(Array(model.events.enumerated()), id: \.offset) { _, event in
                HStack(alignment: .top, spacing: 8) { Circle().fill(mint.opacity(0.65)).frame(width: 4, height: 4).padding(.top, 5); Text(event).font(.system(size: 11)).foregroundStyle(.secondary).textSelection(.enabled) }
            }
        }.padding(18).frame(maxWidth: .infinity, alignment: .leading).background(.black.opacity(0.15), in: RoundedRectangle(cornerRadius: 12))
    }
}

struct ServerCard: View {
    @Binding var server: Server
    let number: String
    let title: String
    let subtitle: String
    let phase: CheckPhase
    let detail: String
    let check: () -> Void
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack { Text(number).font(.system(size: 11, weight: .semibold, design: .monospaced)).foregroundStyle(mint); Spacer(); Image(systemName: "server.rack").foregroundStyle(.secondary) }
            VStack(alignment: .leading, spacing: 5) { Text(title).font(.system(size: 17, weight: .medium)); Text(subtitle).font(.system(size: 11)).foregroundStyle(.secondary) }
            field("SSH · IPv4 или IPv6", text: $server.host, placeholder: "203.0.113.10 / 2001:db8::1")
            Picker("Адрес VPN", selection: $server.addressMode) { ForEach(AddressMode.allCases, id: \.self) { Text($0.title).tag($0) } }
            field("Дополнительный IPv4 этого VPS", text: $server.tunnelIPv4, placeholder: "Необязательно")
            field("Дополнительный IPv6 этого VPS", text: $server.tunnelIPv6, placeholder: "2001:db8::1")
            HStack(spacing: 12) {
                field("Логин", text: $server.user, placeholder: "root")
                field("SSH-порт", text: $server.port, placeholder: "22").frame(width: 75)
            }
            HStack(spacing: 3) {
                authButton("Пароль", useKey: false)
                authButton("SSH-ключ", useKey: true)
            }.padding(3).background(.white.opacity(0.035), in: RoundedRectangle(cornerRadius: 7))
            if server.useKey {
                Button {
                    let panel = NSOpenPanel(); panel.canChooseDirectories = false; panel.canChooseFiles = true; panel.showsHiddenFiles = true
                    if panel.runModal() == .OK, let url = panel.url { server.keyPath = url.path }
                } label: { Label(server.keyPath.isEmpty ? "Выбрать ключ…" : URL(fileURLWithPath: server.keyPath).lastPathComponent, systemImage: "key") }.frame(maxWidth: .infinity, alignment: .leading)
                SecureField("Пароль ключа, если задан", text: $server.secret).textFieldStyle(.roundedBorder)
            } else { SecureField("SSH-пароль", text: $server.secret).textFieldStyle(.roundedBorder) }
            Divider().padding(.top, 2)
            Button(action: check) {
                HStack {
                    Image(systemName: phase == .checking ? "arrow.triangle.2.circlepath" : "network")
                    Text(phase == .passed ? "Проверить ещё раз" : "Проверить подключение")
                    Spacer()
                    Image(systemName: phase.symbol)
                }.font(.system(size: 11, weight: .medium)).foregroundStyle(phase == .failed ? .orange : mint)
                    .padding(.vertical, 10).padding(.horizontal, 12)
                    .background(mint.opacity(0.07), in: RoundedRectangle(cornerRadius: 8))
            }.buttonStyle(.plain).accessibilityLabel("Проверить подключение к серверу \(number)")
            Text(detail).font(.system(size: 10)).foregroundStyle(phase == .failed ? .orange : .secondary)
        }.padding(20).frame(maxWidth: .infinity, alignment: .topLeading).background(panelColor, in: RoundedRectangle(cornerRadius: 16))
            .overlay(RoundedRectangle(cornerRadius: 16).stroke(.white.opacity(0.07), lineWidth: 1))
    }
    func field(_ label: String, text: Binding<String>, placeholder: String) -> some View {
        VStack(alignment: .leading, spacing: 7) { Text(label).font(.system(size: 10)).foregroundStyle(.secondary); TextField(placeholder, text: text).textFieldStyle(.roundedBorder) }
    }
    func authButton(_ title: String, useKey: Bool) -> some View {
        Button {
            if server.useKey != useKey { server.secret = "" }
            server.useKey = useKey
        } label: {
            Text(title).font(.system(size: 11, weight: .medium)).frame(maxWidth: .infinity).padding(.vertical, 6)
                .background(server.useKey == useKey ? Color.white.opacity(0.15) : .clear, in: RoundedRectangle(cornerRadius: 5))
        }.buttonStyle(.plain)
    }
}
