import SwiftUI

struct SecurityPanel: View {
    @ObservedObject var model: InstallerModel
    @State private var expanded=false
    @State private var firewall=false
    @State private var restrictExit=false
    @State private var fail2ban=false
    @State private var updates=false
    @State private var noPassword=false
    @State private var noRoot=false
    @State private var retry=5
    @State private var findtime=10
    @State private var bantime=60
    @State private var ip=""
    @State private var confirm=false
    @State private var restore=false
    var body: some View {
        VStack(alignment:.leading,spacing:16) {
            Button { withAnimation { expanded.toggle() } } label: {
                HStack { Image(systemName:"lock.shield"); Text("Безопасность серверов").font(.headline); Spacer(); Image(systemName:expanded ? "chevron.up":"chevron.down") }
            }.buttonStyle(.plain)
            if expanded {
                Picker("Сервер",selection:$model.securityIndex) { Text("1 · Входной").tag(0); Text("2 · Выходной").tag(1) }.pickerStyle(.segmented)
                HStack { Button("Проверить безопасность") { model.securityAction("audit") }; Button("Проверить активное зондирование") { model.securityAction("probe") } }
                Text("Пробы проверяют TLS/HTTP без авторизации. REALITY использует целевой сайт; обычный TLS и padding сами по себе не скрывают VPN. Отдельный HTTPS-фронтенд для Naive/AnyTLS в этой версии не устанавливается. Проверка не гарантирует отсутствие блокировок.").font(.caption).foregroundStyle(.secondary)
                Divider()
                Text("SSH-ключ и отдельный администратор").font(.subheadline.bold())
                TextField("Имя администратора",text:$model.securityAdmin)
                HStack { TextField("Приватный ключ",text:$model.securityKeyPath); Button("Выбрать…") { model.securityChooseKey(create:false) }; Button("Создать ключ…") { model.securityChooseKey(create:true) } }
                SecureField("Парольная фраза ключа, если задана",text:$model.securityKeyPass)
                HStack { Button("Создать администратора с ключом") { model.securityUseKey(createAdmin:true) }; Button("Проверить существующий вход") { model.securityUseKey(createAdmin:false) } }
                Text("Новый администратор получает sudo без пароля для управления Cascade. Сохраните приватный ключ и имя; текущий вход остаётся доступен до отдельного запрета.").font(.caption).foregroundStyle(.secondary)
                Text("Неотмеченные пункты не изменяются.").font(.caption).foregroundStyle(.secondary)
                Toggle("Отключить SSH-вход по паролю",isOn:$noPassword)
                Toggle("Запретить прямой SSH-вход root",isOn:$noRoot)
                Text(model.securityKeyVerified[model.securityIndex] ? "Вход по ключу и sudo проверены" : "Перед запретом пароля/root нужно проверить отдельного администратора по ключу").font(.caption).foregroundStyle(model.securityKeyVerified[model.securityIndex] ? mint:.secondary)
                Divider()
                Toggle("Включить firewall IPv4 / IPv6, сохранить SSH и VPN",isOn:$firewall)
                if model.securityIndex==1 { Toggle("VPN-порт второго VPS доступен только с первого",isOn:$restrictExit).disabled(!firewall) }
                Text("Другие правила firewall сохраняются. SSH разрешается на текущем порту. Firewall хостинга настраивается в его панели.").font(.caption).foregroundStyle(.secondary)
                Toggle("Защита SSH от перебора — Fail2ban",isOn:$fail2ban)
                if fail2ban { HStack { Stepper("Попыток: \(retry)",value:$retry,in:2...20); Stepper("За \(findtime) мин",value:$findtime,in:1...1440); Stepper("Бан: \(bantime) мин",value:$bantime,in:1...10080) }.font(.caption) }
                Toggle("Автоматические обновления безопасности без автоперезагрузки",isOn:$updates)
                HStack {
                    Button("Применить выбранное…") { confirm=true }.buttonStyle(.borderedProminent).tint(mint).foregroundStyle(.black)
                        .disabled(!(firewall || fail2ban || updates || noPassword || noRoot) || !model.verified || ((noPassword || noRoot) && !model.securityKeyVerified[model.securityIndex]))
                    Button("Восстановить настройки…") { restore=true }
                }
                HStack { TextField("IP для разблокировки",text:$ip); Button("Снять бан SSH") { model.securityAction("unban",options:["ip":ip]) }.disabled(ip.isEmpty) }
                Text("Настройки сохраняются только после нового SSH-сеанса и сквозного VPN-теста. При потере связи — автоматический откат через 240 секунд. Установленные пакеты и новый администратор сохраняются.").font(.caption).foregroundStyle(.secondary)
                ScrollView { Text(model.securityReport).font(.system(size:11,design:.monospaced)).textSelection(.enabled).frame(maxWidth:.infinity,alignment:.leading).padding(12) }.frame(height:260).background(.black.opacity(0.25),in:RoundedRectangle(cornerRadius:8))
            }
        }.padding(20).background(panelColor,in:RoundedRectangle(cornerRadius:16)).disabled(model.busy)
        .alert("Применить выбранные настройки безопасности?",isPresented:$confirm) {
            Button("Применить") { model.securityAction("apply",options:["firewall":firewall,"restrictExit":restrictExit,"fail2ban":fail2ban,"updates":updates,"noPassword":noPassword,"noRoot":noRoot,"retry":retry,"findtime":findtime*60,"bantime":bantime*60]) }; Button("Отмена",role:.cancel) {}
        } message: { Text("Сервер \(model.securityIndex+1). Будут установлены необходимые пакеты и изменены выбранные настройки. SSH и каскад проверяются до отмены автоматического отката.") }
        .alert("Восстановить предыдущие настройки безопасности?",isPresented:$restore) { Button("Восстановить",role:.destructive) { model.securityAction("rollback") }; Button("Отмена",role:.cancel) {} } message: { Text("Будут восстановлены SSH, firewall, Fail2ban и настройки обновлений из последней резервной копии. Изменения этих файлов после копии также будут отменены.") }
    }
}
