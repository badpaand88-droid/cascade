import SwiftUI

enum CheckPhase: Equatable {
    case idle, checking, passed, failed
    var color: Color {
        switch self { case .idle: .white.opacity(0.22); case .checking: .orange; case .passed: mint; case .failed: .red.opacity(0.85) }
    }
    var symbol: String {
        switch self { case .idle: "circle.dotted"; case .checking: "arrow.triangle.2.circlepath"; case .passed: "checkmark.circle.fill"; case .failed: "exclamationmark.circle" }
    }
}

struct ConnectionMap: View {
    let phases: [CheckPhase]
    let hosts: [String]
    let linkPhase: CheckPhase
    let detail: String
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    var body: some View {
        VStack(spacing: 16) {
            HStack {
                Text("СВЯЗЬ СЕРВЕРОВ").font(.system(size: 9, weight: .semibold)).tracking(1.8).foregroundStyle(.secondary)
                Spacer()
                Text("Результаты последней проверки").font(.system(size: 10)).foregroundStyle(.tertiary)
            }
            HStack(spacing: 0) {
                node(0)
                VStack(spacing: 10) {
                    Text(linkPhase == .checking ? "ПРОВЕРЯЕМ МАРШРУТ" : "VPS 01 → VPS 02")
                        .font(.system(size: 8, weight: .medium, design: .monospaced)).tracking(1).foregroundStyle(.secondary)
                    TimelineView(.animation(minimumInterval: 1.0 / 30, paused: reduceMotion || linkPhase == .idle || linkPhase == .failed)) { timeline in
                        Canvas { context, size in
                            let y = size.height / 2
                            var path = Path(); path.move(to: CGPoint(x: 0, y: y)); path.addLine(to: CGPoint(x: size.width, y: y))
                            context.stroke(path, with: .color(.white.opacity(0.09)), lineWidth: 2)
                            if linkPhase == .passed || linkPhase == .checking {
                                context.stroke(path, with: .color(linkPhase.color.opacity(0.65)), style: StrokeStyle(lineWidth: 2, lineCap: .round, dash: linkPhase == .checking ? [5, 6] : []))
                                if !reduceMotion {
                                    let phase = timeline.date.timeIntervalSinceReferenceDate.truncatingRemainder(dividingBy: 2.6) / 2.6
                                    for offset in [0.0, 0.33, 0.66] {
                                        let x = (phase + offset).truncatingRemainder(dividingBy: 1) * size.width
                                        context.fill(Path(ellipseIn: CGRect(x: x - 3, y: y - 3, width: 6, height: 6)), with: .color(linkPhase.color))
                                    }
                                }
                            } else if linkPhase == .failed {
                                context.stroke(path, with: .color(linkPhase.color.opacity(0.6)), style: StrokeStyle(lineWidth: 2, dash: [4, 7]))
                            }
                        }
                    }.frame(height: 14).accessibilityHidden(true)
                    Label(linkPhase == .passed ? "Связь проверена" : linkPhase == .failed ? "Нет подтверждения" : "Ожидает проверки", systemImage: linkPhase.symbol)
                        .font(.system(size: 10)).foregroundStyle(linkPhase == .idle ? .secondary : linkPhase.color)
                }.padding(.horizontal, 12).offset(y: -7)
                node(1)
            }
            Text(detail).font(.system(size: 11)).foregroundStyle(linkPhase == .failed ? .orange : .secondary)
                .frame(maxWidth: .infinity).multilineTextAlignment(.center).textSelection(.enabled)
        }.padding(20).background(panelColor, in: RoundedRectangle(cornerRadius: 16))
            .overlay(RoundedRectangle(cornerRadius: 16).stroke(.white.opacity(0.06)))
    }
    func node(_ index: Int) -> some View {
        let phase = phases[index]
        return VStack(spacing: 9) {
            ZStack {
                RoundedRectangle(cornerRadius: 15).fill(phase.color.opacity(phase == .passed ? 0.12 : 0.05))
                RoundedRectangle(cornerRadius: 15).stroke(phase.color.opacity(0.65), lineWidth: 1)
                Image(systemName: "server.rack").font(.system(size: 27, weight: .light))
                    .foregroundStyle(phase.color)
                    .shadow(color: phase == .passed ? mint.opacity(0.55) : .clear, radius: 12)
                    .symbolEffect(.pulse, options: .repeating, isActive: phase == .checking && !reduceMotion)
            }.frame(width: 66, height: 62).animation(.easeInOut(duration: 0.4), value: phase)
            Text(index == 0 ? "Входной сервер" : "Выходной сервер").font(.system(size: 11, weight: .medium))
            Text(hosts[index].isEmpty ? "Не указан" : hosts[index]).font(.system(size: 9, design: .monospaced)).foregroundStyle(.secondary)
        }.frame(width: 150)
            .accessibilityElement(children: .combine)
            .accessibilityLabel("Сервер \(index + 1), \(phase == .passed ? "SSH проверен" : phase == .checking ? "идёт проверка" : phase == .failed ? "ошибка проверки" : "не проверен")")
    }
}
