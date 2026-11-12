import Foundation

public enum RemoteScripts {
    public static func quote(_ value: String) -> String { "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'" }
    private static let header = """
    set -Eeuo pipefail
    export LC_ALL=C
    umask 077
    fail() { printf '%s\\n' "$*" >&2; exit 1; }
    test "$(id -u)" = 0 || fail 'Нужны root или sudo без запроса пароля.'
    """

    public static func preflight(sni: String, peer: String, role: String, tlsCheck: String? = nil) -> String {
        header + "\n" + """
        . /etc/os-release
        case "$ID:$VERSION_ID" in ubuntu:22.04|ubuntu:24.04|ubuntu:26.04|debian:12|debian:13) ;; *) fail 'Поддерживаются Ubuntu 22.04/24.04/26.04 и Debian 12/13.' ;; esac
        case "$(uname -m)" in x86_64|aarch64) ;; *) fail 'Нужен VPS x86_64 или ARM64.' ;; esac
        test -d /run/systemd/system || fail 'Нужен systemd; контейнеры без systemd не поддерживаются.'
        command -v ss >/dev/null || fail 'Не найден ss. Установите iproute2.'
        command -v openssl >/dev/null || fail 'Не найден openssl.'
        command -v timeout >/dev/null || fail 'Не найден timeout.'
        if test -r /proc/sys/net/ipv6/bindv6only; then
          test "$(cat /proc/sys/net/ipv6/bindv6only)" = 0 || fail 'Для двойного IPv4/IPv6 listener требуется net.ipv6.bindv6only=0. Настройте VPS и повторите проверку.'
        fi
        for p in /etc/bp-cascade /opt/bp-cascade; do
          test ! -L "$p" || fail 'Обнаружена символическая ссылка вместо каталога Cascade.'
          if test -e "$p"; then
            test -f /etc/bp-cascade/managed-by-cascade || fail 'Каталог Cascade уже занят неизвестной установкой.'
          fi
        done
        if test -e /etc/systemd/system/bp-cascade.service; then
          test -f /etc/bp-cascade/managed-by-cascade || fail 'Имя сервиса Cascade уже занято.'
        fi
        if test -f /etc/bp-cascade/managed-by-cascade; then
          test "$(cat /etc/bp-cascade/role)" = \(quote(role)) || fail 'На сервере установлена другая роль каскада.'
          test "$(cat /etc/bp-cascade/peer)" = \(quote(IPAddress.canonical(peer) ?? peer)) || fail 'Этот сервер уже связан с другим VPS. Перезапись остановлена.'
        fi
        listeners="$(ss -H -ltnp 'sport = :443'; ss -H -lunp 'sport = :443')"
        if test -n "$listeners"; then
          pid="$(systemctl show bp-cascade.service -p MainPID --value 2>/dev/null || true)"
          test -n "$pid" && test "$pid" != 0 && printf '%s' "$listeners" | grep -q "pid=$pid," || fail 'Порт 443 TCP/UDP занят другим сервисом. Ничего не остановлено.'
          other="$(printf '%s\\n' "$listeners" | grep -v "pid=$pid," || true)"
          test -z "$other" || fail 'На порту 443 обнаружен дополнительный сервис.'
        fi
        \(tlsCheck ?? ProtocolScripts.tls(ConnectionSettings(), realityName: sni))
        printf 'OS=%s %s\\nARCH=%s\\n' "$ID" "$VERSION_ID" "$(uname -m)"
        if command -v ufw >/dev/null && ufw status | grep -q 'Status: active'; then echo 'UFW=active'; fi
        if test -f /etc/bp-cascade/config.json; then
          echo CONFIG_BEGIN
          base64 -w0 /etc/bp-cascade/config.json
          printf '\\nCONFIG_END\\n'
        fi
        echo PREFLIGHT_OK
        """
    }

    public static func install(config: Data, role: String, peer: String, sni: String, transaction: String, expectedDigest: String?, tlsCheck: String? = nil, network: String = "tcp", sources: [String]? = nil) -> String {
        let payload = config.base64EncodedString()
        return preflight(sni: sni, peer: peer, role: role, tlsCheck: tlsCheck) + "\n" + """
        network=\(quote(network))
        sources=\(quote((sources ?? [peer]).joined(separator: " ")))
        role=\(quote(role))
        peer=\(quote(IPAddress.canonical(peer) ?? peer))
        command -v flock >/dev/null || fail 'Не найден flock (util-linux).'
        exec 9>/run/lock/bp-cascade.lock
        flock -n 9 || fail 'Другая установка Cascade уже выполняется.'
        expected=\(quote(expectedDigest ?? "none"))
        if test "$expected" = none; then
          test ! -f /etc/bp-cascade/config.json || fail 'Конфиг появился после проверки. Проверьте серверы заново.'
        else
          actual="$(sha256sum /etc/bp-cascade/config.json | cut -d ' ' -f1)"
          test "$actual" = "$expected" || fail 'Конфиг изменился после проверки. Проверьте серверы заново.'
        fi
        # Recheck immediately before any deployment, even after a successful preflight.
        listeners="$(ss -H -ltnp 'sport = :443'; ss -H -lunp 'sport = :443')"
        if test -n "$listeners"; then
          test -f /etc/bp-cascade/managed-by-cascade || fail 'Порт 443 занят.'
          pid="$(systemctl show bp-cascade.service -p MainPID --value 2>/dev/null || true)"
          test -n "$pid" && test "$pid" != 0 && printf '%s' "$listeners" | grep -q "pid=$pid," || fail 'Порт 443 занят другим сервисом.'
        fi
        export DEBIAN_FRONTEND=noninteractive
        if ! command -v curl >/dev/null || ! test -f /etc/ssl/certs/ca-certificates.crt; then
          apt-get -q update
          apt-get -qy install --no-install-recommends curl ca-certificates
        fi
        case "$(uname -m)" in
          x86_64) arch=amd64; digest=\(Releases.hashes["linux-amd64"]!) ;;
          aarch64) arch=arm64; digest=\(Releases.hashes["linux-arm64"]!) ;;
          *) fail 'Неподдерживаемая архитектура.' ;;
        esac
        tmp="$(mktemp -d)"
        trap 'rm -rf "$tmp"' EXIT
        curl -fsSL --proto '=https' --tlsv1.2 --connect-timeout 15 --max-time 240 --retry 2 \\
          "https://github.com/SagerNet/sing-box/releases/download/v\(Config.version)/sing-box-\(Config.version)-linux-$arch.tar.gz" -o "$tmp/core.tar.gz"
        printf '%s  %s\\n' "$digest" "$tmp/core.tar.gz" | sha256sum -c - >/dev/null || fail 'SHA-256 sing-box не совпал.'
        tar -xzf "$tmp/core.tar.gz" -C "$tmp"
        bin="$tmp/sing-box-\(Config.version)-linux-$arch/sing-box"
        printf '%s' \(quote(payload)) | base64 -d > "$tmp/config.json"
        LD_LIBRARY_PATH="$(dirname "$bin")" "$bin" check -c "$tmp/config.json"
        getent group bp-cascade >/dev/null || groupadd --system bp-cascade
        id bp-cascade >/dev/null 2>&1 || useradd --system --gid bp-cascade --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin bp-cascade
        install -d -m 700 /etc/bp-cascade
        backup=\(quote("/etc/bp-cascade/backup." + transaction))
        mkdir -m 700 "$backup"
        if test -f /etc/bp-cascade/config.json; then
          cp -p /etc/bp-cascade/config.json "$backup/config.json"
          cp -p /etc/systemd/system/bp-cascade.service "$backup/service"
          cp -p /etc/bp-cascade/role /etc/bp-cascade/peer "$backup/"
          echo existing > "$backup/kind"
        else echo new > "$backup/kind"; fi
        if systemctl is-active --quiet bp-cascade.service; then touch "$backup/was-active"; fi
        if systemctl is-enabled --quiet bp-cascade.service 2>/dev/null; then touch "$backup/was-enabled"; fi
        # The rollback script is kept on the VPS and also usable after the Mac is closed.
        cat > "$backup/rollback.sh" <<'ROLLBACK'
        set -Eeuo pipefail
        umask 077
        backup="$(cd "$(dirname "$0")" && pwd)"
        test ! -f "$backup/rolled-back" || exit 0
        if test -f "$backup/ufw-added"; then
          while read -r rule proto; do
            proto="${proto:-tcp}"
            if test "$rule" = entry; then ufw --force delete allow "443/$proto"; else ufw --force delete allow from "$rule" to any port 443 proto "$proto"; fi
          done < "$backup/ufw-added"
        fi
        systemctl stop bp-cascade.service || true
        if test "$(cat "$backup/kind")" = existing; then
          install -m 640 -o root -g bp-cascade "$backup/config.json" /etc/bp-cascade/config.json
          cp -p "$backup/service" /etc/systemd/system/bp-cascade.service
          cp -p "$backup/role" "$backup/peer" /etc/bp-cascade/
          systemctl daemon-reload
          if test -f "$backup/was-enabled"; then systemctl enable bp-cascade.service; else systemctl disable bp-cascade.service; fi
          if test -f "$backup/was-active"; then systemctl start bp-cascade.service; fi
        else
          systemctl disable bp-cascade.service 2>/dev/null || true
          rm -f /etc/systemd/system/bp-cascade.service /etc/bp-cascade/config.json
          systemctl daemon-reload
        fi
        touch "$backup/rolled-back"
        echo ROLLBACK_OK
        ROLLBACK
        chmod 700 "$backup/rollback.sh"
        printf '%s\\n' "$backup" > /etc/bp-cascade/last-backup
        touch /etc/bp-cascade/managed-by-cascade
        printf '%s\\n' "$role" > /etc/bp-cascade/role
        printf '%s\\n' "$peer" > /etc/bp-cascade/peer
        restore_on_error() { code=$?; trap - ERR HUP TERM; bash "$backup/rollback.sh" >&2 || echo 'ROLLBACK_FAILED' >&2; exit "$code"; }
        trap restore_on_error ERR HUP TERM
        install -d -m 755 /opt/bp-cascade
        if test -f "$(dirname "$bin")/libcronet.so"; then
          install -m 755 "$(dirname "$bin")/libcronet.so" /opt/bp-cascade/libcronet.so.next
          mv /opt/bp-cascade/libcronet.so.next /opt/bp-cascade/libcronet.so
        fi
        install -m 755 "$bin" /opt/bp-cascade/sing-box-\(Config.version).next
        mv /opt/bp-cascade/sing-box-\(Config.version).next /opt/bp-cascade/sing-box-\(Config.version)
        touch /etc/bp-cascade/managed-by-cascade
        printf '%s\\n' "$role" > /etc/bp-cascade/role
        printf '%s\\n' "$peer" > /etc/bp-cascade/peer
        # Directory traversal for the service account; secret config itself stays 0640.
        chown root:bp-cascade /etc/bp-cascade
        chmod 750 /etc/bp-cascade
        install -m 640 -o root -g bp-cascade "$tmp/config.json" /etc/bp-cascade/config.next
        mv /etc/bp-cascade/config.next /etc/bp-cascade/config.json
        cat > /etc/systemd/system/bp-cascade.service <<'UNIT'
        [Unit]
        Description=BadPaand Cascade (sing-box)
        After=network-online.target
        Wants=network-online.target
        [Service]
        User=bp-cascade
        Group=bp-cascade
        WorkingDirectory=/opt/bp-cascade
        Environment=LD_LIBRARY_PATH=/opt/bp-cascade
        ExecStart=/opt/bp-cascade/sing-box-\(Config.version) run -c /etc/bp-cascade/config.json
        Restart=on-failure
        RestartSec=3
        LimitNOFILE=65536
        AmbientCapabilities=CAP_NET_BIND_SERVICE
        CapabilityBoundingSet=CAP_NET_BIND_SERVICE
        NoNewPrivileges=true
        ProtectSystem=strict
        ProtectHome=true
        PrivateTmp=true
        RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
        [Install]
        WantedBy=multi-user.target
        UNIT
        chmod 644 /etc/systemd/system/bp-cascade.service
        if command -v ufw >/dev/null && ufw status | grep -q 'Status: active'; then
          if printf '%s' "$sources" | grep -q ':'; then
            grep -Eq '^IPV6=yes$' /etc/default/ufw || fail 'Для IPv6 включите поддержку IPv6 в UFW и повторите проверку.'
          fi
          if test "$role" = entry; then
            families='0.0.0.0/0'
            if printf '%s' "$sources" | grep -q ':'; then families='0.0.0.0/0 ::/0'; fi
            for source in $families; do
              result="$(ufw allow from "$source" to any port 443 proto "$network")"
              if printf '%s' "$result" | grep -q 'Rule added'; then printf '%s %s\\n' "$source" "$network" >> "$backup/ufw-added"; fi
            done
          else
            for source in $sources; do
              result="$(ufw allow from "$source" to any port 443 proto "$network")"
              if printf '%s' "$result" | grep -q 'Rule added'; then printf '%s %s\\n' "$source" "$network" >> "$backup/ufw-added"; fi
            done
          fi
        fi
        systemctl daemon-reload
        systemctl enable bp-cascade.service >/dev/null
        systemctl restart bp-cascade.service
        sleep 2
        systemctl is-active --quiet bp-cascade.service
        if test "$network" = udp; then ss -H -lun 'sport = :443' | grep -q .; else ss -H -ltn 'sport = :443' | grep -q .; fi
        trap - ERR HUP TERM
        echo INSTALL_OK
        """
    }

    public static func rollback(transaction: String) -> String {
        header + "\n" + """
        backup=\(quote("/etc/bp-cascade/backup." + transaction))
        if ! test -f "$backup/rollback.sh"; then echo ROLLBACK_NOT_NEEDED; exit 0; fi
        exec 9>/run/lock/bp-cascade.lock
        flock -n 9 || fail 'Другая операция Cascade ещё выполняется. Повторите откат позже.'
        bash "$backup/rollback.sh"
        """
    }

    public static func updateClients(config: Data, expectedDigest: String, peer: String, transaction: String) -> String {
        header + "\n" + """
        job=\(quote("/etc/bp-cascade/device-job." + transaction))
        mkdir -m 700 "$job"
        cat > "$job/worker.sh" <<'CASCADE_DEVICE_WORKER'
        \(header)
        job=\(quote("/etc/bp-cascade/device-job." + transaction))
        echo RUNNING > "$job/status"
        tmp=''
        cleanup() { result=$?; if test "$result" != 0; then echo FAILED > "$job/status"; fi; test -z "$tmp" || rm -rf "$tmp"; rm -f "$job/worker.sh"; }
        trap cleanup EXIT
        test -f /etc/bp-cascade/managed-by-cascade || fail 'На сервере нет установленного Cascade.'
        test "$(cat /etc/bp-cascade/role)" = entry || fail 'Устройства добавляются только на входном VPS.'
        test "$(cat /etc/bp-cascade/peer)" = \(quote(IPAddress.canonical(peer) ?? peer)) || fail 'Изменилась пара серверов.'
        exec 9>/run/lock/bp-cascade.lock
        flock -n 9 || fail 'Другая операция Cascade ещё выполняется.'
        actual="$(sha256sum /etc/bp-cascade/config.json | cut -d ' ' -f1)"
        test "$actual" = \(quote(expectedDigest)) || fail 'Конфиг изменился. Загрузите профили с серверов заново.'
        tmp="$(mktemp -d /etc/bp-cascade/device.XXXXXXXX)"
        printf '%s' \(quote(config.base64EncodedString())) | base64 -d > "$tmp/config.json"
        /opt/bp-cascade/sing-box-\(Config.version) check -c "$tmp/config.json"
        backup=\(quote("/etc/bp-cascade/device-backup." + transaction + ".json"))
        cp -p /etc/bp-cascade/config.json "$backup"
        chmod 600 "$backup"
        restore() {
          code=$?; test "$code" != 0 || code=1; trap - ERR TERM
          install -m 640 -o root -g bp-cascade "$backup" /etc/bp-cascade/config.json
          if systemctl restart bp-cascade.service && systemctl is-active --quiet bp-cascade.service; then echo DEVICE_UPDATE_ROLLED_BACK >&2; else echo DEVICE_ROLLBACK_NOT_CONFIRMED >&2; fi
          exit "$code"
        }
        trap restore ERR TERM
        install -m 640 -o root -g bp-cascade "$tmp/config.json" /etc/bp-cascade/config.next
        mv /etc/bp-cascade/config.next /etc/bp-cascade/config.json
        systemctl restart bp-cascade.service
        sleep 1
        systemctl is-active --quiet bp-cascade.service
        trap - ERR TERM
        echo SUCCESS > "$job/status"
        CASCADE_DEVICE_WORKER
        chmod 700 "$job/worker.sh"
        nohup /bin/bash "$job/worker.sh" </dev/null >"$job/log" 2>&1 &
        echo CLIENT_UPDATE_STARTED
        """
    }

    public static func clientUpdateStatus(transaction: String) -> String {
        header + "\n" + """
        job=\(quote("/etc/bp-cascade/device-job." + transaction))
        status="$(cat "$job/status" 2>/dev/null || true)"
        case "$status" in
          SUCCESS) echo CLIENT_UPDATE_SUCCESS ;;
          FAILED) echo CLIENT_UPDATE_FAILED; tail -n 6 "$job/log" >&2 ;;
          *) echo CLIENT_UPDATE_PENDING ;;
        esac
        """
    }

    public static func readClients(peer: String) -> String {
        header + "\n" + """
        test -f /etc/bp-cascade/managed-by-cascade || fail 'Cascade не установлен.'
        test "$(cat /etc/bp-cascade/role)" = entry || fail 'Нужен входной VPS.'
        test "$(cat /etc/bp-cascade/peer)" = \(quote(IPAddress.canonical(peer) ?? peer)) || fail 'Изменилась пара серверов.'
        base64 -w0 /etc/bp-cascade/config.json
        """
    }
}
