import Foundation
import Security

public enum Diagnostics {
    public static let ssh = """
    set -eu
    printf 'SSH_CONNECTED\\n'
    """

    public static func link(host: String, sshPort: String) throws -> String {
        guard IPAddress.isValid(host), let port = Int(sshPort), (1...65535).contains(port) else { throw CascadeError("Некорректный адрес или порт второго VPS.") }
        return """
        set -eu
        command -v timeout >/dev/null || { echo 'На входном сервере нужен timeout.' >&2; exit 1; }
        reached=0
        if timeout 8 bash -c \(RemoteScripts.quote("exec 3<>/dev/tcp/" + host + "/" + sshPort)) 2>/dev/null; then echo TCP_SSH_OK; reached=1; fi
        if timeout 8 bash -c \(RemoteScripts.quote("exec 3<>/dev/tcp/" + host + "/443")) 2>/dev/null; then echo TCP_443_OK; reached=1; fi
        test "$reached" = 1 || { echo 'Входной VPS не смог открыть TCP-соединение к SSH-порту и порту 443 выходного VPS. Проверьте маршрутизацию и firewall хостинга.' >&2; exit 1; }
        echo LINK_OK
        """
    }

    public static func tls(host: String) throws -> String {
        try Config.validateSNI(host)
        return """
        set -eu
        command -v openssl >/dev/null || { echo 'На сервере не найден openssl.' >&2; exit 1; }
        command -v timeout >/dev/null || { echo 'На сервере не найден timeout.' >&2; exit 1; }
        result="$(timeout 16 openssl s_client -connect \(RemoteScripts.quote(host + ":443")) -servername \(RemoteScripts.quote(host)) -tls1_3 -verify_return_error -verify_hostname \(RemoteScripts.quote(host)) </dev/null 2>&1)" || { echo 'Не удалось подтвердить TLS 1.3 и сертификат выбранного имени с этого VPS.' >&2; exit 1; }
        printf '%s' "$result" | grep -q 'TLSv1.3' || { echo 'TLS 1.3 не подтверждён.' >&2; exit 1; }
        echo TLS_OK
        """
    }

    public static func localTLS(host: String) async throws {
        try Config.validateSNI(host)
        let configuration = URLSessionConfiguration.ephemeral
        configuration.tlsMinimumSupportedProtocolVersion = .TLSv13
        configuration.tlsMaximumSupportedProtocolVersion = .TLSv13
        configuration.timeoutIntervalForRequest = 16
        configuration.timeoutIntervalForResource = 20
        configuration.httpShouldSetCookies = false
        let session = URLSession(configuration: configuration)
        defer { session.invalidateAndCancel() }
        var request = URLRequest(url: URL(string: "https://" + host + "/")!)
        request.httpMethod = "HEAD"
        do {
            let (_, response) = try await session.data(for: request)
            guard response is HTTPURLResponse else { throw CascadeError("Сайт не ответил по HTTPS.") }
        } catch {
            throw CascadeError("TLS 1.3 и сертификат имени не подтверждены с этого Mac. " + String(error.localizedDescription.prefix(350)))
        }
    }
}
