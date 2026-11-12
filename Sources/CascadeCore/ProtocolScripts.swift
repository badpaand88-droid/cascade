import Foundation

public enum ProtocolScripts {
    public static func tls(_ s: ConnectionSettings, realityName: String) -> String {
        if s.scheme.isReality { return (try? Diagnostics.tls(host: realityName)) ?? "exit 1" }
        return """
        cert_tmp="$(mktemp -d)"
        trap 'rm -rf "$cert_tmp"' EXIT
        printf '%s' \(RemoteScripts.quote(Data(s.certificate.utf8).base64EncodedString())) | base64 -d > "$cert_tmp/cert.pem"
        printf '%s' \(RemoteScripts.quote(Data(s.key.utf8).base64EncodedString())) | base64 -d > "$cert_tmp/key.pem"
        openssl x509 -in "$cert_tmp/cert.pem" -noout -checkend 604800 >/dev/null || fail 'Сертификат истёк или истекает менее чем через 7 дней.'
        openssl verify -verify_hostname \(RemoteScripts.quote(s.serverName)) -untrusted "$cert_tmp/cert.pem" -CAfile /etc/ssl/certs/ca-certificates.crt "$cert_tmp/cert.pem" >/dev/null 2>&1 || fail 'Не подтверждены имя домена и доверенная полная цепочка сертификата.'
        cert_pub="$(openssl x509 -in "$cert_tmp/cert.pem" -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum | cut -d ' ' -f1)"
        key_pub="$(openssl pkey -in "$cert_tmp/key.pem" -passin pass: -pubout -outform DER 2>/dev/null | sha256sum | cut -d ' ' -f1)"
        test "$cert_pub" = "$key_pub" || fail 'Приватный ключ не соответствует сертификату.'
        rm -rf "$cert_tmp"
        trap - EXIT
        echo TLS_OK
        """
    }
}
