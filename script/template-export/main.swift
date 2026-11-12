import Foundation
import CascadeCore

let sample = Data("CASCADE_CONFIG_PAYLOAD".utf8)
var templates: [String: String] = [
    "preflight": RemoteScripts.preflight(sni: "@@SNI@@", peer: "@@PEER@@", role: "@@ROLE@@", tlsCheck: "@@TLS_CHECK@@"),
    "install": RemoteScripts.install(config: sample, role: "@@ROLE@@", peer: "@@PEER@@", sni: "@@SNI@@", transaction: "@@TX@@", expectedDigest: "@@EXPECTED_DIGEST@@", tlsCheck: "@@TLS_CHECK@@", network: "@@NETWORK@@", sources: ["@@SOURCES@@"]),
    "rollback": RemoteScripts.rollback(transaction: "@@TX@@"),
    "readClients": RemoteScripts.readClients(peer: "@@PEER@@"),
    "updateClients": RemoteScripts.updateClients(config: sample, expectedDigest: "@@EXPECTED_DIGEST@@", peer: "@@PEER@@", transaction: "@@TX@@"),
    "updateStatus": RemoteScripts.clientUpdateStatus(transaction: "@@TX@@"),
    "ssh": Diagnostics.ssh,
    "link": try Diagnostics.link(host: "198.51.100.2", sshPort: "2222"),
    "tls": try Diagnostics.tls(host: "cascade-tls.example.com")
]
for key in templates.keys {
    templates[key] = templates[key]!.replacingOccurrences(of: sample.base64EncodedString(), with: "@@CONFIG_BASE64@@")
        .replacingOccurrences(of: "198.51.100.2", with: "@@PEER@@").replacingOccurrences(of: "/2222", with: "/@@SSH_PORT@@")
        .replacingOccurrences(of: "cascade-tls.example.com", with: "@@SNI@@")
}
let data = try JSONSerialization.data(withJSONObject: templates, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes])
try data.write(to: URL(fileURLWithPath: CommandLine.arguments[1]))
