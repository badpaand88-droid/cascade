import Foundation

public enum ServerSecurity {
    private static var resourceURL: URL {
        if let root=Bundle.main.resourceURL, let bundle=Bundle(url:root.appendingPathComponent("Cascade_CascadeCore.bundle")), let url=bundle.url(forResource:"security",withExtension:"py") { return url }
        return Bundle.module.url(forResource:"security",withExtension:"py")!
    }
    public static var controller: String { get throws { try String(contentsOf: resourceURL, encoding: .utf8) } }
    public static func script(_ request: [String: Any]) throws -> String {
        let payload = try JSONSerialization.data(withJSONObject: request).base64EncodedString()
        let code = try Data(controller.utf8).base64EncodedString()
        return """
        set -eu
        umask 077
        command -v python3 >/dev/null || { echo 'На VPS нужен python3.' >&2; exit 1; }
        work=$(mktemp -d /tmp/cascade-security.XXXXXXXX)
        trap 'rm -rf "$work"' EXIT
        printf '%s' '\(code)' | base64 -d > "$work/security.py"
        printf '%s' '\(payload)' | base64 -d > "$work/request.json"
        python3 "$work/security.py" "$work/request.json"
        """
    }
    public static func request(action: String, server: Server, role: String, sources: [String], tx: String = "", options: [String: Any] = [:]) -> [String: Any] {
        var q: [String: Any] = ["action": action, "user":server.user,"sshPort":Int(server.port) ?? 22,"role":role,"sources":sources,"client":"127.0.0.1"]
        if !tx.isEmpty { q["tx"] = tx }
        return q.merging(options) { _,new in new }
    }
}
