using System.Reflection;
using System.Text;
using System.Text.Json;

namespace Cascade.Core;
public static class ServerSecurity
{
    public static string Script(Dictionary<string, object> request)
    {
        using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("Cascade.Security.py")!;
        using var reader = new StreamReader(stream);
        var code = Convert.ToBase64String(Encoding.UTF8.GetBytes(reader.ReadToEnd()));
        var payload = Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(request));
        return $$"""
        set -eu
        umask 077
        command -v python3 >/dev/null || { echo 'На VPS нужен python3.' >&2; exit 1; }
        work=$(mktemp -d /tmp/cascade-security.XXXXXXXX)
        trap 'rm -rf "$work"' EXIT
        printf '%s' '{{code}}' | base64 -d > "$work/security.py"
        printf '%s' '{{payload}}' | base64 -d > "$work/request.json"
        python3 "$work/security.py" "$work/request.json"
        """;
    }
    public static Dictionary<string, object> Request(string action, Server server, string role, string[] sources, string tx = "")
    {
        var q = new Dictionary<string, object> { ["action"]=action,["user"]=server.User,["sshPort"]=server.Port,["role"]=role,["sources"]=sources,["client"]="127.0.0.1" };
        if (tx.Length > 0) q["tx"] = tx;
        return q;
    }
}
