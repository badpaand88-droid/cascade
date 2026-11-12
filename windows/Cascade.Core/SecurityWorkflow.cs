using System.Text.Json;
using Renci.SshNet;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System.Buffers.Binary;

namespace Cascade.Core;
public sealed partial class Workflow
{
    readonly string[] securityPending = ["", ""];
    public bool[] SecurityKeyVerified { get; } = [false,false];
    public Server SecurityServer(int i) => S(i);
    public async Task<string> SecurityRun(string action, int i, Dictionary<string,object>? options=null, string tx="")
    {
        if (!Installed) throw new InvalidOperationException("Сначала установите или загрузите каскад.");
        var q=ServerSecurity.Request(action,S(i),i==0?"entry":"exit",Addresses.Sources(S(0)),tx);
        if (options is not null) foreach (var v in options) q[v.Key]=v.Value;
        q["sni"]=Sni; q["keyVerified"]=SecurityKeyVerified[i];
        var r=await Transport.Run(S(i),P(i),ServerSecurity.Script(q),true,action=="apply"?480:90);
        if (r.Code!=0) throw new IOException(r.Error);
        return r.Output;
    }
    public async Task<string> SecurityAudit(int i)
    {
        var text=await SecurityRun("audit",i);
        using var doc=JsonDocument.Parse(text); securityPending[i]=doc.RootElement.GetProperty("pending").GetString()??""; return text;
    }
    public async Task<string> SecurityApply(int i,Dictionary<string,object> options)
    {
        await Verify();
        var tx=Guid.NewGuid().ToString("N"); securityPending[i]=tx;
        try {
            var result=await SecurityRun("apply",i,options,tx);
            var fresh=await Transport.Run(S(i),P(i),"set -eu; systemctl is-active --quiet bp-cascade; echo SECURITY_SSH_OK"); fresh.Require("SECURITY_SSH_OK");
            await Verify(); result+="\n"+await SecurityRun("commit",i,tx:tx); securityPending[i]=""; return result;
        } catch {
            try { await SecurityRun("rollback",i,tx:tx); securityPending[i]=""; } catch { }
            throw;
        }
    }
    public async Task<string> SecurityRestore(int i)
    {
        if(securityPending[i].Length>0) {
            var result=await SecurityRun("rollback",i,tx:securityPending[i]); securityPending[i]=""; return result;
        }
        var tx=Guid.NewGuid().ToString("N"); securityPending[i]=tx;
        try {
            var result=await SecurityRun("restore",i,tx:tx);
            var fresh=await Transport.Run(S(i),P(i),"set -eu; systemctl is-active --quiet bp-cascade; echo SECURITY_SSH_OK"); fresh.Require("SECURITY_SSH_OK");
            await Verify(); result+="\n"+await SecurityRun("commit",i,tx:tx); securityPending[i]=""; return result;
        } catch { try { await SecurityRun("rollback",i,tx:tx); securityPending[i]=""; } catch { } throw; }
    }
    public async Task SecurityUseKey(int i,string admin,string path,string pass,bool create)
    {
        var candidate=S(i) with { User=admin,KeyPath=path,Secret=pass }; candidate.Validate();
        if (admin=="root") throw new InvalidOperationException("Выберите отдельного администратора с sudo.");
        if (create) {
            using var key=pass.Length>0?new PrivateKeyFile(path,pass):new PrivateKeyFile(path);
            var alg=key.HostKeyAlgorithms.First(x=>x.Name=="ssh-ed25519");
            await SecurityRun("key",i,new() { ["admin"]=admin,["publicKey"]="ssh-ed25519 "+Convert.ToBase64String(alg.Data) });
        }
        var result=await Transport.Run(candidate,P(i),"set -eu; test \"$(id -u)\" = 0; echo ADMIN_KEY_OK"); result.Require("ADMIN_KEY_OK");
        servers[i]=candidate; SecurityKeyVerified[i]=true;
    }
}

public static class SecurityKeys
{
    public static void Create(string path)
    {
        // CreateNew prevents an existing key being overwritten. Tighten permissions before writing secrets.
        using var file=new FileStream(path,FileMode.CreateNew,FileAccess.Write,FileShare.None);
        if (OperatingSystem.IsWindows()) {
            var access=new System.Security.AccessControl.FileSecurity(); access.SetAccessRuleProtection(true,false);
            var sid=System.Security.Principal.WindowsIdentity.GetCurrent().User!;
            access.SetOwner(sid); access.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(sid,System.Security.AccessControl.FileSystemRights.FullControl,System.Security.AccessControl.AccessControlType.Allow));
            System.IO.FileSystemAclExtensions.SetAccessControl(file,access);
        } else File.SetUnixFileMode(path,UnixFileMode.UserRead|UnixFileMode.UserWrite);
        var key=new Ed25519PrivateKeyParameters(new SecureRandom());
        var pub=key.GeneratePublicKey().GetEncoded();
        static void Number(Stream output,uint value) { Span<byte> b=stackalloc byte[4]; BinaryPrimitives.WriteUInt32BigEndian(b,value); output.Write(b); }
        static void Blob(Stream output,byte[] value) { Number(output,(uint)value.Length); output.Write(value); }
        static byte[] Text(string value)=>System.Text.Encoding.UTF8.GetBytes(value);
        using var publicBlob=new MemoryStream(); Blob(publicBlob,Text("ssh-ed25519")); Blob(publicBlob,pub);
        using var privateBlob=new MemoryStream();
        var check=System.Security.Cryptography.RandomNumberGenerator.GetBytes(4);privateBlob.Write(check);privateBlob.Write(check);
        Blob(privateBlob,Text("ssh-ed25519"));Blob(privateBlob,pub);Blob(privateBlob,key.GetEncoded().Concat(pub).ToArray());Blob(privateBlob,Text("Cascade administrator"));
        for(byte padding=1;privateBlob.Length%8!=0;padding++)privateBlob.WriteByte(padding);
        using var document=new MemoryStream();document.Write(Text("openssh-key-v1\0"));Blob(document,Text("none"));Blob(document,Text("none"));Blob(document,[]);Number(document,1);Blob(document,publicBlob.ToArray());Blob(document,privateBlob.ToArray());
        var text="-----BEGIN OPENSSH PRIVATE KEY-----\n"+Convert.ToBase64String(document.ToArray(),Base64FormattingOptions.InsertLineBreaks)+"\n-----END OPENSSH PRIVATE KEY-----\n";
        file.Write(System.Text.Encoding.ASCII.GetBytes(text));
    }
}
