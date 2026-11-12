using System.Text;
using System.Text.Json.Nodes;

namespace Cascade.Core;

public sealed class Workflow(CoreRuntime? runtime = null)
{
    readonly CoreRuntime core = runtime ?? new();
    readonly Server?[] servers = new Server?[2];
    readonly HostPin?[] pins = new HostPin?[2];
    readonly bool[] authenticated = new bool[2];
    readonly string?[] configs = new string?[2];
    readonly Credentials?[] credentials = new Credentials?[2];
    string transaction = "";
    public string Sni { get; private set; } = "www.microsoft.com";
    public bool BothChecked => authenticated.All(x => x) && pins.All(x => x is not null);
    public bool Prepared { get; private set; }
    public bool Installed { get; private set; }
    public bool CanRollback => transaction.Length > 0;
    public List<DeviceProfile> Devices { get; private set; } = [];
    public Action<string>? Log { get; set; }
    public void SetServer(int index, Server server)
    {
        if (servers[index] == server) return;
        servers[index] = server; Invalidate(index);
    }
    public void Invalidate(int index)
    {
        authenticated[index] = false; pins[index] = null; Prepared = false; Installed = false;
        Devices = []; transaction = "";
    }
    public void ConfigurationChanged() { Prepared = false; Installed = false; Devices = []; transaction = ""; }
    public void SetSni(string sni)
    {
        Profiles.ValidateSni(sni);
        if (sni == Sni) return;
        Sni = sni; Prepared = false; Installed = false; Devices = []; transaction = "";
    }
    Server S(int i) => servers[i] ?? throw new InvalidOperationException($"Введите доступы сервера {i + 1}.");
    HostPin P(int i) => pins[i] ?? throw new InvalidOperationException("Сначала подтвердите SSH-ключ сервера.");
    void Pair()
    {
        S(0).Validate(); S(1).Validate(); Profiles.ValidateSni(Sni);
        if (S(0).Host == S(1).Host) throw new InvalidOperationException("Для каскада нужны два разных VPS.");
        if (!BothChecked) throw new InvalidOperationException("Проверьте SSH обоих серверов.");
    }
    public async Task CheckServer(int index, Func<HostPin, bool> confirm)
    {
        var server = S(index); server.Validate();
        authenticated[index] = false;
        var pin = pins[index];
        if (pin is null) { pin = await Transport.Scan(server); if (!confirm(pin)) throw new OperationCanceledException("Проверка отменена."); }
        var result = await Transport.Run(server, pin, Scripts.Get("ssh"), false, 25); result.Require("SSH_CONNECTED");
        pins[index] = pin; authenticated[index] = true;
        Log?.Invoke($"Сервер {index + 1}: SSH подтверждён. Настройки не менялись.");
    }
    public async Task<string> CheckLink()
    {
        Pair(); var r = await Transport.Run(S(0), P(0), Scripts.Get("link", peer: S(1).Host, sshPort: S(1).Port), false, 30); r.Require("LINK_OK");
        return "TCP доступен: " + string.Join(", ", new[] { r.Output.Contains("TCP_SSH_OK") ? $"SSH {S(1).Port}" : null, r.Output.Contains("TCP_443_OK") ? "443" : null }.Where(s => s is not null));
    }
    public async Task CheckTls()
    {
        Pair();
        for (var i = 0; i < 2; i++) { var r = await Transport.Run(S(i), P(i), Scripts.Get("tls", Sni), false, 25); r.Require("TLS_OK"); }
        Log?.Invoke("TLS 1.3 и сертификат имени подтверждены с обоих VPS.");
    }
    public async Task Prepare(bool existingOnly)
    {
        Pair(); Prepared = false; Installed = false; Devices = [];
        for (var i = 0; i < 2; i++)
        {
            var r = await Transport.Run(S(i), P(i), Scripts.Get("preflight", Sni, S(1 - i).Host, i == 0 ? "entry" : "exit")); r.Require("PREFLIGHT_OK");
            var begin = r.Output.IndexOf("CONFIG_BEGIN\n", StringComparison.Ordinal); var end = r.Output.IndexOf("\nCONFIG_END", StringComparison.Ordinal);
            if (begin >= 0 && end > begin)
            {
                var data = Encoding.UTF8.GetString(Convert.FromBase64String(r.Output[(begin + 13)..end].Trim()));
                var parsed = JsonNode.Parse(data)!.AsObject();
                if (parsed["inbounds"]![0]!["tls"]!["server_name"]!.GetValue<string>() != Sni) throw new InvalidDataException("Укажите прежнее имя TLS-сайта установленного каскада.");
                configs[i] = data; credentials[i] = Credentials.From(parsed);
            }
            else
            {
                if (existingOnly) throw new InvalidOperationException($"На сервере {i + 1} не найден Cascade.");
                configs[i] = null; credentials[i] = Credentials.Create();
            }
            Log?.Invoke($"Сервер {i + 1}: ОС, права, порт и TLS-сайт проверены.");
        }
        Log?.Invoke("Загружаем и проверяем официальное ядро sing-box…"); await core.Ensure();
        for (var i = 0; i < 2; i++) await core.Validate(Config(i));
        await core.Validate(Profiles.Client(S(0).Host, credentials[0]!, Sni)); Prepared = true;
        if (existingOnly) { Installed = true; RefreshDevices(); Log?.Invoke("Профили загружены с VPS без переустановки."); }
    }
    string Config(int i) => configs[i] ?? Profiles.Server(credentials[i]!, Sni, i == 0 ? Profiles.Outbound(S(1).Host, credentials[1]!, Sni) : null);
    void RefreshDevices() => Devices = Profiles.List(Config(0), S(0).Host, Sni);
    public async Task Install()
    {
        Pair(); if (!Prepared) throw new InvalidOperationException("Сначала проверьте готовность серверов.");
        transaction = Guid.NewGuid().ToString("N");
        try
        {
            foreach (var i in new[] { 1, 0 })
            {
                Log?.Invoke($"Устанавливаем сервер {i + 1}…"); var config = Config(i);
                var r = await Transport.Run(S(i), P(i), Scripts.Get("install", Sni, S(1 - i).Host, i == 0 ? "entry" : "exit", transaction,
                    configs[i] is null ? "none" : Profiles.Digest(configs[i]!), config), true, 780); r.Require("INSTALL_OK");
                configs[i] = config; Log?.Invoke($"Сервер {i + 1}: сервис запущен, точка отката сохранена.");
            }
            Installed = true; RefreshDevices();
        }
        catch (Exception e)
        {
            var failures = new List<string>();
            for (var i = 0; i < 2; i++)
            {
                try { var r = await Transport.Run(S(i), P(i), Scripts.Get("rollback", tx: transaction)); if (r.Code != 0 || !r.Output.Contains("ROLLBACK_")) failures.Add(S(i).Host); }
                catch { failures.Add(S(i).Host); }
            }
            Prepared = false;
            throw new IOException(e.Message + (failures.Count == 0 ? "\nОткат подтверждён или изменений ещё не было." : "\nОткат не подтверждён: " + string.Join(", ", failures) + ". Проверьте SSH и повторите откат."), e);
        }
    }
    public async Task<string> Verify()
    {
        if (!Installed) throw new InvalidOperationException("Сначала установите или загрузите каскад.");
        var ip = await core.Probe(S(0).Host, credentials[0]!, Sni); Log?.Invoke("Сквозной тест пройден. Выходной IP: " + ip); return ip;
    }
    public async Task<string> AddDevice(string name)
    {
        Pair(); if (!Installed) throw new InvalidOperationException("Сначала загрузите установленный каскад.");
        var read = await Transport.Run(S(0), P(0), Scripts.Get("readClients", peer: S(1).Host));
        if (read.Code != 0) throw new IOException(read.Error);
        var current = Encoding.UTF8.GetString(Convert.FromBase64String(read.Output.Trim()));
        var (candidate, id) = Profiles.Add(current, name); var profiles = Profiles.List(candidate, S(0).Host, Sni);
        await core.Validate(candidate); await core.Validate(profiles.First(p => p.Id == id).Json);
        var tx = Guid.NewGuid().ToString("N");
        var queued = await Transport.Run(S(0), P(0), Scripts.Get("updateClients", peer: S(1).Host, tx: tx, digest: Profiles.Digest(current), config: candidate)); queued.Require("CLIENT_UPDATE_STARTED");
        Log?.Invoke("Обновление запущено. Ожидаем восстановления связи после перезапуска входного сервиса…");
        var deadline = DateTime.UtcNow.AddSeconds(70);
        while (DateTime.UtcNow < deadline)
        {
            await Task.Delay(1000); Result state;
            try { state = await Transport.Run(S(0), P(0), Scripts.Get("updateStatus", tx: tx), true, 15); } catch { continue; }
            if (state.Output.Contains("CLIENT_UPDATE_FAILED")) throw new IOException("Устройство не добавлено. " + state.Error);
            if (state.Code == 0 && state.Output.Contains("CLIENT_UPDATE_SUCCESS"))
            {
                configs[0] = candidate; RefreshDevices(); Log?.Invoke("Устройство добавлено с отдельным UUID; прежние профили сохранены."); return id;
            }
        }
        throw new IOException("Результат обновления не подтверждён. Восстановите связь и загрузите профили заново перед повторной попыткой.");
    }
    public async Task Rollback()
    {
        if (!CanRollback) throw new InvalidOperationException("В этом сеансе нет точки отката.");
        var failures = new List<string>();
        for (var i = 0; i < 2; i++) { try { var r = await Transport.Run(S(i), P(i), Scripts.Get("rollback", tx: transaction)); r.Require("ROLLBACK_OK"); } catch { failures.Add(S(i).Host); } }
        if (failures.Count > 0) throw new IOException("Откат не подтверждён: " + string.Join(", ", failures));
        Installed = false; Prepared = false; Devices = []; transaction = ""; Log?.Invoke("Откат подтверждён. Выданные профили могут больше не работать.");
    }
    public string SafeError(Exception error)
    {
        var text = error.Message;
        foreach (var secret in servers.Where(s => s is not null).Select(s => s!.Secret).Concat(credentials.Where(c => c is not null).SelectMany(c => new[] { c!.PrivateKey, c.Uuid })).Concat(Devices.Select(d => d.Id)))
            if (secret.Length > 0) text = text.Replace(secret, "[скрыто]", StringComparison.Ordinal);
        return text;
    }
}
