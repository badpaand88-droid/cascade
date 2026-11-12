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
    public ConnectionSettings EntrySettings { get; private set; } = new();
    public ConnectionSettings ExitSettings { get; private set; } = new();
    ConnectionSettings Settings(int i) => i == 0 ? EntrySettings : ExitSettings;
    bool IPv6Dns => S(1).AddressMode == AddressMode.IPv6 || Addresses.Endpoints(S(1)).All(Addresses.V6);
    public void SetSettings(ConnectionSettings entry, ConnectionSettings exit) {
        if (entry == EntrySettings && exit == ExitSettings) return;
        EntrySettings = entry; ExitSettings = exit; ConfigurationChanged();
    }
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
        if (Addresses.Canonical(S(0).Host) == Addresses.Canonical(S(1).Host)) throw new InvalidOperationException("Для каскада нужны два разных VPS.");
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
        Pair(); var reachable = new List<string>();
        foreach (var host in Addresses.Endpoints(S(1))) {
            var r = await Transport.Run(S(0), P(0), Scripts.Get("link", peer: host, sshPort: S(1).Port), false, 30);
            if (r.Code == 0 && r.Output.Contains("LINK_OK")) reachable.Add(host);
        }
        if (reachable.Count == 0) throw new IOException("Между VPS нет доступного TCP-маршрута.");
        return "TCP доступен: " + string.Join(", ", reachable);
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
        if (!existingOnly) { EntrySettings.Validate(Sni); ExitSettings.Validate(Sni); }
        for (var i = 0; i < 2; i++)
        {
            var r = await Transport.Run(S(i), P(i), Scripts.Get("preflight", Sni, S(1 - i).Host, i == 0 ? "entry" : "exit", settings: Settings(i), skipTls: existingOnly)); r.Require("PREFLIGHT_OK");
            var begin = r.Output.IndexOf("CONFIG_BEGIN\n", StringComparison.Ordinal); var end = r.Output.IndexOf("\nCONFIG_END", StringComparison.Ordinal);
            if (begin >= 0 && end > begin)
            {
                var data = Encoding.UTF8.GetString(Convert.FromBase64String(r.Output[(begin + 13)..end].Trim()));
                var parsed = JsonNode.Parse(data)!.AsObject();
                var found = ConnectionSettings.From(parsed);
                if (!existingOnly && (found.Scheme != Settings(i).Scheme || found.ServerName != (found.Reality ? Sni : Settings(i).ServerName))) throw new InvalidDataException("Уже установлен другой протокол или TLS-имя. Загрузите прежние профили. Для смены протокола нужна отдельная миграция.");
                if (i == 0) { EntrySettings = found; if (existingOnly && found.Reality) Sni = found.ServerName; } else ExitSettings = found;
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
        await core.Validate(ProtocolConfig.Client(Addresses.Endpoints(S(0)), credentials[0]!, EntrySettings, Sni, IPv6Dns)); Prepared = true;
        if (existingOnly) { Installed = true; RefreshDevices(); Log?.Invoke("Профили загружены с VPS без переустановки."); }
    }
    string Config(int i) {
        var listen = Addresses.Sources(S(i)).Any(Addresses.V6) ? "::" : "0.0.0.0";
        if (configs[i] is not {} saved) return ProtocolConfig.Server(credentials[i]!, Settings(i), Sni, i == 0 ? ProtocolConfig.Outbounds(Addresses.Endpoints(S(1)), credentials[1]!, ExitSettings, Sni) : null, listen);
        var config = JsonNode.Parse(saved)!; config["inbounds"]![0]!["listen"] = listen;
        if (i == 0) config["outbounds"] = ProtocolConfig.Outbounds(Addresses.Endpoints(S(1)), credentials[1]!, ExitSettings, Sni);
        return config.ToJsonString(Profiles.Pretty);
    }
    void RefreshDevices() => Devices = Profiles.List(Config(0), S(0).Host, Sni, Addresses.Endpoints(S(0)), IPv6Dns);
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
                    configs[i] is null ? "none" : Profiles.Digest(configs[i]!), config, settings: Settings(i), sources: Addresses.Sources(S(0))), true, 780); r.Require("INSTALL_OK");
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
        var ip = await core.ProbeClient(ProtocolConfig.Client(Addresses.Endpoints(S(0)), credentials[0]!, EntrySettings, Sni, IPv6Dns)); Log?.Invoke("Сквозной тест пройден. Выходной IP: " + ip); return ip;
    }
    public async Task<string> AddDevice(string name)
    {
        Pair(); if (!Installed) throw new InvalidOperationException("Сначала загрузите установленный каскад.");
        var read = await Transport.Run(S(0), P(0), Scripts.Get("readClients", peer: S(1).Host));
        if (read.Code != 0) throw new IOException(read.Error);
        var current = Encoding.UTF8.GetString(Convert.FromBase64String(read.Output.Trim()));
        var (candidate, id) = Profiles.Add(current, name); var profiles = Profiles.List(candidate, S(0).Host, Sni, Addresses.Endpoints(S(0)), IPv6Dns);
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
        foreach (var secret in servers.Where(s => s is not null).Select(s => s!.Secret).Concat(credentials.Where(c => c is not null).SelectMany(c => new[] { c!.PrivateKey, c.Uuid })).Concat(Devices.Select(d => d.Id)).Concat(new[] { EntrySettings.Key, ExitSettings.Key }))
            if (secret.Length > 0) text = text.Replace(secret, "[скрыто]", StringComparison.Ordinal);
        return text;
    }
}
