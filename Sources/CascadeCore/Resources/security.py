"""Cascade security controller. Runs only through pinned, privileged SSH.
No VPN credentials or private keys are emitted in reports.
"""
import base64, fcntl, hashlib, ipaddress, json, os, pathlib, pwd, re, shutil, socket, ssl, subprocess, sys, time
P = pathlib.Path
ROOT = P('/var/lib/bp-cascade-security')
MANAGED = [('/etc/ssh/sshd_config.d/00-cascade-security.conf','file'),
           ('/etc/fail2ban/jail.d/99-cascade.local','file'),
           ('/etc/apt/apt.conf.d/99zz-cascade-security','file'),
           ('/etc/ufw','dir'),('/etc/default/ufw','file')]

def run(args, check=True, timeout=35, input=None):
    r = subprocess.run(args, input=input, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    if check and r.returncode: raise RuntimeError('Команда не выполнена: '+args[0]+' '+r.stderr[-500:])
    return r.stdout.strip()

def write(path, text, mode=0o600):
    path=P(path); path.parent.mkdir(parents=True, exist_ok=True)
    temp=path.with_name(path.name+'.cascade-next')
    fd=os.open(str(temp), os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW, mode)
    with os.fdopen(fd,'w') as f: f.write(text)
    os.chmod(temp,mode); os.replace(temp,path)

def supported():
    info=dict(line.split('=',1) for line in P('/etc/os-release').read_text().splitlines() if '=' in line)
    distro=info.get('ID','').strip('"'); ver=info.get('VERSION_ID','').strip('"')
    if (distro,ver) not in [('ubuntu','22.04'),('ubuntu','24.04'),('ubuntu','26.04'),('debian','12'),('debian','13')]:
        raise RuntimeError('Поддерживаются Ubuntu 22.04/24.04/26.04 и Debian 12/13.')
    return distro

def config():
    if not P('/etc/bp-cascade/managed-by-cascade').exists(): raise RuntimeError('На сервере не найден управляемый Cascade.')
    return json.loads(P('/etc/bp-cascade/config.json').read_text())

def ssh_settings(user, client):
    return run(['/usr/sbin/sshd','-T','-C',f'user={user},addr={client},host={client}'])

def active(service): return run(['systemctl','is-active',service],False)=='active'
def enabled(service): return run(['systemctl','is-enabled',service],False) in ['enabled','enabled-runtime']
def report(q):
    cfg=config(); inp=cfg['inbounds'][0]; tls=inp.get('tls',{})
    f2b=run(['fail2ban-client','status','sshd'],False) if shutil.which('fail2ban-client') else 'Не установлен'
    return {'os':P('/etc/os-release').read_text(), 'ssh':ssh_settings(q['user'],q['client']),
      'ports':run(['ss','-H','-lntu'],False), 'firewall':run(['ufw','status','verbose'],False) if shutil.which('ufw') else 'Не установлен',
      'fail2ban':f2b, 'bans':run(['fail2ban-client','get','sshd','banip'],False) if shutil.which('fail2ban-client') else '',
      'updates':'\n'.join(x for x in run(['apt-config','dump'],False).splitlines() if x.startswith(('APT::Periodic','Unattended-Upgrade'))), 'pending':(ROOT/'pending').read_text() if (ROOT/'pending').exists() else '',
      'scheme':inp['type']+(' + REALITY' if tls.get('reality',{}).get('enabled') else ''),
      'service':active('bp-cascade'), 'notice':'Проверка не доказывает отсутствие DPI или блокировок. Fail2ban защищает SSH, а не скрывает VPN.'}

def validate(q):
    if q.get('role') not in ['entry','exit']: raise ValueError('Некорректная роль')
    q['sshPort']=int(q['sshPort'])
    if not 1<=q['sshPort']<=65535: raise ValueError('Некорректный SSH-порт')
    if not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}',q['user']): raise ValueError('Некорректный SSH-пользователь')
    q['client']=str(ipaddress.ip_address(q['client']))
    q['sources']=[str(ipaddress.ip_address(v)) for v in q.get('sources',[])]
    for k,lo,hi in [('retry',2,20),('findtime',60,86400),('bantime',60,604800)]:
        q[k]=int(q.get(k,{'retry':5,'findtime':600,'bantime':3600}[k]))
        if not lo<=q[k]<=hi: raise ValueError('Некорректный интервал Fail2ban')
    if 'tx' in q and not re.fullmatch('[a-f0-9]{32}',q['tx']): raise ValueError('Некорректная транзакция')
    return q

def install(packages):
    missing=[p for p in packages if run(['dpkg-query','-W','-f=${Status}',p],False)!='install ok installed']
    if missing:
        env=os.environ.copy(); env['DEBIAN_FRONTEND']='noninteractive'; env['NEEDRESTART_MODE']='l'
        for args in [['apt-get','-o','DPkg::Lock::Timeout=45','update'],['apt-get','-o','DPkg::Lock::Timeout=45','install','-y','--no-upgrade']+missing]:
            r=subprocess.run(args,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=180)
            if r.returncode: raise RuntimeError('Не удалось установить зависимости: '+r.stderr[-500:])

def snapshot(tx):
    d=ROOT/tx; d.mkdir(mode=0o700)
    state={'files':[], 'services':{s:[active(s),enabled(s)] for s in ['fail2ban','apt-daily.timer','apt-daily-upgrade.timer']},
           'ufw':bool(shutil.which('ufw') and 'Status: active' in run(['ufw','status'],False))}
    for n,(name,kind) in enumerate(MANAGED):
        p=P(name); exists=p.exists(); state['files'].append([name,kind,exists,str(n)])
        if exists:
            if p.is_symlink(): raise RuntimeError('Символическая ссылка в управляемом пути: '+name)
            if kind=='dir': shutil.copytree(p,d/str(n),symlinks=True)
            else: shutil.copy2(p,d/str(n))
    write(d/'state.json',json.dumps(state)); write(ROOT/'pending',tx)
    # This script and payload survive disconnection. Timer is armed before any config edits.
    shutil.copy2(__file__,d/'controller.py'); os.chmod(d/'controller.py',0o600)
    write(d/'rollback.json',json.dumps({'action':'rollback','tx':tx}))
    try:
        run(['systemd-run','--unit=bp-security-'+tx,'--on-active=240s','--timer-property=AccuracySec=1s','/usr/bin/python3',str(d/'controller.py'),str(d/'rollback.json')])
    except BaseException:
        (ROOT/'pending').unlink(missing_ok=True); raise
    return d

def restore(tx, finish=True):
    d=ROOT/tx; state=json.loads((d/'state.json').read_text())
    for name,kind,exists,num in state['files']:
        p=P(name)
        if p.exists():
            if kind=='dir': shutil.rmtree(p)
            else: p.unlink()
        if exists:
            if kind=='dir': shutil.copytree(d/num,p,symlinks=True)
            else: p.parent.mkdir(parents=True,exist_ok=True); shutil.copy2(d/num,p)
    if shutil.which('ufw'): run(['ufw','--force','enable' if state['ufw'] else 'disable'])
    run(['/usr/sbin/sshd','-t']); run(['systemctl','reload','ssh'])
    for s,(was_active,was_enabled) in state['services'].items():
        run(['systemctl','enable' if was_enabled else 'disable',s],was_enabled)
        run(['systemctl','restart' if was_active else 'stop',s],was_active)
    if finish:
        write(d/'result','ROLLED_BACK'); (ROOT/'pending').unlink(missing_ok=True)
        run(['systemctl','stop','bp-security-'+tx+'.timer'],False)

def firewall(q):
    # Existing rules and services are preserved; prepend explicit rules for Cascade.
    default=P('/etc/default/ufw')
    txt=default.read_text(); txt=re.sub(r'^IPV6=.*$', 'IPV6=yes',txt,flags=re.M)
    if 'IPV6=yes' not in txt: txt+='\nIPV6=yes\n'
    write(default,txt,0o644)
    run(['ufw','insert','1','allow',str(q['sshPort'])+'/tcp','comment','Cascade SSH'])
    inp=config()['inbounds'][0]; network=inp.get('network','')
    protos=['udp'] if network=='udp' or inp.get('transport',{}).get('type')=='quic' else ['tcp','udp'] if inp['type']=='naive' and not network else ['tcp']
    for proto in protos:
        if q['role']=='exit' and q.get('restrictExit'):
            if not q['sources']: raise RuntimeError('Нужны адреса первого VPS')
            run(['ufw','insert','1','deny','proto',proto,'from','any','to','any','port','443','comment','Cascade exit guard'])
            for src in q['sources']: run(['ufw','insert','1','allow','proto',proto,'from',src,'to','any','port','443','comment','Cascade entry peer'])
        else: run(['ufw','insert','1','allow',str(443)+'/'+proto,'comment','Cascade VPN'])
    run(['ufw','--force','enable'])

def apply(q):
    config(); distro=supported()
    if P('/etc/bp-cascade/role').read_text().strip()!=q['role']: raise RuntimeError('Роль сервера изменилась; загрузите каскад заново.')
    if (ROOT/'pending').exists(): raise RuntimeError('Есть незавершённая операция; выполните проверку или откат.')
    if q.get('noPassword') or q.get('noRoot'):
        if not q.get('keyVerified') or q['user']=='root': raise RuntimeError('Сначала проверьте SSH-ключ отдельного администратора с sudo.')
        account=pwd.getpwnam(q['user'])
        if not (P(account.pw_dir)/'.ssh/authorized_keys').exists(): raise RuntimeError('У администратора нет authorized_keys.')
        run(['sudo','-n','-u',q['user'],'sudo','-n','true'])
    packages=[]
    if q.get('firewall'): packages+=['ufw']
    if q.get('fail2ban'): packages+=['fail2ban','python3-systemd','nftables']
    if q.get('updates'): packages+=['unattended-upgrades']
    # Install packages first. Package installation isn't rolled back, configuration is.
    install(packages)
    tx=q['tx']; d=snapshot(tx)
    try:
        if q.get('firewall'): firewall(q)
        if q.get('noPassword') or q.get('noRoot'):
            text='# Managed by Cascade security\n'
            if q.get('noPassword'): text+='PasswordAuthentication no\nKbdInteractiveAuthentication no\nPubkeyAuthentication yes\n'
            if q.get('noRoot'): text+='PermitRootLogin no\n'
            write(MANAGED[0][0],text,0o644); run(['/usr/sbin/sshd','-t'])
            eff=ssh_settings(q['user'],q['client'])
            if q.get('noPassword') and ('passwordauthentication no' not in eff or 'kbdinteractiveauthentication no' not in eff): raise RuntimeError('Другие правила SSH переопределяют запрет паролей.')
            if q.get('noRoot') and 'permitrootlogin no' not in ssh_settings('root',q['client']): raise RuntimeError('Другие правила SSH разрешают root.')
            run(['systemctl','reload','ssh'])
        if q.get('fail2ban'):
            # ignoreip is extended, not replaced, including current observed SSH source.
            write(MANAGED[1][0],f'''# Managed by Cascade security
[sshd]
enabled = true
backend = systemd
port = {q['sshPort']}
maxretry = {q['retry']}
findtime = {q['findtime']}
bantime = {q['bantime']}
banaction = nftables-multiport
ignoreip = %(known/ignoreip)s {q['client']} {' '.join(q['sources'])}
''',0o644)
            run(['fail2ban-client','-t']); run(['systemctl','enable','--now','fail2ban']); run(['fail2ban-client','reload'])
            run(['fail2ban-client','status','sshd'])
        if q.get('updates'):
            origin='Ubuntu' if distro=='ubuntu' else 'Debian'
            pattern='origin=Ubuntu,archive=${distro_codename}-security' if distro=='ubuntu' else 'origin=Debian,codename=${distro_codename}-security,label=Debian-Security'
            write(MANAGED[2][0],'''// Managed by Cascade security
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
#clear Unattended-Upgrade::Allowed-Origins;
#clear Unattended-Upgrade::Origins-Pattern;
Unattended-Upgrade::Origins-Pattern { "'''+pattern+'''"; };
Unattended-Upgrade::Automatic-Reboot "false";
''',0o644)
            run(['apt-config','dump']); run(['systemctl','enable','--now','apt-daily.timer','apt-daily-upgrade.timer'])
        if not active('bp-cascade'): raise RuntimeError('Сервис Cascade не работает')
        write(d/'result','PENDING'); return {'pending':tx,'message':'Настройки применены временно. Через 240 секунд — откат, если проверки не подтвердят результат.'}
    except BaseException:
        restore(tx); raise

def key_setup(q):
    user=q.get('admin',''); pub=q.get('publicKey','').strip()
    if not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}',user) or user=='root': raise ValueError('Нужно отдельное имя администратора')
    if not re.fullmatch(r'ssh-ed25519 [A-Za-z0-9+/]+={0,2}(?: [^\r\n]*)?',pub): raise ValueError('Требуется публичный ключ Ed25519')
    # Existing accounts are never granted sudo or modified by this action.
    try: pwd.getpwnam(user); raise RuntimeError('Пользователь уже существует. Выберите новое имя или проверьте существующий SSH-ключ.')
    except KeyError: pass
    run(['useradd','--create-home','--shell','/bin/bash','--password','*',user]); account=pwd.getpwnam(user)
    home=P(account.pw_dir); ssh=home/'.ssh'; ssh.mkdir(mode=0o700); os.chown(ssh,account.pw_uid,account.pw_gid)
    write(ssh/'authorized_keys',pub+'\n'); os.chown(ssh/'authorized_keys',account.pw_uid,account.pw_gid)
    sudo=P('/etc/sudoers.d/cascade-'+user)
    try:
        write(sudo,user+' ALL=(ALL:ALL) NOPASSWD: ALL\n',0o440); run(['visudo','-cf',str(sudo)])
    except BaseException:
        sudo.unlink(missing_ok=True); raise
    return {'message':'Администратор создан. Старый вход сохранён. Проверьте новый вход по ключу перед запретом паролей/root.','admin':user}

def probe(q):
    cfg=config(); inp=cfg['inbounds'][0]; tls=inp.get('tls',{}); reality=tls.get('reality',{}).get('enabled',False)
    name=tls.get('server_name') or q.get('sni','')
    if reality: name=q.get('sni','')
    if not re.fullmatch(r'[A-Za-z0-9.-]{1,253}',name): raise ValueError('Укажите корректное TLS-имя')
    host=str(ipaddress.ip_address(q.get('probeHost', '127.0.0.1')))
    results=[]
    for title,request in [('HTTPS без авторизации',b'GET / HTTP/1.1\r\nHost: '+name.encode()+b'\r\nConnection: close\r\n\r\n'),
                          ('CONNECT без авторизации',b'CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nConnection: close\r\n\r\n'),
                          ('CONNECT с неверным паролем',b'CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Basic Y2FzY2FkZS1wcm9iZTppbnZhbGlk\r\nConnection: close\r\n\r\n')]:
        try:
            context=ssl.create_default_context(); context.set_alpn_protocols(['http/1.1'])
            with socket.create_connection((host,443),timeout=7) as raw:
                with context.wrap_socket(raw,server_hostname=name) as conn:
                    conn.settimeout(7); conn.sendall(request); data=conn.recv(2048)
                    status=data.split(b'\r\n',1)[0].decode('ascii','replace')[:120]
                    results.append({'test':title,'result':status or 'Соединение закрыто','alpn':conn.selected_alpn_protocol()})
        except Exception as e: results.append({'test':title,'result':type(e).__name__})
    return {'tests':results,'reality':reality,'type':inp['type'],
      'notice':'Это наблюдение TLS/HTTP с VPS, не доказательство неразличимости и не внешний DPI-тест. QUIC/H2 и неверные VLESS/AnyTLS-учётные данные здесь не проверяются. Для REALITY ответ зависит от целевого сайта. Naive в sing-box не равен Caddy с probe_resistance.'}

def main(q):
    action=q['action']
    ROOT.mkdir(mode=0o700,parents=True,exist_ok=True)
    lock=open(ROOT/'lock','a'); fcntl.flock(lock,fcntl.LOCK_EX)
    # Share the deployment lock with profile updates and installer rollback.
    deployment=open('/run/lock/bp-cascade.lock','a'); fcntl.flock(deployment,fcntl.LOCK_EX if action=='rollback' else fcntl.LOCK_EX|fcntl.LOCK_NB)
    if action in ['commit','rollback']:
        tx=q['tx']
        if not re.fullmatch('[a-f0-9]{32}',tx): raise ValueError('Некорректная транзакция')
        if not (ROOT/'pending').exists() or (ROOT/'pending').read_text()!=tx: raise RuntimeError('Операция уже завершена или откат выполнен.')
        if action=='rollback': restore(tx); return {'message':'Настройки восстановлены'}
        # Check the deadline before canceling: a late commit cannot overtake rollback.
        if time.time()-(ROOT/tx/'state.json').stat().st_mtime>220: raise RuntimeError('Срок подтверждения истёк; дождитесь отката.')
        run(['systemctl','stop','bp-security-'+tx+'.timer']); write(ROOT/tx/'result','COMMITTED'); (ROOT/'pending').unlink()
        write(ROOT/'latest',tx); return {'message':'Изменения подтверждены; резервная копия сохранена.'}
    if action=='restore':
        if (ROOT/'pending').exists(): raise RuntimeError('Сначала завершите текущую операцию.')
        old=(ROOT/'latest').read_text(); tx=q['tx']
        if not re.fullmatch('[a-f0-9]{32}',tx): raise ValueError('Некорректная транзакция')
        snapshot(tx)
        try: restore(old,finish=False)
        except BaseException:
            restore(tx); raise
        return {'pending':tx,'message':'Предыдущие настройки восстановлены временно; требуется проверка SSH и VPN.'}
    if action=='key': return key_setup(q)
    q=validate(q)
    if action=='audit': return report(q)
    if action=='apply': return apply(q)
    if action=='probe': return probe(q)
    if action=='unban':
        ip=str(ipaddress.ip_address(q['ip'])); run(['fail2ban-client','set','sshd','unbanip',ip]); return {'message':'IP разблокирован'}
    raise ValueError('Неизвестное действие')

if __name__=='__main__':
    try:
        if os.geteuid()!=0: raise RuntimeError('Нужны права root / sudo без пароля.')
        q=json.loads(P(sys.argv[1]).read_text())
        if q.get('action') not in ['commit','rollback','restore','key']:
            # The authoritative source of the client address is supplied by SSH, not the GUI.
            conn=os.environ.get('CASCADE_CONNECTION','').split()
            if len(conn)!=4: raise RuntimeError('SSH_CONNECTION не передан; безопасная настройка недоступна.')
            q['client']=conn[0]
        print(json.dumps(main(q),ensure_ascii=False,indent=2))
    except Exception as e:
        print(str(e),file=sys.stderr); sys.exit(1)
