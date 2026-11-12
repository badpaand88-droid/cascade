"""Assemble local 0.5.0 distribution. Builds are performed beforehand."""
from pathlib import Path
import hashlib,shutil,zipfile,sys
root=Path.cwd(); out=root/'outputs/releases/v0.5.0';out.mkdir(parents=True,exist_ok=True)
stage=root/'work/dmg-stage-0.5';stage.mkdir(parents=True,exist_ok=True)
app=stage/'Cascade.app'
if app.exists():shutil.rmtree(app)
shutil.copytree(root/'outputs/Cascade-0.5.0.app',app,symlinks=True)
link=stage/'Applications'
if not link.exists():link.symlink_to('/Applications')
shutil.copy2(root/'design/Cascade-brand.png',stage/'.panda.png')
shutil.copy2(root/'design/Cascade.icns',stage/'.VolumeIcon.icns')
(stage/'Установка.html').write_text('''<!doctype html><html lang="ru"><meta charset="utf-8"><title>Установка Cascade</title><style>body{background:#000;color:#eee;font:18px system-ui;max-width:720px;margin:50px auto;padding:24px}img{width:210px;image-rendering:pixelated}h1{font-size:38px}li{margin:16px 0}a{color:#91f3cf}</style><img src=".panda.png" alt="Панда с белой обводкой"><h1>Cascade 0.5.0</h1><ol><li>Перетащите Cascade.app в Applications («Программы»).</li><li>Запустите Cascade из «Программ».</li><li>Введите SSH-доступы к двум VPS, установите или загрузите существующий каскад.</li><li>После проверки соединения откройте «Безопасность серверов».</li></ol><p>Раздел включает SSH-ключи, firewall IPv4/IPv6, Fail2ban и обновления. Защита от зондирования зависит от протокола; отдельный HTTPS-фронтенд для Naive/AnyTLS не устанавливается.</p><p>macOS 14+, Apple Silicon. Подпись ad-hoc, без нотариализации Apple.</p></html>''')
if '--stage-only' in sys.argv:
 print('Prepared Mac DMG stage'); raise SystemExit(0)
for name in ['SECURITY.md','TESTING-0.5.md']:
 shutil.copy2(root/'docs'/name,out/name)
text='''Cascade 0.5.0

Mac: Apple Silicon (M1 и новее), macOS 14+. Откройте DMG, перенесите Cascade.app в Applications. В DMG есть инструкция с изображением панды.
Windows: Windows 10/11 x64. Запустите Cascade-Windows-x64-0.5.0-Setup.exe. .NET включён. Установка только для текущего пользователя. Portable: распакуйте весь ZIP и откройте Cascade.exe.

Для обновления завершите прежнюю Cascade, дождитесь окончания серверных операций. На Mac замените приложение; на Windows запустите новый Setup. Действующий sing-box и VPN-профиль автоматически не переключаются.

Раздел «Безопасность серверов» доступен после установки или загрузки каскада. Сначала выполните сквозной тест. Для отключения паролей/root сначала создайте и проверьте отдельного администратора по SSH-ключу. Сохраните резервную копию ключа и имя администратора. Новый администратор имеет sudo без пароля для управления Cascade.

Выбранные настройки применяются с резервной копией и таймером отката. Неотмеченные пункты не меняются. Установленные пакеты и новый администратор при откате сохраняются. Подробнее — SECURITY.md.

Активные пробы: диагностика TLS/HTTP, маскировка REALITY и ограничение второго VPS первым. Отдельный HTTPS-фронтенд для Naive/AnyTLS не устанавливается; полной незаметности программа не обещает.

Mac: ad-hoc подпись, без Developer ID/нотариализации. Windows EXE: без Authenticode. ОС может показать предупреждение неизвестного издателя. Windows GUI/установка/TUN на реальном ПК и новые настройки безопасности на реальных VPS пока не проверены; подробности TESTING-0.5.md.

Исходники и установщики не содержат личных SSH-доступов и VPN-профилей. Для iPhone используйте официальный sing-box и BPF/JSON из Cascade.
'''
(out/'INSTALL-RU.txt').write_text(text)
setup=root/'work/windows-0.5/publish/setup/Cascade-Setup.exe'
shutil.copy2(setup,out/'Cascade-Windows-x64-0.5.0-Setup.exe')
with zipfile.ZipFile(out/'Cascade-Windows-x64-0.5.0-Portable.zip','w',zipfile.ZIP_DEFLATED,compresslevel=6) as z:
 base=root/'work/windows-0.5/publish/app'
 for p in base.rglob('*'):
  if p.is_file():z.write(p,p.relative_to(base))
with zipfile.ZipFile(out/'Cascade-source-0.5.0.zip','w',zipfile.ZIP_DEFLATED,compresslevel=6) as z:
 for folder in ['Sources','Tests','script','windows','design','docs']:
  for p in (root/folder).rglob('*'):
   if p.is_file() and not any(x in ['bin','obj','__pycache__','.DS_Store','publish'] for x in p.relative_to(root).parts) and p.name not in ['payload.zip','payload.sha256']:
    z.write(p,Path('Cascade-source')/p.relative_to(root))
 for name in ['README.md','Package.swift','.gitignore']:z.write(root/name,'Cascade-source/'+name)
print('Prepared release files and DMG stage')
