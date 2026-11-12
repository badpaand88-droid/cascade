# -*- coding: utf-8 -*-
from pathlib import Path
import html
import shutil

root = Path('outputs/каскад')
css = '''body{margin:0;background:#0e1519;color:#e8eeed;font:16px/1.65 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}main{max-width:1060px;margin:auto;padding:50px 26px}h1{font-size:42px;line-height:1.15;margin:12px 0 18px}h2{font-size:23px}a{color:#86efc7}p{color:#acbbb9}.tag{font-size:12px;letter-spacing:2px;color:#86efc7}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(270px,1fr));gap:18px;margin-top:28px}.card{background:#182328;border:1px solid #2a3b40;border-radius:18px;padding:25px}.button{display:inline-block;background:#86efc7;color:#0b1517;padding:11px 18px;border-radius:10px;font-weight:600;text-decoration:none;margin:10px 0}.note{padding:20px;border-left:3px solid #eebd74;background:#261f18;border-radius:10px;color:#dec6a6;margin-top:25px}pre{white-space:pre-wrap;font:15px/1.7 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}img.logo{width:94px;height:94px;float:right;margin:5px 0 10px 20px}footer{margin-top:38px;font-size:13px;color:#8a9e9a}code{color:#ccebdd}'''

page = '''<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Каскад — установка</title><style>CSS</style><main>
<img class="logo" src="Cascade-icon.png" alt="Cascade"><div class="tag">CASCADE · 0.3.0</div>
<h1>Два сервера.<br>Готовое подключение.</h1>
<p>Установщик Cascade для Windows, программа для Mac и инструкция подключения iPhone/iPad через официальный sing-box.</p>
<div class="cards">
<section class="card"><h2>Windows</h2><p>Windows 10/11 x64. Автономный EXE-установщик, .NET включён. Настройка VPS, проверки, отдельные профили устройств, JSON/BPF и QR.</p>
<a class="button" href="Windows/Cascade-Setup-x64.exe">Установщик Windows</a><br><a href="Windows/ИНСТРУКЦИЯ.html">Как установить и подключить</a><br><a href="Windows/Cascade-Portable-x64.zip">Портативная ZIP-версия</a></section>
<section class="card"><h2>iPhone / iPad</h2><p>Клиент sing-box устанавливается из App Store. Индивидуальный профиль создаётся в Cascade на компьютере и передаётся на телефон.</p>
<a class="button" href="iOS/ИНСТРУКЦИЯ.html">Инструкция для iOS</a><br><a href="https://apps.apple.com/us/app/sing-box-mt/id6785326793">Официальный клиент в App Store</a><br><a href="iOS/QR установки из App Store.png">QR установки клиента</a></section>
<section class="card"><h2>Mac</h2><p>Apple Silicon, macOS 14+. Приложение Cascade 0.3 для настройки и управления тем же каскадом.</p>
<a class="button" href="macOS/Cascade-Mac-0.3.0.zip">Программа для Mac</a><br><a href="macOS/ИНСТРУКЦИЯ.html">Инструкция для Mac</a></section>
</div>
<div class="note"><strong>Статус Windows-сборки:</strong> EXE и установщик собраны на Mac. Проверены логика, криптография, конфиги, реальный локальный каскад, QR/BPF и состав установщика. Запуск GUI, установка/удаление и системный VPN на настоящей Windows ещё требуют проверки. Начните с тестового ПК.</div>
<h2>Если каскад уже установлен</h2><p>Введите прежние SSH-доступы → проверьте оба VPS → нажмите <strong>«Получить конфиги»</strong>. Устанавливать серверы заново не нужно. Для каждого устройства создавайте отдельный профиль.</p>
<h2>Что нужно для нового каскада</h2><p>Два разных VPS с Ubuntu 22.04 / 24.04 / 26.04 либо Debian 12 / 13, root или sudo без пароля, свободный TCP 443 и интернет. Собственный домен не требуется.</p>
<p>Реальные SSH-доступы и пользовательские VPN-профили в общий комплект не включены. JSON, BPF и QR выдаются внутри Cascade и содержат ключ доступа.</p>
<p><a href="ПРОВЕРКА.txt">Что проверено</a> · <a href="Исходники/Cascade-source.zip">Исходники и тесты</a> · <a href="SHA256SUMS.txt">Контрольные суммы</a></p>
<footer>Windows EXE без коммерческой Authenticode-подписи; Mac-сборка с локальной подписью. Системные проверки безопасности не отключены. Репозиторий GitHub не создавался.</footer></main></html>'''

(root / 'НАЧАТЬ ЗДЕСЬ.html').write_text(page.replace('CSS', css), encoding='utf-8')
for platform in ['Windows', 'iOS']:
    text = (root / platform / 'ИНСТРУКЦИЯ.txt').read_text(encoding='utf-8')
    (root / platform / 'ИНСТРУКЦИЯ.html').write_text(
        '<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Cascade — '
        + platform + '</title><style>' + css + '</style><main><a href="../НАЧАТЬ ЗДЕСЬ.html">← В начало</a><h1>'
        + platform + '</h1><pre>' + html.escape(text) + '</pre></main></html>', encoding='utf-8')
text = (root / 'macOS' / 'ИНСТРУКЦИЯ.md').read_text(encoding='utf-8')
(root / 'macOS' / 'ИНСТРУКЦИЯ.html').write_text(
    '<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Cascade — Mac</title><style>'
    + css + '</style><main><a href="../НАЧАТЬ ЗДЕСЬ.html">← В начало</a><h1>Mac</h1><pre>' + html.escape(text) + '</pre></main></html>', encoding='utf-8')
shutil.copyfile('design/Cascade-icon.png', root / 'Cascade-icon.png')
(root / 'README.txt').write_text('Откройте файл «НАЧАТЬ ЗДЕСЬ.html».\n\nWindows — установщик и портативная версия.\niOS — официальный клиент и инструкция импорта профиля.\nmacOS — ранее собранная программа.\nИсходники — код и тесты обеих настольных версий.\n\nСтатус и ограничения проверки: ПРОВЕРКА.txt.\n', encoding='utf-8')
print('Offline guides created')
