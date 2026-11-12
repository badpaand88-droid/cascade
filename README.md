# Cascade

Локальное приложение для настройки VPN-каскада на двух собственных Linux VPS. Версии для macOS и Windows; профили можно использовать на iPhone/iPad через официальный sing-box.

```
Устройство → входной VPS → выходной VPS → Интернет
```

На обоих участках — VLESS + REALITY + Vision. Собственный домен и выпуск сертификата не требуются.

## Скачать и установить

**[Готовые сборки Cascade 0.3.0](https://github.com/badpaand88-droid/cascade/releases/tag/v0.3.0)** — собирать исходники не требуется.

| Устройство | Скачать | Установка |
| --- | --- | --- |
| Mac с Apple Silicon (M1 и новее), macOS 14+ | [DMG для Mac](https://github.com/badpaand88-droid/cascade/releases/download/v0.3.0/Cascade-Mac-arm64-0.3.0.dmg) | Откройте DMG, перетащите Cascade в «Программы», запустите оттуда. |
| Windows 10/11 x64 | [EXE-установщик](https://github.com/badpaand88-droid/cascade/releases/download/v0.3.0/Cascade-Windows-x64-0.3.0-Setup.exe) | Запустите файл и следуйте мастеру. .NET уже включён. |
| Windows x64 без установки | [Portable ZIP](https://github.com/badpaand88-droid/cascade/releases/download/v0.3.0/Cascade-Windows-x64-0.3.0-Portable.zip) | Распакуйте весь архив и откройте `Cascade.exe`. |
| iPhone / iPad | [Инструкция iOS](docs/IOS.txt) · [Скачать инструкцию](https://github.com/badpaand88-droid/cascade/releases/download/v0.3.0/Cascade-iOS-Guide.html) | Установите официальный sing-box из App Store, затем импортируйте персональный BPF/JSON из Cascade. |

[Краткая инструкция](https://github.com/badpaand88-droid/cascade/releases/download/v0.3.0/INSTALL-RU.txt) · [Контрольные суммы SHA-256](https://github.com/badpaand88-droid/cascade/releases/download/v0.3.0/SHA256SUMS.txt)

Это предварительная версия. Windows GUI, установка/удаление и TUN ещё не проверены на реальном Windows-ПК. Mac-приложение имеет ad-hoc подпись без нотариализации Apple; EXE пока без Authenticode. ОС может показать предупреждение издателя. Intel Mac этой сборкой не поддерживается. Отдельного приложения Cascade для iOS нет; импорт на физическом iPhone пока не проверен.

Пока репозиторий приватный, скачивание доступно только пользователям с доступом к нему. Для настройки нужны два собственных VPS и SSH-доступ; индивидуальные VPN-профили в релиз не включены.

## Возможности

- SSH по паролю или приватному ключу с подтверждением отпечатка сервера.
- Отдельные проверки SSH, TCP-связи между VPS и TLS-сайта.
- Установка отдельного сервиса `bp-cascade`, проверки конфигов, автозапуск и точки отката.
- Получение профилей существующего каскада без повторной установки.
- Дополнительные профили с отдельными UUID; экспорт JSON, BPF и QR.
- Загрузка официального клиента sing-box с проверкой SHA-256.
- Работа локально: без регистрации, телеметрии и отправки SSH-доступов в облако.

## Требования

Два разных VPS: Ubuntu 22.04/24.04/26.04 или Debian 12/13, systemd, x86_64/ARM64. Нужны root либо `sudo -n`, свободный TCP 443 и доступ к GitHub/выбранному TLS-сайту. Сетевой firewall панели хостинга настраивается отдельно.

**macOS:** Apple Silicon, macOS 14+; Xcode и Swift 6 для сборки.  
**Windows:** Windows 10/11 x64; .NET 10 SDK для сборки. Дистрибутив включает .NET runtime.  
**iOS:** официальный sing-box из App Store, импорт индивидуального BPF/JSON-профиля. Отдельного приложения Cascade для iOS нет.

## Сборка macOS

```sh
./script/build_and_run.sh
# собрать ZIP без запуска
./script/build_and_run.sh --package
```

Результат: `outputs/Cascade.app` и `outputs/Cascade-Mac.zip`. Тесты: `swift test`.

## Сборка Windows

См. [windows/README.md](windows/README.md). Скрипт `windows/build.ps1` собирает автономное приложение и EXE-установщик. Для сборки Windows уже экспортированные серверные шаблоны не требуют Swift.

Общие shell-сценарии Windows генерируются из Mac-реализации:

```sh
swift run CascadeTemplateExporter windows/Assets/remote-scripts.json
```

## Подключение

1. Введите доступы двух VPS и проверьте SSH каждого. Сверьте отпечатки с консолью хостинга.
2. Для нового каскада выполните подготовку и установку; для установленного нажмите «Получить конфиги».
3. Дождитесь сквозного теста и создайте отдельный профиль устройства.
4. Импортируйте JSON/BPF в соответствующий клиент sing-box и включите VPN.

JSON/BPF/QR содержат ключ доступа к VPN. Не добавляйте их в репозиторий. SSH-пароли находятся в памяти приложения и не сохраняются в настройки. Повторное подтверждение отпечатков в пределах сеанса не нужно, если оба SSH-подключения уже проверены и доступы не менялись.

## Статус проверки

Тестовая версия 0.3.0. Mac-версия прошла 28 тестов; реальный каскад после установки через Mac-приложение был проверен. Windows EXE кросс-собран на Mac: проверены криптография, конфиги, локальный двухузловой REALITY-каскад, QR/BPF и состав установщика. **GUI, установка/удаление и системный TUN на настоящей Windows пока не проверены.** Импорт на физическом iPhone также требует проверки.

Mac-сборки имеют локальную ad-hoc подпись без нотариализации Apple. Windows-сборки пока не подписаны Authenticode-сертификатом. Работа конкретной схемы зависит от сети и может меняться.

## Состав проекта

- `Sources/`, `Tests/` — Swift-приложение, общие сценарии и тесты.
- `windows/` — Windows Forms/.NET приложение, установщик, тесты и лицензии зависимостей.
- `design/` — иконка; `script/` — сборка и упаковка.
- `docs/` — инструкции и результаты проверки.

Сборки, SDK, NuGet-кэши, временные данные и пользовательские VPN-профили исключены из Git.

## Зависимости

Cascade — независимый проект. Ядро и официальные клиенты sing-box скачиваются из [SagerNet/sing-box](https://github.com/SagerNet/sing-box); их лицензия GPL-3.0-or-later. Библиотеки Windows и включённые уведомления перечислены в [windows/THIRD-PARTY.txt](windows/THIRD-PARTY.txt) и [windows/Notices/](windows/Notices/).
