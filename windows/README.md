# Cascade Windows 0.3.0

Windows Forms / .NET 10. Самостоятельный установщик двух VPS с VLESS + REALITY + Vision, проверками SSH/TCP/TLS, профилями устройств, экспортом JSON/BPF и QR. GUI и серверные сценарии повторяют возможности Mac-версии.

## Сборка на Windows

Установите официальный .NET 10 SDK. Из папки `windows` выполните команды из `build.ps1` либо запустите скрипт в соответствии с действующей политикой PowerShell. Глобально отключать политики безопасности не требуется. Результат: `publish/setup/Cascade-Setup.exe`, автономная программа: `publish/app/Cascade.exe`.

Прямые зависимости: SSH.NET 2026.0.0, BouncyCastle.Cryptography 2.7.0, QRCoder 1.8.1. Лицензии: `Notices/`. .NET runtime включается в приложение при `dotnet publish -r win-x64 --self-contained true`.

`Assets/remote-scripts.json` генерируется из проверенной Mac-реализации `RemoteScripts` и `Diagnostics`. При изменении этих сценариев на Mac выполните из корня Swift-проекта:

```
swift run CascadeTemplateExporter windows/Assets/remote-scripts.json
```

Для сборки уже экспортированных шаблонов Windows не требует Swift.

## Тесты

```
dotnet run --project Cascade.Tests -- artifacts
```

Если `CASCADE_TEST_CORE` указывает на официальный исполняемый sing-box текущей ОС, проверяются все конфиги. При `CASCADE_NETWORK_TEST=1` выполняется реальный локальный тест двух REALITY-узлов с ключами X25519, созданными в .NET; системный VPN и внешние VPS тест не меняет.

Для проверки упаковки:

```
dotnet run --project Cascade.PackageCheck -- publish/app/Cascade.exe publish/setup/Cascade-Setup.exe Cascade.Setup/obj/Release/net10.0-windows/win-x64/Cascade-Setup.dll
```

## Границы проверки

Windows EXE кросс-собран на macOS. Базовая логика, конфиги, криптография, реальный локальный каскад, QR/BPF и состав EXE проверены. GUI, установка/удаление и системный TUN на настоящей Windows пока не запускались. Установщик не имеет коммерческой Authenticode-подписи.
