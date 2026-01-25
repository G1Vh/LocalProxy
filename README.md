# LocalProxy.NET

Селективный HTTP/HTTPS прокси-сервер на .NET 10, который направляет запросы к определённым доменам через внешний прокси, остальные — напрямую.

## Возможности

- ✅ **HTTP и HTTPS** — полная поддержка через CONNECT туннелирование
- ✅ **Селективная маршрутизация** — гибкая настройка доменов
- ✅ **Hot-reload** — изменение списка доменов без перезапуска
- ✅ **Автоматический Fallback** — при недоступности upstream переключается на прямое соединение
- ✅ **Windows Service** — автоматический запуск при старте системы
- ✅ **Автоустановка** — PowerShell скрипт для установки службы и настройки прокси
- ✅ **Wildcard домены** — поддержка паттернов `*.example.com`
- ✅ **Basic Auth** — аутентификация для upstream прокси

## Требования

- .NET 10 Runtime
- Windows 10/11 или Windows Server
- Права администратора (для установки службы)

## Быстрый старт

### 1. Скачать релиз

Скачайте последнюю версию из [Releases](https://github.com/OWNER/REPO/releases):
- `LocalProxy-vX.X.X-win-x64.zip` — для 64-битных систем
- `LocalProxy-vX.X.X-win-x86.zip` — для 32-битных систем

Или соберите из исходников:

### 2. Сборка из исходников

```powershell
cd LocalProxy
.\publish.bat
```

### 3. Настройка

Отредактируйте `publish/appsettings.json`:

```json
{
  "Port": 3128,
  "UpstreamProxy": {
    "Enabled": true,
    "Host": "proxy.company.com",
    "Port": 8080,
    "Username": "",
    "Password": ""
  },
  "Timeouts": {
    "HttpRequestSeconds": 30,
    "TcpConnectSeconds": 10
  },
  "Domains": [
    "github.com",
    "api.github.com",
    "*.githubcopilot.com"
  ]
}
```

### 4. Установка

**Автоматическая установка (рекомендуется):**

```powershell
cd publish
.\Manage-LocalProxyService.ps1
```

При запуске без параметров откроется **интерактивное меню**:

```
╔═══════════════════════════════════════════════════╗
║                                                   ║
║          LocalProxy Service Manager               ║
║                                                   ║
╚═══════════════════════════════════════════════════╝

  1. Установить службу
     └─ Создать Windows Service + настроить системный прокси

  2. Удалить службу
     └─ Удалить Windows Service + отключить системный прокси

  3. Показать статус
     └─ Проверить состояние службы и настроек

  4. Выход

Выберите действие [1-4]:
```

**Или используйте параметры для автоматизации:**

```powershell
# Установка
.\Manage-LocalProxyService.ps1 -Action Install

# Установка с кастомным портом
.\Manage-LocalProxyService.ps1 -Action Install -Port 8080

# Удаление
.\Manage-LocalProxyService.ps1 -Action Uninstall

# Проверка статуса
.\Manage-LocalProxyService.ps1 -Action Status
```

Скрипт автоматически:
- Создаст Windows Service с автозапуском
- Настроит системный прокси Windows
- Запустит службу

## Конфигурация

### Основные параметры

```json
{
  "Port": 3128,                    // Порт локального прокси
  "UpstreamProxy": {
    "Enabled": true,               // Использовать внешний прокси
    "Host": "proxy.example.com",   // Адрес upstream
    "Port": 8080,                  // Порт upstream
    "Username": "",                // Basic Auth (опционально)
    "Password": ""                 // Basic Auth (опционально)
  },
  "Timeouts": {
    "HttpRequestSeconds": 30,      // Таймаут HTTP запросов
    "TcpConnectSeconds": 10        // Таймаут TCP подключений
  },
  "Domains": [                     // Домены через upstream
    "example.com",                 // Точное совпадение
    "*.example.com"                // Wildcard поддомены
  ]
}
```

**Паттерны доменов:**
- `example.com` — только этот домен
- `*.example.com` — все поддомены (но не сам `example.com`)
- Пути игнорируются, проверяется только домен

**Hot-reload:** Изменения в `Domains` применяются автоматически без перезапуска.

## Управление службой

**Через скрипт:**

```powershell
# Интерактивное меню
.\Manage-LocalProxyService.ps1

# Или напрямую с параметрами
.\Manage-LocalProxyService.ps1 -Action Status
.\Manage-LocalProxyService.ps1 -Action Uninstall
```

**Через PowerShell:**

```powershell
# Проверка статуса
Get-Service LocalProxyService

# Остановка/запуск
Stop-Service LocalProxyService
Start-Service LocalProxyService

# Перезапуск после изменения настроек
Restart-Service LocalProxyService

# Логи Windows Service
Get-EventLog -LogName Application -Source LocalProxyService -Newest 20
```

## Архитектура

```
Client → LocalProxy (localhost:3128) → DomainMatcher
                                              ↓
                                    Match domain?
                                    ↙          ↘
                              Yes: PROXY    No: DIRECT
                                  ↓              ↓
                          Upstream Proxy    Target Host
                                  ↓              ↓
                            Target Host          
```

**Компоненты:**
- **ProxyServer** — TCP-сервер на `TcpListener`, обработка HTTP/HTTPS CONNECT
- **DomainMatcher** — маршрутизация по паттернам с hot-reload
- **ProxySettings** — конфигурация с binding из `appsettings.json`

**HTTPS:** Прозрачное CONNECT туннелирование, SSL/TLS не дешифруется  
**Fallback:** При ошибке upstream автоматически переключается на прямое соединение

## Troubleshooting

### Прокси не работает

```powershell
# Проверка службы
Get-Service LocalProxyService  # Должна быть Running

# Проверка порта
netstat -ano | findstr :3128  # Должен слушать 127.0.0.1:3128

# Проверка системного прокси
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" | Select ProxyEnable, ProxyServer
# ProxyEnable: 1, ProxyServer: localhost:3128
```

**Решение:** Переустановите через `.\Manage-LocalProxyService.ps1 -Action Uninstall` и `-Action Install`

### HTTPS не работает (ERR_SSL_PROTOCOL_ERROR)

**Причины:**
- Upstream прокси недоступен
- Неверная аутентификация
- Домен не в списке `Domains`

**Проверка:**
```powershell
# Проверить доступность upstream
Test-NetConnection proxy.example.com -Port 8080

# Временно отключить upstream для теста
# В appsettings.json: "Enabled": false
```

### Служба не запускается

```powershell
# Проверить логи
Get-EventLog -LogName Application -Source LocalProxyService -Newest 5

# Запустить в консоли для отладки
cd publish
.\LocalProxy.exe
```

**Частые причины:**
- Порт 3128 занят (смените в `appsettings.json`)
- Ошибки в JSON конфигурации
- Отсутствует `appsettings.json`

### Hot-reload не работает

Только изменения в `Domains` перезагружаются автоматически. Для других параметров:

```powershell
Restart-Service LocalProxyService
```

## Тестирование

```powershell
# Запуск всех тестов
dotnet test

# Ручной тест
cd LocalProxy
dotnet run

# В другом терминале
$env:HTTP_PROXY="http://localhost:3128"
$env:HTTPS_PROXY="http://localhost:3128"
curl -v https://github.com
```

## Логирование

Настройка уровня логов в `appsettings.json`:

```json
"Logging": {
  "LogLevel": {
    "Default": "Information",
    "Microsoft.AspNetCore": "Warning",
    "LocalProxy": "Debug"
  }
}
```

**Формат:**
```
2026-01-25 10:30:45 info: LocalProxy.Services.ProxyServer[0] Proxy server listening on port 3128
2026-01-25 10:30:50 info: CONNECT github.com:443 -> PROXY
2026-01-25 10:30:51 info: CONNECT example.com:443 -> DIRECT
2026-01-25 10:30:52 warn: Upstream proxy failed, falling back to direct
```

## Производительность

- **Latency:** ~1-2ms overhead
- **Memory:** ~20-30MB idle, ~40-80MB под нагрузкой
- **Connections:** 1000+ одновременных соединений
- **CPU:** <1% в idle

## Известные ограничения

- Hot-reload только для `Domains`, остальные параметры требуют перезапуска
- Один upstream прокси (нельзя разные upstream для разных доменов)
- Только доменные паттерны (нет IP-based маршрутизации)
- Только HTTP/HTTPS (нет SOCKS/FTP)

## Разработка

### Сборка из исходников

```powershell
git clone https://github.com/OWNER/REPO.git
cd LocalProxy.NET
dotnet restore
dotnet build -c Release
dotnet test
cd LocalProxy
.\publish.bat
```

### Создание релиза

Релизы создаются автоматически через GitHub Actions:

1. Обновите версию в `LocalProxy/LocalProxy.csproj`
2. Запустите workflow **"Create Release"** на GitHub
3. Укажите версию (например, `v0.3.0`)

Подробнее: [.github/ACTIONS.md](.github/ACTIONS.md)

## Лицензия

MIT License - см. [LICENSE](LICENSE)