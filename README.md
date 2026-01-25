# LocalProxy.NET

Селективный HTTP/HTTPS прокси-сервер на .NET 10, который направляет запросы к определённым доменам через внешний прокси, остальные — напрямую.

## Возможности

- ✅ **HTTP и HTTPS** — полная поддержка через CONNECT туннелирование
- ✅ **Селективная маршрутизация** — гибкая настройка доменов через конфигурацию
- ✅ **Hot-reload** — изменение конфигурации без перезапуска
- ✅ **Fallback** — автоматическое переключение на прямое соединение при ошибке upstream
- ✅ **Windows Service** — встроенная поддержка запуска как службы Windows
- ✅ **Wildcard поддомены** — поддержка паттернов `*.example.com`
- ✅ **Аутентификация** — Basic Auth для upstream прокси
- ✅ **Настраиваемые таймауты** — через конфигурацию

## Требования

- .NET 10 Runtime
- Windows 10/11 или Windows Server

## Быстрый старт

### 1. Сборка проекта

```powershell
dotnet build -c Release
dotnet publish -c Release -o ./publish
```

### 2. Настройка конфигурации

Отредактируйте `appsettings.json`:

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

### 3. Запуск

*Режим разработки:*
```powershell
dotnet run
```

*Production:*
```powershell
cd publish
.\LocalProxy.exe
```

## Конфигурация

### Секция `Port`
Порт локального прокси-сервера (по умолчанию: `3128`).

### Секция `UpstreamProxy`
| Параметр | Тип | Описание |
|----------|-----|----------|
| `Enabled` | `bool` | Включить маршрутизацию через внешний прокси |
| `Host` | `string` | Адрес upstream прокси |
| `Port` | `int` | Порт upstream прокси |
| `Username` | `string` | Имя пользователя для Basic Auth (необязательно) |
| `Password` | `string` | Пароль для Basic Auth (необязательно) |

### Секция `Timeouts`
| Параметр | Тип | Описание |
|----------|-----|----------|
| `HttpRequestSeconds` | `int` | Таймаут HTTP-запросов в секундах (по умолчанию: 30) |
| `TcpConnectSeconds` | `int` | Таймаут TCP-соединений в секундах (по умолчанию: 10) |

### Секция `Domains`
Массив доменных паттернов для маршрутизации через upstream прокси.

**Поддерживаемые форматы:**
- `example.com` — точное совпадение домена
- `*.example.com` — все поддомены (не включает сам `example.com`)

**Примеры:**
```json
"Domains": [
  "github.com",              // github.com -> PROXY
  "api.github.com",          // api.github.com -> PROXY
  "*.githubcopilot.com",     // api.githubcopilot.com -> PROXY
                             // githubcopilot.com -> DIRECT
  "*.business.githubcopilot.com"  // dashboard.business.githubcopilot.com -> PROXY
]
```

## Установка как Windows Service

### Вариант 1: Native Windows Service (встроенная поддержка)

```powershell
# 1. Скопируйте publish в C:\Services\LocalProxy\

# 2. Создайте службу
sc.exe create LocalProxyService binPath= "C:\Services\LocalProxy\LocalProxy.exe" start= auto DisplayName= "Local Proxy Server"

# 3. Настройте описание
sc.exe description LocalProxyService "Selective routing proxy server"

# 4. Настройте автоматический перезапуск при сбое
sc.exe failure LocalProxyService reset= 86400 actions= restart/5000/restart/5000/restart/5000

# 5. Запустите службу
sc.exe start LocalProxyService

# Проверка статуса
sc.exe query LocalProxyService

# Остановка
sc.exe stop LocalProxyService

# Удаление
sc.exe delete LocalProxyService
```

### Вариант 2: Task Scheduler (автозапуск при входе)

```powershell
$Action = New-ScheduledTaskAction -Execute "C:\Services\LocalProxy\LocalProxy.exe" -WorkingDirectory "C:\Services\LocalProxy"
$Trigger = New-ScheduledTaskTrigger -AtStartup
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

Register-ScheduledTask -TaskName "LocalProxyServer" -Action $Action -Trigger $Trigger -Settings $Settings -Principal $Principal
```

## Логирование

Логи выводятся в консоль с уровнями:
- `Information` — основные события (старт, запросы, fallback)
- `Warning` — ошибки upstream прокси с fallback
- `Error` — критические ошибки

**Формат логов:**
```
2026-01-24 22:10:26 info: LocalProxy.Services.ProxyServer[0] CONNECT api.github.com:443 -> PROXY
2026-01-24 22:10:27 info: LocalProxy.Services.ProxyServer[0] GET http://example.com/ -> DIRECT
2026-01-24 22:10:28 warn: Upstream proxy failed for CONNECT github.com:443, falling back to direct
```

## Архитектура

```
┌─────────────────┐
│  Client (Browser)  │
└────────┬─────────┘
         │
         ▼
┌─────────────────────────────────┐
│   LocalProxy (localhost:3128)   │
│   ┌──────────────────────────┐  │
│   │  ProxyServer (TcpListener) │  │
│   │  - HandleConnectAsync    │  │
│   │  - HandleHttpAsync       │  │
│   └──────────┬───────────────┘  │
│              │                   │
│              ▼                   │
│   ┌──────────────────────────┐  │
│   │  DomainMatcher           │  │
│   │  (Hot-reload patterns)   │  │
│   └──────────┬───────────────┘  │
│              │                   │
└──────────────┼───────────────────┘
               │
       ┌───────┴────────┐
       │                │
       ▼                ▼
┌─────────────┐  ┌──────────────┐
│   DIRECT    │  │ Upstream Proxy│
│ (github.com)│  │(api.github.com)│
└─────────────┘  └──────────────┘
```

### Основные компоненты:

1. **ProxyServer** (`Services/ProxyServer.cs`) — низкоуровневый TCP-сервер на `TcpListener`
   - Парсинг HTTP-запросов
   - CONNECT туннелирование для HTTPS
   - Fallback логика

2. **DomainMatcher** (`Services/DomainMatcher.cs`) — сопоставление доменов с паттернами
   - Hot-reload через `IOptionsMonitor`
   - Wildcard поддомены
   - Thread-safe кэширование

3. **ProxySettings** (`Models/ProxySettings.cs`) — конфигурационные DTO
   - Binding из `appsettings.json`
   - Helper методы для upstream proxy URL

## Как это работает

### HTTPS (CONNECT туннелирование)
1. Клиент отправляет `CONNECT github.com:443`
2. `DomainMatcher` проверяет домен по паттернам
3. Если совпадение → устанавливается туннель через upstream прокси
4. Иначе → прямое TCP-соединение к целевому хосту
5. Отправляется `200 Connection Established`
6. Начинается bidirectional копирование байтов между клиентом и целью

### HTTP
1. Клиент отправляет `GET http://example.com/`
2. `DomainMatcher` проверяет домен
3. Если совпадение → `HttpClient` с `WebProxy` отправляет запрос через upstream
4. Иначе → `HttpClient` отправляет напрямую
5. Ответ копируется обратно клиенту

### Fallback
При ошибке upstream прокси:
1. Логируется предупреждение
2. Автоматически создаётся прямое соединение
3. Запрос помечается как `DIRECT (fallback)`

## Тестирование

Запуск тестов:
```powershell
dotnet test
```

Тесты покрывают:
- ✅ Сопоставление доменов (точное, wildcard)
- ✅ Hot-reload конфигурации
- ✅ Парсинг паттернов с путями (игнорируются)

## Производительность

- **Latency overhead:** ~1-2ms для маршрутизации
- **Memory:** ~20-30MB в idle
- **Connections:** Поддержка тысяч одновременных соединений
- **Hot-reload:** <100ms на перезагрузку паттернов

## Troubleshooting

### Прокси не работает

**Проверьте:**
1. Порт 3128 свободен: `netstat -ano | findstr :3128`
2. Системный прокси настроен: `Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" | Select ProxyEnable, ProxyServer`
3. Логи показывают запросы

### ERR_SSL_PROTOCOL_ERROR

**Причина:** Проблема с CONNECT туннелированием

**Решение:**
1. Убедитесь, что домен в списке `Domains` для upstream
2. Проверьте доступность upstream прокси
3. Проверьте логи на ошибки соединения

### Upstream прокси недоступен

**Поведение:** Автоматический fallback на DIRECT

**Проверка:**
```powershell
# Проверка доступности upstream
Test-NetConnection -ComputerName proxy.company.com -Port 8080
```

### Hot-reload не работает

**Причина:** Изменение `appsettings.json` не подхватывается

**Решение:**
1. Убедитесь, что `reloadOnChange: true` в `Program.cs`
2. Сохраните файл (flush на диск)
3. Проверьте права на файл

## Лицензия

MIT License