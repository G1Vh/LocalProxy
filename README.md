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

Скачайте последнюю версию из [Releases](https://github.com/G1Vh/LocalProxy/releases):
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

**Паттерны доменов:**
- `example.com` — только этот домен
- `*.example.com` — все поддомены (но не сам `example.com`)
- Пути игнорируются, проверяется только домен

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

## Лицензия

MIT License - см. [LICENSE](LICENSE)
