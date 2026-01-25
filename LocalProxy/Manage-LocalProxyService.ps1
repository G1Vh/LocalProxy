#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Управление LocalProxy как службой Windows с настройкой системного прокси.

.DESCRIPTION
    Скрипт устанавливает/удаляет LocalProxy как службу Windows с автозапуском
    и управляет настройками системного прокси.
    
    При запуске без параметров открывается интерактивное меню.

.PARAMETER Action
    Действие: Install, Uninstall или Status (опционально, если не указано - откроется меню)

.PARAMETER Port
    Порт прокси-сервера (по умолчанию: 3128)

.EXAMPLE
    .\Manage-LocalProxyService.ps1
    Интерактивное меню выбора действия
    
.EXAMPLE
    .\Manage-LocalProxyService.ps1 -Action Install
    Установка службы с параметрами по умолчанию
    
.EXAMPLE
    .\Manage-LocalProxyService.ps1 -Action Install -Port 8080
    Установка службы с кастомным портом
    
.EXAMPLE
    .\Manage-LocalProxyService.ps1 -Action Uninstall
    Удаление службы
#>

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Install", "Uninstall", "Status")]
    [string]$Action,
    
    [Parameter(Mandatory=$false)]
    [int]$Port = 3128
)

$ServiceName = "LocalProxyService"
$ServiceDisplayName = "Local Proxy Server"
$ServiceDescription = "Selective routing proxy server for HTTP/HTTPS traffic"

# Путь к exe рядом со скриптом
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ExePath = Join-Path $ScriptDir "LocalProxy.exe"

function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    Write-Host $Message -ForegroundColor $Color
}

function Test-ServiceExists {
    param([string]$Name)
    $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
    return $null -ne $service
}

function Install-LocalProxyService {
    Write-ColorOutput "`n=== Установка LocalProxy как службы Windows ===" "Cyan"
    
    # Проверка существования exe
    if (-not (Test-Path $ExePath)) {
        Write-ColorOutput "ОШИБКА: Не найден файл $ExePath" "Red"
        exit 1
    }
    
    Write-ColorOutput "Найден: $ExePath" "Green"
    
    # Проверка существующей службы
    if (Test-ServiceExists $ServiceName) {
        Write-ColorOutput "Служба '$ServiceName' уже существует. Удаляю..." "Yellow"
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        sc.exe delete $ServiceName | Out-Null
        Start-Sleep -Seconds 2
    }
    
    # Создание службы
    Write-ColorOutput "Создаю службу Windows..." "Cyan"
    $createResult = sc.exe create $ServiceName binPath= "`"$ExePath`"" start= auto DisplayName= $ServiceDisplayName
    
    if ($LASTEXITCODE -ne 0) {
        Write-ColorOutput "ОШИБКА: Не удалось создать службу" "Red"
        Write-ColorOutput $createResult "Red"
        exit 1
    }
    
    Write-ColorOutput "Служба создана успешно" "Green"
    
    # Установка описания
    sc.exe description $ServiceName $ServiceDescription | Out-Null
    
    # Настройка автоперезапуска при сбое (перезапуск через 5 сек, 3 попытки)
    sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/5000/restart/5000 | Out-Null
    Write-ColorOutput "Настроен автоматический перезапуск при сбое" "Green"
    
    # Запуск службы
    Write-ColorOutput "Запускаю службу..." "Cyan"
    $startResult = sc.exe start $ServiceName
    
    if ($LASTEXITCODE -ne 0) {
        Write-ColorOutput "ПРЕДУПРЕЖДЕНИЕ: Не удалось запустить службу" "Yellow"
        Write-ColorOutput $startResult "Yellow"
        Write-ColorOutput "Попробуйте запустить вручную: sc.exe start $ServiceName" "Yellow"
    } else {
        Start-Sleep -Seconds 2
        $service = Get-Service -Name $ServiceName
        if ($service.Status -eq "Running") {
            Write-ColorOutput "Служба успешно запущена" "Green"
        } else {
            Write-ColorOutput "Статус службы: $($service.Status)" "Yellow"
        }
    }
    
    # Настройка системного прокси
    Write-ColorOutput "`nНастройка системного прокси..." "Cyan"
    Set-SystemProxy -Enable $true -Port $Port
    
    Write-ColorOutput "`n=== Установка завершена ===" "Green"
    Write-ColorOutput "Служба: $ServiceName" "White"
    Write-ColorOutput "Статус: sc.exe query $ServiceName" "White"
    Write-ColorOutput "Остановка: sc.exe stop $ServiceName" "White"
    Write-ColorOutput "Запуск: sc.exe start $ServiceName" "White"
    Write-ColorOutput "Прокси: localhost:$Port" "White"
}

function Uninstall-LocalProxyService {
    Write-ColorOutput "`n=== Удаление LocalProxy ===" "Cyan"
    
    # Проверка существования службы
    if (-not (Test-ServiceExists $ServiceName)) {
        Write-ColorOutput "Служба '$ServiceName' не найдена" "Yellow"
    } else {
        # Остановка службы
        Write-ColorOutput "Остановка службы..." "Cyan"
        $service = Get-Service -Name $ServiceName
        if ($service.Status -ne "Stopped") {
            Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
        }
        
        # Удаление службы
        Write-ColorOutput "Удаление службы..." "Cyan"
        sc.exe delete $ServiceName | Out-Null
        
        if ($LASTEXITCODE -eq 0) {
            Write-ColorOutput "Служба удалена успешно" "Green"
        } else {
            Write-ColorOutput "ОШИБКА: Не удалось удалить службу" "Red"
        }
    }
    
    # Отключение системного прокси
    Write-ColorOutput "`nОтключение системного прокси..." "Cyan"
    Set-SystemProxy -Enable $false
    
    Write-ColorOutput "`n=== Удаление завершено ===" "Green"
}

function Set-SystemProxy {
    param(
        [bool]$Enable,
        [int]$Port = 3128
    )
    
    $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    
    try {
        if ($Enable) {
            Set-ItemProperty -Path $regPath -Name ProxyEnable -Value 1
            Set-ItemProperty -Path $regPath -Name ProxyServer -Value "localhost:$Port"
            Write-ColorOutput "Системный прокси включен: localhost:$Port" "Green"
        } else {
            Set-ItemProperty -Path $regPath -Name ProxyEnable -Value 0
            Write-ColorOutput "Системный прокси отключен" "Green"
        }
        
        # Уведомление системы об изменении настроек прокси
        $signature = @'
[DllImport("wininet.dll")]
public static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);
'@
        $type = Add-Type -MemberDefinition $signature -Name WinInet -Namespace Win32 -PassThru
        $INTERNET_OPTION_SETTINGS_CHANGED = 39
        $INTERNET_OPTION_REFRESH = 37
        $type::InternetSetOption(0, $INTERNET_OPTION_SETTINGS_CHANGED, 0, 0) | Out-Null
        $type::InternetSetOption(0, $INTERNET_OPTION_REFRESH, 0, 0) | Out-Null
        
        Write-ColorOutput "Настройки прокси применены к системе" "Green"
    }
    catch {
        Write-ColorOutput "ОШИБКА при настройке системного прокси: $_" "Red"
    }
}

function Show-Status {
    Write-ColorOutput "`n=== Статус LocalProxy ===" "Cyan"
    
    # Проверка службы
    if (Test-ServiceExists $ServiceName) {
        $service = Get-Service -Name $ServiceName
        Write-ColorOutput "`nСлужба Windows:" "Yellow"
        Write-Host "  Имя: $ServiceName"
        Write-Host "  Статус: $($service.Status)" -ForegroundColor $(if ($service.Status -eq "Running") { "Green" } else { "Red" })
        Write-Host "  Тип запуска: $($service.StartType)"
    } else {
        Write-ColorOutput "`nСлужба Windows:" "Yellow"
        Write-ColorOutput "  НЕ УСТАНОВЛЕНА" "Red"
    }
    
    # Проверка системного прокси
    $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    $proxyEnable = (Get-ItemProperty -Path $regPath).ProxyEnable
    $proxyServer = (Get-ItemProperty -Path $regPath).ProxyServer
    
    Write-ColorOutput "`nСистемный прокси:" "Yellow"
    if ($proxyEnable -eq 1) {
        Write-ColorOutput "  Включен: $proxyServer" "Green"
    } else {
        Write-ColorOutput "  Отключен" "Red"
    }
    
    # Проверка порта
    Write-ColorOutput "`nСетевой порт:" "Yellow"
    $tcpConnection = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
    if ($tcpConnection) {
        Write-ColorOutput "  Порт $Port слушается (LocalAddress: $($tcpConnection.LocalAddress))" "Green"
    } else {
        Write-ColorOutput "  Порт $Port не слушается" "Red"
    }
    
    # Проверка exe файла
    Write-ColorOutput "`nФайл прокси:" "Yellow"
    if (Test-Path $ExePath) {
        Write-Host "  Найден: $ExePath"
        $fileInfo = Get-Item $ExePath
        Write-Host "  Размер: $([math]::Round($fileInfo.Length / 1KB, 2)) KB"
        Write-Host "  Изменён: $($fileInfo.LastWriteTime)"
    } else {
        Write-ColorOutput "  НЕ НАЙДЕН: $ExePath" "Red"
    }
    
    Write-Host ""
}

function Show-Menu {
    Clear-Host
    Write-Host ""
    Write-Host "╔═══════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                                                   ║" -ForegroundColor Cyan
    Write-Host "║          LocalProxy Service Manager               ║" -ForegroundColor Cyan
    Write-Host "║                                                   ║" -ForegroundColor Cyan
    Write-Host "╚═══════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  1. " -NoNewline -ForegroundColor White
    Write-Host "Установить службу" -ForegroundColor Green
    Write-Host "     └─ Создать Windows Service + настроить системный прокси" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  2. " -NoNewline -ForegroundColor White
    Write-Host "Удалить службу" -ForegroundColor Red
    Write-Host "     └─ Удалить Windows Service + отключить системный прокси" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  3. " -NoNewline -ForegroundColor White
    Write-Host "Показать статус" -ForegroundColor Yellow
    Write-Host "     └─ Проверить состояние службы и настроек" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  4. " -NoNewline -ForegroundColor White
    Write-Host "Выход" -ForegroundColor Gray
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
}

function Get-UserChoice {
    while ($true) {
        Write-Host "Выберите действие [1-4]: " -NoNewline -ForegroundColor Cyan
        $choice = Read-Host
        
        switch ($choice) {
            "1" { return "Install" }
            "2" { return "Uninstall" }
            "3" { return "Status" }
            "4" { return "Exit" }
            default {
                Write-ColorOutput "Неверный выбор. Введите число от 1 до 4." "Red"
            }
        }
    }
}

function Get-PortInput {
    Write-Host ""
    Write-Host "Порт прокси-сервера (Enter для 3128): " -NoNewline -ForegroundColor Cyan
    $input = Read-Host
    
    if ([string]::IsNullOrWhiteSpace($input)) {
        return 3128
    }
    
    $portNum = 0
    if ([int]::TryParse($input, [ref]$portNum) -and $portNum -gt 0 -and $portNum -lt 65536) {
        return $portNum
    } else {
        Write-ColorOutput "Неверный порт. Используется порт по умолчанию: 3128" "Yellow"
        return 3128
    }
}

# Основная логика
try {
    # Если параметры не указаны - показываем меню
    if ([string]::IsNullOrEmpty($Action)) {
        while ($true) {
            Show-Menu
            $choice = Get-UserChoice
            
            if ($choice -eq "Exit") {
                Write-ColorOutput "`nВыход из программы." "Gray"
                exit 0
            }
            
            if ($choice -eq "Install") {
                $Port = Get-PortInput
            }
            
            switch ($choice) {
                "Install" {
                    Install-LocalProxyService
                    Write-Host "`nНажмите Enter для возврата в меню..." -ForegroundColor Gray
                    Read-Host
                }
                "Uninstall" {
                    Uninstall-LocalProxyService
                    Write-Host "`nНажмите Enter для возврата в меню..." -ForegroundColor Gray
                    Read-Host
                }
                "Status" {
                    Show-Status
                    Write-Host "Нажмите Enter для возврата в меню..." -ForegroundColor Gray
                    Read-Host
                }
            }
        }
    } else {
        # Запуск с параметрами (неинтерактивный режим)
        switch ($Action) {
            "Install" {
                Install-LocalProxyService
            }
            "Uninstall" {
                Uninstall-LocalProxyService
            }
            "Status" {
                Show-Status
            }
        }
    }
}
catch {
    Write-ColorOutput "`nФАТАЛЬНАЯ ОШИБКА: $_" "Red"
    exit 1
}
