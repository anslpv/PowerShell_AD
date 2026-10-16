<#
    Setup-WinRM-Target.ps1
    ----------------------
    Настраивает WinRM (PowerShell Remoting) на ОДНОМ целевом компьютере, чтобы Process Monitor мог к нему
    подключаться (Invoke-Command). Предназначен для запуска АВТОМАТИЧЕСКИ, через GPO - как сценарий запуска
    компьютера (Startup Script): выполняется от имени SYSTEM при каждой загрузке Windows, до входа любого
    пользователя, и не требует, чтобы WinRM уже работал (в отличие от самого Process Monitor). Подробная
    инструкция по настройке GPO - в файле Deploy-WinRM-GPO.md рядом с этим скриптом.

    Можно запускать и вручную - на самом проблемном компьютере, под администратором:
        powershell -ExecutionPolicy Bypass -File .\Setup-WinRM-Target.ps1
    Или удалённо через PsExec (если доступ по SMB есть, а WinRM ещё нет):
        PsExec.exe \\ARM31905 -s powershell -ExecutionPolicy Bypass -File \\сервер\share\Setup-WinRM-Target.ps1

    Для каких ошибок Process Monitor этот скрипт предназначен (см. журнал на вкладке "Журнал"):

    1) "Клиенту не удаётся подключиться к узлу назначения... Ознакомьтесь с журналами и документацией для
       определения запущенной на узле назначения службы WS-Management (IIS или WinRM)... winrm quickconfig"
       -> служба WinRM не настроена/не запущена/нет слушателя - исправляется Enable-PSRemoting.

    2) "WinRM не удаётся выполнить операцию... в брандмауэре задано исключение для службы WinRM... По
       умолчанию исключение брандмауэра для WinRM для общедоступных профилей ограничивает доступ к удалённым
       компьютерам в той же локальной подсети"
       -> WinRM в целом включён, но правило брандмауэра разрешает доступ только в пределах локальной подсети
       (сетевой профиль компьютера определился как "Общедоступная сеть", а не "Сеть домена" - так бывает,
       например, если при загрузке компьютер не успел достучаться до контроллера домена). Enable-PSRemoting
       по умолчанию в этом случае сам откажется работать ("опасно включать на общедоступной сети") -
       используется -SkipNetworkProfileCheck, а правило брандмауэра дополнительно явно включается для ВСЕХ
       профилей, а не только для домена.

    3) "...не удалось соединиться с удалённым сервером... Ошибка с кодом 0x80090324... Для проверки
       подлинности Kerberos требуется переход через границу компьютера... неизвестное имя пользователя или
       неверный пароль" - WinRM и брандмауэр тут ни при чём (это проблема именно Kerberos-аутентификации
       ЭТОГО компьютера в домене, а не службы WinRM). Самые частые причины - рассинхронизация времени с
       контроллером домена (Kerberos допускает расхождение не больше 5 минут) и "сломанный" защищённый канал
       с доменом (пароль учётной записи компьютера в AD разошёлся с тем, что хранится локально - бывает,
       если компьютер долго был выключен/отключён от домена). Скрипт проверяет и то, и другое, и пробует
       исправить сам (принудительная синхронизация времени, Test-ComputerSecureChannel -Repair) - если не
       получилось, нужна перезагрузка компьютера или повторное присоединение к домену.

    Безопасно запускать повторно (идемпотентен) - при старте компьютера через GPO будет выполняться при
    КАЖДОЙ загрузке; если WinRM уже настроен правильно, скрипт просто подтвердит это и ничего не меняет.

    Журнал работы (что именно было сделано/найдено) записывается в файл - при запуске через GPO Startup
    Script консоли не видно, поэтому именно по этому файлу потом проверяют результат на самом компьютере:
        %ProgramData%\ProcessMonitor\winrm-setup.log

    Код возврата: 0 - WinRM настроен и отвечает локально; 1 - обнаружена проблема, которую скрипт не смог
    исправить сам (подробности в журнале).
#>

#Requires -Version 2

$ErrorActionPreference = 'Stop'

# $script:LogFile - журнал этого запуска (дописывается, не стирается - чтобы видеть историю по загрузкам).
# Пишем и в файл (Write-LogLine), и на экран (Write-Host) - при ручном запуске видно сразу, при запуске
# через GPO (без консоли) остаётся файл.
$script:LogDir = Join-Path $env:ProgramData 'ProcessMonitor'
$script:LogFile = Join-Path $script:LogDir 'winrm-setup.log'
try {
    if (-not (Test-Path -LiteralPath $script:LogDir)) { New-Item -ItemType Directory -Path $script:LogDir -Force | Out-Null }
}
catch { $script:LogFile = $null }   # нет доступа на запись - работаем дальше без файла, хотя бы на экран

function Write-LogLine {
    param([string]$Text)
    if ($script:LogFile) {
        try { Add-Content -LiteralPath $script:LogFile -Value ("{0}  {1}" -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), $Text) -Encoding UTF8 }
        catch { }
    }
}

function Write-Step {
    param([string]$Text)
    Write-Host ''
    Write-Host "=== $Text ===" -ForegroundColor Cyan
    Write-LogLine "=== $Text ==="
}

function Write-Ok {
    param([string]$Text)
    Write-Host "[ OK ] $Text" -ForegroundColor Green
    Write-LogLine "[ OK ] $Text"
}

function Write-Problem {
    param([string]$Text)
    Write-Host "[ERROR] $Text" -ForegroundColor Red
    Write-LogLine "[ERROR] $Text"
}

Write-LogLine "----- Запуск Setup-WinRM-Target.ps1 (компьютер: $env:COMPUTERNAME) -----"

try {
    # --- 0. Проверка прав администратора -------------------------------------
    Write-Step 'Проверка прав администратора'
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $isAdmin = (New-Object Security.Principal.WindowsPrincipal($currentUser)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Problem 'Скрипт запущен не от администратора. Перезапустите PowerShell "от имени администратора" и повторите (при запуске через GPO Startup Script это не требуется - он сам выполняется от имени SYSTEM).'
        exit 1
    }
    Write-Ok "Запущено от имени: $($currentUser.Name) (администратор)"

    # --- 1. Служба WinRM: автозапуск и старт ---------------------------------
    Write-Step 'Служба WinRM (WS-Management)'
    $svc = Get-Service -Name WinRM -ErrorAction SilentlyContinue
    if (-not $svc) {
        Write-Problem 'Служба WinRM не найдена в списке служб Windows - на этой версии Windows штатный WinRM недоступен или повреждена установка компонента. Дальше скрипт не может продолжить.'
        exit 1
    }
    if ($svc.StartType -ne 'Automatic') {
        Set-Service -Name WinRM -StartupType Automatic
        Write-Ok "Тип запуска WinRM изменён на ""Автоматически"" (было: $($svc.StartType)) - иначе после перезагрузки WinRM может не подняться сам."
    }
    else {
        Write-Ok 'Тип запуска WinRM уже "Автоматически"'
    }
    if ($svc.Status -ne 'Running') {
        Start-Service -Name WinRM
        Write-Ok 'Служба WinRM запущена'
    }
    else {
        Write-Ok 'Служба WinRM уже запущена'
    }

    # --- 2. Включение PowerShell Remoting ------------------------------------
    # -SkipNetworkProfileCheck - без него Enable-PSRemoting сама откажется настраивать WinRM для сетей с
    # профилем "Общедоступная" (ошибка 2 из описания выше - ровно этот случай, когда сетевой адаптер на
    # момент загрузки не успел определиться как "Сеть домена"), а исключение для этого профиля нам и нужно.
    # Это особенно важно именно при запуске через GPO Startup Script: сценарий выполняется ДО того, как
    # сетевой адаптер успевает достучаться до контроллера домена и определить профиль "Сеть домена" - то
    # есть каждый раз в самый неподходящий момент, когда без -SkipNetworkProfileCheck Enable-PSRemoting
    # отказалась бы работать.
    Write-Step 'Включение PowerShell Remoting (Enable-PSRemoting)'
    try {
        Enable-PSRemoting -Force -SkipNetworkProfileCheck
        Write-Ok 'Enable-PSRemoting выполнен (слушатель WinRM, правило брандмауэра, WS-Management - настроены)'
    }
    catch {
        Write-Problem "Enable-PSRemoting завершился с ошибкой: $($_.Exception.Message)"
        Write-Host 'Пробую резервный вариант - winrm quickconfig...' -ForegroundColor Yellow
        & winrm quickconfig -quiet
        if ($LASTEXITCODE -ne 0) {
            Write-Problem "winrm quickconfig тоже завершился с ошибкой (код $LASTEXITCODE). Настройте WinRM вручную."
            exit 1
        }
        Write-Ok 'winrm quickconfig выполнен'
    }

    # --- 3. Правило брандмауэра - явно для ВСЕХ профилей ---------------------
    # Сама ошибка 2 ("исключение брандмауэра для WinRM для общедоступных профилей ограничивает доступ к
    # удалённым компьютерам в той же локальной подсети") означает, что правило для профиля "Общедоступная"
    # существует, но сработает только для локальной подсети - а компьютер администратора обычно в ДРУГОЙ
    # подсети. Поэтому включаем правило на ВСЕХ профилях (Domain/Private/Public), а не только на текущем.
    Write-Step 'Правило брандмауэра "Windows Remote Management" на всех профилях сети'
    $fwRules = @(Get-NetFirewallRule -Name 'WINRM-HTTP-In-TCP*' -ErrorAction SilentlyContinue)
    if ($fwRules.Count -gt 0) {
        foreach ($rule in $fwRules) {
            Set-NetFirewallRule -Name $rule.Name -Enabled True -Profile Domain, Private, Public
        }
        Write-Ok "Правило(а) WinRM включено(ы) для профилей Domain/Private/Public: $(($fwRules | ForEach-Object { $_.Name }) -join ', ')"
    }
    else {
        # Старые ОС (Windows Server 2008 без Get-NetFirewallRule, PowerShell 2.0) - используем netsh.
        & netsh advfirewall firewall set rule group="Windows Remote Management" new enable=yes profile=domain,private,public | Out-Null
        Write-Ok 'Правило WinRM включено для всех профилей через netsh (резервный вариант для старых ОС)'
    }

    # --- 4. Синхронизация времени с контроллером домена ----------------------
    # Kerberos отказывает в аутентификации (ошибка 0x80090324, "неизвестное имя пользователя или неверный
    # пароль" - хотя пароль тут ни при чём), если часы этого компьютера расходятся с контроллером домена
    # больше чем на 5 минут (политика домена MaxClockSkew). w32tm /resync принудительно синхронизирует
    # время прямо сейчас, не дожидаясь обычного расписания службы времени. Не фатально, если не получилось
    # (например, компьютер ещё не видит контроллер домена на этом шаге загрузки) - просто предупреждение.
    Write-Step 'Синхронизация времени с контроллером домена (важно для Kerberos)'
    try {
        $w32tmResult = & w32tm /resync /nowait 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Ok "Синхронизация времени запущена: $($w32tmResult -join ' ')"
        }
        else {
            Write-Problem "w32tm /resync завершился с кодом $LASTEXITCODE (не критично - контроллер домена может быть ещё не виден на этом шаге загрузки): $($w32tmResult -join ' ')"
        }
    }
    catch {
        Write-Problem "Не удалось запустить синхронизацию времени: $($_.Exception.Message)"
    }

    # --- 5. Защищённый канал с доменом (secure channel) -----------------------
    # Та же ошибка 0x80090324 - вторая частая причина: пароль учётной записи КОМПЬЮТЕРА в AD разошёлся с
    # тем, что хранится локально (бывает, если компьютер долго был выключен/отключён от сети или домен
    # восстанавливали из бэкапа). Test-ComputerSecureChannel -Repair чинит это сама, используя учётные
    # данные компьютера (доступны, т. к. скрипт выполняется от SYSTEM) - без участия администратора.
    # Команда появилась в PowerShell 3.0 - на машинах со старым PowerShell 2.0 просто пропускаем проверку.
    Write-Step 'Защищённый канал с доменом (secure channel)'
    if (Get-Command Test-ComputerSecureChannel -ErrorAction SilentlyContinue) {
        try {
            if (Test-ComputerSecureChannel) {
                Write-Ok 'Защищённый канал с доменом исправен'
            }
            else {
                Write-Problem 'Защищённый канал с доменом НЕ исправен - пробую восстановить (Test-ComputerSecureChannel -Repair)...'
                if (Test-ComputerSecureChannel -Repair -ErrorAction Stop) {
                    Write-Ok 'Защищённый канал с доменом восстановлен'
                }
                else {
                    Write-Problem 'Не удалось восстановить защищённый канал - нужна перезагрузка компьютера или повторное присоединение к домену (вручную, администратором).'
                }
            }
        }
        catch {
            Write-Problem "Проверка/восстановление защищённого канала завершилось с ошибкой: $($_.Exception.Message)"
        }
    }
    else {
        Write-Problem 'Test-ComputerSecureChannel недоступна (PowerShell старше 3.0) - проверку защищённого канала пропускаю.'
    }

    # --- 6. Самопроверка: WinRM отвечает локально ----------------------------
    Write-Step 'Проверка: WinRM отвечает на этом компьютере'
    try {
        $null = Test-WSMan -ComputerName localhost
        Write-Ok 'Test-WSMan localhost - служба отвечает'
    }
    catch {
        Write-Problem "Test-WSMan localhost не прошёл: $($_.Exception.Message)"
        exit 1
    }

    Write-Host ''
    Write-Host 'Готово. Проверьте подключение с компьютера администратора:' -ForegroundColor Cyan
    Write-Host "    Test-WSMan -ComputerName $($env:COMPUTERNAME)" -ForegroundColor Cyan
    Write-Host 'Если не отвечает оттуда - проверьте, что порт 5985/TCP не блокируется промежуточным (аппаратным) брандмауэром/маршрутизатором между подсетями, а не только локальным Windows Firewall.' -ForegroundColor Yellow
    Write-LogLine 'Завершено успешно.'
    exit 0
}
catch {
    Write-Problem "Непредвиденная ошибка: $($_.Exception.Message)"
    Write-LogLine $_.ScriptStackTrace
    exit 1
}
