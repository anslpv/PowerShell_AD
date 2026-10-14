#requires -Version 5.1
<#
.SYNOPSIS
    Мониторинг запущенных процессов на компьютерах Active Directory с блокировкой по хэшу.

.DESCRIPTION
    Графическое приложение (WinForms):
      * берёт список компьютеров из AD;
      * по WinRM собирает запущенные процессы и их хэши (MD5 / SHA1 / SHA256);
      * показывает таблицу |№|Время запуска процесса|Имя|Хэш| (плюс компьютер, пользователь и путь) и хранит
        историю в JSON-файлах;
      * блокирует запуск файла с выбранным хэшем хэш-правилом SRP в доменной GPO, по одной или сразу нескольким
        строкам;
      * умеет проверять по журналу событий Windows, не пытались ли запускать уже заблокированный файл;
      * умеет сканировать компьютеры по расписанию без окна (-ScheduledScan, см. README.md).

    Скрипт самодостаточный (один файл), сторонних драйверов не требует.
    Подробности и требования - в README.md.

.PARAMETER SelfTest
    Не открывать окно, а проверить на этом компьютере всё, от чего зависит работа (версия PowerShell, JSON-хранилище,
    хэширование, Windows Forms, WinRM, AD, модуль GroupPolicy), и вывести [ OK ] / [WARN] / [FAIL] по каждому пункту.

.PARAMETER DataPath
    Папка для JSON-файлов с данными. По умолчанию data рядом со скриптом. Прежнее имя -DbPath работает как псевдоним.

.PARAMETER ScheduledScan
    Не открывать окно, а выполнить одно сканирование компьютеров из сохранённого списка (вкладка "Компьютеры",
    кнопка "Сохранить список для плановых сканирований") и сразу завершиться. Для запуска по расписанию
    (Планировщик заданий Windows) без присутствия человека за экраном. Результат - только в файле журнала
    (data\logs\processmonitor.log), на экран ничего не выводится, кроме кода возврата процесса (0 - успех).
#>
[CmdletBinding()]
param(
    [Alias('DbPath')]
    [string]$DataPath,
    [switch]$SelfTest,
    [switch]$ScheduledScan
)

# WinForms требует STA; в Windows PowerShell 5.1 консоль обычно уже STA, но не при запуске из ISE/планировщика.
# Перезапуск возможен только если известен путь к файлу скрипта ($PSCommandPath пуст при вставке кода в консоль или F8 в ISE).
# -ScheduledScan окна не открывает (и -SelfTest тоже), поэтому STA им не нужен - перезапуск в их случае только
# замедлил бы плановый запуск лишним процессом powershell.exe.
if (-not $SelfTest -and -not $ScheduledScan -and $PSCommandPath -and [Threading.Thread]::CurrentThread.GetApartmentState() -ne [Threading.ApartmentState]::STA) {
    $relaunch = @('-NoProfile', '-STA', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
    if ($DataPath) { $relaunch += @('-DataPath', "`"$DataPath`"") }
    & powershell.exe @relaunch
    exit $LASTEXITCODE
}

# ПЕРЕМЕННЫЕ ВЕРХНЕГО УРОВНЯ
#   $SelfTest         - параметр-переключатель: выполнить самопроверку (Invoke-SelfTest) вместо открытия окна.
#   $ScheduledScan    - параметр-переключатель: выполнить одно плановое сканирование (Invoke-ScheduledScan) и выйти,
#                       без окна - для запуска из Планировщика заданий Windows.
#   $DataPath         - параметр скрипта: папка JSON-файлов с данными (если не задана - data рядом со скриптом).
#   $relaunch         - (в блоке выше) аргументы для повторного запуска powershell.exe в режиме STA.
#   $script:AppRoot   - папка, где лежит скрипт; от неё строится путь к папке data\. Если путь к файлу скрипта
#                       определить нельзя (код вставлен в консоль, запущен выделенный фрагмент в ISE), берётся текущая папка.
$script:AppRoot = $PSScriptRoot
if (-not $script:AppRoot -and $MyInvocation.MyCommand.Path) { $script:AppRoot = Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $script:AppRoot) { $script:AppRoot = (Get-Location).ProviderPath }
if (-not $DataPath) { $DataPath = Join-Path $script:AppRoot 'data' }
# Относительный путь (например, -DataPath .\d) приводим к полному относительно текущей папки PowerShell.
$DataPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($DataPath)

# ===========================================================================
# Хранилище данных (JSON-файлы)
# ===========================================================================

# Что лежит в папке данных ($script:StoreDir, по умолчанию data\ рядом со скриптом):
#   scans.json              - список сканирований: номер, дата, сколько компьютеров опрошено / ответило / не ответило,
#                             имена ответивших компьютеров;
#   scans\scan-000001.json  - процессы одного сканирования (по файлу на каждое сканирование);
#   blocks.json             - журнал блокировок.
# Файлы - обычный UTF-8 JSON без BOM, их можно открыть в любом редакторе. Запись идёт через временный
# файл (.tmp) с последующей заменой, поэтому обрыв посреди записи не портит уже сохранённые данные.
# Приложение рассчитано на один запущенный экземпляр: одновременная запись из двух окон не поддерживается.

# $script:StoreDir - папка с JSON-файлами; заполняется в Initialize-Database. (Имя НЕ должно совпадать с параметром
#                    скрипта $DataPath: $script:DataPath - это та же самая переменная, и присваивание затёрло бы параметр.)
# $script:Scans    - список сканирований из scans.json, держится в памяти (ArrayList словарей: Id, ScanDate, Requested,
#                    Succeeded, Failed, Computers). Процессы в память целиком не загружаются - читаются по запросу.
# $script:Blocks   - журнал блокировок из blocks.json в памяти (ArrayList словарей: Id, BlockDate, Name, Algorithm,
#                    Hash, Size, GpoName, RuleId, Active).
# $script:JsonSerializer - JavaScriptSerializer из .NET Framework, используется ТОЛЬКО для чтения JSON (быстро и даёт чистые
#                    .NET-словари). Запись идёт через ConvertTo-Json. Если JavaScriptSerializer недоступен или
#                    сбойнул (например, при проверке на PowerShell 7), чтение идёт через ConvertFrom-Json.
$script:StoreDir = $null
$script:Scans = $null
$script:Blocks = $null
$script:JsonSerializer = $null
try {
    Add-Type -AssemblyName System.Web.Extensions -ErrorAction Stop
    $script:JsonSerializer = New-Object System.Web.Script.Serialization.JavaScriptSerializer
    $script:JsonSerializer.MaxJsonLength = [int]::MaxValue     # по умолчанию лимит 2 МБ - для списка процессов мало
}
catch {
    $script:JsonSerializer = $null
}

# ConvertTo-JsonText - превращает данные (словари, списки, строки, числа) в компактный текст JSON штатным ConvertTo-Json.
#   Раньше здесь был собственный сериализатор и JavaScriptSerializer, но в Windows PowerShell 5.1 они падали (циклическая
#   ссылка на PowerShell-обёртку, ошибки вызова методов): штатный командлет с обёртками PowerShell справляется сам.
#   -InputObject (а не конвейер) нужен, чтобы список из одного элемента не превращался в объект.
#   -Depth 10 - глубина вложенности с запасом (у нас не больше 4). -Data что сериализовать.
function ConvertTo-JsonText {
    param([Parameter(Mandatory)]$Data)
    return (ConvertTo-Json -InputObject $Data -Depth 10 -Compress)
}

# ConvertTo-PlainData - превращает результат ConvertFrom-Json (PSCustomObject и массивы) в хэш-таблицы и ArrayList,
#   чтобы работал доступ $d['Ключ']. Нужна только в запасном варианте чтения на PowerShell 5.1 без JavaScriptSerializer.
#   -Value результат ConvertFrom-Json. $d - собираемая хэш-таблица; $prop - свойство объекта; $list / $i - список и его элемент.
function ConvertTo-PlainData {
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [System.Management.Automation.PSCustomObject]) {
        $d = @{}
        foreach ($prop in $Value.PSObject.Properties) { $d[$prop.Name] = ConvertTo-PlainData -Value $prop.Value }
        return $d
    }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        $list = New-Object System.Collections.ArrayList
        foreach ($i in $Value) { [void]$list.Add((ConvertTo-PlainData -Value $i)) }
        return , $list
    }
    return $Value
}

# ConvertFrom-JsonText - превращает текст JSON в словари и массивы (объект JSON -> словарь, доступ $d['Ключ']).
#   Сначала пробует быстрый JavaScriptSerializer.DeserializeObject (чистые .NET-типы); если его нет или он сбойнул -
#   ConvertFrom-Json (на PowerShell 6+ с -AsHashtable, на 5.1 с преобразованием через ConvertTo-PlainData).
#   -Text строка с JSON.
function ConvertFrom-JsonText {
    param([Parameter(Mandatory)][string]$Text)
    if ($script:JsonSerializer) {
        try { return $script:JsonSerializer.DeserializeObject($Text) }
        catch { }       # переходим к запасному варианту ниже
    }
    if ($PSVersionTable.PSVersion.Major -ge 6) { return (ConvertFrom-Json -InputObject $Text -AsHashtable) }
    return (ConvertTo-PlainData -Value (ConvertFrom-Json -InputObject $Text))
}

# Read-JsonFile - читает JSON-файл. Возвращает $null, если файла нет или он пустой; если файл повреждён - ошибка.
#   -Path путь к файлу. $text - содержимое файла.
function Read-JsonFile {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $text = [System.IO.File]::ReadAllText($Path, [System.Text.Encoding]::UTF8)
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }
    try {
        return (ConvertFrom-JsonText -Text $text)
    }
    catch {
        throw "Файл повреждён или не является JSON: $Path ($($_.Exception.Message))"
    }
}

# Write-JsonFile - записывает данные в JSON-файл (UTF-8 без BOM) через временный файл. Создаёт папку при необходимости.
#   -Path файл; -Data данные. $dir - папка файла; $tmp - временный файл рядом с целевым.
function Write-JsonFile {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)]$Data)
    $dir = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $tmp = $Path + '.tmp'
    [System.IO.File]::WriteAllText($tmp, (ConvertTo-JsonText -Data $Data), (New-Object System.Text.UTF8Encoding($false)))
    Move-Item -LiteralPath $tmp -Destination $Path -Force      # -Force: заменить существующий файл
}

# Get-JsonList - достаёт из прочитанного документа список по ключу. Если документа или ключа нет - пустой массив.
#   -Document словарь из Read-JsonFile (или $null); -Key имя поля, например 'Scans'.
function Get-JsonList {
    param($Document, [string]$Key)
    if ($null -eq $Document -or -not $Document.ContainsKey($Key) -or $null -eq $Document[$Key]) { return @() }
    return @($Document[$Key])
}

# Initialize-Database - готовит хранилище: создаёт папку данных, читает scans.json и blocks.json в память и
#   проверяет, что в папку можно писать (при первом запуске создаёт пустые файлы).
#   -Path папка данных. Бросает исключение, если файлы повреждены или папка недоступна для записи.
function Initialize-Database {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { New-Item -ItemType Directory -Path $Path -Force | Out-Null }
    $script:StoreDir = $Path
    $script:Scans = New-Object System.Collections.ArrayList
    $script:Blocks = New-Object System.Collections.ArrayList

    $scansFile = Join-Path $Path 'scans.json'
    $blocksFile = Join-Path $Path 'blocks.json'
    $scansDoc = Read-JsonFile -Path $scansFile
    $blocksDoc = Read-JsonFile -Path $blocksFile
    foreach ($item in (Get-JsonList -Document $scansDoc -Key 'Scans')) { [void]$script:Scans.Add($item) }
    foreach ($item in (Get-JsonList -Document $blocksDoc -Key 'Blocks')) { [void]$script:Blocks.Add($item) }

    if (-not $scansDoc) { Save-ScanIndex }
    if (-not $blocksDoc) { Save-BlockLog }
}

# Save-ScanIndex - записывает список сканирований из памяти в scans.json.
function Save-ScanIndex {
    Write-JsonFile -Path (Join-Path $script:StoreDir 'scans.json') -Data ([ordered]@{ Version = 1; Scans = $script:Scans })
}

# Save-BlockLog - записывает журнал блокировок из памяти в blocks.json.
function Save-BlockLog {
    Write-JsonFile -Path (Join-Path $script:StoreDir 'blocks.json') -Data ([ordered]@{ Version = 1; Blocks = $script:Blocks })
}

# Get-ScanFilePath - путь к файлу с процессами сканирования: <данные>\scans\scan-000001.json. -Id номер сканирования.
function Get-ScanFilePath {
    param([Parameter(Mandatory)][int]$Id)
    Join-Path (Join-Path $script:StoreDir 'scans') ('scan-{0:D6}.json' -f $Id)
}

# ---- Список компьютеров для плановых сканирований ---------------------------
# Отдельный от галочек в окне список (data\scheduled-computers.json): его сохраняют один раз на вкладке
# "Компьютеры" кнопкой "Сохранить список для плановых сканирований", а читает headless-режим -ScheduledScan
# (см. Invoke-ScheduledScan) при запуске по расписанию, когда окна и галочек нет вообще.

# Save-ScheduledComputerList - сохраняет список имён компьютеров для плановых сканирований. -Names имена.
function Save-ScheduledComputerList {
    param([string[]]$Names)
    Write-JsonFile -Path (Join-Path $script:StoreDir 'scheduled-computers.json') -Data ([ordered]@{ Version = 1; Computers = @($Names) })
}

# Get-ScheduledComputerList - читает сохранённый список имён компьютеров. Пустой массив, если файла нет.
function Get-ScheduledComputerList {
    $doc = Read-JsonFile -Path (Join-Path $script:StoreDir 'scheduled-computers.json')
    return @(Get-JsonList -Document $doc -Key 'Computers' | ForEach-Object { [string]$_ })
}

# ---- Сканирования и процессы -------------------------------------------------

# New-Scan - выдаёт номер и дату нового сканирования (в файл ничего не пишется до Save-Processes).
#   -Requested сколько компьютеров собираются опрашивать.
#   Возвращает { Id = номер (на 1 больше максимального), Date = "гггг-мм-дд чч:мм:сс", Requested }.
function New-Scan {
    param([int]$Requested)
    $id = 1
    foreach ($scan in $script:Scans) {
        if ([int]$scan['Id'] -ge $id) { $id = [int]$scan['Id'] + 1 }
    }
    return [pscustomobject]@{ Id = $id; Date = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'); Requested = $Requested }
}

# Save-Processes - сохраняет собранные процессы сканирования в его файл и добавляет сканирование в scans.json.
#   Сначала пишется файл с процессами, потом индекс: сканирование "появляется" только после успешной записи обоих.
#   Поля User (владелец процесса) и StartTime (время запуска процесса) сохраняются вместе с ним.
#   -ScanId, -ScanDate, -Requested  данные из New-Scan; -Rows  собранные объекты с удалённых компьютеров;
#   -Succeeded / -Failed  сколько компьютеров ответило / не ответило.
#   Локальные: $computers - имена компьютеров, приславших данные; $list - записи процессов для файла;
#   $r - текущая строка. Имена компьютеров и хэши сохраняются в ВЕРХНЕМ регистре, строки упорядочены
#   по компьютеру и имени.
function Save-Processes {
    param(
        [Parameter(Mandatory)][int]$ScanId,
        [Parameter(Mandatory)][string]$ScanDate,
        [int]$Requested,
        [object[]]$Rows,
        [int]$Succeeded,
        [int]$Failed
    )
    $computers = @{}
    $list = New-Object System.Collections.ArrayList
    foreach ($r in @($Rows | Sort-Object { [string]$_.Computer }, { [string]$_.Name })) {
        $computer = ([string]$r.Computer).ToUpper()
        $computers[$computer] = $true
        [void]$list.Add([ordered]@{
                Computer = $computer
                User      = [string]$r.User
                StartTime = [string]$r.StartTime
                Name      = [string]$r.Name
                Path     = [string]$r.Path
                Size     = [long]$r.Size
                MD5      = ([string]$r.MD5).ToUpper()
                SHA1     = ([string]$r.SHA1).ToUpper()
                SHA256   = ([string]$r.SHA256).ToUpper()
            })
    }
    Write-JsonFile -Path (Get-ScanFilePath -Id $ScanId) -Data ([ordered]@{ Version = 1; ScanId = $ScanId; Processes = $list })

    [void]$script:Scans.Add([ordered]@{
            Id        = $ScanId
            ScanDate  = $ScanDate
            Requested = $Requested
            Succeeded = $Succeeded
            Failed    = $Failed
            Computers = [string[]]@($computers.Keys | Sort-Object)
        })
    try {
        Save-ScanIndex
    }
    catch {
        $script:Scans.RemoveAt($script:Scans.Count - 1)     # индекс не записан - откатываем и в памяти
        throw
    }
}

# Get-Scans - список сканирований (новые сверху) для выпадающего списка.
#   Возвращает таблицу: Id и Title вида "2026-10-12 14:03:11  (ПК: 42 из 50)".
function Get-Scans {
    $table = New-Object System.Data.DataTable
    [void]$table.Columns.Add('Id', [int])
    [void]$table.Columns.Add('Title', [string])
    for ($i = $script:Scans.Count - 1; $i -ge 0; $i--) {
        $scan = $script:Scans[$i]
        $title = '{0}  (ПК: {1} из {2})' -f $scan['ScanDate'], $scan['Succeeded'], $scan['Requested']
        [void]$table.Rows.Add([int]$scan['Id'], $title)
    }
    return , $table
}

# Get-ProcessTable - данные для основной таблицы процессов.
#   -ScanId     номер сканирования; 0 - показать все сканирования (новые первыми);
#   -Algorithm  какой хэш показывать в колонке Hash: MD5, SHA1 или SHA256.
#   Возвращает таблицу: ScanDate, StartTime, Name, Hash, Computer, User, Path, Size. StartTime - когда запущен сам
#   процесс (в часовом поясе компьютера, на котором он работает), ScanDate - когда прошло сканирование. User -
#   пользователь, запустивший процесс. Оба поля пустые в сканированиях, сохранённых до их появления.
#   Локальные: $table - результат; $scan - сканирование из индекса; $doc - прочитанный файл сканирования;
#   $p - процесс из файла; $user / $startTime - его пользователь и время запуска. Если файл сканирования потерян,
#   оно пропускается.
function Get-ProcessTable {
    param(
        [int]$ScanId = 0,
        [ValidateSet('MD5', 'SHA1', 'SHA256')][string]$Algorithm = 'MD5'
    )
    $table = New-Object System.Data.DataTable
    [void]$table.Columns.Add('ScanDate', [string])
    [void]$table.Columns.Add('StartTime', [string])
    [void]$table.Columns.Add('Name', [string])
    [void]$table.Columns.Add('Hash', [string])
    [void]$table.Columns.Add('Computer', [string])
    [void]$table.Columns.Add('User', [string])
    [void]$table.Columns.Add('Path', [string])
    [void]$table.Columns.Add('Size', [long])

    $table.BeginLoadData()
    for ($i = $script:Scans.Count - 1; $i -ge 0; $i--) {
        $scan = $script:Scans[$i]
        if ($ScanId -gt 0 -and [int]$scan['Id'] -ne $ScanId) { continue }
        $doc = Read-JsonFile -Path (Get-ScanFilePath -Id ([int]$scan['Id']))
        foreach ($p in (Get-JsonList -Document $doc -Key 'Processes')) {
            $user = ''
            if ($p.ContainsKey('User')) { $user = [string]$p['User'] }           # старые сканирования без этого поля
            $startTime = ''
            if ($p.ContainsKey('StartTime')) { $startTime = [string]$p['StartTime'] }
            [void]$table.Rows.Add([string]$scan['ScanDate'], $startTime, [string]$p['Name'], [string]$p[$Algorithm],
                [string]$p['Computer'], $user, [string]$p['Path'], [long]$p['Size'])
        }
    }
    $table.EndLoadData()
    return , $table
}

# Get-HashLocations - где найден хэш: компьютеры и пути по ПОСЛЕДНЕМУ сканированию каждого компьютера.
#   Нужна, чтобы показать "найден на N компьютерах" и чтобы знать, где завершать процессы.
#   -Algorithm, -Hash  алгоритм и значение хэша. Возвращает таблицу: Computer, Path.
#   Идём по сканированиям от новых к старым; $resolved - компьютеры, для которых последнее сканирование уже
#   найдено; $fresh - компьютеры, для которых текущее сканирование - последнее; $seen - защита от повторов.
function Get-HashLocations {
    param(
        [Parameter(Mandatory)][ValidateSet('MD5', 'SHA1', 'SHA256')][string]$Algorithm,
        [Parameter(Mandatory)][string]$Hash
    )
    $table = New-Object System.Data.DataTable
    [void]$table.Columns.Add('Computer', [string])
    [void]$table.Columns.Add('Path', [string])

    $wanted = $Hash.ToUpper()
    $resolved = @{}
    $seen = @{}
    for ($i = $script:Scans.Count - 1; $i -ge 0; $i--) {
        $scan = $script:Scans[$i]
        $fresh = @{}
        foreach ($c in @($scan['Computers'])) {
            if ($c -and -not $resolved.ContainsKey($c)) { $fresh[$c] = $true; $resolved[$c] = $true }
        }
        if ($fresh.Count -eq 0) { continue }
        $doc = Read-JsonFile -Path (Get-ScanFilePath -Id ([int]$scan['Id']))
        foreach ($p in (Get-JsonList -Document $doc -Key 'Processes')) {
            if ([string]$p[$Algorithm] -ne $wanted -or -not $fresh.ContainsKey([string]$p['Computer'])) { continue }
            $key = '{0}|{1}' -f $p['Computer'], $p['Path']
            if ($seen.ContainsKey($key)) { continue }
            $seen[$key] = $true
            [void]$table.Rows.Add([string]$p['Computer'], [string]$p['Path'])
        }
    }
    return , $table
}

# ---- Блокировки ------------------------------------------------------------

# Add-BlockRecord - записывает в журнал блокировок (blocks.json) новую активную блокировку.
#   -Name имя файла; -Algorithm и -Hash хэш; -Size размер файла; -GpoName в какой GPO добавлено правило;
#   -RuleId GUID правила в GPO (по нему правило потом удаляется). Номер записи = максимальный + 1.
function Add-BlockRecord {
    param(
        [string]$Name,
        [Parameter(Mandatory)][string]$Algorithm,
        [Parameter(Mandatory)][string]$Hash,
        [long]$Size,
        [Parameter(Mandatory)][string]$GpoName,
        [Parameter(Mandatory)][string]$RuleId,
        [ValidateSet('Computer', 'User')][string]$Scope = 'Computer',
        [string]$Target = 'Все пользователи компьютера'
    )
    $id = 1
    foreach ($b in $script:Blocks) {
        if ([int]$b['Id'] -ge $id) { $id = [int]$b['Id'] + 1 }
    }
    [void]$script:Blocks.Add([ordered]@{
            Id        = $id
            BlockDate = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
            Name      = $Name
            Algorithm = $Algorithm
            Hash      = $Hash.ToUpper()
            Size      = $Size
            GpoName   = $GpoName
            RuleId    = $RuleId
            Active    = 1
            Scope     = $Scope
            Target    = $Target
        })
    try {
        Save-BlockLog
    }
    catch {
        $script:Blocks.RemoveAt($script:Blocks.Count - 1)
        throw
    }
}

# Get-BlockTable - все блокировки (новые сверху) для вкладки "Блокировки".
#   Поле Status: "Активна" (Active=1) или "Снята". EventCount/LastEventTime - результат последней проверки
#   срабатываний (см. Update-BlockEventInfo); у блокировок, которые ещё не проверяли, EventCount = -1
#   ("не проверялось" - отличие от 0, то есть "проверили, попыток не было"), LastEventTime пусто.
#   Scope/Target - новые поля ("для кого" заблокировано: вся машина или конкретный пользователь/группа, см.
#   Add-BlockRecord); у записей, сделанных до появления этой возможности, их нет в файле на диске, поэтому
#   читаются с запасным значением ('Computer'/'Все пользователи компьютера') - как раз для таких старых записей.
function Get-BlockTable {
    $table = New-Object System.Data.DataTable
    [void]$table.Columns.Add('Id', [int])
    [void]$table.Columns.Add('BlockDate', [string])
    [void]$table.Columns.Add('Name', [string])
    [void]$table.Columns.Add('Algorithm', [string])
    [void]$table.Columns.Add('Hash', [string])
    [void]$table.Columns.Add('GpoName', [string])
    [void]$table.Columns.Add('RuleId', [string])
    [void]$table.Columns.Add('Active', [int])
    [void]$table.Columns.Add('Status', [string])
    [void]$table.Columns.Add('EventCount', [int])
    [void]$table.Columns.Add('Occurrences', [string])
    [void]$table.Columns.Add('LastEventTime', [string])
    [void]$table.Columns.Add('Scope', [string])
    [void]$table.Columns.Add('Target', [string])
    for ($i = $script:Blocks.Count - 1; $i -ge 0; $i--) {
        $b = $script:Blocks[$i]
        $status = if ([int]$b['Active'] -eq 1) { 'Активна' } else { 'Снята' }
        $eventCount = -1
        # .Contains(), а не .ContainsKey(): свежедобавленные за этот сеанс записи - OrderedDictionary ([ordered]@{...}
        # в Add-BlockRecord), а у неё нет ContainsKey (есть только у Hashtable, в который превращаются записи ПОСЛЕ
        # перечитывания с диска). .Contains() есть у обоих типов.
        if ($b.Contains('EventCount')) { $eventCount = [int]$b['EventCount'] }
        $lastEventTime = ''
        if ($b.Contains('LastEventTime')) { $lastEventTime = [string]$b['LastEventTime'] }
        $scope = 'Computer'
        if ($b.Contains('Scope') -and $b['Scope']) { $scope = [string]$b['Scope'] }
        $target = 'Все пользователи компьютера'
        if ($b.Contains('Target') -and $b['Target']) { $target = [string]$b['Target'] }
        $occurrences = if ($eventCount -lt 0) { 'не проверялось' } else { [string]$eventCount }
        [void]$table.Rows.Add([int]$b['Id'], [string]$b['BlockDate'], [string]$b['Name'], [string]$b['Algorithm'],
            [string]$b['Hash'], [string]$b['GpoName'], [string]$b['RuleId'], [int]$b['Active'], $status,
            $eventCount, $occurrences, $lastEventTime, $scope, $target)
    }
    return , $table
}

# Get-ActiveBlock - ищет действующую блокировку для пары алгоритм+хэш.
#   Возвращает запись журнала (словарь) или $null, если такой блокировки нет (защита от дублей).
function Get-ActiveBlock {
    param([string]$Algorithm, [string]$Hash)
    foreach ($b in $script:Blocks) {
        if ([int]$b['Active'] -eq 1 -and [string]$b['Algorithm'] -eq $Algorithm -and [string]$b['Hash'] -eq $Hash.ToUpper()) {
            return $b
        }
    }
    return $null
}

# Disable-BlockRecord - помечает блокировку в журнале снятой (Active=0) и сохраняет файл. -Id номер записи.
function Disable-BlockRecord {
    param([Parameter(Mandatory)][int]$Id)
    foreach ($b in $script:Blocks) {
        if ([int]$b['Id'] -eq $Id) { $b['Active'] = 0 }
    }
    Save-BlockLog
}

# Update-BlockEventInfo - сохраняет результат проверки срабатываний блокировки (см. Invoke-CheckBlockEvents):
#   сколько событий отказа SRP найдено и когда было последнее. -Id номер записи; -Count сколько найдено;
#   -LastTime когда было последнее (пусто, если не найдено ни одного).
function Update-BlockEventInfo {
    param([Parameter(Mandatory)][int]$Id, [Parameter(Mandatory)][int]$Count, [string]$LastTime)
    foreach ($b in $script:Blocks) {
        if ([int]$b['Id'] -eq $Id) {
            $b['EventCount'] = $Count
            $b['LastEventTime'] = $LastTime
        }
    }
    Save-BlockLog
}

# Get-HashComputersEver - на каких компьютерах хэш встречался хоть КОГДА-НИБУДЬ (по всем сканированиям, а не
#   только по последнему для каждого компьютера, в отличие от Get-HashLocations). Нужна для проверки
#   срабатываний: опрашивать стоит и те компьютеры, где файл уже не бежит, но раньше встречался - именно там
#   он мог сработать после блокировки. Читает файлы ВСЕХ сканирований, поэтому при большой истории (сотни
#   сканирований) может быть не быстрой - как и просмотр "Все сканирования" на вкладке "Процессы".
#   Локальные: $wanted - хэш в верхнем регистре; $computers - найденные имена (ключи хэш-таблицы, без повторов);
#   $scan - текущее сканирование; $doc - его файл; $p - текущий процесс в нём.
function Get-HashComputersEver {
    param(
        [Parameter(Mandatory)][ValidateSet('MD5', 'SHA1', 'SHA256')][string]$Algorithm,
        [Parameter(Mandatory)][string]$Hash
    )
    $wanted = $Hash.ToUpper()
    $computers = @{}
    foreach ($scan in $script:Scans) {
        $doc = Read-JsonFile -Path (Get-ScanFilePath -Id ([int]$scan['Id']))
        foreach ($p in (Get-JsonList -Document $doc -Key 'Processes')) {
            if ([string]$p[$Algorithm] -eq $wanted) { $computers[[string]$p['Computer']] = $true }
        }
    }
    return @($computers.Keys | Sort-Object)
}

# ===========================================================================
# Компьютеры AD и удалённый сбор
# ===========================================================================

# Список компьютеров из AD и удалённый сбор запущенных процессов через WinRM.

# Get-AdComputers - читает из AD включённые компьютеры с Windows (запрос LDAP через ADSI).
#   -SearchBase  DN контейнера/OU для поиска; пусто - весь домен.
#   Возвращает объекты { Name = имя, Host = DNS-имя (или имя, если DNS-имени нет), OS = версия Windows }.
#   Локальные: $searcher - объект поиска; $results - найденные записи; $r - текущая запись;
#   $name / $dns / $os - значения полей.
function Get-AdComputers {
    param([string]$SearchBase)

    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    if ($SearchBase) {
        $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$SearchBase")
    }
    # Только включённые учётные записи компьютеров с Windows.
    $searcher.Filter = '(&(objectCategory=computer)(operatingSystem=Windows*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'
    $searcher.PageSize = 1000
    foreach ($prop in 'name', 'dnshostname', 'operatingsystem') {
        [void]$searcher.PropertiesToLoad.Add($prop)
    }

    $results = $searcher.FindAll()
    try {
        foreach ($r in $results) {
            $name = [string]$r.Properties['name'][0]
            $dns = if ($r.Properties['dnshostname'].Count) { [string]$r.Properties['dnshostname'][0] } else { $name }
            $os = if ($r.Properties['operatingsystem'].Count) { [string]$r.Properties['operatingsystem'][0] } else { '' }
            [pscustomobject]@{ Name = $name; Host = $dns; OS = $os }
        }
    }
    finally {
        $results.Dispose()
        $searcher.Dispose()
    }
}

# Get-AdOrganizationalUnits - список подразделений (OU) домена для выпадающего списка "Привязать к" на вкладке
#   "Блокировки" (чтобы не искать и не копировать DN вручную). Первой строкой всегда идёт корень домена (сам домен
#   тоже можно выбрать как цель привязки GPO - это применит правило ко всем компьютерам домена).
#   Возвращает объекты { Name = имя OU (для домена - сам DN), Dn = полный DN }, отсортированные по DN (так
#   вложенные OU идут предсказуемо рядом с родительскими). Локальные: $root - корень домена (RootDSE);
#   $domainDn - его DN; $searcher - объект поиска; $results - найденные OU; $r - текущая запись.
function Get-AdOrganizationalUnits {
    $root = [System.DirectoryServices.DirectoryEntry]'LDAP://RootDSE'
    $domainDn = [string]$root.Properties['defaultNamingContext'][0]
    [pscustomobject]@{ Name = '(весь домен)'; Dn = $domainDn }

    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$domainDn")
    $searcher.Filter = '(objectCategory=organizationalUnit)'
    $searcher.PageSize = 1000
    [void]$searcher.PropertiesToLoad.Add('name')
    [void]$searcher.PropertiesToLoad.Add('distinguishedname')

    $results = $searcher.FindAll()
    try {
        foreach ($r in ($results | Sort-Object { [string]$_.Properties['distinguishedname'][0] })) {
            [pscustomobject]@{ Name = [string]$r.Properties['name'][0]; Dn = [string]$r.Properties['distinguishedname'][0] }
        }
    }
    finally {
        $results.Dispose()
        $searcher.Dispose()
    }
}

# Get-AdUsersAndGroups - пользователи и группы AD для выпадающего списка "Пользователь/группа" на вкладке
#   "Блокировки" (блокировка не для всех, а для конкретной учётной записи или группы - см. Invoke-BlockSelected).
#   Как и Get-AdOrganizationalUnits, грузит весь список сразу и может быть не быстрой в большом домене.
#   Возвращает { Sam = sAMAccountName (именно он нужен Set-GPPermission); Display = отображаемое имя;
#   Type = 'User' или 'Group' }, отсортированные по Display. Записи без sAMAccountName пропускаются.
#   Локальные: $root/$domainDn/$searcher/$results/$r - как в Get-AdOrganizationalUnits; $sam/$display/$cat/$type -
#   поля текущей записи ($cat - DN класса объекта, по нему отличаем группу от пользователя).
function Get-AdUsersAndGroups {
    $root = [System.DirectoryServices.DirectoryEntry]'LDAP://RootDSE'
    $domainDn = [string]$root.Properties['defaultNamingContext'][0]
    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$domainDn")
    $searcher.Filter = '(|(&(objectCategory=person)(objectClass=user))(objectCategory=group))'
    $searcher.PageSize = 1000
    foreach ($prop in 'samaccountname', 'displayname', 'name', 'objectcategory') {
        [void]$searcher.PropertiesToLoad.Add($prop)
    }

    $results = $searcher.FindAll()
    try {
        foreach ($r in ($results | Sort-Object {
                    if ($_.Properties['displayname'].Count) { [string]$_.Properties['displayname'][0] } else { [string]$_.Properties['name'][0] }
                })) {
            $sam = if ($r.Properties['samaccountname'].Count) { [string]$r.Properties['samaccountname'][0] } else { '' }
            if (-not $sam) { continue }
            $display = if ($r.Properties['displayname'].Count) { [string]$r.Properties['displayname'][0] } else { [string]$r.Properties['name'][0] }
            $cat = [string]$r.Properties['objectcategory'][0]
            $type = if ($cat -match '(?i)^CN=Group,') { 'Group' } else { 'User' }
            [pscustomobject]@{ Sam = $sam; Display = $display; Type = $type }
        }
    }
    finally {
        $results.Dispose()
        $searcher.Dispose()
    }
}

# Resolve-AdPrincipalType - определяет, пользователь это или группа, по sAMAccountName, если тип не пришёл
#   вместе с выбором из списка (например, имя набрано вручную). -Sam  sAMAccountName. Возвращает 'User',
#   'Group' или $null (учётная запись не найдена или AD недоступен - вызывающий код должен в этом случае
#   остановиться и попросить выбрать запись из списка, а не угадывать тип).
function Resolve-AdPrincipalType {
    param([Parameter(Mandatory)][string]$Sam)
    $searcher = $null
    try {
        $root = [System.DirectoryServices.DirectoryEntry]'LDAP://RootDSE'
        $domainDn = [string]$root.Properties['defaultNamingContext'][0]
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$domainDn")
        $searcher.Filter = "(sAMAccountName=$Sam)"
        [void]$searcher.PropertiesToLoad.Add('objectcategory')
        $r = $searcher.FindOne()
        if (-not $r) { return $null }
        $cat = [string]$r.Properties['objectcategory'][0]
        return $(if ($cat -match '(?i)^CN=Group,') { 'Group' } else { 'User' })
    }
    catch {
        return $null
    }
    finally {
        if ($searcher) { $searcher.Dispose() }
    }
}

# $script:CollectScript - скрипт, который выполняется НА УДАЛЁННОМ компьютере (передаётся в Invoke-Command).
#   Читает Win32_Process; для каждого процесса определяет владельца (пользователя, запустившего процесс) методом
#   GetOwner(), берёт время его запуска (Win32_Process.CreationDate) и для каждого уникального файла считает
#   MD5/SHA1/SHA256 за один проход чтения; возвращает объекты { Computer, User, StartTime, Name, Path, Size,
#   MD5, SHA1, SHA256 }. Работает и в PowerShell 2.0.
#   StartTime - когда процесс был запущен ("гггг-мм-дд чч:мм:сс" в часовом поясе удалённого компьютера); если
#   WMI не отдал время (процесс уже завершился) - пустая строка.
#   User - "ДОМЕН\логин" владельца процесса (системные процессы: "NT AUTHORITY\SYSTEM", "NT AUTHORITY\NETWORK SERVICE" и т. п.);
#   если владельца определить нельзя (процесс уже завершился, нет доступа) - пустая строка.
#   Запись одна на пару "файл + владелец": если один и тот же exe запущен разными пользователями, будет несколько строк,
#   а несколько копий у одного пользователя дают одну строку. Хэш файла считается один раз и берётся из кэша.
#   Локальные: $procs - все процессы из WMI; $cache - путь (в нижнем регистре) -> результат хэширования (или $null,
#   если файл недоступен); $seen - уже выданные пары "путь|владелец"; $algs - три объекта хэширования;
#   $buffer - буфер чтения 1 МБ; $proc - текущий процесс; $path - путь к exe; $key - путь в нижнем регистре;
#   $o - результат GetOwner() (Domain, User); $owner - "ДОМЕН\логин"; $startTime - время запуска процесса;
#   $rowKey - ключ пары "путь|владелец";
#   $info - результат хэширования файла; $stream - открытый файл (читать запущенные файлы разрешено);
#   $n - сколько байт прочитано; $a - текущий алгоритм. Недоступные файлы пропускаются.
$script:CollectScript = {
    $ErrorActionPreference = 'Stop'
    $cache = @{}
    $seen = @{}
    $algs = @{
        MD5    = [System.Security.Cryptography.MD5]::Create()
        SHA1   = [System.Security.Cryptography.SHA1]::Create()
        SHA256 = [System.Security.Cryptography.SHA256]::Create()
    }
    $buffer = New-Object byte[] 1048576

    $procs = @(Get-WmiObject -Class Win32_Process)
    foreach ($proc in $procs) {
        $path = $proc.ExecutablePath
        if (-not $path) { continue }
        $key = $path.ToLower()

        $owner = ''
        try { $o = $proc.GetOwner(); if ($o.User) { $owner = $o.Domain + '\' + $o.User } } catch { }

        $startTime = ''
        try {
            if ($proc.CreationDate) {
                $startTime = [System.Management.ManagementDateTimeConverter]::ToDateTime($proc.CreationDate).ToString('yyyy-MM-dd HH:mm:ss')
            }
        }
        catch { }

        $rowKey = $key + '|' + $owner.ToLower()
        if ($seen.ContainsKey($rowKey)) { continue }
        $seen[$rowKey] = $true

        if (-not $cache.ContainsKey($key)) {
            $info = $null
            try {
                $stream = New-Object System.IO.FileStream($path, [System.IO.FileMode]::Open,
                    [System.IO.FileAccess]::Read, ([System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete))
                try {
                    foreach ($a in $algs.Values) { $a.Initialize() }
                    while (($n = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                        foreach ($a in $algs.Values) { [void]$a.TransformBlock($buffer, 0, $n, $null, 0) }
                    }
                    foreach ($a in $algs.Values) { [void]$a.TransformFinalBlock($buffer, 0, 0) }
                    $info = New-Object PSObject -Property @{
                        Size   = $stream.Length
                        MD5    = [BitConverter]::ToString($algs.MD5.Hash).Replace('-', '')
                        SHA1   = [BitConverter]::ToString($algs.SHA1.Hash).Replace('-', '')
                        SHA256 = [BitConverter]::ToString($algs.SHA256.Hash).Replace('-', '')
                    }
                }
                finally {
                    $stream.Close()
                }
            }
            catch {
                $info = $null       # файл недоступен или удалён
            }
            $cache[$key] = $info
        }
        $info = $cache[$key]
        if (-not $info) { continue }

        New-Object PSObject -Property @{
            Computer  = $env:COMPUTERNAME
            User      = $owner
            StartTime = $startTime
            Name      = $proc.Name
            Path      = $path
            Size     = $info.Size
            MD5      = $info.MD5
            SHA1     = $info.SHA1
            SHA256   = $info.SHA256
        }
    }
}

# $script:ApplyBlockScript - скрипт, который выполняется НА УДАЛЁННОМ компьютере сразу после добавления блокировки:
#   принудительно обновляет групповые политики (gpupdate /target:computer /force), чтобы правило SRP подействовало
#   немедленно, а не ждало планового обновления (по умолчанию - до 90 минут), затем ЗАВЕРШАЕТ уже запущенные
#   экземпляры заблокированного файла и показывает каждому затронутому пользователю на экране (msg.exe) короткое
#   уведомление, что запускать это нельзя. По отдельному запросу (-LogoffSessions, администратор подтверждает его
#   каждый раз в окне блокировки) ПОСЛЕ уведомления также принудительно завершает сеанс (logoff.exe) именно того
#   пользователя, у кого был открыт процесс, - это закрывает ВСЕ его программы на этом компьютере, не только
#   заблокированный файл, поэтому не делается по умолчанию. Всё это происходит автоматически при блокировке.
#   $Map  - хэш-таблица "ИМЯ КОМПЬЮТЕРА (в верхнем регистре) -> массив путей к файлу".
#   $TerminateProcesses - завершать ли найденные запущенные экземпляры ($true/$false; UI всегда передаёт $true,
#   параметр оставлен для тестов и на случай, если понадобится более осторожный режим "только gpupdate").
#   $NotifyText - текст уведомления (без имени файла - оно подставляется автоматически).
#   $LogoffSessions - завершать ли принудительно сеанс пользователя, у которого процесс был завершён ($true/$false).
#   $RestrictOwnerSam - если не пусто, закрывать/уведомлять/завершать сеанс только у процессов, чей владелец
#   (без имени домена) совпадает с этим именем без учёта регистра - используется для блокировки "по конкретному
#   пользователю" (Scope=User), чтобы не закрыть легитимно запущенный тот же файл у ДРУГИХ пользователей
#   компьютера, для которых правило SRP не действует. Для блокировки "по группе" такой проверки нет (сверить
#   членство в группе можно было бы только обращением к AD с этого же компьютера, что не проверено на реальном
#   домене - см. общую оговорку про недоказанные Windows-специфичные места в начале разговора) - поэтому для
#   групп, как и для обычной блокировки на весь компьютер, закрываются все текущие запущенные экземпляры файла
#   независимо от того, кто их запустил; постоянная защита (новые попытки запуска) при этом всё равно верно
#   ограничена только членами группы - это даёт сама Security Filtering GPO (см. Set-GpoUserFiltering), а не
#   этот скрипт.
#   Возвращает объект { Computer, GpUpdate ("OK" или код), GpUpdateOutput (текст, который вывел gpupdate.exe -
#   заполняется только при ненулевом коде, чтобы сразу видеть причину сбоя без похода за gpresult /h),
#   TerminateRequested, Found (сколько запущенных экземпляров
#   найдено - считается независимо от TerminateRequested), Killed (сколько реально завершено),
#   Notified (скольким пользователям показано уведомление), LoggedOff (сколько сеансов принудительно завершено -
#   один раз на сеанс (SessionId), даже если в нём было несколько запущенных экземпляров), FailReasons (причины
#   неудач метода Terminate, без повторов), Error }.
#   Found может быть больше Killed: причина - в FailReasons (чаще всего нет прав на завершение процесса).
#   Found = 0 при непустом $paths значит, что на момент применения процесс с таким путём уже не запущен
#   (завершился сам, или путь в данных сканирования устарел). Уведомление и завершение сеанса выполняются, только
#   если процесс реально завершён (TRUE Kill), и только один раз на пользователя/сеанс, даже если он держал
#   открытыми несколько копий файла.
#   $SkipGpUpdate - не вызывать gpupdate.exe вообще (GpUpdate в результате будет "пропущено"). Нужен для
#   Invoke-BlockSweep - повторной проверки уже заблокированных файлов после каждого сканирования: она не зависит
#   от групповой политики (в т. ч. не требует, чтобы GPO была привязана и вообще применялась - см. обсуждение
#   про ошибку "LocalGPO") и не должна тратить время на обновление политик при каждом сканировании.
#   Локальные: $res - возвращаемый результат; $paths - пути, по которым ищем запущенные экземпляры;
#   $reasonMap - код возврата Terminate() -> текст причины; $notified - кому уведомление уже отправлено;
#   $loggedOff - какие сеансы (SessionId) уже завершены в этом запуске (защита от дублей, если у пользователя
#   было несколько запущенных экземпляров в одном сеансе); $p - процесс из WMI; $owner - владелец именно этого
#   запущенного экземпляра (берётся заново через GetOwner(), а не из данных сканирования - на момент блокировки
#   им может быть уже другой пользователь); $r - результат Terminate(); $reason - текст причины для конкретного кода.
$script:ApplyBlockScript = {
    param($Map, $TerminateProcesses, $NotifyText = 'Нельзя такое запускать: этот файл заблокирован политикой безопасности.', $LogoffSessions = $false, $RestrictOwnerSam = '', $SkipGpUpdate = $false)
    $res = New-Object PSObject -Property @{
        Computer           = $env:COMPUTERNAME
        GpUpdate           = ''
        GpUpdateOutput     = ''
        TerminateRequested = [bool]$TerminateProcesses
        Found              = 0
        Killed             = 0
        Notified           = 0
        LoggedOff          = 0
        FailReasons        = ''
        Error              = ''
    }
    # Коды возврата Win32_Process.Terminate(): https://learn.microsoft.com/windows/win32/cimwin32prov/terminate-method-in-class-win32-process
    $reasonMap = @{
        2  = 'нет прав на завершение процесса (Access Denied)'
        3  = 'недостаточно привилегий (Insufficient Privilege)'
        8  = 'неизвестная ошибка (Unknown Failure)'
        9  = 'процесс уже не существует (Not Found)'
        21 = 'некорректный параметр (Invalid Parameter)'
    }
    try {
        if ($SkipGpUpdate) {
            $res.GpUpdate = 'пропущено'
        }
        else {
            # Предыдущая попытка (через $OutputEncoding перед обычным "& gpupdate.exe ... | Out-String") не помогла -
            # $OutputEncoding управляет тем, в какой кодировке PowerShell ОТПРАВЛЯЕТ текст НА ВХОД внешней программе,
            # а не тем, как он РАСШИФРОВЫВАЕТ её вывод, так что к этой задаче он вообще не относился. Вместо того
            # чтобы полагаться на то, как PowerShell сам решает читать вывод консольной программы (через [Console]::
            # OutputEncoding, которого в сеансе без настоящей консоли - а именно так выполняется этот скрипт, через
            # Invoke-Command/WinRM - может не быть вовсе), запускаем gpupdate.exe напрямую через .NET
            # System.Diagnostics.Process и явно задаём кодировку чтения его stdout/stderr сами - это не зависит от
            # наличия консоли и от того, что в неё "думает" PowerShell. Кодировка - настоящая OEM-кодовая страница
            # этого компьютера (та, в которой консольные программы печатают текст), берётся из реестра, как это
            # делает сам chcp.com; если почему-либо не получилось определить - используется кодировка по умолчанию
            # (тогда кириллица может остаться нечитаемой, но код возврата и остальная часть применения блокировки
            # всё равно отработают).
            $oemEncoding = [System.Text.Encoding]::Default
            try {
                $oemCp = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Nls\CodePage' -Name OEMCP -ErrorAction Stop).OEMCP
                $oemEncoding = [System.Text.Encoding]::GetEncoding([int]$oemCp)
            }
            catch { }

            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = "$env:windir\System32\gpupdate.exe"
            $psi.Arguments = '/target:computer /force'
            $psi.UseShellExecute = $false
            $psi.RedirectStandardOutput = $true
            $psi.RedirectStandardError = $true
            $psi.StandardOutputEncoding = $oemEncoding
            $psi.StandardErrorEncoding = $oemEncoding
            $gpProc = [System.Diagnostics.Process]::Start($psi)
            $gpStdOut = $gpProc.StandardOutput.ReadToEnd()
            $gpStdErr = $gpProc.StandardError.ReadToEnd()
            $gpProc.WaitForExit()
            $gpExitCode = $gpProc.ExitCode

            if ($gpExitCode -eq 0) {
                $res.GpUpdate = 'OK'
            }
            else {
                $res.GpUpdate = 'код ' + $gpExitCode
                # Выводим реальный текст gpupdate.exe, чтобы ненулевой код было видно сразу в журнале, без похода за gpresult /h на сам компьютер.
                $res.GpUpdateOutput = (($gpStdOut + $gpStdErr) -replace '[\r\n]+', ' ').Trim()
            }
        }

        $paths = @($Map[$env:COMPUTERNAME.ToUpper()])
        if ($paths.Count -gt 0) {
            $reasons = @{}
            $notified = @{}
            $loggedOff = @{}
            foreach ($p in (Get-WmiObject -Class Win32_Process)) {
                if ($p.ExecutablePath -and ($paths -contains $p.ExecutablePath)) {
                    $owner = ''
                    try { $o = $p.GetOwner(); if ($o.User) { $owner = $o.User } } catch { }
                    if ($RestrictOwnerSam) {
                        $ownerSam = $owner
                        $slash = $owner.LastIndexOf('\')
                        if ($slash -ge 0) { $ownerSam = $owner.Substring($slash + 1) }
                        if ($ownerSam -ine $RestrictOwnerSam) { continue }
                    }
                    $res.Found = $res.Found + 1
                    if ($TerminateProcesses) {
                        $r = $p.Terminate()
                        if ($r.ReturnValue -eq 0) {
                            $res.Killed = $res.Killed + 1
                            if ($owner -and -not $notified.ContainsKey($owner)) {
                                $notified[$owner] = $true
                                try {
                                    & "$env:windir\System32\msg.exe" $owner /TIME:30 $NotifyText 2>&1 | Out-Null
                                    if ($LASTEXITCODE -eq 0) { $res.Notified = $res.Notified + 1 }
                                }
                                catch { }
                            }
                            if ($LogoffSessions -and -not $loggedOff.ContainsKey([int]$p.SessionId)) {
                                $loggedOff[[int]$p.SessionId] = $true
                                try {
                                    & "$env:windir\System32\logoff.exe" $p.SessionId 2>&1 | Out-Null
                                    if ($LASTEXITCODE -eq 0) { $res.LoggedOff = $res.LoggedOff + 1 }
                                }
                                catch { }
                            }
                        }
                        else {
                            $reason = $reasonMap[[int]$r.ReturnValue]
                            if (-not $reason) { $reason = 'код ' + $r.ReturnValue }
                            $reasons[$reason] = $true
                        }
                    }
                }
            }
            $res.FailReasons = (@($reasons.Keys | Sort-Object) -join '; ')
        }
    }
    catch {
        $res.Error = $_.Exception.Message
    }
    $res
}

# Get-RemoteSessionOption - настройки удалённого сеанса: ждать подключения до 20 с (не зависать на
#   выключенных ПК), одна операция - до 15 мин (хватает на хэширование больших файлов), без загрузки профиля.
function Get-RemoteSessionOption {
    New-PSSessionOption -OpenTimeout 20000 -OperationTimeout 900000 -NoMachineProfile
}

# Start-Collection - запускает сбор процессов сразу на нескольких компьютерах в фоне (Invoke-Command -AsJob).
#   -ComputerName  имена компьютеров; -ThrottleLimit  сколько компьютеров опрашивать одновременно (32).
#   Возвращает родительское задание: по одному дочернему заданию на каждый компьютер.
function Start-Collection {
    param(
        [Parameter(Mandatory)][string[]]$ComputerName,
        [int]$ThrottleLimit = 32
    )
    Invoke-Command -ComputerName $ComputerName -ScriptBlock $script:CollectScript `
        -SessionOption (Get-RemoteSessionOption) -ThrottleLimit $ThrottleLimit `
        -AsJob -JobName 'ProcMon-Collect'
}

# Start-BlockApply - в фоне запускает $script:ApplyBlockScript (обновление политик, завершение процессов,
#   уведомление и, по желанию, принудительное завершение сеанса пользователей) на компьютерах, где найден
#   заблокированный файл.
#   -Map  "ИМЯ КОМПЬЮТЕРА -> пути к файлу" (ключи Map - список компьютеров);
#   -TerminateProcesses  завершать ли найденные запущенные экземпляры;
#   -NotifyText  текст уведомления пользователю при завершении его процесса;
#   -LogoffSessions  завершать ли принудительно сеанс пользователя после завершения его процесса. Возвращает задание.
function Start-BlockApply {
    param([Parameter(Mandatory)][hashtable]$Map, [bool]$TerminateProcesses = $false, [string]$NotifyText, [bool]$LogoffSessions = $false, [string]$RestrictOwnerSam = '', [bool]$SkipGpUpdate = $false)
    Invoke-Command -ComputerName @($Map.Keys) -ScriptBlock $script:ApplyBlockScript `
        -ArgumentList $Map, $TerminateProcesses, $NotifyText, $LogoffSessions, $RestrictOwnerSam, $SkipGpUpdate -SessionOption (Get-RemoteSessionOption) -ThrottleLimit 32 `
        -AsJob -JobName 'ProcMon-Apply'
}

# $script:SrpEventScript - скрипт, который выполняется НА УДАЛЁННОМ компьютере: ищет в журнале событий Windows
#   следы того, что кто-то пытался запустить ИМЕННО этот заблокированный файл после указанного момента времени.
#   Software Restriction Policies при отказе в запуске пишет событие в журнал Application от источника "SRP"
#   с одним из кодов 865 (запрещено по пути), 866 (по хэшу - это как раз наш случай), 867 (по сертификату),
#   868 (по зоне Интернета) или 882 (запрещено правилом по умолчанию). ВАЖНО: эти коды и имя источника - по
#   документации Microsoft, НЕ проверены на реальном журнале событий (нет доступа к Windows для проверки);
#   если на практике они окажутся другими, функция просто ничего не найдёт (поймано в try/catch), а не упадёт
#   с ошибкой - то есть худший случай - ложный "0 событий", а не сбой.
#   Чтобы не зависеть от формата и языка текста события (путь и сопровождающие слова могут быть локализованы
#   по-разному), сам хэш в сообщении ищется так: все символы, кроме шестнадцатеричных цифр, убираются, и
#   проверяется, встречается ли искомый хэш (32/40/64 символа) как есть внутри получившейся строки - само
#   шестнадцатеричное значение хэша в событии не переводится ни на одном языке.
#   -Hash  хэш, который ищем (без разделителей, регистр не важен); -Since  с какого момента искать события
#   (обычно дата блокировки). Возвращает объекты { Computer, Time, Id, Message } - по одному на найденное событие.
#   Локальные: $hash - хэш в верхнем регистре; $events - все подходящие по коду и времени события; $e - текущее
#   событие; $normalized - его текст без ничего, кроме hex-цифр.
$script:SrpEventScript = {
    param($Hash, $Since)
    $hash = ([string]$Hash).ToUpper()
    try {
        $events = Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'SRP'; Id = 865, 866, 867, 868, 882; StartTime = $Since } -ErrorAction Stop
    }
    catch {
        return      # событий нет, либо журнал/источник недоступен - для вызывающего кода это одно и то же: "ничего не найдено"
    }
    foreach ($e in $events) {
        $normalized = ($e.Message -replace '[^0-9A-Fa-f]', '').ToUpper()
        if ($normalized.Contains($hash)) {
            New-Object PSObject -Property @{
                Computer = $env:COMPUTERNAME
                Time     = $e.TimeCreated
                Id       = $e.Id
                Message  = $e.Message
            }
        }
    }
}

# Start-SrpEventCheck - в фоне запускает $script:SrpEventScript на указанных компьютерах.
#   -ComputerName  где искать; -Hash  что искать; -Since  с какого момента. Возвращает задание.
function Start-SrpEventCheck {
    param([Parameter(Mandatory)][string[]]$ComputerName, [Parameter(Mandatory)][string]$Hash, [Parameter(Mandatory)][datetime]$Since)
    Invoke-Command -ComputerName $ComputerName -ScriptBlock $script:SrpEventScript -ArgumentList $Hash, $Since `
        -SessionOption (Get-RemoteSessionOption) -ThrottleLimit 32 -AsJob -JobName 'ProcMon-Events'
}

# Get-JobProgress - прогресс фонового задания: сколько компьютеров уже завершили работу.
#   Возвращает { Done = завершено, Total = всего }. $children - дочерние задания, $done - число завершённых.
function Get-JobProgress {
    param([Parameter(Mandatory)]$Job)
    $children = @($Job.ChildJobs)
    $done = @($children | Where-Object { $_.State -notin 'Running', 'NotStarted' }).Count
    [pscustomobject]@{ Done = $done; Total = $children.Count }
}

# Receive-JobResults - забирает итог фонового задания и удаляет задание.
#   Возвращает { Data = все полученные объекты, Failures = компьютеры, не давшие данных, с причиной
#   (Computer, Message), Succeeded = сколько компьютеров ответило }.
#   Локальные: $data - собранные данные; $failures - список сбоев; $succeeded - счётчик успешных;
#   $child - задание одного компьютера; $items - его данные; $reason / $message - причина сбоя.
function Receive-JobResults {
    param([Parameter(Mandatory)]$Job)

    $data = New-Object System.Collections.ArrayList
    $failures = New-Object System.Collections.ArrayList
    $succeeded = 0
    foreach ($child in $Job.ChildJobs) {
        if ($child.State -eq 'Completed') {
            $succeeded++
            $items = @(Receive-Job -Job $child -ErrorAction SilentlyContinue)
            if ($items.Count -gt 0) { $data.AddRange($items) }
        }
        else {
            $reason = $child.JobStateInfo.Reason
            $message = if ($reason) { ($reason.Message -replace '\s+', ' ').Trim() } else { [string]$child.State }
            [void]$failures.Add([pscustomobject]@{ Computer = $child.Location; Message = $message })
        }
    }
    Remove-Job -Job $Job -Force -ErrorAction SilentlyContinue
    [pscustomobject]@{ Data = $data; Failures = $failures; Succeeded = $succeeded }
}

# ===========================================================================
# Блокировка по хэшу (SRP / GPO)
# ===========================================================================

# Блокировка запуска по хэшу через Software Restriction Policies (SRP) в доменной GPO.
# Правило пишется в Registry.pol GPO как хэш-правило уровня "Запрещено" (Disallowed):
#   HKLM\Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers\0\Hashes\{GUID}
# Требуется модуль GroupPolicy (RSAT: Group Policy Management) на машине администратора.

# $script:SrpBase - раздел реестра политики SRP в Computer Configuration (действует на всех пользователей
#   компьютера - обычный режим блокировки).
$script:SrpBase = 'HKLM\Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers'
# $script:SrpBaseUser - тот же раздел, но в User Configuration (HKCU): правило действует только там, где
#   применяется ПОЛЬЗОВАТЕЛЬСКАЯ часть GPO, то есть для того, кто вошёл в систему под нужной учётной записью,
#   независимо от того, на каком компьютере домена он это делает. Сама по себе запись хэша в User Configuration
#   ничего не ограничивает по пользователю - фактическое ограничение "кому" даёт Security Filtering GPO
#   (см. Set-GpoUserFiltering): без него правило действует на всех, кого достаёт привязка GPO, точно как в
#   Computer Configuration.
$script:SrpBaseUser = 'HKCU\Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers'

# $script:SrpHashAlg - код алгоритма хэша для значения HashAlg правила SRP (MD5=0x8003, SHA1=0x8004, SHA256=0x800C).
$script:SrpHashAlg = @{ MD5 = 32771; SHA1 = 32772; SHA256 = 32780 }
# $script:HashLength - сколько шестнадцатеричных символов в хэше каждого алгоритма (для проверки ввода).
$script:HashLength = @{ MD5 = 32; SHA1 = 40; SHA256 = 64 }

# $script:NotifyTemplate - текст уведомления, которое видит пользователь при закрытии заблокированного файла
#   (имя файла подставляется вместо {0}). Объявлено здесь, а не в UI-блоке ниже, потому что используется и из
#   Invoke-BlockSweep (см. ниже), которая должна работать и в режиме -ScheduledScan - там код до UI-блока
#   вообще не доходит (скрипт завершается раньше, см. "if ($ScheduledScan) {...; exit}").
$script:NotifyTemplate = 'Нельзя такое запускать: «{0}» заблокировано политикой безопасности.'

# $script:SrpExecutableTypes - расширения файлов, которые SRP проверяет (записываются в GPO один раз вместе с базовыми настройками).
$script:SrpExecutableTypes = @(
    'ADE', 'ADP', 'BAS', 'BAT', 'CHM', 'CMD', 'COM', 'CPL', 'CRT', 'EXE', 'HLP', 'HTA', 'INF', 'INS', 'ISP',
    'LNK', 'MDB', 'MDE', 'MSC', 'MSI', 'MSP', 'MST', 'OCX', 'PCD', 'PIF', 'REG', 'SCR', 'SHS', 'URL', 'VB', 'WSC'
)

# Test-GroupPolicyModule - есть ли на этом компьютере модуль GroupPolicy (RSAT). Возвращает $true/$false.
function Test-GroupPolicyModule {
    [bool](Get-Module -ListAvailable -Name GroupPolicy)
}

# Test-ProtectedPath - защита от самоубийства домена: возвращает $true, если файл лежит в X:\Windows\...
#   Блокировка по хэшу svchost.exe или explorer.exe остановила бы все компьютеры, поэтому такие файлы
#   блокировать запрещено. -Path  путь к файлу.
function Test-ProtectedPath {
    param([string]$Path)
    if (-not $Path) { return $false }
    return [bool]($Path -match '(?i)^[a-z]:\\windows\\')
}

# ConvertFrom-HexString - превращает строку "DEADBEEF" в массив байт (нужен для записи хэша в реестр).
#   -Hex  строка из шестнадцатеричных символов чётной длины. $bytes - результат.
function ConvertFrom-HexString {
    param([Parameter(Mandatory)][string]$Hex)
    $bytes = New-Object byte[] ($Hex.Length / 2)
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        $bytes[$i] = [Convert]::ToByte($Hex.Substring($i * 2, 2), 16)
    }
    , $bytes
}

# Test-HashValue - проверяет, что строка является корректным хэшем: только hex-символы и длина
#   соответствует алгоритму (MD5 - 32, SHA1 - 40, SHA256 - 64). Возвращает $true/$false.
function Test-HashValue {
    param([string]$Algorithm, [string]$Hash)
    return [bool]($Hash -match '^[0-9A-Fa-f]+$' -and $Hash.Length -eq $script:HashLength[$Algorithm])
}

# Set-GpoUserFiltering - настраивает Security Filtering GPO так, чтобы она (и записанные в неё правила User
#   Configuration) применялась ТОЛЬКО к указанному пользователю/группе, а не ко всем ("Authenticated Users",
#   которых New-GPO ставит по умолчанию). Без этого шага блокировка "по пользователю" на деле действовала бы
#   на всех, кто попадает под привязку GPO - ровно как обычная, компьютерная. -GpoName  имя GPO;
#   -PrincipalSam  sAMAccountName пользователя/группы; -PrincipalType  'User' или 'Group'.
#   Идемпотентна: повторный вызов для уже настроенной GPO ничего не меняет.
#   Локальные: $current - текущие права GPO; $hasApply - есть ли уже GpoApply у этого principal;
#   $authUsersApply - есть ли ещё права на Apply у "Authenticated Users" (их нужно снять).
function Set-GpoUserFiltering {
    param(
        [Parameter(Mandatory)][string]$GpoName,
        [Parameter(Mandatory)][string]$PrincipalSam,
        [Parameter(Mandatory)][ValidateSet('User', 'Group')][string]$PrincipalType
    )
    $current = @(Get-GPPermission -Name $GpoName -All -ErrorAction Stop)
    $hasApply = $current | Where-Object { $_.Trustee.Name -eq $PrincipalSam -and $_.Permission -eq 'GpoApply' }
    if (-not $hasApply) {
        [void](Set-GPPermission -Name $GpoName -TargetName $PrincipalSam -TargetType $PrincipalType -PermissionLevel GpoApply -ErrorAction Stop)
    }
    $authUsersApply = $current | Where-Object { $_.Trustee.Name -eq 'Authenticated Users' -and $_.Permission -eq 'GpoApply' }
    if ($authUsersApply) {
        [void](Set-GPPermission -Name $GpoName -TargetName 'Authenticated Users' -TargetType Group -PermissionLevel None -ErrorAction Stop)
    }
}

# Initialize-SrpGpo - готовит GPO к хранению правил: создаёт её, если нет; записывает базовые параметры
#   SRP (если их ещё нет - существующие не перезаписываются); при необходимости привязывает к OU/домену;
#   если задан -PrincipalSam - ограничивает действие GPO только этим пользователем/группой (Set-GpoUserFiltering).
#   -GpoName  имя GPO; -LinkTarget  DN контейнера для привязки (пусто - не привязывать); -Scope  'Computer'
#   (по умолчанию) или 'User' - базовые настройки SRP пишутся ТОЛЬКО в этот раздел (Computer или User
#   Configuration), а не в оба сразу: у каждой GPO, которую создаёт это приложение, только ОДНО назначение
#   (компьютерная блокировка - свои GPO с базовым именем; блокировка по пользователю/группе - свои отдельные
#   GPO с суффиксом, см. Resolve-BlockTarget), поэтому второй раздел такой GPO никогда не использовался бы, и
#   писать туда пустую, бесполезную конфигурацию SRP (DefaultLevel/PolicyScope и т. п. без единого правила)
#   незачем - раньше это делалось, пока не выяснилось, что GPMC начинает отказываться строить отчёт "Параметры"
#   для такой GPO ("Ссылка на объект не указывает на экземпляр объекта").
#   -PrincipalSam/-PrincipalType  см. Set-GpoUserFiltering (пусто - фильтрация не трогается, GPO действует на
#   всех, как обычная компьютерная блокировка). Возвращает GPO.
#   Локальные: $gpo - объект GPO; $base - раздел реестра (Computer или User, по -Scope); $hasBase - есть ли в
#   GPO базовые настройки SRP в этом разделе; $linked - уже привязана ли GPO к контейнеру.
#   Базовые значения: DefaultLevel=262144 ("Неограниченный": всё, что не запрещено, работает), TransparentEnabled=1,
#   PolicyScope=0 (все пользователи), AuthenticodeEnabled=0, ExecutableTypes (список расширений).
function Initialize-SrpGpo {
    param(
        [Parameter(Mandatory)][string]$GpoName,
        [string]$LinkTarget,
        [ValidateSet('Computer', 'User')][string]$Scope = 'Computer',
        [string]$PrincipalSam,
        # Без ValidateSet: параметр необязательный, и при вызове без -PrincipalSam сюда часто передают пустую
        # строку явно (например, Add-SrpHashBlock всегда передаёт своё $PrincipalType дальше) - ValidateSet
        # отверг бы такой явный пустой вызов, хотя он корректен (значит "фильтрация не нужна"). Проверка набора
        # 'User'/'Group' в любом случае происходит там, где это по-настоящему важно - в Set-GpoUserFiltering,
        # куда $PrincipalType передаётся только если задан $PrincipalSam.
        [string]$PrincipalType
    )
    Import-Module GroupPolicy -ErrorAction Stop

    $gpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
    if (-not $gpo) {
        $gpo = New-GPO -Name $GpoName -Comment 'Блокировка процессов по хэшу (создано ProcessMonitor)' -ErrorAction Stop
    }

    $base = if ($Scope -eq 'User') { $script:SrpBaseUser } else { $script:SrpBase }
    $hasBase = $true
    try {
        [void](Get-GPRegistryValue -Name $GpoName -Key $base -ValueName DefaultLevel -ErrorAction Stop)
    }
    catch {
        $hasBase = $false
    }
    if (-not $hasBase) {
        # DefaultLevel 262144 = "Неограниченный": всё, что не запрещено правилами, запускается как раньше.
        [void](Set-GPRegistryValue -Name $GpoName -Key $base -ValueName DefaultLevel -Type DWord -Value 262144)
        [void](Set-GPRegistryValue -Name $GpoName -Key $base -ValueName TransparentEnabled -Type DWord -Value 1)
        [void](Set-GPRegistryValue -Name $GpoName -Key $base -ValueName PolicyScope -Type DWord -Value 0)
        [void](Set-GPRegistryValue -Name $GpoName -Key $base -ValueName AuthenticodeEnabled -Type DWord -Value 0)
        [void](Set-GPRegistryValue -Name $GpoName -Key $base -ValueName ExecutableTypes -Type MultiString -Value $script:SrpExecutableTypes)
    }

    if ($LinkTarget) {
        $linked = (Get-GPInheritance -Target $LinkTarget -ErrorAction Stop).GpoLinks |
            Where-Object { $_.DisplayName -eq $GpoName }
        if (-not $linked) {
            [void](New-GPLink -Name $GpoName -Target $LinkTarget -ErrorAction Stop)
        }
    }
    if ($PrincipalSam) {
        Set-GpoUserFiltering -GpoName $GpoName -PrincipalSam $PrincipalSam -PrincipalType $PrincipalType
    }
    return $gpo
}

# Add-SrpHashBlock - добавляет в GPO хэш-правило уровня "Запрещено". Возвращает GUID правила "{xxxxxxxx-...}".
#   -GpoName, -LinkTarget, -PrincipalSam, -PrincipalType  GPO, привязка и ограничение по пользователю/группе
#   (см. Initialize-SrpGpo); -Name  имя файла (для описания правила); -Algorithm и -Hash  хэш; -Size  размер
#   файла (SRP сверяет и его). -Scope  'Computer' (по умолчанию - правило в Computer Configuration, действует
#   на всех пользователей компьютера) или 'User' (правило в User Configuration этой же GPO; реально ограничивает
#   конкретного пользователя/группу только в сочетании с -PrincipalSam - без него это просьба "для всех", только
#   записанная в другой раздел реестра).
#   Значения правила в реестре: ItemData (хэш в байтах), ItemSize (размер), HashAlg (алгоритм), SaferFlags=0,
#   LastModified (дата изменения), Description (описание).
#   Локальные: $base - раздел реестра (Computer или User, в зависимости от -Scope); $ruleId - GUID нового
#   правила; $key - раздел реестра правила; $bytes - хэш в байтах; $description - текст описания.
function Add-SrpHashBlock {
    param(
        [Parameter(Mandatory)][string]$GpoName,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][ValidateSet('MD5', 'SHA1', 'SHA256')][string]$Algorithm,
        [Parameter(Mandatory)][string]$Hash,
        [long]$Size,
        [string]$LinkTarget,
        [ValidateSet('Computer', 'User')][string]$Scope = 'Computer',
        [string]$PrincipalSam,
        [string]$PrincipalType          # см. комментарий у этого же параметра в Initialize-SrpGpo - без ValidateSet
    )
    if (-not (Test-HashValue -Algorithm $Algorithm -Hash $Hash)) {
        throw "Некорректный $Algorithm-хэш: '$Hash'."
    }
    [void](Initialize-SrpGpo -GpoName $GpoName -LinkTarget $LinkTarget -Scope $Scope -PrincipalSam $PrincipalSam -PrincipalType $PrincipalType)

    $base = if ($Scope -eq 'User') { $script:SrpBaseUser } else { $script:SrpBase }
    $ruleId = [Guid]::NewGuid().ToString('B')
    $key = '{0}\0\Hashes\{1}' -f $base, $ruleId
    $bytes = ConvertFrom-HexString -Hex $Hash

    $description = '{0} (добавлено ProcessMonitor {1})' -f $Name, (Get-Date).ToString('yyyy-MM-dd')
    [void](Set-GPRegistryValue -Name $GpoName -Key $key -ValueName ItemData -Type Binary -Value $bytes)
    [void](Set-GPRegistryValue -Name $GpoName -Key $key -ValueName ItemSize -Type QWord -Value $Size)
    [void](Set-GPRegistryValue -Name $GpoName -Key $key -ValueName HashAlg -Type DWord -Value $script:SrpHashAlg[$Algorithm])
    [void](Set-GPRegistryValue -Name $GpoName -Key $key -ValueName SaferFlags -Type DWord -Value 0)
    [void](Set-GPRegistryValue -Name $GpoName -Key $key -ValueName LastModified -Type QWord -Value ([DateTime]::UtcNow.ToFileTimeUtc()))
    [void](Set-GPRegistryValue -Name $GpoName -Key $key -ValueName Description -Type String -Value $description)
    return $ruleId
}

# Remove-SrpHashBlock - удаляет правило из GPO по его GUID. -GpoName  имя GPO; -RuleId  GUID из журнала блокировок;
#   -Scope  в каком разделе искать правило - 'Computer' (по умолчанию, для совместимости со старыми записями
#   журнала, у которых поля Scope ещё не было) или 'User' (см. Add-SrpHashBlock).
# Get-GpoLinkSummary - сколько у GPO реальных привязок (Link) к OU/домену и сколько из них включено.
#   Читает отчёт GPO (GenerateReport) и считает узлы <LinksTo> - именно по ним gpupdate на клиенте решает,
#   какие GPO вообще обрабатывать; DefaultLevel/Hashes внутри самой GPO не играют роли, если привязок нет.
#   -GpoName  имя GPO. Возвращает $null, если GPO не существует или отчёт получить не удалось (нет прав,
#   не установлен модуль и т. п.) - в этом случае вызывающий код должен считать состояние неизвестным и не
#   делать по одной этой проверке категоричных выводов. Иначе - { Total = всего привязок, Enabled = сколько
#   из них включено (отключённые Link ничего не применяют), Paths = их DN }.
#   Локальные: $gpo - объект GPO; $xml - разобранный XML-отчёт; $links - узлы <LinksTo>; $enabled - из них включённые.
function Get-GpoLinkSummary {
    param([Parameter(Mandatory)][string]$GpoName)
    try {
        Import-Module GroupPolicy -ErrorAction Stop
        $gpo = Get-GPO -Name $GpoName -ErrorAction Stop
        $xml = [xml]$gpo.GenerateReport([Microsoft.GroupPolicy.ReportType]::Xml)
        $links = @($xml.GPO.LinksTo | Where-Object { $_ })
        $enabled = @($links | Where-Object { [string]$_.Enabled -eq 'true' })
        return [pscustomobject]@{ Total = $links.Count; Enabled = $enabled.Count; Paths = @($links | ForEach-Object { [string]$_.SOMPath }) }
    }
    catch {
        return $null
    }
}

function Remove-SrpHashBlock {
    param(
        [Parameter(Mandatory)][string]$GpoName,
        [Parameter(Mandatory)][string]$RuleId,
        [ValidateSet('Computer', 'User')][string]$Scope = 'Computer'
    )
    Import-Module GroupPolicy -ErrorAction Stop
    $base = if ($Scope -eq 'User') { $script:SrpBaseUser } else { $script:SrpBase }
    $key = '{0}\0\Hashes\{1}' -f $base, $RuleId
    [void](Remove-GPRegistryValue -Name $GpoName -Key $key -ErrorAction Stop)
}


# ===========================================================================
# Журнал в файле
# ===========================================================================

# $script:LogFile - файл журнала на диске (data\logs\processmonitor.log). Записи ДОБАВЛЯЮТСЯ в конец и не стираются
#   при перезапуске программы; при размере больше 5 МБ файл переименовывается в processmonitor.log.1 (старый .1 заменяется).
$script:LogFile = Join-Path $DataPath 'logs\processmonitor.log'

# Write-LogFile - дописывает сообщение в файл журнала со строкой даты и времени "гггг-мм-дд чч:мм:сс  сообщение".
#   -Message текст; -Time время записи. Файл в UTF-8 с BOM (корректно открывается Блокнотом). Любая ошибка записи
#   (нет прав, файл занят) молча игнорируется: журнал не должен ронять программу.
#   Локальные: $dir - папка журнала; $info - сведения о файле (для проверки размера).
function Write-LogFile {
    param([string]$Message, [datetime]$Time = (Get-Date))
    if (-not $script:LogFile) { return }
    try {
        $dir = Split-Path -Parent $script:LogFile
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $info = Get-Item -LiteralPath $script:LogFile -ErrorAction SilentlyContinue
        if ($info -and $info.Length -gt 5MB) { Move-Item -LiteralPath $script:LogFile -Destination ($script:LogFile + '.1') -Force }
        $line = '{0}  {1}{2}' -f $Time.ToString('yyyy-MM-dd HH:mm:ss'), $Message, [Environment]::NewLine
        [System.IO.File]::AppendAllText($script:LogFile, $line, (New-Object System.Text.UTF8Encoding($true)))
    }
    catch {
        # ничего: журнал вспомогательный
    }
}

# ===========================================================================
# Самопроверка (запуск: .\ProcessMonitor.ps1 -SelfTest)
# ===========================================================================

# $script:TestFailed - сколько обязательных проверок самопроверки не пройдено.
$script:TestFailed = 0

# Test-Step - выполняет одну проверку и печатает результат.
#   -Name название проверки; -Block код проверки (бросает исключение при неудаче, может вернуть строку с подробностями);
#   -Optional необязательная проверка: неудача печатается как [WARN] и не считается ошибкой (например, нет WinRM или AD).
#   Локальные: $info - строка подробностей из -Block; $color / $tag - цвет и метка результата.
function Test-Step {
    param([string]$Name, [scriptblock]$Block, [switch]$Optional)
    try {
        $info = & $Block
        $line = '[ OK ] ' + $Name
        if ($info) { $line += ' - ' + $info }
        Write-Host $line -ForegroundColor Green
    }
    catch {
        $tag = '[FAIL]'
        $color = 'Red'
        if ($Optional) { $tag = '[WARN]'; $color = 'Yellow' }
        else { $script:TestFailed++ }
        Write-Host ('{0} {1} - {2}' -f $tag, $Name, $_.Exception.Message) -ForegroundColor $color
    }
}

# Assert-True - бросает исключение с сообщением, если условие ложно. -Condition проверяемое условие; -Message текст ошибки.
function Assert-True {
    param($Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

# Invoke-SelfTest - проверяет на ЭТОМ компьютере то, от чего зависит приложение; ничего не меняет в реальных данных
#   (хранилище проверяется во временной папке, которая потом удаляется). Возвращает число непройденных
#   обязательных проверок (0 - всё хорошо). Локальные: $tmp - временная папка; $rows - тестовые строки процессов;
#   $scan - тестовое сканирование; $self - путь к powershell.exe текущего процесса; $collected - результат
#   локального запуска $script:CollectScript; $ref - эталонный хэш из Get-FileHash; $job / $res - тест WinRM.
function Invoke-SelfTest {
    $script:TestFailed = 0
    Write-Host 'Самопроверка Process Monitor' -ForegroundColor Cyan

    Test-Step 'Версия PowerShell' {
        $v = $PSVersionTable.PSVersion
        Assert-True ($v.Major -gt 5 -or ($v.Major -eq 5 -and $v.Minor -ge 1)) "нужна версия 5.1 или новее, сейчас $v"
        '{0}, {1}, CLR {2}' -f $v, $PSVersionTable.PSEdition, $PSVersionTable.CLRVersion
    }
    Test-Step 'Режим потока STA (нужен для окна)' {
        Assert-True ([Threading.Thread]::CurrentThread.GetApartmentState() -eq [Threading.ApartmentState]::STA) 'поток не STA - запускайте через powershell.exe -STA'
    }
    Test-Step 'Папка данных определена и доступна для записи' {
        Assert-True $DataPath 'путь к папке данных пуст ($DataPath)'
        if (-not (Test-Path -LiteralPath $DataPath)) { New-Item -ItemType Directory -Path $DataPath -Force | Out-Null }
        $probe = Join-Path $DataPath ('.write-test-' + [Guid]::NewGuid().ToString('N'))
        [IO.File]::WriteAllText($probe, 'ok')
        Remove-Item -LiteralPath $probe -Force
        $DataPath
    }
    Test-Step 'Запись журнала в файл (дописывание, кириллица)' {
        $oldLog = $script:LogFile
        $script:LogFile = Join-Path ([IO.Path]::GetTempPath()) ('pm-log-' + [Guid]::NewGuid().ToString('N') + '\test.log')
        try {
            Write-LogFile -Message 'первая запись'
            Write-LogFile -Message 'вторая запись'
            $text = [IO.File]::ReadAllText($script:LogFile, [Text.Encoding]::UTF8)
            Assert-True ($text -match 'первая запись' -and $text -match 'вторая запись') 'записи не сохранились или кириллица искажена'
            Assert-True (@($text -split "`n" | Where-Object { $_ }).Count -eq 2) 'вторая запись затёрла первую вместо дописывания'
        }
        finally {
            Remove-Item -LiteralPath (Split-Path -Parent $script:LogFile) -Recurse -Force -ErrorAction SilentlyContinue
            $script:LogFile = $oldLog
        }
    }
    Test-Step 'Сериализатор JSON' {
        if ($PSVersionTable.PSEdition -eq 'Desktop') {
            Assert-True $script:JsonSerializer 'JavaScriptSerializer недоступен (System.Web.Extensions)'
            'JavaScriptSerializer'
        }
        else { 'запасной вариант ConvertTo-Json (не Windows PowerShell)' }
    }
    Test-Step 'Проверка хэша и защита системных путей' {
        Assert-True (Test-HashValue -Algorithm MD5 -Hash ('A' * 32)) 'MD5 из 32 символов должен считаться корректным'
        Assert-True (-not (Test-HashValue -Algorithm MD5 -Hash ('G' * 32))) 'не-hex хэш должен отклоняться'
        Assert-True (Test-ProtectedPath -Path 'C:\Windows\System32\svchost.exe') 'каталог Windows должен быть защищён'
        Assert-True (-not (Test-ProtectedPath -Path 'C:\Program Files\App\a.exe')) 'Program Files не должен быть защищён'
        Assert-True ((ConvertFrom-HexString -Hex 'DEADBEEF').Length -eq 4) 'ConvertFrom-HexString вернул не 4 байта'
    }
    Test-Step 'JSON-хранилище (сканирования, процессы, блокировки, кириллица, перезагрузка с диска)' {
        $tmp = Join-Path ([IO.Path]::GetTempPath()) ('pm-selftest-' + [Guid]::NewGuid().ToString('N'))
        try {
            Initialize-Database -Path $tmp
            $rows = @(
                [pscustomobject]@{ Computer = 'pc1'; User = 'DOM\иванов'; StartTime = '2026-01-02 10:00:00'; Name = 'тест.exe'; Path = "C:\Прог\`"тест`"`t.exe"; Size = 5GB; MD5 = 'aa'; SHA1 = 'bb'; SHA256 = 'cc' },
                [pscustomobject]@{ Computer = 'PC2'; Name = 'b.exe'; Path = 'C:\b.exe'; Size = 10; MD5 = 'aa'; SHA1 = 'dd'; SHA256 = 'ee' }
            )
            $scan = New-Scan -Requested 3
            Save-Processes -ScanId $scan.Id -ScanDate $scan.Date -Requested 3 -Rows $rows -Succeeded 2 -Failed 1
            Add-BlockRecord -Name 'тест.exe' -Algorithm MD5 -Hash 'aa' -Size 5GB -GpoName 'G' -RuleId '{1}'

            $script:Scans = $null; $script:Blocks = $null
            Initialize-Database -Path $tmp                       # заново читаем всё с диска
            $table = Get-ProcessTable -ScanId $scan.Id -Algorithm MD5
            Assert-True ($table.Rows.Count -eq 2) "ожидалось 2 строки, получено $($table.Rows.Count)"
            Assert-True ($table.Rows[0].Name -eq 'b.exe' -or $table.Rows[1].Name -eq 'b.exe') 'не найден b.exe'
            $ru = @($table.Rows | Where-Object { $_.Name -eq 'тест.exe' })
            Assert-True ($ru.Count -eq 1) 'кириллица в имени потеряна'
            Assert-True ($ru[0].Size -eq 5GB) 'размер больше 4 ГБ искажён'
            Assert-True ($ru[0].Path -ceq ('C:\Прог\"тест"' + "`t.exe")) 'кавычки, обратная косая и табуляция в пути искажены'
            Assert-True ($ru[0].Computer -eq 'PC1' -and $ru[0].Hash -eq 'AA') 'имя/хэш должны быть в верхнем регистре'
            Assert-True ($ru[0].User -ceq 'DOM\иванов') 'пользователь компьютера не сохранился'
            Assert-True ($ru[0].StartTime -eq '2026-01-02 10:00:00') 'время запуска процесса не сохранилось'
            Assert-True (@($table.Rows | Where-Object { $_.Name -eq 'b.exe' })[0].User -eq '') 'пустой пользователь должен читаться как пустая строка'
            Assert-True ((Get-HashLocations -Algorithm MD5 -Hash 'aa').Rows.Count -eq 2) 'Get-HashLocations: ожидалось 2 места'
            Assert-True (Get-ActiveBlock -Algorithm MD5 -Hash 'AA') 'активная блокировка не найдена после перезагрузки'
            Disable-BlockRecord -Id 1
            Assert-True (-not (Get-ActiveBlock -Algorithm MD5 -Hash 'AA')) 'блокировка не снялась'
            Assert-True ((Get-BlockTable).Rows[0].Status -eq 'Снята') 'статус блокировки неверный'
            $bytes = [IO.File]::ReadAllBytes((Join-Path $tmp 'scans.json'))
            Assert-True (-not ($bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB)) 'файл JSON записан с BOM'
            'записей: 2, файлов: ' + @(Get-ChildItem $tmp -Recurse -File).Count
        }
        finally {
            Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    Test-Step 'Хэширование процессов (локальный запуск скрипта сбора, сверка с Get-FileHash)' {
        $self = (Get-Process -Id $PID).Path
        $collected = @(& $script:CollectScript)
        Assert-True ($collected.Count -gt 0) 'не получено ни одного процесса (Win32_Process)'
        $mine = @($collected | Where-Object { $_.Path -ieq $self })
        Assert-True ($mine.Count -ge 1) "не найден собственный процесс: $self"
        Assert-True ($mine[0].PSObject.Properties.Name -contains 'User') 'в результате сбора нет поля User'
        Assert-True ($mine[0].PSObject.Properties.Name -contains 'StartTime') 'в результате сбора нет поля StartTime'
        Assert-True ([string]$mine[0].StartTime) 'не определилось время запуска собственного процесса'
        foreach ($alg in 'MD5', 'SHA1', 'SHA256') {
            $ref = (Get-FileHash -LiteralPath $self -Algorithm $alg).Hash
            Assert-True ($mine[0].$alg -eq $ref) "$alg не совпал с Get-FileHash"
        }
        $me = '{0}\{1}' -f $env:USERDOMAIN, $env:USERNAME
        $owned = @($mine | Where-Object { $_.User -ieq $me })
        'строк: ' + $collected.Count + ', владелец собственного процесса ' + $(if ($owned.Count -gt 0) { $me + ' определён верно' } else { 'НЕ определился (ожидался ' + $me + ')' })
    }
    Test-Step 'Windows Forms (создание окна и таблицы без показа)' {
        Add-Type -AssemblyName System.Windows.Forms, System.Drawing
        $form = New-Object System.Windows.Forms.Form
        $grid = New-Object System.Windows.Forms.DataGridView
        $form.Controls.Add($grid)
        $form.Dispose()
    }
    Test-Step 'Модуль GroupPolicy (RSAT) - нужен для блокировки' -Optional {
        Assert-True (Test-GroupPolicyModule) 'модуль не найден; установите Group Policy Management (RSAT)'
    }
    Test-Step 'Запрос списка компьютеров из AD' -Optional {
        $found = @(Get-AdComputers | Select-Object -First 5)
        Assert-True ($found.Count -gt 0) 'компьютеры не найдены'
        'например: ' + (($found | ForEach-Object { $_.Host }) -join ', ')
    }
    Test-Step 'WinRM: сбор процессов с этого компьютера через Invoke-Command -AsJob' -Optional {
        $job = Start-Collection -ComputerName $env:COMPUTERNAME
        $null = Wait-Job -Job $job -Timeout 180
        Assert-True ($job.State -ne 'Running') 'за 180 с задание не завершилось'
        $res = Receive-JobResults -Job $job
        Assert-True ($res.Succeeded -eq 1) ('WinRM не ответил: ' + (($res.Failures | ForEach-Object { $_.Message }) -join '; '))
        'получено записей: ' + $res.Data.Count
    }

    if ($script:TestFailed -eq 0) { Write-Host 'Итог: обязательные проверки пройдены.' -ForegroundColor Green }
    else { Write-Host ('Итог: не пройдено обязательных проверок: {0}.' -f $script:TestFailed) -ForegroundColor Red }
    return $script:TestFailed
}

if ($SelfTest) {
    $code = Invoke-SelfTest
    exit ([int]$code)
}

# Invoke-ScheduledScan - headless-сканирование для запуска по расписанию (см. -ScheduledScan): берёт список
#   компьютеров, сохранённый заранее на вкладке "Компьютеры", опрашивает их синхронно (ждёт завершения, в отличие
#   от интерактивного режима, где это делает таймер окна) и сохраняет результат как обычное сканирование.
#   Блокировкой тут и не пахнет - это сознательно: решение заблокировать процесс должен принимать человек, глядя
#   на таблицу, а не скрипт по расписанию. Возвращает код: 0 - сохранено хотя бы с одного компьютера, 1 - нет
#   списка компьютеров, ни один не ответил, или сбой запуска. Пишет только в файл журнала (Write-LogFile) и в
#   консоль - окна нет. Локальные: $names - сохранённый список; $job - фоновое задание сбора (используется и
#   здесь, просто с синхронным ожиданием через Wait-Job, а не таймером окна); $result - его итог
#   (Receive-JobResults); $f - сбой одного компьютера; $scan - созданное сканирование.
function Invoke-ScheduledScan {
    $names = @(Get-ScheduledComputerList)
    if ($names.Count -eq 0) {
        $msg = 'Плановое сканирование: список компьютеров пуст. Сохраните его на вкладке "Компьютеры" (кнопка "Сохранить список для плановых сканирований") и повторите.'
        Write-LogFile -Message $msg
        Write-Host $msg -ForegroundColor Yellow
        return 1
    }
    Write-LogFile -Message "=== Плановое сканирование: старт, компьютеров $($names.Count) ==="
    try {
        $job = Start-Collection -ComputerName $names
    }
    catch {
        Write-LogFile -Message "Плановое сканирование: не удалось запустить сбор - $($_.Exception.Message)"
        return 1
    }
    $null = Wait-Job -Job $job -Timeout 3600      # запас сверх таймаутов Get-RemoteSessionOption на всякий случай
    $result = Receive-JobResults -Job $job
    foreach ($f in $result.Failures) {
        Write-LogFile -Message ("Плановое сканирование: [{0}] нет данных: {1}" -f $f.Computer, $f.Message)
    }
    if ($result.Succeeded -eq 0) {
        Write-LogFile -Message 'Плановое сканирование: ни один компьютер не ответил.'
        return 1
    }
    $scan = New-Scan -Requested $names.Count
    Save-Processes -ScanId $scan.Id -ScanDate $scan.Date -Requested $names.Count -Rows $result.Data.ToArray() `
        -Succeeded $result.Succeeded -Failed $result.Failures.Count
    Write-LogFile -Message ("=== Плановое сканирование завершено: компьютеров {0} из {1}, записей {2} ===" -f $result.Succeeded, $names.Count, $result.Data.Count)
    Invoke-BlockSweep -Rows $result.Data.ToArray()
    return 0
}

# Invoke-BlockSweep - "невод": после КАЖДОГО сканирования (ручного или планового) сверяет свежесобранные строки
#   с активными блокировками (Get-BlockTable) и для каждого совпадения сразу закрывает найденные запущенные
#   экземпляры файла - НЕ дожидаясь и вообще НЕ полагаясь на GPO/SRP (-SkipGpUpdate у Start-BlockApply):
#   gpupdate здесь даже не вызывается. Это сознательный компромисс взамен проблем с групповой политикой на
#   конкретном домене (см. обсуждение про "LocalGPO" в журнале) - ценой окна между запуском заблокированного
#   файла и следующим сканированием (а не мгновенно, как настоящий SRP), зато вообще не зависит от того,
#   работает ли GPO. Принудительное завершение сеанса сюда сознательно не входит (-LogoffSessions $false) - это
#   сильное действие, оставлено только для явного запроса администратора при самой блокировке
#   (Invoke-BlockSelected/-Batch), не для автоматической фоновой проверки без присмотра.
#   -Rows  строки свежесобранного сканирования - ровно то же, что передаётся в Save-Processes (с полями
#   Computer/Name/Path/MD5/SHA1/SHA256 и т. д.) - проверяются только ОНИ, а не вся история, чтобы не закрывать
#   и не уведомлять повторно по старым, уже не актуальным данным.
#   Работает и из обычного UI (Complete-Scan, после обычного сканирования), и из -ScheduledScan (headless,
#   см. выше) - поэтому сама функция объявлена ДО блока "if ($ScheduledScan) {...; exit}" ниже (в headless-режиме
#   скрипт до UI-блока с остальными функциями блокировки вообще не доходит), а внутри проверяет $ScheduledScan,
#   чтобы: в headless-режиме дождаться результата синхронно (Wait-Job) и записать его в файловый журнал
#   (Write-LogFile - доступна всегда), а в обычном UI-режиме не блокировать окно и поставить задание на
#   наблюдение таймером (Register-UiJob/Complete-BlockApply - доступны только в UI-режиме, но к моменту, когда
#   этот код реально выполнится по нажатию кнопки, они уже определены).
#   Локальные: $blocks - активные блокировки; $b - текущая блокировка; $algo/$hash - её алгоритм и хэш;
#   $matches - строки сканирования с таким же хэшем; $map - "компьютер -> пути к файлу"; $notifyText - текст
#   уведомления с именем файла; $label - текст для журнала; $job - фоновое задание закрытия; $result - его итог
#   (только в headless-режиме, см. Receive-JobResults).
function Invoke-BlockSweep {
    param([Parameter(Mandatory)][object[]]$Rows)
    if ($Rows.Count -eq 0) { return }
    $blocks = @((Get-BlockTable).Rows | Where-Object { [int]$_.Active -eq 1 })
    if ($blocks.Count -eq 0) { return }

    foreach ($b in $blocks) {
        $algo = [string]$b.Algorithm
        $hash = [string]$b.Hash
        $matches = @($Rows | Where-Object { [string]$_.$algo -eq $hash })
        if ($matches.Count -eq 0) { continue }

        $map = @{}
        foreach ($m in $matches) {
            $key = ([string]$m.Computer).ToUpper()
            $path = [string]$m.Path
            if (-not $map.ContainsKey($key)) { $map[$key] = @() }
            if ($map[$key] -notcontains $path) { $map[$key] += $path }
        }
        $notifyText = $script:NotifyTemplate -f ([string]$b.Name)
        $label = "'{0}' ({1} {2})" -f $b.Name, $algo, $hash

        try {
            $job = Start-BlockApply -Map $map -TerminateProcesses $true -NotifyText $notifyText -LogoffSessions $false -RestrictOwnerSam '' -SkipGpUpdate $true
        }
        catch {
            $msg = "После сканирования: не удалось запустить закрытие $label - $($_.Exception.Message)"
            if ($ScheduledScan) { Write-LogFile -Message $msg } else { Write-Log $msg }
            continue
        }

        $msg = "После сканирования: заблокированный файл $label обнаружен запущенным на $($map.Count) компьютер(ах) - закрываю..."
        if ($ScheduledScan) {
            Write-LogFile -Message $msg
            $null = Wait-Job -Job $job -Timeout 300
            $result = Receive-JobResults -Job $job
            foreach ($r in $result.Data) {
                Write-LogFile -Message ("[{0}] найдено: {1}; завершено: {2}; уведомлено: {3}" -f $r.Computer, $r.Found, $r.Killed, $r.Notified)
            }
            foreach ($f in $result.Failures) {
                Write-LogFile -Message ("[{0}] не применено: {1}" -f $f.Computer, $f.Message)
            }
        }
        else {
            Write-Log $msg
            Register-UiJob -Job $job -OnDone { param($j) Complete-BlockApply -Job $j }
        }
    }
}

if ($ScheduledScan) {
    try {
        Initialize-Database -Path $DataPath
    }
    catch {
        Write-Host "Не удалось открыть хранилище данных: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
    $code = Invoke-ScheduledScan
    exit ([int]$code)
}

Add-Type -AssemblyName System.Windows.Forms, System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

# ===========================================================================
# ИНТЕРФЕЙС
# ===========================================================================

# Show-Message - показывает окно сообщения с кнопкой OK. -Text текст; -Title заголовок; -Icon значок (Information/Warning/Error).
function Show-Message {
    param(
        [string]$Text,
        [string]$Title = 'Process Monitor',
        [System.Windows.Forms.MessageBoxIcon]$Icon = [System.Windows.Forms.MessageBoxIcon]::Information
    )
    [void][System.Windows.Forms.MessageBox]::Show($Text, $Title, [System.Windows.Forms.MessageBoxButtons]::OK, $Icon)
}

# Confirm-Action - окно "Да / Нет" (по умолчанию выбрано "Нет"). Возвращает $true, только если нажато "Да".
function Confirm-Action {
    param([string]$Text, [string]$Title = 'Подтверждение')
    $answer = [System.Windows.Forms.MessageBox]::Show($Text, $Title,
        [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning,
        [System.Windows.Forms.MessageBoxDefaultButton]::Button2)
    return ($answer -eq [System.Windows.Forms.DialogResult]::Yes)
}

try {
    Initialize-Database -Path $DataPath
}
catch {
    Show-Message -Text "Не удалось открыть хранилище данных:`n$($_.Exception.Message)`n`nГде: $($_.InvocationInfo.PositionMessage)`n$($_.ScriptStackTrace)" -Icon Error
    exit 1
}

# ---------------------------------------------------------------------------
# Элементы интерфейса
# ---------------------------------------------------------------------------

# New-Label - создаёт надпись для панели инструментов. -Text текст. $l - создаваемый элемент.
function New-Label {
    param([string]$Text)
    $l = New-Object System.Windows.Forms.Label
    $l.Text = $Text
    $l.AutoSize = $true
    $l.Margin = New-Object System.Windows.Forms.Padding(8, 8, 2, 0)
    return $l
}

# New-Button - создаёт кнопку. -Text подпись; -Width ширина в пикселях. $b - создаваемый элемент.
function New-Button {
    param([string]$Text, [int]$Width = 150)
    $b = New-Object System.Windows.Forms.Button
    $b.Text = $Text
    $b.Width = $Width
    $b.Height = 27
    $b.Margin = New-Object System.Windows.Forms.Padding(4, 4, 4, 4)
    return $b
}

# New-Toolbar - создаёт панель для кнопок и полей, прижатую к верху вкладки (элементы переносятся на новую строку). $p - панель.
function New-Toolbar {
    $p = New-Object System.Windows.Forms.FlowLayoutPanel
    $p.Dock = 'Top'
    $p.AutoSize = $true
    $p.WrapContents = $true
    return $p
}

# New-Grid - создаёт пустую таблицу только для чтения и добавляет в неё колонку "№".
#   Номер вычисляется при отрисовке (RowIndex + 1), поэтому при сортировке и поиске нумерация всегда 1,2,3...
#   -MultiSelect  разрешить выделять несколько строк (Ctrl/Shift+клик) - нужно для массовой блокировки.
#   Локальные: $g - таблица; $num - колонка "№"; в обработчике CellFormatting $e - данные отрисовываемой ячейки.
function New-Grid {
    param([switch]$MultiSelect)
    $g = New-Object System.Windows.Forms.DataGridView
    $g.Dock = 'Fill'
    $g.ReadOnly = $true
    $g.AllowUserToAddRows = $false
    $g.AllowUserToDeleteRows = $false
    $g.AllowUserToResizeRows = $false
    $g.SelectionMode = 'FullRowSelect'
    $g.MultiSelect = [bool]$MultiSelect
    $g.AutoGenerateColumns = $false
    $g.RowHeadersVisible = $false
    $g.BackgroundColor = [System.Drawing.Color]::White
    $g.ColumnHeadersHeightSizeMode = 'AutoSize'
    # Колонка "№" - вычисляемая: нумерует строки в текущем порядке сортировки и фильтра.
    $num = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
    $num.HeaderText = '№'
    $num.Name = 'Num'
    $num.Width = 55
    $num.SortMode = 'NotSortable'
    [void]$g.Columns.Add($num)
    $g.Add_CellFormatting({
            param($sender, $e)
            if ($e.ColumnIndex -eq 0 -and $e.RowIndex -ge 0) {
                # Именно строка: при FormattingApplied = $true таблица ждёт уже готовый текст, а число даёт FormatException.
                $e.Value = [string]($e.RowIndex + 1)
                $e.FormattingApplied = $true
            }
        })
    # Ошибки отображения данных не должны сыпать окнами "Исключение в DataGridView" - просто пропускаем.
    $g.Add_DataError({
            param($sender, $e)
            $e.ThrowException = $false
        })
    return $g
}

# Add-GridColumn - добавляет в таблицу текстовую колонку.
#   -Grid таблица; -Header заголовок; -Property имя поля данных, которое колонка показывает; -Width ширина;
#   -Fill колонка занимает всё оставшееся место; -Mono моноширинный шрифт (для хэшей). $c - колонка.
function Add-GridColumn {
    param($Grid, [string]$Header, [string]$Property, [int]$Width, [switch]$Fill, [switch]$Mono)
    $c = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
    $c.HeaderText = $Header
    $c.DataPropertyName = $Property
    $c.Name = $Property
    $c.Width = $Width
    if ($Fill) { $c.AutoSizeMode = 'Fill' }
    if ($Mono) { $c.DefaultCellStyle.Font = New-Object System.Drawing.Font('Consolas', 9) }
    [void]$Grid.Columns.Add($c)
}

# ЭЛЕМЕНТЫ ГЛАВНОГО ОКНА
#   $script:Form  - главное окно;
#   $tabs         - контейнер вкладок; $tabComputers / $tabProcesses / $tabBlocks / $tabLog - вкладки
#                   "Компьютеры", "Процессы", "Блокировки", "Журнал".
$script:Form = New-Object System.Windows.Forms.Form
$script:Form.Text = 'Process Monitor - процессы в Active Directory'
$script:Form.Size = New-Object System.Drawing.Size(1180, 720)
$script:Form.MinimumSize = New-Object System.Drawing.Size(900, 500)
$script:Form.StartPosition = 'CenterScreen'

$tabs = New-Object System.Windows.Forms.TabControl
$tabs.Dock = 'Fill'
$tabComputers = New-Object System.Windows.Forms.TabPage -Property @{ Text = 'Компьютеры' }
$tabProcesses = New-Object System.Windows.Forms.TabPage -Property @{ Text = 'Процессы' }
$tabBlocks = New-Object System.Windows.Forms.TabPage -Property @{ Text = 'Блокировки' }
$tabLog = New-Object System.Windows.Forms.TabPage -Property @{ Text = 'Журнал' }
$tabs.TabPages.AddRange(@($tabComputers, $tabProcesses, $tabBlocks, $tabLog))

# --- Строка состояния ------------------------------------------------------
# Строка состояния внизу окна:
#   $status - сама строка; $script:StatusLabel - текст состояния (меняется через Set-Status);
#   $script:Progress - индикатор прогресса сбора (виден только во время сбора).
$status = New-Object System.Windows.Forms.StatusStrip
$script:StatusLabel = New-Object System.Windows.Forms.ToolStripStatusLabel -Property @{ Text = 'Готово'; Spring = $true; TextAlign = 'MiddleLeft' }
$script:Progress = New-Object System.Windows.Forms.ToolStripProgressBar -Property @{ Width = 220; Visible = $false }
[void]$status.Items.Add($script:StatusLabel)
[void]$status.Items.Add($script:Progress)

# --- Журнал ----------------------------------------------------------------
# $script:LogBox - текстовое поле вкладки "Журнал" (только чтение); сюда пишет Write-Log.
$script:LogBox = New-Object System.Windows.Forms.TextBox -Property @{
    Multiline = $true; ReadOnly = $true; ScrollBars = 'Vertical'; Dock = 'Fill'
    Font = (New-Object System.Drawing.Font('Consolas', 9)); BackColor = [System.Drawing.Color]::White
}
$tabLog.Controls.Add($script:LogBox)

# Панель вкладки "Журнал": $logBar - панель; $btnOpenLog - "Открыть файл журнала" (открывает файл в Блокноте).
$logBar = New-Toolbar
$btnOpenLog = New-Button 'Открыть файл журнала' 190
$logBar.Controls.Add($btnOpenLog)
$tabLog.Controls.Add($logBar)

# Write-Log - пишет сообщение сразу в два места: в окно (строка "чч:мм:сс  сообщение") и в файл журнала (Write-LogFile).
#   -Message текст сообщения. $now - момент записи (одинаков для окна и файла).
function Write-Log {
    param([string]$Message)
    $now = Get-Date
    if ($script:LogBox) { $script:LogBox.AppendText(('{0}  {1}{2}' -f $now.ToString('HH:mm:ss'), $Message, [Environment]::NewLine)) }
    Write-LogFile -Message $Message -Time $now
}

# Import-LogHistory - при запуске показывает в окне последние записи из файла журнала (по умолчанию 200 строк),
#   чтобы история не пропадала после перезапуска. -Last сколько последних строк показать. $lines - прочитанные строки.
function Import-LogHistory {
    param([int]$Last = 200)
    if (-not $script:LogFile -or -not (Test-Path -LiteralPath $script:LogFile)) { return }
    try {
        $lines = @(Get-Content -LiteralPath $script:LogFile -Tail $Last -Encoding UTF8)
        if ($lines.Count -gt 0) {
            $script:LogBox.AppendText(('--- предыдущие записи из файла (последние {0}) ---{1}{2}{1}--- текущий запуск ---{1}' -f $lines.Count, [Environment]::NewLine, ($lines -join [Environment]::NewLine)))
        }
    }
    catch {
        # не удалось прочитать историю - не страшно
    }
}

# Set-Status - выводит текст в строке состояния окна. -Text текст.
function Set-Status {
    param([string]$Text)
    $script:StatusLabel.Text = $Text
}

# --- Вкладка "Компьютеры" --------------------------------------------------
# Вкладка "Компьютеры":
#   $compBar - панель инструментов вкладки;
#   $btnLoadAd - "Загрузить из AD"; $btnAll / $btnNone - отметить все / снять отметки;
#   $script:SearchBaseBox - поле DN подразделения (OU) для поиска в AD (пусто - весь домен);
#   $script:ManualBox + $btnAddManual - поле и кнопка ручного добавления компьютера;
#   $btnScan - "Собрать процессы"; $btnStop - "Остановить" сбор (активна только во время сбора);
#   $btnSaveSchedule - сохраняет отмеченные компьютеры как список для плановых сканирований
#   (см. -ScheduledScan в справке скрипта и README - запуск по расписанию без окна);
#   $btnLoadSchedule - добавляет в список и отмечает компьютеры из уже сохранённого расписания (проверить/поправить);
#   $script:CompList - список компьютеров с флажками (имя и ОС); отмеченные будут опрошены.
$compBar = New-Toolbar
$btnLoadAd = New-Button 'Загрузить из AD' 140
$btnAll = New-Button 'Выбрать все' 100
$btnNone = New-Button 'Снять выбор' 100
$script:SearchBaseBox = New-Object System.Windows.Forms.TextBox -Property @{ Width = 300; Margin = (New-Object System.Windows.Forms.Padding(2, 7, 2, 0)) }
$script:ManualBox = New-Object System.Windows.Forms.TextBox -Property @{ Width = 160; Margin = (New-Object System.Windows.Forms.Padding(2, 7, 2, 0)) }
$btnAddManual = New-Button 'Добавить' 80
$btnScan = New-Button 'Собрать процессы' 150
$btnStop = New-Button 'Остановить' 100
$btnStop.Enabled = $false
$btnSaveSchedule = New-Button 'Сохранить список для плановых сканирований' 260
$btnLoadSchedule = New-Button 'Загрузить сохранённый список' 190
$compBar.Controls.AddRange(@($btnLoadAd, (New-Label 'OU (DN, необязательно):'), $script:SearchBaseBox,
        $btnAll, $btnNone, (New-Label 'Добавить вручную:'), $script:ManualBox, $btnAddManual, $btnScan, $btnStop,
        $btnSaveSchedule, $btnLoadSchedule))

$script:CompList = New-Object System.Windows.Forms.ListView
$script:CompList.Dock = 'Fill'
$script:CompList.View = 'Details'
$script:CompList.CheckBoxes = $true
$script:CompList.FullRowSelect = $true
[void]$script:CompList.Columns.Add('Компьютер', 320)
[void]$script:CompList.Columns.Add('Операционная система', 320)

$tabComputers.Controls.Add($script:CompList)
$tabComputers.Controls.Add($compBar)

# --- Вкладка "Процессы" ----------------------------------------------------
# Вкладка "Процессы":
#   $procBar - панель инструментов; $script:ScanCombo - выбор сканирования ("Все сканирования" или конкретное);
#   $script:AlgoCombo - какой хэш показывать и использовать для блокировки (MD5/SHA1/SHA256);
#   $script:FilterBox - поиск по имени, хэшу, компьютеру, пользователю и пути; $btnRefresh - "Обновить" (перечитать данные);
#   $btnBlock - "Заблокировать по хэшу..." (выделено несколько строк Ctrl/Shift+клик - массовая блокировка,
#   Invoke-BlockSelectedBatch; одна - как раньше, Invoke-BlockSelected); $script:ProcGrid - таблица процессов
#   (№, время запуска процесса, Имя, Хэш, Компьютер, Пользователь, Путь), поддерживает выделение нескольких строк.
$procBar = New-Toolbar
$script:ScanCombo = New-Object System.Windows.Forms.ComboBox -Property @{ Width = 260; DropDownStyle = 'DropDownList'; Margin = (New-Object System.Windows.Forms.Padding(2, 5, 2, 0)) }
$script:AlgoCombo = New-Object System.Windows.Forms.ComboBox -Property @{ Width = 80; DropDownStyle = 'DropDownList'; Margin = (New-Object System.Windows.Forms.Padding(2, 5, 2, 0)) }
[void]$script:AlgoCombo.Items.AddRange(@('MD5', 'SHA1', 'SHA256'))
$script:AlgoCombo.SelectedIndex = 0
$script:FilterBox = New-Object System.Windows.Forms.TextBox -Property @{ Width = 200; Margin = (New-Object System.Windows.Forms.Padding(2, 7, 2, 0)) }
$btnRefresh = New-Button 'Обновить' 90
$btnBlock = New-Button 'Заблокировать по хэшу...' 190
$procBar.Controls.AddRange(@((New-Label 'Сканирование:'), $script:ScanCombo, (New-Label 'Хэш:'), $script:AlgoCombo,
        (New-Label 'Поиск:'), $script:FilterBox, $btnRefresh, $btnBlock))

$script:ProcGrid = New-Grid -MultiSelect
Add-GridColumn $script:ProcGrid 'Запуск процесса' 'StartTime' 150
Add-GridColumn $script:ProcGrid 'Имя' 'Name' 180
Add-GridColumn $script:ProcGrid 'Хэш' 'Hash' 330 -Mono
Add-GridColumn $script:ProcGrid 'Компьютер' 'Computer' 130
Add-GridColumn $script:ProcGrid 'Пользователь' 'User' 170
Add-GridColumn $script:ProcGrid 'Путь' 'Path' 300 -Fill

$tabProcesses.Controls.Add($script:ProcGrid)
$tabProcesses.Controls.Add($procBar)

# --- Вкладка "Блокировки" --------------------------------------------------
# Вкладка "Блокировки":
#   $blockBar - панель инструментов; $script:GpoBox - имя GPO, в которую добавляются правила (для блокировки
#   "по пользователю/группе" - базовое имя, к нему автоматически добавляется суффикс с принципалом, см.
#   Resolve-BlockTarget - у каждого пользователя/группы своя отдельная GPO);
#   $script:LinkCombo - DN контейнера, к которому привязать GPO (необязательно); редактируемый выпадающий
#   список: можно вставить/набрать DN вручную, а можно выбрать OU из списка, который загружает $btnLoadOUs
#   (см. Import-AdOUs) - пункты показываются как "Имя OU — DN", а при блокировке используется только DN
#   (после последнего " — " в тексте поля; если разделителя нет - весь текст считается DN, как раньше).
#   $script:ScopeCombo - "Все пользователи компьютера" (обычная блокировка, как раньше) или "Пользователь/группа
#   AD" - тогда правило SRP пишется в User Configuration той же GPO, а Security Filtering GPO ограничивается
#   принципалом из $script:PrincipalCombo (см. Set-GpoUserFiltering), так что оно реально действует только на
#   него/неё, а не на всех, кого достаёт привязка. $script:PrincipalCombo - sAMAccountName пользователя/группы;
#   редактируемый выпадающий список, как $script:LinkCombo, заполняется $btnLoadPrincipals (Import-AdPrincipals)
#   пунктами "sam — имя [пользователь/группа]"; включается/выключается при смене $script:ScopeCombo.
#   На известных компьютерах (где файл встречался в последнем сканировании) блокировка автоматически: обновляет
#   политики (gpupdate), завершает уже запущенные экземпляры файла и показывает каждому затронутому пользователю
#   уведомление $script:NotifyTemplate (имя файла подставляется вместо {0}) - всё без отдельных флажков. Для
#   блокировки по конкретному пользователю это закрытие тоже ограничено им (владелец процесса сверяется -
#   см. $script:ApplyBlockScript); для группы - нет, см. предупреждение в Invoke-BlockSelected.
#   $btnUnblock - "Снять блокировку"; $btnCheckEvents - "Проверить срабатывания" (ищет в журнале событий Windows
#   попытки запуска заблокированного файла после даты блокировки - см. Invoke-CheckBlockEvents, там же оговорка
#   про недоказанность кодов событий); $script:BlockGrid - таблица всех блокировок.
$blockBar = New-Toolbar
$script:GpoBox = New-Object System.Windows.Forms.TextBox -Property @{ Width = 260; Text = 'Process Hash Block (SRP)'; Margin = (New-Object System.Windows.Forms.Padding(2, 7, 2, 0)) }
$script:LinkCombo = New-Object System.Windows.Forms.ComboBox -Property @{ Width = 340; DropDownStyle = 'DropDown'; Margin = (New-Object System.Windows.Forms.Padding(2, 5, 2, 0)) }
$btnLoadOUs = New-Button 'Загрузить OU из AD' 160
$script:ScopeCombo = New-Object System.Windows.Forms.ComboBox -Property @{ Width = 200; DropDownStyle = 'DropDownList'; Margin = (New-Object System.Windows.Forms.Padding(2, 5, 2, 0)) }
[void]$script:ScopeCombo.Items.AddRange(@('Все пользователи компьютера', 'Пользователь/группа AD'))
$script:ScopeCombo.SelectedIndex = 0
$script:PrincipalCombo = New-Object System.Windows.Forms.ComboBox -Property @{ Width = 300; DropDownStyle = 'DropDown'; Margin = (New-Object System.Windows.Forms.Padding(2, 5, 2, 0)); Enabled = $false }
$btnLoadPrincipals = New-Button 'Загрузить пользователей/группы из AD' 230
$btnLoadPrincipals.Enabled = $false
$btnUnblock = New-Button 'Снять блокировку' 140
$btnCheckEvents = New-Button 'Проверить срабатывания' 190
$blockBar.Controls.AddRange(@((New-Label 'GPO:'), $script:GpoBox, (New-Label 'Привязать к (DN, можно выбрать из списка):'), $script:LinkCombo,
        $btnLoadOUs, (New-Label 'Область:'), $script:ScopeCombo, (New-Label 'Пользователь/группа:'), $script:PrincipalCombo,
        $btnLoadPrincipals, $btnUnblock, $btnCheckEvents))
$script:ScopeCombo.Add_SelectedIndexChanged({
        $isUser = [string]$script:ScopeCombo.SelectedItem -eq 'Пользователь/группа AD'
        $script:PrincipalCombo.Enabled = $isUser
        $btnLoadPrincipals.Enabled = $isUser
    })

$script:BlockGrid = New-Grid
Add-GridColumn $script:BlockGrid 'Дата' 'BlockDate' 140
Add-GridColumn $script:BlockGrid 'Имя' 'Name' 160
Add-GridColumn $script:BlockGrid 'Алгоритм' 'Algorithm' 70
Add-GridColumn $script:BlockGrid 'Хэш' 'Hash' 330 -Mono
Add-GridColumn $script:BlockGrid 'Применяется к' 'Target' 160
Add-GridColumn $script:BlockGrid 'Срабатываний' 'Occurrences' 100
Add-GridColumn $script:BlockGrid 'Последнее срабатывание' 'LastEventTime' 150
Add-GridColumn $script:BlockGrid 'Статус' 'Status' 80
Add-GridColumn $script:BlockGrid 'GPO' 'GpoName' 200 -Fill

$tabBlocks.Controls.Add($script:BlockGrid)
$tabBlocks.Controls.Add($blockBar)

$script:Form.Controls.Add($tabs)
$script:Form.Controls.Add($status)

# ---------------------------------------------------------------------------
# Фоновые задания: таймер опрашивает Invoke-Command -AsJob, не блокируя окно
# ---------------------------------------------------------------------------

# $script:PendingJobs - фоновые задания, за которыми следит таймер; элемент: { Job, OnProgress, OnDone }.
# $script:ScanJob     - текущее задание сбора процессов (или $null, если сбор не идёт); нужно кнопке "Остановить".
$script:PendingJobs = New-Object System.Collections.ArrayList
$script:ScanJob = $null

# Register-UiJob - ставит фоновое задание на наблюдение таймера.
#   -Job задание; -OnProgress блок, вызываемый, пока задание выполняется (обновить прогресс);
#   -OnDone блок, вызываемый один раз по завершении (получить и обработать результат).
function Register-UiJob {
    param($Job, [scriptblock]$OnProgress, [scriptblock]$OnDone)
    [void]$script:PendingJobs.Add(@{ Job = $Job; OnProgress = $OnProgress; OnDone = $OnDone })
}

# $script:Timer - таймер окна (раз в 0,7 с): проверяет $script:PendingJobs, обновляет прогресс и обрабатывает
#   завершённые задания. Так окно остаётся живым, пока идёт опрос. $item - наблюдаемое задание.
$script:Timer = New-Object System.Windows.Forms.Timer
$script:Timer.Interval = 700
$script:Timer.Add_Tick({
        foreach ($item in @($script:PendingJobs)) {
            if ($item.Job.State -in 'Running', 'NotStarted') {
                # Сбой в обновлении прогресса не должен прерывать сам сбор: пишем в журнал один раз и продолжаем ждать.
                if ($item.OnProgress) {
                    try { & $item.OnProgress $item.Job }
                    catch {
                        if (-not $item.ProgressFailed) {
                            $item.ProgressFailed = $true
                            Write-Log ("Ошибка обновления прогресса: {0}`n{1}`n{2}" -f $_.Exception.Message, $_.InvocationInfo.PositionMessage, $_.ScriptStackTrace)
                        }
                    }
                }
                continue
            }
            [void]$script:PendingJobs.Remove($item)
            try { & $item.OnDone $item.Job }
            catch {
                Write-Log ("Ошибка обработки задания: {0}`n{1}`n{2}" -f $_.Exception.Message, $_.InvocationInfo.PositionMessage, $_.ScriptStackTrace)
            }
        }
    })
$script:Timer.Start()

# Set-ScanBusy - переключает интерфейс между "идёт сбор" и "свободно": блокирует кнопки запуска и загрузки
#   из AD, включает "Остановить", показывает/прячет индикатор. -Busy $true - сбор идёт.
function Set-ScanBusy {
    param([bool]$Busy)
    $btnScan.Enabled = -not $Busy
    $btnLoadAd.Enabled = -not $Busy
    $btnStop.Enabled = $Busy
    $script:Progress.Visible = $Busy
    if (-not $Busy) { $script:Progress.Value = 0 }
}

# ---------------------------------------------------------------------------
# Компьютеры
# ---------------------------------------------------------------------------

# Add-ComputerItem - добавляет компьютер в список (повторы по имени игнорируются).
#   -HostName имя; -OS описание ОС; -Checked отмечен ли флажок (по умолчанию да). $item - строка списка.
function Add-ComputerItem {
    param([string]$HostName, [string]$OS, [bool]$Checked = $true)
    foreach ($existing in $script:CompList.Items) {
        if ($existing.Text -ieq $HostName) { return }
    }
    $item = New-Object System.Windows.Forms.ListViewItem($HostName)
    [void]$item.SubItems.Add($OS)
    $item.Checked = $Checked
    [void]$script:CompList.Items.Add($item)
}

# Import-AdComputers - обработчик "Загрузить из AD": запрашивает компьютеры (Get-AdComputers) и заполняет
#   список. $computers - полученные записи (по DNS-имени); $c - текущая запись.
function Import-AdComputers {
    $script:Form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    try {
        Set-Status 'Запрос списка компьютеров из AD...'
        $computers = @(Get-AdComputers -SearchBase $script:SearchBaseBox.Text.Trim() | Sort-Object Host)
        $script:CompList.BeginUpdate()
        try {
            foreach ($c in $computers) { Add-ComputerItem -HostName $c.Host -OS $c.OS }
        }
        finally {
            $script:CompList.EndUpdate()
        }
        Write-Log "Из AD получено компьютеров: $($computers.Count)"
        Set-Status "Из AD получено компьютеров: $($computers.Count)"
    }
    catch {
        Write-Log "Ошибка запроса к AD: $($_.Exception.Message)"
        Show-Message -Text "Не удалось получить список из AD:`n$($_.Exception.Message)" -Icon Error
        Set-Status 'Ошибка запроса к AD'
    }
    finally {
        $script:Form.Cursor = [System.Windows.Forms.Cursors]::Default
    }
}

# Import-AdOUs - обработчик "Загрузить OU из AD": заполняет $script:LinkCombo списком "Имя — DN"
#   (первый пункт - "(весь домен) — <DN домена>"), сохраняя уже введённый пользователем текст поля.
#   $kept - текст поля до обновления (чтобы не сбрасывать то, что уже набрано/выбрано); $ous - полученные OU.
function Import-AdOUs {
    $script:Form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    try {
        Set-Status 'Запрос списка подразделений (OU) из AD...'
        $kept = $script:LinkCombo.Text
        $ous = @(Get-AdOrganizationalUnits)
        $script:LinkCombo.Items.Clear()
        foreach ($ou in $ous) { [void]$script:LinkCombo.Items.Add(('{0} — {1}' -f $ou.Name, $ou.Dn)) }      # внешние скобки обязательны: внутри .Add(...) запятая разделяет аргументы метода, а не части -f
        $script:LinkCombo.Text = $kept
        Write-Log "Из AD получено подразделений (OU): $($ous.Count - 1)"
        Set-Status "Из AD получено подразделений (OU): $($ous.Count - 1)"
    }
    catch {
        Write-Log "Ошибка запроса OU из AD: $($_.Exception.Message)"
        Show-Message -Text "Не удалось получить список OU из AD:`n$($_.Exception.Message)" -Icon Error
        Set-Status 'Ошибка запроса OU из AD'
    }
    finally {
        $script:Form.Cursor = [System.Windows.Forms.Cursors]::Default
    }
}

# ConvertTo-LinkTargetDn - достаёт DN из текста поля "Привязать к". Если выбран пункт списка (есть " — "),
#   возвращает часть после ПОСЛЕДНЕГО " — " (имя OU не экранируется и теоретически может содержать такую же
#   подстроку, поэтому берём последнее вхождение - сам DN её в норме не содержит). Иначе считает весь текст
#   DN, набранным или вставленным вручную, как было до появления списка. -Text содержимое поля.
function ConvertTo-LinkTargetDn {
    param([string]$Text)
    $Text = $Text.Trim()
    $sep = $Text.LastIndexOf(' — ')
    if ($sep -ge 0) { return $Text.Substring($sep + 3).Trim() }
    return $Text
}

# Import-AdPrincipals - обработчик "Загрузить пользователей/группы из AD": заполняет $script:PrincipalCombo
#   списком "sam — отображаемое имя [пользователь|группа]", сохраняя уже введённый пользователем текст поля.
#   $kept - текст поля до обновления; $items - полученные пользователи и группы (см. Get-AdUsersAndGroups).
function Import-AdPrincipals {
    $script:Form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    try {
        Set-Status 'Запрос пользователей и групп из AD...'
        $kept = $script:PrincipalCombo.Text
        $items = @(Get-AdUsersAndGroups)
        $script:PrincipalCombo.Items.Clear()
        foreach ($p in $items) {
            $typeLabel = if ($p.Type -eq 'Group') { 'группа' } else { 'пользователь' }
            [void]$script:PrincipalCombo.Items.Add(('{0} — {1} [{2}]' -f $p.Sam, $p.Display, $typeLabel))
        }
        $script:PrincipalCombo.Text = $kept
        Write-Log "Из AD получено пользователей и групп: $($items.Count)"
        Set-Status "Из AD получено пользователей и групп: $($items.Count)"
    }
    catch {
        Write-Log "Ошибка запроса пользователей/групп из AD: $($_.Exception.Message)"
        Show-Message -Text "Не удалось получить список пользователей и групп из AD:`n$($_.Exception.Message)" -Icon Error
        Set-Status 'Ошибка запроса пользователей/групп из AD'
    }
    finally {
        $script:Form.Cursor = [System.Windows.Forms.Cursors]::Default
    }
}

# ConvertTo-PrincipalInfo - разбирает текст поля "Пользователь/группа" на sAMAccountName и тип.
#   Если текст выбран из списка (формат "sam — имя [пользователь]" или "... [группа]", см. Import-AdPrincipals) -
#   оба значения известны сразу, без обращения к AD. Если текст набран вручную (просто sam, без " — " и
#   "[...]") - Type возвращается $null, и вызывающий код должен сам определить тип (Resolve-AdPrincipalType)
#   перед тем, как писать правило в GPO. -Text содержимое поля.
function ConvertTo-PrincipalInfo {
    param([string]$Text)
    $Text = $Text.Trim()
    $type = $null
    if ($Text -match '\[(пользователь|группа)\]\s*$') {
        $type = if ($matches[1] -eq 'группа') { 'Group' } else { 'User' }
        $Text = $Text.Substring(0, $Text.Length - $matches[0].Length).TrimEnd()
    }
    $sep = $Text.IndexOf(' — ')
    $sam = if ($sep -ge 0) { $Text.Substring(0, $sep).Trim() } else { $Text }
    [pscustomobject]@{ Sam = $sam; Type = $type }
}

# ---------------------------------------------------------------------------
# Сбор процессов
# ---------------------------------------------------------------------------

# Start-Scan - обработчик "Собрать процессы": берёт отмеченные компьютеры, запускает сбор в фоне и
#   регистрирует наблюдение за ним. Локальные: $names - имена отмеченных компьютеров; $p - прогресс
#   (Done/Total) внутри блока OnProgress; $job - задание.
function Start-Scan {
    $names = @($script:CompList.CheckedItems | ForEach-Object { $_.Text })
    if ($names.Count -eq 0) {
        Show-Message -Text 'Отметьте компьютеры на вкладке "Компьютеры" (или загрузите их из AD).' -Icon Warning
        return
    }
    Set-ScanBusy $true
    $script:Progress.Maximum = $names.Count
    $script:Progress.Value = 0
    Write-Log "Старт сбора: компьютеров $($names.Count)"
    Set-Status "Опрос компьютеров: 0 из $($names.Count)"
    try {
        $script:ScanJob = Start-Collection -ComputerName $names
    }
    catch {
        Set-ScanBusy $false
        Write-Log "Не удалось запустить сбор: $($_.Exception.Message)"
        Show-Message -Text $_.Exception.Message -Icon Error
        return
    }
    Register-UiJob -Job $script:ScanJob -OnProgress {
        param($job)
        $p = Get-JobProgress -Job $job
        if ($p.Total -gt 0) {
            $script:Progress.Maximum = $p.Total
            $script:Progress.Value = [Math]::Min($p.Done, $p.Total)
            Set-Status "Опрос компьютеров: $($p.Done) из $($p.Total)"
        }
    } -OnDone {
        param($job)
        Complete-Scan -Job $job
    }
}

# Complete-Scan - вызывается, когда сбор завершён: показывает ошибки в журнале, сохраняет данные в хранилище
#   как новое сканирование и открывает его на вкладке "Процессы".
#   -Job завершённое задание. Локальные: $requested - сколько компьютеров опрашивали; $result - итог
#   (см. Receive-JobResults); $f - сбой одного компьютера; $scan - созданное сканирование (Id, Date).
function Complete-Scan {
    param($Job)
    $requested = @($Job.ChildJobs).Count
    $result = Receive-JobResults -Job $Job
    $script:ScanJob = $null
    Set-ScanBusy $false

    foreach ($f in $result.Failures) {
        Write-Log ("[{0}] нет данных: {1}" -f $f.Computer, $f.Message)
    }
    if ($result.Succeeded -eq 0) {
        Write-Log 'Сбор завершён: ни один компьютер не ответил.'
        Set-Status 'Сбор завершён: ни один компьютер не ответил (см. журнал)'
        return
    }

    $scan = New-Scan -Requested $requested
    Save-Processes -ScanId $scan.Id -ScanDate $scan.Date -Requested $requested -Rows $result.Data.ToArray() `
        -Succeeded $result.Succeeded -Failed $result.Failures.Count
    Write-Log ("Сбор завершён: компьютеров {0} из {1}, записей {2}" -f $result.Succeeded, $requested, $result.Data.Count)
    Set-Status ("Сбор завершён: компьютеров {0} из {1}, записей {2}" -f $result.Succeeded, $requested, $result.Data.Count)
    Invoke-BlockSweep -Rows $result.Data.ToArray()

    Update-ScanList -SelectScanId $scan.Id
    $tabs.SelectedTab = $tabProcesses
}

# ---------------------------------------------------------------------------
# Таблица процессов
# ---------------------------------------------------------------------------

# $script:Loading  - $true, пока заполняется выпадающий список сканирований; на это время таблица не перерисовывается.
# $script:ProcView - текущее представление таблицы процессов (DataView): через него работают сортировка и поиск.
$script:Loading = $false
$script:ProcView = $null

# Update-ScanList - перечитывает список сканирований в выпадающий список ("Все сканирования" + каждое
#   сканирование) и обновляет таблицу. -SelectScanId  какое сканирование выбрать (0 - последнее).
#   $table - таблица для списка; $row - строка сканирования из хранилища.
function Update-ScanList {
    param([int]$SelectScanId = 0)
    $script:Loading = $true
    try {
        $table = New-Object System.Data.DataTable
        [void]$table.Columns.Add('Id', [int])
        [void]$table.Columns.Add('Title', [string])
        [void]$table.Rows.Add(0, 'Все сканирования')
        foreach ($row in (Get-Scans).Rows) {
            [void]$table.Rows.Add([int]$row.Id, [string]$row.Title)
        }
        $script:ScanCombo.DisplayMember = 'Title'
        $script:ScanCombo.ValueMember = 'Id'
        $script:ScanCombo.DataSource = $table
        if ($SelectScanId -gt 0) {
            $script:ScanCombo.SelectedValue = $SelectScanId
        }
        elseif ($table.Rows.Count -gt 1) {
            $script:ScanCombo.SelectedIndex = 1     # последнее сканирование
        }
    }
    finally {
        $script:Loading = $false
    }
    Update-ProcessGrid
}

# Update-ProcessGrid - загружает процессы выбранного сканирования с выбранным алгоритмом хэша в таблицу и применяет поиск.
#   $scanId - номер выбранного сканирования (0 - все); $algorithm - MD5/SHA1/SHA256; $table - данные из хранилища.
function Update-ProcessGrid {
    if ($script:Loading) { return }
    $scanId = 0
    if ($null -ne $script:ScanCombo.SelectedValue) { $scanId = [int]$script:ScanCombo.SelectedValue }
    $algorithm = [string]$script:AlgoCombo.SelectedItem
    $table = Get-ProcessTable -ScanId $scanId -Algorithm $algorithm
    $script:ProcView = $table.DefaultView
    $script:ProcGrid.DataSource = $script:ProcView
    Update-ProcessFilter
}

# ConvertTo-RowFilterLike - экранирует текст поиска для фильтра таблицы (DataView.RowFilter):
#   спецсимволы [ ] * % оборачиваются в квадратные скобки, апостроф удваивается.
#   -Text текст из поля поиска. $sb - собираемая строка; $ch - текущий символ.
function ConvertTo-RowFilterLike {
    param([string]$Text)
    # Спецсимволы LIKE в DataView.RowFilter экранируются квадратными скобками, апостроф удваивается.
    $sb = New-Object System.Text.StringBuilder
    foreach ($ch in $Text.ToCharArray()) {
        switch ($ch) {
            '[' { [void]$sb.Append('[[]') }
            ']' { [void]$sb.Append('[]]') }
            '*' { [void]$sb.Append('[*]') }
            '%' { [void]$sb.Append('[%]') }
            "'" { [void]$sb.Append("''") }
            default { [void]$sb.Append($ch) }
        }
    }
    return $sb.ToString()
}

# Update-ProcessFilter - применяет текст из поля "Поиск" к таблице (по имени, хэшу, компьютеру и пути)
#   и показывает число найденных записей. $text - введённый текст; $like - его экранированный вариант.
function Update-ProcessFilter {
    if (-not $script:ProcView) { return }
    $text = $script:FilterBox.Text.Trim()
    if ($text) {
        $like = ConvertTo-RowFilterLike -Text $text
        $script:ProcView.RowFilter = "Name LIKE '%$like%' OR Hash LIKE '%$like%' OR Computer LIKE '%$like%' OR User LIKE '%$like%' OR Path LIKE '%$like%'"
    }
    else {
        $script:ProcView.RowFilter = ''
    }
    Set-Status ("Записей: {0}" -f $script:ProcView.Count)
}

# ---------------------------------------------------------------------------
# Блокировка
# ---------------------------------------------------------------------------

# Update-BlockGrid - перечитывает журнал блокировок и показывает его на вкладке "Блокировки".
function Update-BlockGrid {
    $script:BlockGrid.DataSource = (Get-BlockTable).DefaultView
}

# Resolve-BlockTarget - читает элементы управления "Область" ($script:ScopeCombo) и "Пользователь/группа"
#   ($script:PrincipalCombo) и возвращает, для кого ставится блокировка: вся машина (по умолчанию) или
#   конкретный пользователь/группа AD. Используется и в Invoke-BlockSelected, и в Invoke-BlockSelectedBatch -
#   поля на вкладке "Блокировки" общие для всего приложения, как GPO и привязка.
#   -BaseGpoName  имя GPO из поля "GPO" (для компьютерной блокировки используется как есть; для блокировки
#   по пользователю/группе к нему добавляется суффикс с именем принципала - у каждого пользователя/группы
#   своя отдельная GPO, см. Set-GpoUserFiltering, иначе Security Filtering одной GPO ограничивала бы
#   действие сразу всех её правил одним и тем же набором людей).
#   Возвращает { Scope = 'Computer'/'User'; PrincipalSam; PrincipalType; Target (текст для журнала/таблицы);
#   GpoName (реальное имя GPO для Add-SrpHashBlock/Get-GpoLinkSummary) } или $null, если выбран режим
#   "Пользователь/группа", но поле не заполнено или тип принципала не определён - в этом случае сообщение
#   уже показано (Show-Message), вызывающий код должен просто остановиться (return).
#   Локальные: $scopeSelected - выбранный пункт $script:ScopeCombo; $text - текст поля принципала;
#   $info - разбор текста (ConvertTo-PrincipalInfo); $type - его тип (из текста или Resolve-AdPrincipalType);
#   $typeLabel - "Пользователь"/"Группа" для отображения.
function Resolve-BlockTarget {
    param([Parameter(Mandatory)][string]$BaseGpoName)

    $scopeSelected = [string]$script:ScopeCombo.SelectedItem
    if ($scopeSelected -ne 'Пользователь/группа AD') {
        return [pscustomobject]@{
            Scope = 'Computer'; PrincipalSam = ''; PrincipalType = $null
            Target = 'Все пользователи компьютера'; GpoName = $BaseGpoName
        }
    }

    $text = $script:PrincipalCombo.Text.Trim()
    if (-not $text) {
        Show-Message -Icon Warning -Text ('Укажите пользователя или группу в поле "Пользователь/группа", или ' +
            'выберите в поле "Область" пункт "Все пользователи компьютера".')
        return $null
    }
    $info = ConvertTo-PrincipalInfo -Text $text
    $type = $info.Type
    if (-not $type) { $type = Resolve-AdPrincipalType -Sam $info.Sam }
    if (-not $type) {
        Show-Message -Icon Error -Text (
            "Не удалось определить, пользователь это или группа: `"$($info.Sam)`".`n`n" +
            'Нажмите "Загрузить пользователей/группы из AD" и выберите нужную запись из списка, либо проверьте правильность имени.'
        )
        return $null
    }
    $typeLabel = if ($type -eq 'Group') { 'Группа' } else { 'Пользователь' }
    [pscustomobject]@{
        Scope         = 'User'
        PrincipalSam  = $info.Sam
        PrincipalType = $type
        Target        = "${typeLabel}: $($info.Sam)"
        GpoName       = "$BaseGpoName - ${typeLabel}: $($info.Sam)"
    }
}

# Invoke-BlockSelected - обработчик "Заблокировать по хэшу...". Порядок действий:
#   1) проверки (выбрана строка, указана GPO, хэш корректен, файл не в Windows\, есть модуль GroupPolicy,
#      блокировка ещё не действует); 1а) если у GPO нет ни одной включённой привязки (Link) и поле "Привязать
#      к" пустое - отдельное предупреждение ДО основного подтверждения: без привязки правило не подействует
#      нигде, как бы часто ни выполнялся gpupdate; 2) окно подтверждения; 3) правило добавляется в GPO и в
#      журнал (с тем же предупреждением, если оно относится к этому разу); 4) на всех компьютерах, где файл
#      встречался в последнем сканировании, АВТОМАТИЧЕСКИ, без отдельных флажков: обновляются политики (gpupdate
#      - правило SRP действует немедленно, а не после планового обновления, по умолчанию до 90 минут),
#      завершаются уже запущенные экземпляры файла, а их пользователям показывается уведомление ($script:NotifyTemplate).
#   Локальные: $row - выбранная строка таблицы; $algorithm / $hash / $name / $path / $size - данные файла;
#   $gpo - имя GPO; $linkTarget - DN для привязки; $linkSummary - текущие привязки GPO (Get-GpoLinkSummary,
#   может быть $null, если проверить не удалось); $hasEnabledLink - есть ли у GPO хоть одна включённая
#   привязка сейчас; $willBeUnlinked - после этого раза привязки по-прежнему не будет; $locations - где хэш
#   найден; $computerCount - на скольких компьютерах; $notifyText - готовый текст уведомления (имя файла
#   подставлено); $message - текст подтверждения; $ruleId - GUID созданного правила; $map - "компьютер -> пути"
#   для применения; $loc, $key - элемент и ключ при его построении; $logoffSessions - ответ администратора на
#   отдельный вопрос про принудительное завершение сеанса (спрашивается только когда есть что завершать);
#   $job - фоновое задание применения.
function Invoke-BlockSelected {
    if (-not $script:ProcGrid.CurrentRow -or -not $script:ProcGrid.CurrentRow.DataBoundItem) {
        Show-Message -Text 'Выберите строку с процессом в таблице.' -Icon Warning
        return
    }
    $row = $script:ProcGrid.CurrentRow.DataBoundItem.Row
    $algorithm = [string]$script:AlgoCombo.SelectedItem
    $hash = [string]$row['Hash']
    $name = [string]$row['Name']
    $path = [string]$row['Path']
    $size = 0L
    if ($row['Size'] -isnot [DBNull]) { $size = [long]$row['Size'] }
    $gpoBase = $script:GpoBox.Text.Trim()
    $linkTarget = ConvertTo-LinkTargetDn -Text $script:LinkCombo.Text

    if (-not $gpoBase) {
        Show-Message -Text 'Укажите имя GPO на вкладке "Блокировки".' -Icon Warning
        return
    }
    if (-not (Test-HashValue -Algorithm $algorithm -Hash $hash)) {
        Show-Message -Text "У выбранной записи нет корректного $algorithm-хэша." -Icon Warning
        return
    }
    if (Test-ProtectedPath -Path $path) {
        Show-Message -Icon Error -Text ("Файл находится в каталоге Windows:`n{0}`n`nБлокировка системных файлов по хэшу может вывести из строя все компьютеры домена, поэтому она запрещена." -f $path)
        return
    }
    if (-not (Test-GroupPolicyModule)) {
        Show-Message -Icon Error -Text 'Не найден модуль GroupPolicy. Установите на этом компьютере компонент "Group Policy Management" (RSAT).'
        return
    }
    if (Get-ActiveBlock -Algorithm $algorithm -Hash $hash) {
        Show-Message -Text 'Для этого хэша блокировка уже активна (см. вкладку "Блокировки").'
        return
    }
    $target = Resolve-BlockTarget -BaseGpoName $gpoBase
    if (-not $target) { return }
    $gpo = $target.GpoName

    # Привязка (Link) GPO к OU/домену - то, от чего реально зависит, подействует ли правило: без привязки
    # gpupdate на клиенте даже не возьмёт эту GPO в обработку, сколько бы хэшей в ней ни было добавлено.
    # $linkSummary = $null значит "не удалось проверить" (например, GPO ещё не существует - тогда будет
    # создана без привязки, если не задано -LinkTarget); $willBeUnlinked - после этого вызова привязки не будет.
    $linkSummary = Get-GpoLinkSummary -GpoName $gpo
    $hasEnabledLink = $linkSummary -and $linkSummary.Enabled -gt 0
    $willBeUnlinked = -not $hasEnabledLink -and -not $linkTarget
    if ($willBeUnlinked) {
        Show-Message -Title 'GPO не привязана' -Icon Warning -Text (
            "ВНИМАНИЕ: у GPO `"$gpo`" сейчас нет ни одной включённой привязки (Link) к OU или домену, и поле " +
            "`"Привязать к`" не заполнено.`n`n" +
            "Без привязки правило SRP НЕ ПОДЕЙСТВУЕТ ни на одном компьютере, сколько бы раз ни выполнялся gpupdate - " +
            "клиент просто не станет обрабатывать эту GPO.`n`n" +
            "Чтобы правило заработало: либо укажите DN нужного OU/домена в поле `"Привязать к`" на этой вкладке и " +
            "заблокируйте ещё раз, либо привяжите GPO вручную в GPMC (ПКМ по OU -> Link an Existing GPO)."
        )
    }

    $locations = Get-HashLocations -Algorithm $algorithm -Hash $hash
    $computerCount = @($locations.Rows | ForEach-Object { $_.Computer } | Select-Object -Unique).Count
    $notifyText = $script:NotifyTemplate -f $name
    $message = "Заблокировать запуск файла по хэшу?`n`nИмя: $name`n${algorithm}: $hash`nРазмер: $size байт`nПример пути: $path`nНайден на компьютерах (последнее сканирование): $computerCount`n`nПрименяется к: $($target.Target)`nGPO: $gpo"
    if ($linkTarget) { $message += "`nПривязка: $linkTarget" }
    else { $message += "`nGPO будет создана/изменена; убедитесь, что она привязана к нужному OU." }
    if ($computerCount -gt 0) {
        $message += "`n`nНа этих компьютерах сразу после добавления правила: обновятся политики (gpupdate), будут" +
            " закрыты уже запущенные экземпляры файла, а их пользователям будет показано сообщение:`n`"$notifyText`""
        if ($target.Scope -eq 'User' -and $target.PrincipalType -eq 'Group') {
            $message += "`n`nЗакрытие коснётся ВСЕХ, кто сейчас запустил этот файл, а не только членов группы " +
                "`"$($target.PrincipalSam)`" - проверить членство в группе при немедленном завершении приложение не " +
                "умеет. Сама блокировка новых запусков при этом действует правильно - только на членов группы."
        }
    }
    if (-not (Confirm-Action -Text $message -Title 'Блокировка по хэшу')) { return }

    $script:Form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    try {
        $ruleId = Add-SrpHashBlock -GpoName $gpo -Name $name -Algorithm $algorithm -Hash $hash -Size $size -LinkTarget $linkTarget `
            -Scope $target.Scope -PrincipalSam $target.PrincipalSam -PrincipalType $target.PrincipalType
        Add-BlockRecord -Name $name -Algorithm $algorithm -Hash $hash -Size $size -GpoName $gpo -RuleId $ruleId -Scope $target.Scope -Target $target.Target
        Write-Log "Блокировка добавлена: $name ($algorithm $hash), применяется к: $($target.Target), GPO '$gpo', правило $ruleId"
        if ($willBeUnlinked) {
            Write-Log "ВНИМАНИЕ: GPO '$gpo' не привязана ни к одному OU/домену - блокировка НЕ действует, пока вы её не привяжете (поле `"Привязать к`" или вручную в GPMC)."
        }
        Update-BlockGrid
    }
    catch {
        Write-Log "Ошибка блокировки: $($_.Exception.Message)"
        Show-Message -Text "Не удалось добавить правило в GPO:`n$($_.Exception.Message)" -Icon Error
        return
    }
    finally {
        $script:Form.Cursor = [System.Windows.Forms.Cursors]::Default
    }

    if ($locations.Rows.Count -gt 0) {
        # Отдельный вопрос про завершение сеанса - более серьёзное действие, чем закрытие одного процесса
        # (закрывает ВСЕ программы пользователя на этом компьютере), поэтому спрашивается явно каждый раз,
        # с ответом "Нет" по умолчанию (см. Confirm-Action).
        $logoffSessions = Confirm-Action -Title 'Завершение сеанса пользователя' -Text (
            "Процесс будет закрыт на найденных компьютерах. Нужно ли дополнительно принудительно завершить сеанс " +
            "пользователя(ей), у которых он был открыт (в целях безопасности и предотвращения нарушений)?`n`n" +
            "Это закроет ВСЕ открытые у них программы на этом компьютере, а не только заблокированный файл, и они " +
            "будут немедленно отключены от сеанса."
        )
        $map = @{}
        foreach ($loc in $locations.Rows) {
            $key = ([string]$loc.Computer).ToUpper()
            if (-not $map.ContainsKey($key)) { $map[$key] = @() }
            $map[$key] += [string]$loc.Path
        }
        $restrictOwnerSam = if ($target.Scope -eq 'User' -and $target.PrincipalType -eq 'User') { $target.PrincipalSam } else { '' }
        $action = 'gpupdate + завершение процессов + уведомление'
        if ($logoffSessions) { $action += ' + завершение сеанса' }
        Write-Log "Применение на $($map.Count) компьютерах ($action)..."
        Set-Status "Применение блокировки на $($map.Count) компьютерах..."
        try {
            $job = Start-BlockApply -Map $map -TerminateProcesses $true -NotifyText $notifyText -LogoffSessions $logoffSessions -RestrictOwnerSam $restrictOwnerSam
            Register-UiJob -Job $job -OnDone { param($j) Complete-BlockApply -Job $j }
        }
        catch {
            Write-Log "Не удалось запустить применение: $($_.Exception.Message)"
        }
    }
    else {
        Show-Message -Text 'Правило добавлено в GPO. Компьютер, на котором видели этот файл, сейчас не определён (нет данных сканирования), поэтому обновление политик не запущено - политика дойдёт до клиентов при плановом обновлении (по умолчанию до 90 минут). Пересканируйте компьютеры и повторите блокировку, чтобы обновить политики сразу.'
    }
}

# Complete-BlockApply - вызывается по завершении обновления политик (и, если запрошено, завершения процессов):
#   пишет в журнал по каждому компьютеру результат gpupdate, сколько запущенных экземпляров найдено и сколько
#   реально завершено (с причиной, если завершить не удалось или завершение не запрашивалось), а также
#   компьютеры, недоступные по WinRM. -Job завершённое задание; $result - итог (Receive-JobResults);
#   $r - результат одного компьютера; $f - сбой.
function Complete-BlockApply {
    param($Job)
    $result = Receive-JobResults -Job $Job
    foreach ($r in $result.Data) {
        $line = "[{0}] gpupdate: {1}" -f $r.Computer, $r.GpUpdate
        if ($r.GpUpdateOutput) { $line += " (вывод: $($r.GpUpdateOutput))" }
        if ($r.TerminateRequested) {
            $line += "; найдено запущенных: {0}; завершено: {1}; уведомлено пользователей: {2}" -f $r.Found, $r.Killed, $r.Notified
            if ($r.LoggedOff -gt 0) { $line += "; завершено сеансов: {0}" -f $r.LoggedOff }
            if ($r.Found -gt $r.Killed -and $r.FailReasons) { $line += "; не завершено из-за: $($r.FailReasons)" }
            if ($r.Found -eq 0) { $line += ' (на момент применения процесс уже не был запущен)' }
        }
        elseif ($r.Found -gt 0) {
            $line += "; найдено запущенных: {0} (завершение не запрошено)" -f $r.Found
        }
        if ($r.Error) { $line += "; ошибка: $($r.Error)" }
        Write-Log $line
    }
    foreach ($f in $result.Failures) {
        Write-Log ("[{0}] не применено: {1}" -f $f.Computer, $f.Message)
    }
    Set-Status ("Применение завершено: успешно {0}, ошибок {1}" -f $result.Succeeded, $result.Failures.Count)
}

# Invoke-BlockSelectedBatch - обработчик "Заблокировать по хэшу..." при выделении НЕСКОЛЬКИХ строк: для каждого
#   уникального хэша среди них (один и тот же файл, выбранный на разных компьютерах, - это одна блокировка, не
#   несколько) выполняет те же шаги, что Invoke-BlockSelected для одной строки, но с ОДНИМ общим подтверждением
#   и ОДНИМ вопросом про завершение сеанса на весь пакет, а не по разу на каждый файл. GPO и привязка общие для
#   всех (поля на вкладке "Блокировки" одни на всё приложение), поэтому предупреждение про непривязанную GPO
#   тоже показывается один раз. Уже заблокированные, с некорректным хэшем или защищённым путём файлы молча
#   пропускаются (перечисляются в сообщении, почему), остальные блокируются; ошибка на одном хэше не прерывает
#   обработку остальных - каждая пишется в журнал отдельно. Применение (gpupdate/завершение/уведомление)
#   запускается отдельным фоновым заданием на каждый файл (переиспользует Start-BlockApply без изменений), все
#   они просто стартуют одним нажатием кнопки, а не создают одно сложное общее задание.
#   -Rows  выбранные строки таблицы процессов (DataRow, как у Invoke-BlockSelected).
#   Локальные: $algorithm - алгоритм хэша (общий, из $script:AlgoCombo); $gpo/$linkTarget - общие GPO и привязка;
#   $seen - хэши, уже учтённые при разборе (защита от дублей); $toBlock - файлы к блокировке (Name/Hash/Path/Size);
#   $skipped - пропущенные файлы с причиной; $row/$hash/$name/$path/$size - разбор текущей строки;
#   $linkSummary/$hasEnabledLink/$willBeUnlinked - то же, что в Invoke-BlockSelected, проверяется один раз;
#   $message - текст общего подтверждения; $anyLocations - есть ли смысл спрашивать про завершение сеанса;
#   $logoffSessions - общий ответ про завершение сеанса; $blocked - сколько файлов реально заблокировано;
#   $item - текущий файл из $toBlock; $ruleId - GUID созданного правила; $locations/$map/$loc/$key/$notifyText/$job -
#   то же самое, что в Invoke-BlockSelected, но внутри цикла по каждому файлу из $toBlock.
function Invoke-BlockSelectedBatch {
    param([Parameter(Mandatory)][object[]]$Rows)

    $algorithm = [string]$script:AlgoCombo.SelectedItem
    $gpoBase = $script:GpoBox.Text.Trim()
    $linkTarget = ConvertTo-LinkTargetDn -Text $script:LinkCombo.Text

    if (-not $gpoBase) {
        Show-Message -Text 'Укажите имя GPO на вкладке "Блокировки".' -Icon Warning
        return
    }
    if (-not (Test-GroupPolicyModule)) {
        Show-Message -Icon Error -Text 'Не найден модуль GroupPolicy. Установите на этом компьютере компонент "Group Policy Management" (RSAT).'
        return
    }
    $target = Resolve-BlockTarget -BaseGpoName $gpoBase
    if (-not $target) { return }
    $gpo = $target.GpoName
    $restrictOwnerSam = if ($target.Scope -eq 'User' -and $target.PrincipalType -eq 'User') { $target.PrincipalSam } else { '' }

    $seen = @{}
    $toBlock = New-Object System.Collections.ArrayList
    $skipped = New-Object System.Collections.ArrayList
    foreach ($row in $Rows) {
        $hash = [string]$row['Hash']
        $name = [string]$row['Name']
        $path = [string]$row['Path']
        if ($seen.ContainsKey($hash)) { continue }      # тот же файл уже встречался среди выбранных строк
        $seen[$hash] = $true

        if (-not (Test-HashValue -Algorithm $algorithm -Hash $hash)) {
            [void]$skipped.Add("$name - нет корректного $algorithm-хэша")
            continue
        }
        if (Test-ProtectedPath -Path $path) {
            [void]$skipped.Add("$name - файл в каталоге Windows, блокировка запрещена")
            continue
        }
        if (Get-ActiveBlock -Algorithm $algorithm -Hash $hash) {
            [void]$skipped.Add("$name - блокировка уже активна")
            continue
        }
        $size = 0L
        if ($row['Size'] -isnot [DBNull]) { $size = [long]$row['Size'] }
        [void]$toBlock.Add([pscustomobject]@{ Name = $name; Hash = $hash; Path = $path; Size = $size })
    }

    if ($toBlock.Count -eq 0) {
        Show-Message -Icon Warning -Text ("Блокировать нечего:`n`n" + ($skipped -join "`n"))
        return
    }

    $linkSummary = Get-GpoLinkSummary -GpoName $gpo
    $hasEnabledLink = $linkSummary -and $linkSummary.Enabled -gt 0
    $willBeUnlinked = -not $hasEnabledLink -and -not $linkTarget
    if ($willBeUnlinked) {
        Show-Message -Title 'GPO не привязана' -Icon Warning -Text (
            "ВНИМАНИЕ: у GPO `"$gpo`" сейчас нет ни одной включённой привязки (Link) к OU или домену, и поле " +
            "`"Привязать к`" не заполнено.`n`n" +
            "Без привязки ни одно из следующих правил НЕ ПОДЕЙСТВУЕТ ни на одном компьютере, сколько бы раз ни " +
            "выполнялся gpupdate - клиент просто не станет обрабатывать эту GPO.`n`n" +
            "Чтобы правила заработали: либо укажите DN нужного OU/домена в поле `"Привязать к`" и заблокируйте " +
            "ещё раз, либо привяжите GPO вручную в GPMC (ПКМ по OU -> Link an Existing GPO)."
        )
    }

    $message = "Заблокировать запуск $($toBlock.Count) файлов по хэшу?`n`n" +
        (($toBlock | ForEach-Object { "  - $($_.Name)" }) -join "`n") + "`n`nПрименяется к: $($target.Target)`nGPO: $gpo"
    if ($linkTarget) { $message += "`nПривязка: $linkTarget" }
    else { $message += "`nGPO будет создана/изменена; убедитесь, что она привязана к нужному OU." }
    if ($skipped.Count -gt 0) { $message += "`n`nПропущено ($($skipped.Count)):`n" + ($skipped -join "`n") }
    $message += "`n`nНа компьютерах, где эти файлы встречались в последнем сканировании, сразу после добавления " +
        "правил: обновятся политики (gpupdate), будут закрыты уже запущенные экземпляры, а их пользователям " +
        "будет показано уведомление."
    if ($target.Scope -eq 'User' -and $target.PrincipalType -eq 'Group') {
        $message += "`n`nЗакрытие коснётся ВСЕХ, кто сейчас запустил эти файлы, а не только членов группы " +
            "`"$($target.PrincipalSam)`" - членство в группе при немедленном завершении не проверяется. Сама " +
            "блокировка новых запусков действует правильно - только на членов группы."
    }
    if (-not (Confirm-Action -Text $message -Title "Блокировка по хэшу ($($toBlock.Count) файлов)")) { return }

    $anyLocations = $false
    foreach ($item in $toBlock) {
        if ((Get-HashLocations -Algorithm $algorithm -Hash $item.Hash).Rows.Count -gt 0) { $anyLocations = $true; break }
    }
    $logoffSessions = $false
    if ($anyLocations) {
        $logoffSessions = Confirm-Action -Title 'Завершение сеанса пользователя' -Text (
            "Процессы будут закрыты на найденных компьютерах. Нужно ли дополнительно принудительно завершить " +
            "сеанс пользователя(ей), у которых они были открыты (в целях безопасности и предотвращения " +
            "нарушений)?`n`nЭто закроет ВСЕ открытые у них программы на этом компьютере, а не только " +
            "заблокированные файлы, и они будут немедленно отключены от сеанса. Ответ один на весь пакет."
        )
    }

    $script:Form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    $blocked = 0
    try {
        foreach ($item in $toBlock) {
            try {
                $ruleId = Add-SrpHashBlock -GpoName $gpo -Name $item.Name -Algorithm $algorithm -Hash $item.Hash -Size $item.Size -LinkTarget $linkTarget `
                    -Scope $target.Scope -PrincipalSam $target.PrincipalSam -PrincipalType $target.PrincipalType
                Add-BlockRecord -Name $item.Name -Algorithm $algorithm -Hash $item.Hash -Size $item.Size -GpoName $gpo -RuleId $ruleId -Scope $target.Scope -Target $target.Target
                Write-Log "Блокировка добавлена: $($item.Name) ($algorithm $($item.Hash)), применяется к: $($target.Target), GPO '$gpo', правило $ruleId"
                $blocked++
            }
            catch {
                Write-Log "Ошибка блокировки $($item.Name): $($_.Exception.Message)"
                continue
            }

            $locations = Get-HashLocations -Algorithm $algorithm -Hash $item.Hash
            if ($locations.Rows.Count -eq 0) { continue }
            $map = @{}
            foreach ($loc in $locations.Rows) {
                $key = ([string]$loc.Computer).ToUpper()
                if (-not $map.ContainsKey($key)) { $map[$key] = @() }
                $map[$key] += [string]$loc.Path
            }
            $notifyText = $script:NotifyTemplate -f $item.Name
            try {
                $job = Start-BlockApply -Map $map -TerminateProcesses $true -NotifyText $notifyText -LogoffSessions $logoffSessions -RestrictOwnerSam $restrictOwnerSam
                Register-UiJob -Job $job -OnDone { param($j) Complete-BlockApply -Job $j }
            }
            catch {
                Write-Log "Не удалось запустить применение для $($item.Name): $($_.Exception.Message)"
            }
        }
    }
    finally {
        $script:Form.Cursor = [System.Windows.Forms.Cursors]::Default
    }
    if ($willBeUnlinked -and $blocked -gt 0) {
        Write-Log "ВНИМАНИЕ: GPO '$gpo' не привязана ни к одному OU/домену - $blocked блокировок НЕ действуют, пока вы её не привяжете."
    }
    Update-BlockGrid
    Write-Log "Массовая блокировка завершена: добавлено $blocked из $($toBlock.Count)."
    Set-Status "Массовая блокировка: добавлено $blocked из $($toBlock.Count)."
}

# Invoke-UnblockSelected - обработчик "Снять блокировку": после подтверждения удаляет правило из GPO и
#   помечает запись в журнале снятой. $row - выбранная блокировка; $text - текст подтверждения.
function Invoke-UnblockSelected {
    if (-not $script:BlockGrid.CurrentRow -or -not $script:BlockGrid.CurrentRow.DataBoundItem) {
        Show-Message -Text 'Выберите блокировку в таблице.' -Icon Warning
        return
    }
    $row = $script:BlockGrid.CurrentRow.DataBoundItem.Row
    if ([int]$row['Active'] -ne 1) {
        Show-Message -Text 'Эта блокировка уже снята.'
        return
    }
    if (-not (Test-GroupPolicyModule)) {
        Show-Message -Icon Error -Text 'Не найден модуль GroupPolicy (RSAT).'
        return
    }
    $text = "Снять блокировку?`n`nИмя: $($row['Name'])`n$($row['Algorithm']): $($row['Hash'])`nПрименяется к: $($row['Target'])`nGPO: $($row['GpoName'])"
    if (-not (Confirm-Action -Text $text -Title 'Снятие блокировки')) { return }

    $script:Form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    try {
        Remove-SrpHashBlock -GpoName ([string]$row['GpoName']) -RuleId ([string]$row['RuleId']) -Scope ([string]$row['Scope'])
        Disable-BlockRecord -Id ([int]$row['Id'])
        Write-Log "Блокировка снята: $($row['Name']) ($($row['Algorithm']) $($row['Hash']))"
        Update-BlockGrid
        Show-Message -Text 'Правило удалено из GPO. Клиенты применят изменение при обновлении политик.'
    }
    catch {
        Write-Log "Ошибка снятия блокировки: $($_.Exception.Message)"
        Show-Message -Text "Не удалось удалить правило:`n$($_.Exception.Message)" -Icon Error
    }
    finally {
        $script:Form.Cursor = [System.Windows.Forms.Cursors]::Default
    }
}

# Invoke-CheckBlockEvents - обработчик "Проверить срабатывания": на всех компьютерах, где хэш выбранной
#   блокировки встречался хоть когда-нибудь (Get-HashComputersEver, не только в последнем сканировании),
#   ищет в журнале событий Windows следы попыток его запустить после даты блокировки (Start-SrpEventCheck).
#   Результат - в Complete-CheckBlockEvents, когда фоновое задание завершится.
#   Важная оговорка (см. комментарий у $script:SrpEventScript): код события и имя источника - по документации,
#   не проверены на реальном журнале; если они other на вашей версии Windows, проверка тихо покажет 0 событий.
#   Локальные: $row - выбранная блокировка; $algorithm/$hash/$id - её данные; $since - дата блокировки
#   (BlockDate, строка "гггг-мм-дд чч:мм:сс", парсится как обычная дата); $computers - где хэш видели;
#   $job - фоновое задание. OnDone-обработчик собран через .GetNewClosure(), иначе $id потеряется к моменту
#   вызова (таймер окна вызывает его из совсем другой области видимости).
function Invoke-CheckBlockEvents {
    if (-not $script:BlockGrid.CurrentRow -or -not $script:BlockGrid.CurrentRow.DataBoundItem) {
        Show-Message -Text 'Выберите блокировку в таблице.' -Icon Warning
        return
    }
    $row = $script:BlockGrid.CurrentRow.DataBoundItem.Row
    $algorithm = [string]$row['Algorithm']
    $hash = [string]$row['Hash']
    $id = [int]$row['Id']
    $since = [datetime]$row['BlockDate']

    $computers = @(Get-HashComputersEver -Algorithm $algorithm -Hash $hash)
    if ($computers.Count -eq 0) {
        Show-Message -Text 'Компьютеры, где встречался этот файл, неизвестны (нет данных сканирования) - проверять нечего.'
        return
    }
    Write-Log "Проверка срабатываний блокировки '$($row['Name'])' на $($computers.Count) компьютерах (с $($row['BlockDate']))..."
    Set-Status "Проверка срабатываний на $($computers.Count) компьютерах..."
    try {
        $job = Start-SrpEventCheck -ComputerName $computers -Hash $hash -Since $since
        Register-UiJob -Job $job -OnDone { param($j) Complete-CheckBlockEvents -Job $j -BlockId $id }.GetNewClosure()
    }
    catch {
        Write-Log "Не удалось запустить проверку срабатываний: $($_.Exception.Message)"
    }
}

# Complete-CheckBlockEvents - вызывается по завершении проверки срабатываний: считает общее число найденных
#   событий и самое позднее из них, сохраняет в журнал блокировок (Update-BlockEventInfo) и обновляет таблицу.
#   -Job завершённое задание; -BlockId номер блокировки, для которой проверяли.
#   Локальные: $result - итог (Receive-JobResults); $events - найденные события (result.Data); $last - самое
#   позднее время среди них; $e - текущее событие; $byComputer - для журнала, сколько событий на каком ПК.
function Complete-CheckBlockEvents {
    param($Job, [int]$BlockId)
    $result = Receive-JobResults -Job $Job
    $events = @($result.Data)
    $last = $null
    $byComputer = @{}
    foreach ($e in $events) {
        if (-not $last -or $e.Time -gt $last) { $last = $e.Time }
        $key = [string]$e.Computer
        if (-not $byComputer.ContainsKey($key)) { $byComputer[$key] = 0 }
        $byComputer[$key] = $byComputer[$key] + 1
    }
    $lastText = if ($last) { $last.ToString('yyyy-MM-dd HH:mm:ss') } else { '' }
    Update-BlockEventInfo -Id $BlockId -Count $events.Count -LastTime $lastText
    Update-BlockGrid
    if ($events.Count -gt 0) {
        $details = ($byComputer.GetEnumerator() | ForEach-Object { "$($_.Key): $($_.Value)" }) -join ', '
        Write-Log "Проверка срабатываний: найдено событий $($events.Count) ($details), последнее - $lastText"
    }
    else {
        Write-Log 'Проверка срабатываний: попыток запуска не найдено (или они не распознаны - см. оговорку про коды событий в README).'
    }
    foreach ($f in $result.Failures) {
        Write-Log ("[{0}] не удалось проверить: {1}" -f $f.Computer, $f.Message)
    }
    Set-Status "Проверка срабатываний завершена: найдено событий $($events.Count)"
}

# ---------------------------------------------------------------------------
# Обработчики событий
# ---------------------------------------------------------------------------

# Связь кнопок и действий. $i - элемент списка компьютеров; $n - имя, введённое для ручного добавления.
#   "Остановить" останавливает $script:ScanJob; смена сканирования/алгоритма перезагружает таблицу;
#   ввод в поле поиска фильтрует таблицу; при закрытии окна таймер и все фоновые задания останавливаются;
#   при показе окна загружаются сканирования и блокировки, а в журнал пишется путь к папке данных и предупреждение,
#   если нет модуля GroupPolicy.
$btnLoadAd.Add_Click({ Import-AdComputers })
$btnAll.Add_Click({ foreach ($i in $script:CompList.Items) { $i.Checked = $true } })
$btnNone.Add_Click({ foreach ($i in $script:CompList.Items) { $i.Checked = $false } })
$btnAddManual.Add_Click({
        $n = $script:ManualBox.Text.Trim()
        if ($n) { Add-ComputerItem -HostName $n -OS '(добавлен вручную)'; $script:ManualBox.Clear() }
    })
$btnScan.Add_Click({ Start-Scan })
$btnStop.Add_Click({
        if ($script:ScanJob) {
            Stop-Job -Job $script:ScanJob -ErrorAction SilentlyContinue
            Write-Log 'Сбор остановлен пользователем (будут сохранены уже полученные данные).'
        }
    })
$btnSaveSchedule.Add_Click({
        $names = @($script:CompList.CheckedItems | ForEach-Object { $_.Text })
        if ($names.Count -eq 0) {
            Show-Message -Text 'Отметьте компьютеры, которые должны опрашиваться по расписанию.' -Icon Warning
            return
        }
        try {
            Save-ScheduledComputerList -Names $names
            Write-Log "Список для плановых сканирований сохранён: компьютеров $($names.Count)"
            Show-Message -Text (
                "Сохранено компьютеров: $($names.Count).`n`n" +
                "Чтобы сканирование запускалось по расписанию без открытия окна, добавьте задание в Планировщик заданий Windows, запускающее:`n`n" +
                "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -ScheduledScan`n`n" +
                "Подробности и важное про учётную запись для задания - в README.md."
            )
        }
        catch {
            Write-Log "Не удалось сохранить список для плановых сканирований: $($_.Exception.Message)"
            Show-Message -Text "Не удалось сохранить список:`n$($_.Exception.Message)" -Icon Error
        }
    })
$btnLoadSchedule.Add_Click({
        $names = @(Get-ScheduledComputerList)
        if ($names.Count -eq 0) {
            Show-Message -Text 'Сохранённый список для плановых сканирований пуст.'
            return
        }
        $script:CompList.BeginUpdate()
        try {
            foreach ($n in $names) {
                Add-ComputerItem -HostName $n -OS '(из списка плановых сканирований)'
                foreach ($item in $script:CompList.Items) { if ($item.Text -ieq $n) { $item.Checked = $true } }
            }
        }
        finally {
            $script:CompList.EndUpdate()
        }
        Write-Log "Загружен сохранённый список плановых сканирований: компьютеров $($names.Count)"
    })
$script:ScanCombo.Add_SelectedIndexChanged({ Update-ProcessGrid })
$script:AlgoCombo.Add_SelectedIndexChanged({ Update-ProcessGrid })
$script:FilterBox.Add_TextChanged({ Update-ProcessFilter })
$btnRefresh.Add_Click({ Update-ScanList })
$btnBlock.Add_Click({
        $rows = @($script:ProcGrid.SelectedRows | ForEach-Object { $_.DataBoundItem.Row })
        if ($rows.Count -gt 1) { Invoke-BlockSelectedBatch -Rows $rows }
        else { Invoke-BlockSelected }
    })
$btnLoadOUs.Add_Click({ Import-AdOUs })
$btnLoadPrincipals.Add_Click({ Import-AdPrincipals })
$btnUnblock.Add_Click({ Invoke-UnblockSelected })
$btnCheckEvents.Add_Click({ Invoke-CheckBlockEvents })
$btnOpenLog.Add_Click({
        if (Test-Path -LiteralPath $script:LogFile) { Start-Process -FilePath 'notepad.exe' -ArgumentList ('"{0}"' -f $script:LogFile) }
        else { Show-Message -Text ('Файл журнала ещё не создан: ' + $script:LogFile) }
    })

$script:Form.Add_FormClosing({
        $script:Timer.Stop()
        foreach ($item in @($script:PendingJobs)) {
            Stop-Job -Job $item.Job -ErrorAction SilentlyContinue
            Remove-Job -Job $item.Job -Force -ErrorAction SilentlyContinue
        }
    })

$script:Form.Add_Shown({
        Update-ScanList
        Update-BlockGrid
        Import-LogHistory
        Write-Log ('=== Запуск Process Monitor (PowerShell {0}, пользователь {1}\{2}) ===' -f $PSVersionTable.PSVersion, $env:USERDOMAIN, $env:USERNAME)
        Write-Log "Данные: $DataPath"
        Write-Log "Файл журнала: $($script:LogFile)"
        try {
            $self = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
            Write-Log ('Файл скрипта: {0}, строк {1}, SHA256 {2}' -f $self, @(Get-Content -LiteralPath $self).Count, (Get-FileHash -LiteralPath $self -Algorithm SHA256).Hash.Substring(0, 16))
        }
        catch { }
        if (-not (Test-GroupPolicyModule)) {
            Write-Log 'Внимание: модуль GroupPolicy (RSAT) не найден - блокировка будет недоступна.'
        }
    })

[void]$script:Form.ShowDialog()
