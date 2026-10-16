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
      * блокирует запуск файла с выбранным хэшем - список блокировок хранится в своих данных приложения
        (никакой групповой политики), по одной или сразу нескольким строкам;
      * сама следит за уже активными блокировками: после каждого сканирования (ручного или планового) сверяет
        собранные процессы со списком блокировок и, если находит совпадение, сразу закрывает процесс, уведомляет
        пользователя и, если для этой блокировки включено, завершает его сеанс и полностью отключает его учётную
        запись в домене (см. README.md - это отдельная, опциональная на каждую блокировку мера);
      * умеет сканировать компьютеры по расписанию без окна (-ScheduledScan, см. README.md).

    Скрипт самодостаточный (один файл), сторонних драйверов не требует.
    Подробности и требования - в README.md.

.PARAMETER SelfTest
    Не открывать окно, а проверить на этом компьютере всё, от чего зависит работа (версия PowerShell, JSON-хранилище,
    хэширование, Windows Forms, WinRM, AD), и вывести [ OK ] / [WARN] / [FAIL] по каждому пункту.

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
#                    Hash, Size, Active, LockAccount, EventCount, LastEventTime).
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

# ConvertTo-PlainData - приводит результат разбора JSON (ЛЮБОГО из серилизаторов ниже) к хэш-таблицам
#   (Hashtable) и ArrayList, чтобы везде в коде можно было писать $d['Ключ'] и $d.Contains('Ключ')/
#   .ContainsKey('Ключ') одинаково, независимо от того, КАКИМ серилизатором запись была прочитана.
#   Это важно: JavaScriptSerializer.DeserializeObject (основной путь на настоящем Windows PowerShell 5.1,
#   где есть System.Web.Extensions) возвращает для JSON-объекта не Hashtable, а
#   System.Collections.Generic.Dictionary[string,object] - у него есть .ContainsKey(), но ВЫЗОВ .Contains()
#   с одной строкой не находит подходящей перегрузки (есть только версия для KeyValuePair) и бросает
#   "Cannot find an overload for "Contains" and the argument count: 1" - ровно это и ловит .Contains() в
#   остальном коде (намеренно универсальный для [ordered]@{} и Hashtable - см. комментарии у Get-BlockTable).
#   Без этой нормализации код работал бы только там, где JavaScriptSerializer недоступен (например, не на
#   настоящем Windows PowerShell, а в PowerShell 7/Linux - именно поэтому проблема не поймалась раньше).
#   -Value результат разбора JSON. $d - собираемая хэш-таблица; $prop - свойство PSCustomObject;
#   $key - ключ словаря; $list / $i - список и его элемент.
function ConvertTo-PlainData {
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [System.Management.Automation.PSCustomObject]) {
        $d = @{}
        foreach ($prop in $Value.PSObject.Properties) { $d[$prop.Name] = ConvertTo-PlainData -Value $prop.Value }
        return $d
    }
    if ($Value -is [System.Collections.IDictionary]) {
        $d = @{}
        foreach ($key in @($Value.Keys)) { $d[$key] = ConvertTo-PlainData -Value $Value[$key] }
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
#   Сначала пробует быстрый JavaScriptSerializer.DeserializeObject; если его нет или он сбойнул - ConvertFrom-Json
#   (на PowerShell 6+ с -AsHashtable). Результат ЛЮБОГО из путей проходит через ConvertTo-PlainData - без этого
#   JavaScriptSerializer отдавал бы Dictionary[string,object] вместо Hashtable (см. её комментарий).
#   -Text строка с JSON.
function ConvertFrom-JsonText {
    param([Parameter(Mandatory)][string]$Text)
    if ($script:JsonSerializer) {
        try { return (ConvertTo-PlainData -Value $script:JsonSerializer.DeserializeObject($Text)) }
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
    $script:BlockHits = New-Object System.Collections.ArrayList

    $scansFile = Join-Path $Path 'scans.json'
    $blocksFile = Join-Path $Path 'blocks.json'
    $hitsFile = Join-Path $Path 'block-hits.json'
    $scansDoc = Read-JsonFile -Path $scansFile
    $blocksDoc = Read-JsonFile -Path $blocksFile
    $hitsDoc = Read-JsonFile -Path $hitsFile
    foreach ($item in (Get-JsonList -Document $scansDoc -Key 'Scans')) { [void]$script:Scans.Add($item) }
    foreach ($item in (Get-JsonList -Document $blocksDoc -Key 'Blocks')) { [void]$script:Blocks.Add($item) }
    foreach ($item in (Get-JsonList -Document $hitsDoc -Key 'Hits')) { [void]$script:BlockHits.Add($item) }

    if (-not $scansDoc) { Save-ScanIndex }
    if (-not $blocksDoc) { Save-BlockLog }
    if (-not $hitsDoc) { Save-BlockHits }
}

# Save-ScanIndex - записывает список сканирований из памяти в scans.json.
function Save-ScanIndex {
    Write-JsonFile -Path (Join-Path $script:StoreDir 'scans.json') -Data ([ordered]@{ Version = 1; Scans = $script:Scans })
}

# Save-BlockLog - записывает журнал блокировок из памяти в blocks.json.
function Save-BlockLog {
    Write-JsonFile -Path (Join-Path $script:StoreDir 'blocks.json') -Data ([ordered]@{ Version = 1; Blocks = $script:Blocks })
}

# Save-BlockHits - записывает подробный журнал обнаружений (каждый отдельный случай, когда заблокированный
#   файл застали запущенным - время/компьютер/пользователь/путь) из памяти в block-hits.json.
function Save-BlockHits {
    Write-JsonFile -Path (Join-Path $script:StoreDir 'block-hits.json') -Data ([ordered]@{ Version = 1; Hits = $script:BlockHits })
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

# Get-HashLocations - где найден хэш: компьютеры, пути и пользователи по ПОСЛЕДНЕМУ сканированию каждого компьютера.
#   Нужна, чтобы показать "найден на N компьютерах", знать, где завершать процессы, и кто их запустил (для
#   подробного журнала обнаружений, Add-BlockHit).
#   -Algorithm, -Hash  алгоритм и значение хэша. Возвращает таблицу: Computer, Path, User.
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
    [void]$table.Columns.Add('User', [string])

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
            $user = ''
            if ($p.ContainsKey('User')) { $user = [string]$p['User'] }        # старые сканирования без этого поля
            [void]$table.Rows.Add([string]$p['Computer'], [string]$p['Path'], $user)
        }
    }
    return , $table
}

# ---- Блокировки ------------------------------------------------------------

# Add-BlockRecord - записывает в журнал блокировок (blocks.json) новую активную блокировку.
#   -Name имя файла; -Algorithm и -Hash хэш; -Size размер файла; -LockAccount - блокировать ли ПОЛНОСТЬЮ учётную
#   запись в домене (см. README.md) у того, кого поймают запустившим этот файл - помимо закрытия самого процесса
#   и уведомления (решается один раз здесь, при создании блокировки, а не каждый раз при обнаружении).
#   Номер записи = максимальный + 1.
function Add-BlockRecord {
    param(
        [string]$Name,
        [Parameter(Mandatory)][string]$Algorithm,
        [Parameter(Mandatory)][string]$Hash,
        [long]$Size,
        [bool]$LockAccount = $false
    )
    $id = 1
    foreach ($b in $script:Blocks) {
        if ([int]$b['Id'] -ge $id) { $id = [int]$b['Id'] + 1 }
    }
    [void]$script:Blocks.Add([ordered]@{
            Id          = $id
            BlockDate   = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
            Name        = $Name
            Algorithm   = $Algorithm
            Hash        = $Hash.ToUpper()
            Size        = $Size
            Active      = 1
            LockAccount = [int]$LockAccount
            EventCount  = 0
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
#   Поле Status: "Активна" (Active=1) или "Снята". EventCount/LastEventTime/LastComputer/LastUser - сколько раз,
#   когда, на каком компьютере и под каким пользователем в последний раз сканирование заставало этот файл
#   запущенным уже ПОСЛЕ блокировки (см. Add-BlockHit - считает сама проверка после сканирования, журнал событий
#   Windows не используется; подробный журнал каждого отдельного случая - Get-BlockHitsTable/block-hits.json).
#   LockAccount - заблокирована ли ПОЛНОСТЬЮ учётная запись того, кого поймают с этим файлом (см. Add-BlockRecord);
#   у записей, сделанных до появления этой возможности, поля LockAccount/EventCount/LastComputer/LastUser нет в
#   файле на диске, поэтому читаются с запасным значением (0/пусто) - для них эти колонки просто окажутся
#   пустыми/нулевыми.
function Get-BlockTable {
    $table = New-Object System.Data.DataTable
    [void]$table.Columns.Add('Id', [int])
    [void]$table.Columns.Add('BlockDate', [string])
    [void]$table.Columns.Add('Name', [string])
    [void]$table.Columns.Add('Algorithm', [string])
    [void]$table.Columns.Add('Hash', [string])
    [void]$table.Columns.Add('Active', [int])
    [void]$table.Columns.Add('Status', [string])
    [void]$table.Columns.Add('LockAccount', [string])
    [void]$table.Columns.Add('EventCount', [int])
    [void]$table.Columns.Add('LastEventTime', [string])
    [void]$table.Columns.Add('LastComputer', [string])
    [void]$table.Columns.Add('LastUser', [string])
    for ($i = $script:Blocks.Count - 1; $i -ge 0; $i--) {
        $b = $script:Blocks[$i]
        $status = if ([int]$b['Active'] -eq 1) { 'Активна' } else { 'Снята' }
        $eventCount = 0
        # .Contains(), а не .ContainsKey(): свежедобавленные за этот сеанс записи - OrderedDictionary ([ordered]@{...}
        # в Add-BlockRecord), а у неё нет ContainsKey (есть только у Hashtable, в который превращаются записи ПОСЛЕ
        # перечитывания с диска). .Contains() есть у обоих типов.
        if ($b.Contains('EventCount')) { $eventCount = [int]$b['EventCount'] }
        $lastEventTime = ''
        if ($b.Contains('LastEventTime')) { $lastEventTime = [string]$b['LastEventTime'] }
        $lastComputer = ''
        if ($b.Contains('LastComputer')) { $lastComputer = [string]$b['LastComputer'] }
        $lastUser = ''
        if ($b.Contains('LastUser')) { $lastUser = [string]$b['LastUser'] }
        $lockAccount = 'Нет'
        if ($b.Contains('LockAccount') -and [int]$b['LockAccount'] -eq 1) { $lockAccount = 'Да' }
        [void]$table.Rows.Add([int]$b['Id'], [string]$b['BlockDate'], [string]$b['Name'], [string]$b['Algorithm'],
            [string]$b['Hash'], [int]$b['Active'], $status, $lockAccount, $eventCount, $lastEventTime,
            $lastComputer, $lastUser)
    }
    return , $table
}

# Get-BlockHitsTable - подробный журнал обнаружений ОДНОЙ блокировки (для окна "История обнаружений"): каждая
#   строка - отдельный случай, когда сканирование застало файл запущенным. -BlockId номер блокировки.
#   Возвращает таблицу Time/Computer/User/Path, новые сверху.
function Get-BlockHitsTable {
    param([Parameter(Mandatory)][int]$BlockId)
    $table = New-Object System.Data.DataTable
    [void]$table.Columns.Add('Time', [string])
    [void]$table.Columns.Add('Computer', [string])
    [void]$table.Columns.Add('User', [string])
    [void]$table.Columns.Add('Path', [string])
    for ($i = $script:BlockHits.Count - 1; $i -ge 0; $i--) {
        $h = $script:BlockHits[$i]
        if ([int]$h['BlockId'] -ne $BlockId) { continue }
        [void]$table.Rows.Add([string]$h['Time'], [string]$h['Computer'], [string]$h['User'], [string]$h['Path'])
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

# Add-BlockHit - отмечает ОДИН конкретный случай, когда сканирование (ручное или плановое) застало заблокированный
#   файл запущенным УЖЕ ПОСЛЕ блокировки - вызывается из Invoke-BlockSweep/Invoke-BlockSelected(Batch) по разу на
#   каждое отдельное сочетание компьютер+пользователь+путь, а не по запросу администратора (в отличие от прежней
#   кнопки "Проверить срабатывания", которая опиралась на журнал событий Windows - теперь этого источника нет, но
#   он и не нужен: сама проверка после сканирования и есть факт обнаружения).
#   -BlockId номер блокировки; -Computer компьютер; -User пользователь (если известен); -Path путь к файлу.
#   Делает две вещи: 1) обновляет сводные поля самой блокировки в blocks.json - EventCount (копится за всё время),
#   LastEventTime/LastComputer/LastUser (последний случай, для быстрого взгляда на вкладке "Блокировки");
#   2) добавляет подробную запись в журнал обнаружений block-hits.json (время/компьютер/пользователь/путь
#   каждого случая отдельно - для окна "История обнаружений", Get-BlockHitsTable).
function Add-BlockHit {
    param(
        [Parameter(Mandatory)][int]$BlockId,
        [Parameter(Mandatory)][string]$Computer,
        [string]$User = '',
        [string]$Path = ''
    )
    $time = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    foreach ($b in $script:Blocks) {
        if ([int]$b['Id'] -eq $BlockId) {
            $current = 0
            if ($b.Contains('EventCount')) { $current = [int]$b['EventCount'] }
            $b['EventCount'] = $current + 1
            $b['LastEventTime'] = $time
            $b['LastComputer'] = $Computer
            $b['LastUser'] = $User
        }
    }
    $id = 1
    foreach ($h in $script:BlockHits) {
        if ([int]$h['Id'] -ge $id) { $id = [int]$h['Id'] + 1 }
    }
    [void]$script:BlockHits.Add([ordered]@{
            Id       = $id
            BlockId  = $BlockId
            Time     = $time
            Computer = $Computer
            User     = $User
            Path     = $Path
        })
    Save-BlockLog
    Save-BlockHits
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

# Get-AdUsersWithOuStatus - читает из AD ВСЕХ пользователей домена (запрос LDAP через ADSI, как и
#   Get-AdComputers) вместе с их подразделением (OU) и статусом учётной записи (включена/отключена) - для
#   вкладки "Пользователи". Возвращает объекты { Name, Sam, Disabled, OuPath, Dn }: OuPath - массив названий
#   OU от КОРНЯ к листу (ближе к пользователю), разобранный из distinguishedName - используется для построения
#   дерева (Update-UsersTree). Пользователи не в подразделении (например, встроенный контейнер CN=Users) -
#   OuPath = @('(без OU)').
#   Локальные: $searcher/$results - поиск; $r - текущая запись; $dn - её distinguishedName;
#   $comps - части DN, разбитые по запятой; $ouParts - только части, начинающиеся с "OU=" (без этого префикса).
function Get-AdUsersWithOuStatus {
    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.Filter = '(&(objectCategory=person)(objectClass=user))'
    $searcher.PageSize = 1000
    foreach ($prop in 'distinguishedname', 'samaccountname', 'name', 'useraccountcontrol') {
        [void]$searcher.PropertiesToLoad.Add($prop)
    }

    $results = $searcher.FindAll()
    try {
        foreach ($r in $results) {
            if (-not $r.Properties['distinguishedname'].Count) { continue }
            $dn = [string]$r.Properties['distinguishedname'][0]
            $sam = if ($r.Properties['samaccountname'].Count) { [string]$r.Properties['samaccountname'][0] } else { '' }
            $name = if ($r.Properties['name'].Count) { [string]$r.Properties['name'][0] } else { $sam }
            $uac = if ($r.Properties['useraccountcontrol'].Count) { [int]$r.Properties['useraccountcontrol'][0] } else { 0 }
            $disabled = (($uac -band 0x2) -ne 0)

            # DN вида "CN=Иванов Иван,OU=Продажи,OU=Сотрудники,DC=pp,DC=local" - части "OU=..." идут от самого
            # БЛИЗКОГО к пользователю подразделения к самому дальнему, поэтому порядок разворачивается, чтобы
            # получить путь от корня (как ожидает Update-UsersTree при построении дерева).
            $comps = $dn -split ','
            $ouParts = @($comps | Where-Object { $_ -match '^OU=' } | ForEach-Object { ($_ -replace '^OU=', '').Trim() })
            [array]::Reverse($ouParts)
            if ($ouParts.Count -eq 0) { $ouParts = @('(без OU)') }

            [pscustomobject]@{ Name = $name; Sam = $sam; Disabled = $disabled; OuPath = $ouParts; Dn = $dn }
        }
    }
    finally {
        $results.Dispose()
        $searcher.Dispose()
    }
}

# Disable-AdAccount - ПОЛНОСТЬЮ отключает учётную запись пользователя в AD (бит ACCOUNTDISABLE = 0x2 в атрибуте
#   userAccountControl) - человек не сможет войти вообще никуда в домене (ни на один компьютер, почту и т. п.),
#   пока администратор не включит учётную запись обратно вручную. Используется для блокировок с LockAccount=1
#   (см. Add-BlockRecord) - вызывается с машины АДМИНИСТРАТОРА (не с того компьютера, где процесс был пойман:
#   запись в AD оттуда скорее всего не сработала бы из-за "двойного перехода" Kerberos - у Invoke-Command нет
#   делегирования учётных данных администратора на третью систему, то есть на контроллер домена - поэтому
#   сервер/компьютер пытался бы обратиться к AD от своего ИМЕНИ, а не от имени администратора, и, скорее всего,
#   получил бы отказ в доступе). Через ADSI (System.DirectoryServices), без модуля ActiveDirectory - как и
#   остальная работа с AD в этом приложении.
#   -Sam  sAMAccountName пользователя (без имени домена). Возвращает $true, если учётная запись найдена и
#   отключена, $false - если её не нашли, или отключить не удалось (нет прав, AD недоступен и т. п.);
#   вызывающий код должен в этом случае залогировать неудачу, а не считать её исключением.
#   Локальные: $root/$domainDn - корень домена; $searcher - объект поиска; $result - найденная запись;
#   $user - сам объект пользователя (для записи); $uac - текущее значение userAccountControl.
# Set-AdAccountDisabledFlag - общая часть Disable-AdAccount/Enable-AdAccount: находит пользователя по
#   sAMAccountName и выставляет/снимает бит ACCOUNTDISABLE (0x2) в userAccountControl.
#   -Sam логин; -Disabled $true - отключить, $false - включить обратно. Возвращает $true/$false (успех).
function Set-AdAccountDisabledFlag {
    param([Parameter(Mandatory)][string]$Sam, [Parameter(Mandatory)][bool]$Disabled)
    $searcher = $null
    try {
        $root = [System.DirectoryServices.DirectoryEntry]'LDAP://RootDSE'
        $domainDn = [string]$root.Properties['defaultNamingContext'][0]
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$domainDn")
        $searcher.Filter = "(sAMAccountName=$Sam)"
        [void]$searcher.PropertiesToLoad.Add('useraccountcontrol')
        $result = $searcher.FindOne()
        if (-not $result) { return $false }
        $user = $result.GetDirectoryEntry()
        $uac = [int]$user.Properties['userAccountControl'][0]
        $newUac = if ($Disabled) { $uac -bor 0x2 } else { $uac -band (-bnot 0x2) }
        $user.Properties['userAccountControl'].Value = $newUac
        $user.CommitChanges()
        return $true
    }
    catch {
        return $false
    }
    finally {
        if ($searcher) { $searcher.Dispose() }
    }
}

function Disable-AdAccount {
    param([Parameter(Mandatory)][string]$Sam)
    Set-AdAccountDisabledFlag -Sam $Sam -Disabled $true
}

# Enable-AdAccount - снимает бит ACCOUNTDISABLE (включает учётную запись обратно) - используется из
#   Invoke-RestoreSelectedUser (правый клик по пользователю на вкладке "Пользователи"), чтобы администратор
#   мог вернуть доступ без переключения в ADUC/dsa.msc.
function Enable-AdAccount {
    param([Parameter(Mandatory)][string]$Sam)
    Set-AdAccountDisabledFlag -Sam $Sam -Disabled $false
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

# $script:ApplyBlockScript - скрипт, который выполняется НА УДАЛЁННОМ компьютере: ЗАВЕРШАЕТ уже запущенные
#   экземпляры заблокированного файла и показывает каждому затронутому пользователю на экране (msg.exe) короткое
#   уведомление, что запускать это нельзя. По отдельному запросу (-LogoffSessions) ПОСЛЕ уведомления также
#   принудительно завершает сеанс (logoff.exe) именно того пользователя, у кого был открыт процесс, - это
#   закрывает ВСЕ его программы на этом компьютере, не только заблокированный файл. Никакой групповой политики
#   не трогает вообще - единственный механизм блокировки теперь это мониторинг (см. Invoke-BlockSweep): файл
#   закрывается, как только сканирование застаёт его запущенным, а не превентивно в момент попытки запуска.
#   $Map  - хэш-таблица "ИМЯ КОМПЬЮТЕРА (в верхнем регистре) -> массив путей к файлу".
#   $NotifyText - текст уведомления (без имени файла - оно подставляется автоматически).
#   $LogoffSessions - завершать ли принудительно сеанс пользователя, у которого процесс был завершён ($true/$false).
#   $LockAccount - требуется ли для этой блокировки ПОЛНОСТЬЮ отключить учётную запись пойманного пользователя в
#   AD (см. Add-BlockRecord/README.md). Сама запись в AD отсюда НЕ делается (см. Disable-AdAccount - двойной
#   переход Kerberos не даст этому скрипту, выполняющемуся на удалённом компьютере, записать что-либо в AD от
#   имени администратора) - этот скрипт только СОБИРАЕТ список владельцев закрытых процессов в UsersToLock,
#   а сам вызов Disable-AdAccount и запись в отдельный журнал блокировок учётных записей делает код на машине
#   администратора (Invoke-AccountLockFollowUp), разбирая результат уже ПОСЛЕ того, как это задание завершится.
#   Возвращает объект { Computer, Found (сколько запущенных экземпляров найдено), Killed (сколько реально
#   завершено), Notified (скольким пользователям показано уведомление), LoggedOff (сколько сеансов принудительно
#   завершено - один раз на сеанс (SessionId), даже если в нём было несколько запущенных экземпляров),
#   FailReasons (причины неудач метода Terminate, без повторов), UsersToLock (владельцы закрытых процессов,
#   "ДОМЕН\логин", без повторов - заполняется, только если -LockAccount), Error }.
#   Found может быть больше Killed: причина - в FailReasons (чаще всего нет прав на завершение процесса).
#   Found = 0 при непустом $paths значит, что на момент применения процесс с таким путём уже не запущен
#   (завершился сам, или путь в данных сканирования устарел). Уведомление, завершение сеанса и UsersToLock
#   заполняются, только если процесс реально завершён (TRUE Kill), и только один раз на пользователя/сеанс, даже
#   если он держал открытыми несколько копий файла.
#   Локальные: $res - возвращаемый результат; $paths - пути, по которым ищем запущенные экземпляры;
#   $reasonMap - код возврата Terminate() -> текст причины; $notified - кому уведомление уже отправлено;
#   $loggedOff - какие сеансы (SessionId) уже завершены в этом запуске (защита от дублей); $toLock - владельцы,
#   которых нужно внести в UsersToLock (защита от дублей); $p - процесс из WMI; $owner - владелец именно этого
#   запущенного экземпляра (берётся заново через GetOwner(), а не из данных сканирования - на момент применения
#   им может быть уже другой пользователь); $r - результат Terminate(); $reason - текст причины для конкретного кода.
$script:ApplyBlockScript = {
    param($Map, $NotifyText = 'Нельзя такое запускать: этот файл заблокирован политикой безопасности.', $LogoffSessions = $false, $LockAccount = $false)
    $res = New-Object PSObject -Property @{
        Computer    = $env:COMPUTERNAME
        Found       = 0
        Killed      = 0
        Notified    = 0
        LoggedOff   = 0
        FailReasons = ''
        UsersToLock = @()
        Error       = ''
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
        $paths = @($Map[$env:COMPUTERNAME.ToUpper()])
        if ($paths.Count -gt 0) {
            $reasons = @{}
            $notified = @{}
            $loggedOff = @{}
            $toLock = @{}
            foreach ($p in (Get-WmiObject -Class Win32_Process)) {
                if ($p.ExecutablePath -and ($paths -contains $p.ExecutablePath)) {
                    $res.Found = $res.Found + 1
                    $owner = ''
                    try { $o = $p.GetOwner(); if ($o.User) { $owner = $o.User } } catch { }

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
                        if ($LockAccount -and $owner -and -not $toLock.ContainsKey($owner)) {
                            $toLock[$owner] = $true
                        }
                    }
                    else {
                        $reason = $reasonMap[[int]$r.ReturnValue]
                        if (-not $reason) { $reason = 'код ' + $r.ReturnValue }
                        $reasons[$reason] = $true
                    }
                }
            }
            $res.FailReasons = (@($reasons.Keys | Sort-Object) -join '; ')
            $res.UsersToLock = @($toLock.Keys)
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

# Get-OnlineComputers - проверяет пингом (ICMP), какие из перечисленных компьютеров сейчас включены и отвечают
#   по сети, и возвращает только их. Делается ПАРАЛЛЕЛЬНО для всех сразу через System.Net.NetworkInformation.Ping
#   (SendPingAsync) с коротким таймаутом - иначе проверка десятков компьютеров, часть из которых выключена,
#   последовательным Test-Connection сама по себе заняла бы минуты; так же быстро, независимо от их количества,
#   отсеиваются и выключенные машины, которым иначе пришлось бы ждать 20-секундного таймаута открытия
#   WinRM-сессии (см. Get-RemoteSessionOption) на каждую. -ComputerName список имён; -TimeoutMs таймаут ОДНОГО
#   пинга в миллисекундах (1000 по умолчанию - этого достаточно в пределах локальной сети/домена).
#   Возвращает только имена ответивших компьютеров, в точности как они были переданы (не меняет регистр/имя).
#   Если отправить пинг не удалось вообще (например, имя не резолвится в DNS) - компьютер просто считается
#   недоступным, без ошибки: вызывающему коду не нужно знать разницу между "выключен" и "не резолвится".
#   Локальные: $pending - по одному элементу { Name, Ping, Task } на каждый компьютер; $tasks - только реально
#   отправленные задачи ping (для WaitAll); $p - текущий элемент при разборе результатов; $ok - ответил ли он.
function Get-OnlineComputers {
    param([Parameter(Mandatory)][string[]]$ComputerName, [int]$TimeoutMs = 1000)
    $pending = foreach ($name in $ComputerName) {
        $ping = New-Object System.Net.NetworkInformation.Ping
        $task = $null
        try { $task = $ping.SendPingAsync($name, $TimeoutMs) } catch { }
        [pscustomobject]@{ Name = $name; Ping = $ping; Task = $task }
    }
    $tasks = @($pending | Where-Object { $_.Task } | ForEach-Object { $_.Task })
    if ($tasks.Count -gt 0) {
        # Сбой/таймаут отдельных задач превращает WaitAll в исключение (AggregateException), но не мешает
        # результатам ОСТАЛЬНЫХ, уже завершившихся задач - поэтому ошибка просто игнорируется, а не прерывает проверку.
        try { [System.Threading.Tasks.Task]::WaitAll($tasks) } catch { }
    }
    $online = foreach ($p in $pending) {
        $ok = $false
        if ($p.Task -and $p.Task.IsCompleted -and -not $p.Task.IsFaulted) {
            try { $ok = ($p.Task.Result.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) } catch { }
        }
        if ($ok) { $p.Name }
        $p.Ping.Dispose()
    }
    , @($online)
}

# Start-RemoteCollection - вторая половина сбора: уже ЗНАЯ, кто онлайн/офлайн (после пинга - см. Get-OnlineComputers/
#   Start-PingCheck), запускает Invoke-Command -AsJob только на ответивших и оформляет результат так же, как
#   раньше делала Start-Collection. Вынесена отдельно, чтобы ею могли пользоваться и Start-Collection (пинг
#   синхронно, для self-test и планового headless-сканирования - там нет окна, которое можно заморозить), и
#   Complete-PingCheck (пинг уже прошёл в фоновом задании - см. его комментарий, почему это важно для
#   интерактивного режима).
#   -ComputerName  весь исходный список (включая офлайн, для RequestedCount); -Online/-Offline  результат пинга;
#   -ThrottleLimit  сколько компьютеров опрашивать одновременно.
#   Возвращает родительское задание - по одному дочернему заданию на каждый ВКЛЮЧЁННЫЙ компьютер (у остальных
#   дочерних заданий не будет - вместо этого у возвращённого задания есть дополнительные свойства
#   RequestedCount и OfflineFailures (отсеянные пингом, в формате { Computer, Message }, как Failures у
#   Receive-JobResults) - Receive-JobResults сама подмешивает их в общий список Failures, вызывающему коду
#   ничего отдельно делать не нужно. Если онлайн компьютеров нет вообще - настоящее задание всё равно
#   создаётся (Start-Job с пустым телом), чтобы остальной конвейер (Register-UiJob, Get-JobProgress,
#   Receive-JobResults), рассчитанный на настоящий объект задания, продолжал работать без особого случая
#   "задания нет". Локальные: $offlineFailures - офлайн-компьютеры в формате Failures; $job - создаваемое задание.
function Start-RemoteCollection {
    param(
        [Parameter(Mandatory)][string[]]$ComputerName,
        [string[]]$Online,
        [string[]]$Offline,
        [int]$ThrottleLimit = 32
    )
    $offlineFailures = @($Offline | ForEach-Object {
            [pscustomobject]@{ Computer = $_; Message = 'не отвечает на ping (выключен или недоступен по сети)' }
        })

    if ($Online.Count -gt 0) {
        $job = Invoke-Command -ComputerName $Online -ScriptBlock $script:CollectScript `
            -SessionOption (Get-RemoteSessionOption) -ThrottleLimit $ThrottleLimit `
            -AsJob -JobName 'ProcMon-Collect'
    }
    else {
        $job = Start-Job -Name 'ProcMon-Collect' -ScriptBlock { }
    }
    Add-Member -InputObject $job -MemberType NoteProperty -Name RequestedCount -Value $ComputerName.Count -Force
    Add-Member -InputObject $job -MemberType NoteProperty -Name OfflineFailures -Value $offlineFailures -Force
    return $job
}

# Start-Collection - запускает сбор процессов сразу на нескольких компьютерах в фоне (Invoke-Command -AsJob),
#   предварительно отсеяв пингом (Get-OnlineComputers) те, что сейчас выключены или недоступны по сети - на них
#   WinRM вообще не пробуется, они сразу попадают в итоговые Failures с понятной причиной (через Receive-JobResults).
#   Пинг здесь выполняется СИНХРОННО (на вызывающем потоке) - подходит только там, где нет окна, которое можно
#   заморозить (self-test, плановое headless-сканирование, -ScheduledScan): интерактивный режим (кнопка
#   "Собрать процессы") использует вместо этого Start-PingCheck/Complete-PingCheck, см. их комментарии.
#   -ComputerName  имена компьютеров (весь запрошенный список, включая потенциально выключенные);
#   -ThrottleLimit  сколько компьютеров опрашивать одновременно (32).
#   Локальные: $online/$offline - включённые/выключенные по результату пинга.
function Start-Collection {
    param(
        [Parameter(Mandatory)][string[]]$ComputerName,
        [int]$ThrottleLimit = 32
    )
    $online = @(Get-OnlineComputers -ComputerName $ComputerName)
    $offline = @($ComputerName | Where-Object { $online -notcontains $_ })
    return Start-RemoteCollection -ComputerName $ComputerName -Online $online -Offline $offline -ThrottleLimit $ThrottleLimit
}

# Start-PingCheck - проверяет пингом доступность компьютеров В ФОНОВОМ ЗАДАНИИ (отдельный процесс PowerShell),
#   а не на потоке окна. Это важно: внутри Ping.SendPingAsync(имя, таймаут) разрешение имени в IP-адрес (DNS) -
#   синхронная операция и НЕ ограничена параметром таймаута - если хотя бы один компьютер из списка не резолвится
#   быстро (устаревшая запись, недоступный DNS-сервер и т. п.), вызов на потоке окна зависал бы на неопределённое
#   время, а с ним и само окно (оно безотзывно занято до возврата из обработчика кнопки - ни Timer, ни отрисовка
#   не могут сработать). Поэтому у интерактивного сбора (Start-Scan) этот шаг вынесен в Start-Job - такой же
#   приём, как и у самого сбора процессов (Invoke-Command -AsJob), только нет готового "асинхронного" аналога
#   у пинга, поэтому используется обычное фоновое задание.
#   -ComputerName список имён; -TimeoutMs таймаут одного пинга (как у Get-OnlineComputers).
#   Возвращает задание; его результат (после Receive-Job) - { Online, Offline }.
function Start-PingCheck {
    param([Parameter(Mandatory)][string[]]$ComputerName, [int]$TimeoutMs = 1000)
    Start-Job -Name 'ProcMon-Ping' -ScriptBlock {
        param($Names, $TimeoutMs)
        $pending = foreach ($name in $Names) {
            $ping = New-Object System.Net.NetworkInformation.Ping
            $task = $null
            try { $task = $ping.SendPingAsync($name, $TimeoutMs) } catch { }
            [pscustomobject]@{ Name = $name; Ping = $ping; Task = $task }
        }
        $tasks = @($pending | Where-Object { $_.Task } | ForEach-Object { $_.Task })
        if ($tasks.Count -gt 0) {
            try { [System.Threading.Tasks.Task]::WaitAll($tasks) } catch { }
        }
        $online = @(foreach ($p in $pending) {
                $ok = $false
                if ($p.Task -and $p.Task.IsCompleted -and -not $p.Task.IsFaulted) {
                    try { $ok = ($p.Task.Result.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) } catch { }
                }
                if ($ok) { $p.Name }
                $p.Ping.Dispose()
            })
        [pscustomobject]@{ Online = $online; Offline = @($Names | Where-Object { $online -notcontains $_ }) }
    } -ArgumentList $ComputerName, $TimeoutMs
}

# Start-BlockApply - в фоне запускает $script:ApplyBlockScript (завершение процессов, уведомление и, по
#   желанию, принудительное завершение сеанса пользователей) на компьютерах, где найден заблокированный файл.
#   -Map  "ИМЯ КОМПЬЮТЕРА -> пути к файлу" (ключи Map - список компьютеров);
#   -NotifyText  текст уведомления пользователю при завершении его процесса;
#   -LogoffSessions  завершать ли принудительно сеанс пользователя после завершения его процесса;
#   -LockAccount  требуется ли для этой блокировки блокировать учётную запись пойманных пользователей в AD
#   (см. $script:ApplyBlockScript/Invoke-AccountLockFollowUp). Возвращает задание.
function Start-BlockApply {
    param([Parameter(Mandatory)][hashtable]$Map, [string]$NotifyText, [bool]$LogoffSessions = $false, [bool]$LockAccount = $false)
    Invoke-Command -ComputerName @($Map.Keys) -ScriptBlock $script:ApplyBlockScript `
        -ArgumentList $Map, $NotifyText, $LogoffSessions, $LockAccount -SessionOption (Get-RemoteSessionOption) -ThrottleLimit 32 `
        -AsJob -JobName 'ProcMon-Apply'
}

# Get-JobProgress - прогресс фонового задания: сколько компьютеров уже завершили работу. Компьютеры, отсеянные
#   пингом в Start-Collection (свойство OfflineFailures у $Job, если оно есть - см. там же), сразу считаются
#   завершёнными и входят и в Done, и в Total - ждать их уже не нужно, результат по ним известен сразу.
#   Возвращает { Done = завершено, Total = всего }. $children - дочерние задания; $offlineCount - сколько
#   отсеяно пингом; $done - число завершённых (включая отсеянные).
function Get-JobProgress {
    param([Parameter(Mandatory)]$Job)
    $children = @($Job.ChildJobs)
    $offlineCount = 0
    if ($Job.PSObject.Properties['OfflineFailures']) { $offlineCount = @($Job.OfflineFailures).Count }
    $done = @($children | Where-Object { $_.State -notin 'Running', 'NotStarted' }).Count + $offlineCount
    [pscustomobject]@{ Done = $done; Total = $children.Count + $offlineCount }
}

# Receive-JobResults - забирает итог фонового задания и удаляет задание. Компьютеры, отсеянные пингом в
#   Start-Collection (свойство OfflineFailures у $Job, если оно есть), попадают в Failures так же, как обычный
#   сбой WinRM - вызывающему коду не нужно знать, что часть сбоев определилась ещё до старта задания.
#   Возвращает { Data = все полученные объекты, Failures = компьютеры, не давшие данных, с причиной
#   (Computer, Message), Succeeded = сколько компьютеров ответило }.
#   Локальные: $data - собранные данные; $failures - список сбоев (начинается с OfflineFailures, если есть);
#   $succeeded - счётчик успешных; $child - задание одного компьютера; $items - его данные;
#   $reason / $message - причина сбоя.
function Receive-JobResults {
    param([Parameter(Mandatory)]$Job)

    $data = New-Object System.Collections.ArrayList
    $failures = New-Object System.Collections.ArrayList
    if ($Job.PSObject.Properties['OfflineFailures']) {
        foreach ($f in @($Job.OfflineFailures)) { [void]$failures.Add($f) }
    }
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
# Блокировка по хэшу (без GPO) и блокировка учётной записи
# ===========================================================================

# Блокировка запуска по хэшу теперь не использует Software Restriction Policies/GPO вообще - список
# заблокированных хэшей хранится только в данных приложения (blocks.json) и применяется мониторингом:
# после каждого сканирования (ручного или планового) свежесобранные процессы сверяются с этим списком, и
# совпавшие сразу закрываются (см. Invoke-BlockSweep). Это значит, что между запуском заблокированного файла
# и ближайшим сканированием есть окно - в отличие от SRP, превентивной блокировки запуска здесь нет.

# $script:HashLength - сколько шестнадцатеричных символов в хэше каждого алгоритма (для проверки ввода).
$script:HashLength = @{ MD5 = 32; SHA1 = 40; SHA256 = 64 }

# $script:NotifyTemplate - текст уведомления, которое видит пользователь при закрытии заблокированного файла
#   (имя файла подставляется вместо {0}) - для обычной блокировки, без блокировки учётной записи.
# $script:LockNotifyTemplate - то же самое, но для блокировки с LockAccount=1: дополнительно сообщает, что
#   учётная запись будет заблокирована и для разблокировки нужно обратиться к системному администратору.
# Объявлены здесь, а не в UI-блоке ниже, потому что используются и из Invoke-BlockSweep, которая должна
# работать и в режиме -ScheduledScan - там код до UI-блока вообще не доходит (скрипт завершается раньше,
# см. "if ($ScheduledScan) {...; exit}").
$script:NotifyTemplate = 'Нельзя такое запускать: «{0}» заблокировано политикой безопасности.'
$script:LockNotifyTemplate = 'Нельзя использовать «{0}» - это запрещено политикой безопасности. Ваша учётная запись будет заблокирована. Для разблокировки обратитесь к системному администратору.'

# Test-ProtectedPath - защита от самоубийства домена: возвращает $true, если файл лежит в X:\Windows\...
#   Блокировка по хэшу svchost.exe или explorer.exe остановила бы все компьютеры, поэтому такие файлы
#   блокировать запрещено. -Path  путь к файлу.
function Test-ProtectedPath {
    param([string]$Path)
    if (-not $Path) { return $false }
    return [bool]($Path -match '(?i)^[a-z]:\\windows\\')
}

# Test-HashValue - проверяет, что строка является корректным хэшем: только hex-символы и длина
#   соответствует алгоритму (MD5 - 32, SHA1 - 40, SHA256 - 64). Возвращает $true/$false.
function Test-HashValue {
    param([string]$Algorithm, [string]$Hash)
    return [bool]($Hash -match '^[0-9A-Fa-f]+$' -and $Hash.Length -eq $script:HashLength[$Algorithm])
}

# ===========================================================================
# Журнал в файле
# ===========================================================================

# $script:LogFile - файл журнала на диске (data\logs\processmonitor.log). Записи ДОБАВЛЯЮТСЯ в конец и не стираются
#   при перезапуске программы; при размере больше 5 МБ файл переименовывается в processmonitor.log.1 (старый .1 заменяется).
$script:LogFile = Join-Path $DataPath 'logs\processmonitor.log'
# $script:AccountBlockLogFile - ОТДЕЛЬНЫЙ файл журнала, только для событий блокировки учётных записей
#   (data\logs\account-blocks.log) - выписка из общего журнала специально для аудита этой, самой серьёзной
#   меры: кого, когда и за что заблокировали на уровне домена. Та же ротация, что и у обычного журнала
#   (см. Write-LogFile).
$script:AccountBlockLogFile = Join-Path $DataPath 'logs\account-blocks.log'

# Write-LogFile - дописывает сообщение в файл журнала со строкой даты и времени "гггг-мм-дд чч:мм:сс  сообщение".
#   -Message текст; -Time время записи; -Path какой файл журнала (по умолчанию - основной, $script:LogFile;
#   для аудита блокировок учётных записей передаётся $script:AccountBlockLogFile, см. Write-AccountBlockLog).
#   Файл в UTF-8 с BOM (корректно открывается Блокнотом). Любая ошибка записи
#   (нет прав, файл занят) молча игнорируется: журнал не должен ронять программу.
#   Локальные: $dir - папка журнала; $info - сведения о файле (для проверки размера).
function Write-LogFile {
    param([string]$Message, [datetime]$Time = (Get-Date), [string]$Path = $script:LogFile)
    if (-not $Path) { return }
    try {
        $dir = Split-Path -Parent $Path
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $info = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
        if ($info -and $info.Length -gt 5MB) { Move-Item -LiteralPath $Path -Destination ($Path + '.1') -Force }
        $line = '{0}  {1}{2}' -f $Time.ToString('yyyy-MM-dd HH:mm:ss'), $Message, [Environment]::NewLine
        [System.IO.File]::AppendAllText($Path, $line, (New-Object System.Text.UTF8Encoding($true)))
    }
    catch {
        # ничего: журнал вспомогательный
    }
}

# Write-AccountBlockLog - дописывает строку в ОТДЕЛЬНЫЙ файл журнала блокировок учётных записей
#   ($script:AccountBlockLogFile) - тонкая обёртка над Write-LogFile с другим файлом по умолчанию.
function Write-AccountBlockLog {
    param([string]$Message, [datetime]$Time = (Get-Date))
    Write-LogFile -Message $Message -Time $Time -Path $script:AccountBlockLogFile
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
            Add-BlockRecord -Name 'тест.exe' -Algorithm MD5 -Hash 'aa' -Size 5GB

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
            Add-BlockHit -BlockId 1 -Computer 'PC1' -User 'DOM\иванов' -Path 'C:\тест.exe'
            Add-BlockHit -BlockId 1 -Computer 'PC3' -User 'DOM\petrov' -Path 'C:\тест.exe'
            $blockRow = (Get-BlockTable).Rows | Where-Object { [int]$_.Id -eq 1 }
            Assert-True ($blockRow.EventCount -eq 2) "EventCount: ожидалось 2, получено $($blockRow.EventCount)"
            Assert-True ($blockRow.LastComputer -eq 'PC3' -and $blockRow.LastUser -eq 'DOM\petrov') 'LastComputer/LastUser не обновились последним случаем'
            $hits = Get-BlockHitsTable -BlockId 1
            Assert-True ($hits.Rows.Count -eq 2) "журнал обнаружений: ожидалось 2 записи, получено $($hits.Rows.Count)"
            Assert-True ($hits.Rows[0].Computer -eq 'PC3') 'журнал обнаружений должен быть новыми сверху'
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

# Invoke-AccountLockFollowUp - общая обработка результата Start-BlockApply в части блокировки учётных записей -
#   используется и из UI (Complete-BlockApply), и из headless-sweep (Invoke-BlockSweep в режиме -ScheduledScan).
#   Для каждого владельца из UsersToLock (см. $script:ApplyBlockScript) КАЖДОГО компьютера в результате:
#   отключает его учётную запись в AD (Disable-AdAccount - делается здесь, на машине администратора, а не на
#   удалённом компьютере, где выполнялся сам $script:ApplyBlockScript - см. там же, почему) и пишет исход в
#   отдельный журнал блокировок учётных записей (Write-AccountBlockLog).
#   -Result  итог Receive-JobResults. -BlockLabel  текст для журнала (имя файла и хэш - "'bad.exe' (MD5 ...)").
#   Ничего не возвращает - все эффекты это запись в AD и в файл журнала.
#   Локальные: $r - результат одного компьютера; $owner - "ДОМЕН\логин"; $sam - то же без имени домена;
#   $ok - удалось ли отключить; $status - текст для журнала.
function Invoke-AccountLockFollowUp {
    param([Parameter(Mandatory)]$Result, [string]$BlockLabel = '')
    foreach ($r in $Result.Data) {
        foreach ($owner in @($r.UsersToLock)) {
            $sam = $owner
            $slash = $owner.LastIndexOf('\')
            if ($slash -ge 0) { $sam = $owner.Substring($slash + 1) }
            $ok = Disable-AdAccount -Sam $sam
            $status = if ($ok) { 'учётная запись отключена' } else { 'НЕ УДАЛОСЬ отключить учётную запись (нет прав или учётная запись не найдена)' }
            Write-AccountBlockLog -Message ("Пользователь {0} (компьютер {1}{2}): {3}" -f $owner, $r.Computer, $(if ($BlockLabel) { ", файл $BlockLabel" } else { '' }), $status)
        }
    }
}

# Invoke-BlockSweep - "невод": после КАЖДОГО сканирования (ручного или планового) сверяет свежесобранные строки
#   с активными блокировками (Get-BlockTable) и для каждого совпадения сразу закрывает найденные запущенные
#   экземпляры файла, уведомляет пользователя и, если для этой блокировки включено (LockAccount=1), завершает
#   его сеанс и полностью блокирует его учётную запись в AD. Единственный механизм enforcement в приложении -
#   никакой групповой политики нет, поэтому между запуском заблокированного файла и ближайшим сканированием
#   есть окно (а не мгновенная блокировка, как раньше была бы через SRP).
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
#   $matches - строки сканирования с таким же хэшем; $map - "компьютер -> пути к файлу"; $lockAccount - включена
#   ли для этой блокировки блокировка учётной записи; $notifyText - текст уведомления (обычный или про блокировку
#   учётки); $label - текст для журнала; $job - фоновое задание закрытия; $result - его итог (только в
#   headless-режиме, см. Receive-JobResults).
function Invoke-BlockSweep {
    # [AllowEmptyCollection()] - без неё Mandatory-параметр массива в PowerShell отказывается привязать
    # ПУСТОЙ массив (бросает ошибку ещё до первой строки тела функции) - а пустой $Rows - совершенно
    # нормальный случай (сканирование прошло успешно, но ни один опрошенный компьютер не вернул ни одной
    # строки), который и обрабатывается следующей строкой.
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows)
    if ($Rows.Count -eq 0) { return }
    $blocks = @((Get-BlockTable).Rows | Where-Object { [int]$_.Active -eq 1 })
    if ($blocks.Count -eq 0) { return }

    foreach ($b in $blocks) {
        $algo = [string]$b.Algorithm
        $hash = [string]$b.Hash
        $matches = @($Rows | Where-Object { [string]$_.$algo -eq $hash })
        if ($matches.Count -eq 0) { continue }

        $map = @{}
        $hitEvents = New-Object System.Collections.ArrayList
        $seenHit = @{}
        foreach ($m in $matches) {
            $key = ([string]$m.Computer).ToUpper()
            $path = [string]$m.Path
            if (-not $map.ContainsKey($key)) { $map[$key] = @() }
            if ($map[$key] -notcontains $path) { $map[$key] += $path }
            $hitKey = '{0}|{1}|{2}' -f $key, [string]$m.User, $path
            if (-not $seenHit.ContainsKey($hitKey)) {
                $seenHit[$hitKey] = $true
                [void]$hitEvents.Add(@{ Computer = $key; User = [string]$m.User; Path = $path })
            }
        }
        $lockAccount = [string]$b.LockAccount -eq 'Да'
        $notifyText = if ($lockAccount) { $script:LockNotifyTemplate -f ([string]$b.Name) } else { $script:NotifyTemplate -f ([string]$b.Name) }
        $label = "'{0}' ({1} {2})" -f $b.Name, $algo, $hash

        foreach ($h in $hitEvents) { Add-BlockHit -BlockId ([int]$b.Id) -Computer $h.Computer -User $h.User -Path $h.Path }

        try {
            $job = Start-BlockApply -Map $map -NotifyText $notifyText -LogoffSessions $lockAccount -LockAccount $lockAccount
        }
        catch {
            $msg = "После сканирования: не удалось запустить закрытие $label - $($_.Exception.Message)"
            if ($ScheduledScan) { Write-LogFile -Message $msg } else { Write-Log $msg }
            continue
        }

        $consequence = if ($lockAccount) { ' - закрываю, завершаю сеанс и блокирую учётную запись...' } else { ' - закрываю...' }
        $msg = "После сканирования: заблокированный файл $label обнаружен запущенным на $($map.Count) компьютер(ах)$consequence"
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
            if ($lockAccount) { Invoke-AccountLockFollowUp -Result $result -BlockLabel $label }
        }
        else {
            Write-Log $msg
            Register-UiJob -Job $job -OnDone { param($j) Complete-BlockApply -Job $j -LockAccount $lockAccount -BlockLabel $label }.GetNewClosure()
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
$tabUsers = New-Object System.Windows.Forms.TabPage -Property @{ Text = 'Пользователи' }
$tabLog = New-Object System.Windows.Forms.TabPage -Property @{ Text = 'Журнал' }
$tabs.TabPages.AddRange(@($tabComputers, $tabProcesses, $tabBlocks, $tabUsers, $tabLog))

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
#   $blockBar - панель инструментов; $script:LockAccountCheck - "Также блокировать учётную запись пользователя
#   при обнаружении" - решается один раз на КАЖДУЮ создаваемую блокировку (состояние чекбокса читается в момент
#   нажатия "Заблокировать по хэшу...", сохраняется в самой записи блокировки - LockAccount, см. Add-BlockRecord -
#   и больше не меняется для неё; чтобы изменить решение для уже созданной блокировки, нужно снять её и
#   создать заново). Если включено: при каждом обнаружении запущенным (сразу при блокировке и при каждом
#   следующем сканировании, см. Invoke-BlockSweep) - закрытие файла, уведомление, ПРИНУДИТЕЛЬНОЕ завершение
#   сеанса и ПОЛНОЕ отключение учётной записи пользователя в AD (см. README.md); если выключено - как раньше,
#   только закрытие и уведомление, а завершение сеанса администратор решает каждый раз отдельным вопросом.
#   $btnUnblock - "Снять блокировку"; $btnHitHistory - "История обнаружений" (подробный журнал по выбранной
#   блокировке - время/компьютер/пользователь каждого случая, см. Get-BlockHitsTable); $script:BlockGrid -
#   таблица всех блокировок (Срабатываний/Последнее обнаружение/компьютер/пользователь - теперь считает сама
#   проверка после сканирования, Invoke-BlockSweep, а не журнал событий Windows, как раньше у "Проверить
#   срабатывания" - эта кнопка убрана за ненадобностью).
$blockBar = New-Toolbar
$script:LockAccountCheck = New-Object System.Windows.Forms.CheckBox -Property @{
    Text = 'Также блокировать учётную запись пользователя при обнаружении'; AutoSize = $true
    Margin = (New-Object System.Windows.Forms.Padding(8, 10, 2, 0))
}
$btnUnblock = New-Button 'Снять блокировку' 140
$btnHitHistory = New-Button 'История обнаружений' 170
$blockBar.Controls.AddRange(@($script:LockAccountCheck, $btnUnblock, $btnHitHistory))

$script:BlockGrid = New-Grid
Add-GridColumn $script:BlockGrid 'Дата' 'BlockDate' 140
Add-GridColumn $script:BlockGrid 'Имя' 'Name' 160
Add-GridColumn $script:BlockGrid 'Алгоритм' 'Algorithm' 70
Add-GridColumn $script:BlockGrid 'Хэш' 'Hash' 330 -Mono
Add-GridColumn $script:BlockGrid 'Блокировка учётной записи' 'LockAccount' 160
Add-GridColumn $script:BlockGrid 'Срабатываний' 'EventCount' 100
Add-GridColumn $script:BlockGrid 'Последнее обнаружение' 'LastEventTime' 150
Add-GridColumn $script:BlockGrid 'Последний компьютер' 'LastComputer' 130
Add-GridColumn $script:BlockGrid 'Последний пользователь' 'LastUser' 150
Add-GridColumn $script:BlockGrid 'Статус' 'Status' 100 -Fill

$tabBlocks.Controls.Add($script:BlockGrid)
$tabBlocks.Controls.Add($blockBar)

# --- Вкладка "Пользователи" -------------------------------------------------
# Вкладка "Пользователи": все пользователи домена деревом по подразделениям (OU) - показывает, у кого
# учётная запись отключена (красным) или активна (зелёным); не связана напрямую с блокировками по хэшу - это
# просто общий обзор состояния учётных записей в AD (в т. ч. удобно проверить результат блокировки учётной
# записи, см. "Блокировка учётной записи" в README.md, без необходимости открывать ADUC).
#   $usersBar - панель инструментов; $btnLoadUsers - "Загрузить из AD"; $script:UsersTree - само дерево
#   (правый клик по пользователю - "Включить учётную запись обратно", см. $script:UsersContextMenu и
#   Invoke-RestoreSelectedUser); $script:UserBlockLogBox - журнал блокировок учётных записей снизу (та же
#   выписка, что и в файле data\logs\account-blocks.log - время, пользователь, компьютер, причина).
$usersBar = New-Toolbar
$btnLoadUsers = New-Button 'Загрузить из AD' 140
$usersLegend = New-Label 'Красным - учётная запись отключена; зелёным - активна; правый клик по пользователю - включить обратно'
$usersBar.Controls.AddRange(@($btnLoadUsers, $usersLegend))

$script:UsersTree = New-Object System.Windows.Forms.TreeView
$script:UsersTree.Dock = 'Fill'
$script:UsersTree.Font = New-Object System.Drawing.Font('Segoe UI', 9)

# Контекстное меню по правому клику - только для пользователя (узел OU не несёт Tag, см. Update-UsersTree,
# поэтому для него пункт меню не показывается вовсе - Add_Opening ниже отменяет открытие меню).
$script:UsersContextMenu = New-Object System.Windows.Forms.ContextMenuStrip
$script:RestoreUserMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem('Включить учётную запись обратно')
[void]$script:UsersContextMenu.Items.Add($script:RestoreUserMenuItem)
$script:UsersTree.ContextMenuStrip = $script:UsersContextMenu

$usersLogPanel = New-Object System.Windows.Forms.Panel -Property @{ Dock = 'Bottom'; Height = 160 }
$usersLogLabel = New-Object System.Windows.Forms.Label -Property @{
    Text = 'Журнал блокировок учётных записей:'; Dock = 'Top'; AutoSize = $false; Height = 20
    Padding = (New-Object System.Windows.Forms.Padding(2, 4, 0, 0))
}
$script:UserBlockLogBox = New-Object System.Windows.Forms.TextBox -Property @{
    Multiline = $true; ReadOnly = $true; ScrollBars = 'Vertical'; Dock = 'Fill'
    Font = (New-Object System.Drawing.Font('Consolas', 9)); BackColor = [System.Drawing.Color]::White
}
$usersLogPanel.Controls.Add($script:UserBlockLogBox)
$usersLogPanel.Controls.Add($usersLogLabel)

$tabUsers.Controls.Add($script:UsersTree)
$tabUsers.Controls.Add($usersLogPanel)
$tabUsers.Controls.Add($usersBar)

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

# Update-UsersTree - обработчик "Загрузить из AD" на вкладке "Пользователи": запрашивает всех пользователей
#   (Get-AdUsersWithOuStatus) и строит дерево по подразделениям - узлы верхнего уровня и дальше вглубь - это
#   сами OU, листья - пользователи, подписанные "Имя (логин)" и подсвеченные цветом по статусу учётной записи.
#   Повторный вызов полностью пересобирает дерево (Nodes.Clear()), поэтому безопасно нажимать ещё раз, чтобы
#   увидеть текущее состояние.
#   Локальные: $users - все пользователи с их OU и статусом; $nodeMap - уже созданные узлы OU по полному пути
#   (чтобы не создавать один и тот же узел повторно для разных пользователей из одной OU); $parent - коллекция
#   узлов, в которую сейчас добавляем (меняется на дочернюю на каждом шаге вглубь по OuPath); $path - путь к
#   текущему уровню OU (накопительно, через "\", ключ для $nodeMap); $ouNode/$leaf - создаваемые узлы;
#   $disabledCount - сколько отключённых учётных записей найдено (для строки состояния).
function Update-UsersTree {
    $script:Form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    Set-Status 'Запрос пользователей из AD...'
    $script:UsersTree.Nodes.Clear()
    try {
        $users = @(Get-AdUsersWithOuStatus | Sort-Object { $_.OuPath -join '\' }, Name)
        $nodeMap = @{}
        $disabledCount = 0
        foreach ($u in $users) {
            $path = ''
            $parent = $script:UsersTree.Nodes
            foreach ($seg in $u.OuPath) {
                $path = if ($path) { "$path\$seg" } else { $seg }
                if ($nodeMap.ContainsKey($path)) {
                    $ouNode = $nodeMap[$path]
                }
                else {
                    $ouNode = New-Object System.Windows.Forms.TreeNode($seg)
                    $nodeMap[$path] = $ouNode
                    [void]$parent.Add($ouNode)
                }
                $parent = $ouNode.Nodes
            }
            $leaf = New-Object System.Windows.Forms.TreeNode("$($u.Name) ($($u.Sam))")
            $leaf.Tag = $u.Sam     # отличает лист-пользователя от узла OU (у того Tag не задан) - см. контекстное меню
            if ($u.Disabled) {
                $leaf.BackColor = [System.Drawing.Color]::FromArgb(255, 205, 205)
                $disabledCount++
            }
            else {
                $leaf.BackColor = [System.Drawing.Color]::FromArgb(205, 255, 205)
            }
            $leaf.ForeColor = [System.Drawing.Color]::Black
            [void]$parent.Add($leaf)
        }
        Write-Log "Пользователи AD загружены: всего $($users.Count), отключено $disabledCount"
        Set-Status "Пользователей: $($users.Count), отключено: $disabledCount"
    }
    catch {
        Write-Log "Ошибка запроса пользователей из AD: $($_.Exception.Message)"
        Show-Message -Text "Не удалось получить список пользователей:`n$($_.Exception.Message)" -Icon Error
        Set-Status 'Ошибка запроса пользователей из AD'
    }
    finally {
        $script:Form.Cursor = [System.Windows.Forms.Cursors]::Default
    }
    Update-AccountBlockLogView
}

# Update-AccountBlockLogView - показывает в нижней панели вкладки "Пользователи" последние записи файла
#   data\logs\account-blocks.log (кто, когда, за каким компьютером и за какой файл был заблокирован/включён
#   обратно) - та же выписка, что и на диске, просто без необходимости открывать файл в Блокноте. Вызывается
#   из Update-UsersTree (при каждом обновлении дерева) и из Invoke-RestoreSelectedUser.
#   -Last сколько последних строк показать. $lines - прочитанные строки.
function Update-AccountBlockLogView {
    param([int]$Last = 300)
    if (-not $script:AccountBlockLogFile -or -not (Test-Path -LiteralPath $script:AccountBlockLogFile)) {
        $script:UserBlockLogBox.Text = '(пока нет записей - ни одна учётная запись ещё не блокировалась)'
        return
    }
    try {
        $lines = @(Get-Content -LiteralPath $script:AccountBlockLogFile -Tail $Last -Encoding UTF8)
        $script:UserBlockLogBox.Text = if ($lines.Count -gt 0) { $lines -join [Environment]::NewLine } else { '(пока нет записей)' }
        $script:UserBlockLogBox.SelectionStart = $script:UserBlockLogBox.Text.Length
        $script:UserBlockLogBox.ScrollToCaret()
    }
    catch {
        $script:UserBlockLogBox.Text = "Не удалось прочитать журнал блокировок учётных записей: $($_.Exception.Message)"
    }
}

# Invoke-RestoreSelectedUser - обработчик пункта контекстного меню "Включить учётную запись обратно"
#   (правый клик по пользователю на вкладке "Пользователи"): после подтверждения снимает ACCOUNTDISABLE
#   (Enable-AdAccount), пишет событие в тот же журнал блокировок учётных записей (чтобы включение обратно
#   тоже было видно в аудите - кто, когда) и перестраивает дерево (сразу видно, что строка позеленела).
#   Локальные: $node - выбранный узел дерева; $sam - логин (Tag узла); $label - подпись узла для диалогов.
function Invoke-RestoreSelectedUser {
    $node = $script:UsersTree.SelectedNode
    if (-not $node -or -not $node.Tag) { return }
    $sam = [string]$node.Tag
    $label = $node.Text
    if (-not (Confirm-Action -Title 'Включение учётной записи' -Text (
                "Включить учётную запись «{0}» обратно?`n`nПользователь снова сможет входить в домен." -f $label))) { return }
    try {
        $ok = Enable-AdAccount -Sam $sam
        if ($ok) {
            Write-AccountBlockLog -Message ("Пользователь {0}: учётная запись включена обратно администратором приложения" -f $sam)
            Write-Log "Учётная запись включена обратно: $sam"
            Set-Status "Учётная запись включена обратно: $sam"
            Update-UsersTree
        }
        else {
            Show-Message -Icon Error -Text ("Не удалось включить учётную запись «{0}» обратно - проверьте права на изменение userAccountControl и что учётная запись существует." -f $sam)
        }
    }
    catch {
        Write-Log "Ошибка включения учётной записи $sam : $($_.Exception.Message)"
        Show-Message -Text "Не удалось включить учётную запись:`n$($_.Exception.Message)" -Icon Error
    }
}

# ---------------------------------------------------------------------------
# Сбор процессов
# ---------------------------------------------------------------------------

# Start-Scan - обработчик "Собрать процессы": берёт отмеченные компьютеры и запускает ПРОВЕРКУ ДОСТУПНОСТИ
#   (пинг) в фоновом задании (Start-PingCheck) - не напрямую сбор, см. её комментарий про зависание окна на
#   DNS. Сам сбор (Invoke-Command -AsJob) запускается дальше, из Complete-PingCheck, когда список
#   ответивших компьютеров уже известен. Локальные: $names - имена отмеченных компьютеров; $pingJob - заданиe
#   проверки доступности.
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
    Set-Status "Проверка доступности компьютеров (ping)..."
    try {
        $pingJob = Start-PingCheck -ComputerName $names
    }
    catch {
        Set-ScanBusy $false
        Write-Log "Не удалось запустить проверку доступности: $($_.Exception.Message)"
        Show-Message -Text $_.Exception.Message -Icon Error
        return
    }
    Register-UiJob -Job $pingJob -OnDone { param($job) Complete-PingCheck -Job $job -ComputerName $names }.GetNewClosure()
}

# Complete-PingCheck - вызывается по завершении фонового пинга (Start-PingCheck): теперь, когда известно, кто
#   онлайн, запускает настоящий сбор (Start-RemoteCollection - Invoke-Command -AsJob) и ставит ЕГО на
#   наблюдение таймером, как раньше делал Start-Scan сразу после Start-Collection. -Job завершённое задание
#   пинга; -ComputerName весь исходный список (для RequestedCount/Offline). Локальные: $pingResult -
#   { Online, Offline } (результат Start-PingCheck); $p - прогресс (Done/Total) внутри блока OnProgress.
function Complete-PingCheck {
    param($Job, [string[]]$ComputerName)
    $pingResult = Receive-Job -Job $Job -ErrorAction SilentlyContinue
    Remove-Job -Job $Job -Force -ErrorAction SilentlyContinue
    $online = @($pingResult.Online)
    $offline = @($pingResult.Offline)

    try {
        $script:ScanJob = Start-RemoteCollection -ComputerName $ComputerName -Online $online -Offline $offline
    }
    catch {
        Set-ScanBusy $false
        Write-Log "Не удалось запустить сбор: $($_.Exception.Message)"
        Show-Message -Text $_.Exception.Message -Icon Error
        return
    }
    Set-Status "Опрос компьютеров: 0 из $($ComputerName.Count)"
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
#   -Job завершённое задание. Локальные: $requested - сколько компьютеров опрашивали (весь исходный список,
#   включая отсеянные пингом в Start-Collection - RequestedCount, если есть; иначе, для совместимости,
#   как раньше - число дочерних заданий); $result - итог (см. Receive-JobResults); $f - сбой одного компьютера;
#   $scan - созданное сканирование (Id, Date).
function Complete-Scan {
    param($Job)
    $requested = if ($Job.PSObject.Properties['RequestedCount']) { [int]$Job.RequestedCount } else { @($Job.ChildJobs).Count }
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

# Invoke-BlockSelected - обработчик "Заблокировать по хэшу...". Порядок действий:
#   1) проверки (выбрана строка, хэш корректен, файл не в Windows\, блокировка ещё не действует);
#   2) окно подтверждения (текст зависит от того, включена ли блокировка учётной записи - $script:LockAccountCheck);
#   3) запись добавляется в журнал блокировок (Add-BlockRecord - никакого обращения к GPO, это просто данные
#      приложения); 4) на всех компьютерах, где файл встречался в последнем сканировании, СРАЗУ: завершаются
#      уже запущенные экземпляры файла, их пользователям показывается уведомление, и если включена блокировка
#      учётной записи - принудительно завершается их сеанс и позже (Complete-BlockApply) отключается учётная
#      запись в AD. Дальнейшее обнаружение (если кто-то запустит файл заново) - уже забота Invoke-BlockSweep
#      после следующего сканирования, а не этой функции.
#   Локальные: $row - выбранная строка таблицы; $algorithm / $hash / $name / $path / $size - данные файла;
#   $lockAccount - включена ли блокировка учётной записи (чекбокс); $locations - где хэш найден; $computerCount -
#   на скольких компьютерах; $notifyText - готовый текст уведомления (обычный или про блокировку учётки);
#   $message - текст подтверждения; $map - "компьютер -> пути" для применения; $loc, $key - элемент и ключ при
#   его построении; $logoffSessions - завершать ли сеанс (всегда true, если включена блокировка учётной записи;
#   иначе - отдельный вопрос администратору); $job - фоновое задание применения.
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

    if (-not (Test-HashValue -Algorithm $algorithm -Hash $hash)) {
        Show-Message -Text "У выбранной записи нет корректного $algorithm-хэша." -Icon Warning
        return
    }
    if (Test-ProtectedPath -Path $path) {
        Show-Message -Icon Error -Text ("Файл находится в каталоге Windows:`n{0}`n`nБлокировка системных файлов по хэшу может вывести из строя все компьютеры домена, поэтому она запрещена." -f $path)
        return
    }
    if (Get-ActiveBlock -Algorithm $algorithm -Hash $hash) {
        Show-Message -Text 'Для этого хэша блокировка уже активна (см. вкладку "Блокировки").'
        return
    }

    $lockAccount = $script:LockAccountCheck.Checked
    $locations = Get-HashLocations -Algorithm $algorithm -Hash $hash
    $computerCount = @($locations.Rows | ForEach-Object { $_.Computer } | Select-Object -Unique).Count
    $notifyText = if ($lockAccount) { $script:LockNotifyTemplate -f $name } else { $script:NotifyTemplate -f $name }

    $message = "Заблокировать запуск файла по хэшу?`n`nИмя: $name`n${algorithm}: $hash`nРазмер: $size байт`nПример пути: $path`nНайден на компьютерах (последнее сканирование): $computerCount"
    if ($lockAccount) {
        $message += "`n`nПРИ ОБНАРУЖЕНИИ ЗАПУЩЕННЫМ (сейчас и при каждом следующем сканировании): файл будет " +
            "закрыт, пользователю показано уведомление, его сеанс немедленно завершён, а учётная запись ПОЛНОСТЬЮ " +
            "ОТКЛЮЧЕНА в домене - для возврата доступа потребуется обращение к системному администратору."
    }
    elseif ($computerCount -gt 0) {
        $message += "`n`nНа этих компьютерах сразу после добавления блокировки файл будет закрыт, а пользователю " +
            "показано уведомление:`n`"$notifyText`""
    }
    if (-not (Confirm-Action -Text $message -Title 'Блокировка по хэшу')) { return }

    try {
        Add-BlockRecord -Name $name -Algorithm $algorithm -Hash $hash -Size $size -LockAccount $lockAccount
        Write-Log "Блокировка добавлена: $name ($algorithm $hash)$(if ($lockAccount) { ' [с блокировкой учётной записи]' })"
        Update-BlockGrid
    }
    catch {
        Write-Log "Ошибка блокировки: $($_.Exception.Message)"
        Show-Message -Text "Не удалось добавить блокировку:`n$($_.Exception.Message)" -Icon Error
        return
    }

    if ($locations.Rows.Count -gt 0) {
        # Блокировка учётной записи сама подразумевает завершение сеанса (нет смысла отключать учётную запись,
        # оставляя пользователя в уже открытом сеансе) - отдельный вопрос про завершение сеанса задаётся, только
        # если учётная запись НЕ блокируется; ответ по умолчанию "Нет" (см. Confirm-Action), так как это
        # закрывает ВСЕ программы пользователя на этом компьютере, а не только заблокированный файл.
        $logoffSessions = $lockAccount
        if (-not $lockAccount) {
            $logoffSessions = Confirm-Action -Title 'Завершение сеанса пользователя' -Text (
                "Процесс будет закрыт на найденных компьютерах. Нужно ли дополнительно принудительно завершить сеанс " +
                "пользователя(ей), у которых он был открыт (в целях безопасности и предотвращения нарушений)?`n`n" +
                "Это закроет ВСЕ открытые у них программы на этом компьютере, а не только заблокированный файл, и они " +
                "будут немедленно отключены от сеанса."
            )
        }
        $map = @{}
        foreach ($loc in $locations.Rows) {
            $key = ([string]$loc.Computer).ToUpper()
            if (-not $map.ContainsKey($key)) { $map[$key] = @() }
            $map[$key] += [string]$loc.Path
        }
        $blockId = [int](Get-ActiveBlock -Algorithm $algorithm -Hash $hash)['Id']
        foreach ($loc in $locations.Rows) {
            Add-BlockHit -BlockId $blockId -Computer ([string]$loc.Computer).ToUpper() -User ([string]$loc.User) -Path ([string]$loc.Path)
        }
        $action = 'завершение процессов + уведомление'
        if ($logoffSessions) { $action += ' + завершение сеанса' }
        if ($lockAccount) { $action += ' + блокировка учётной записи' }
        Write-Log "Применение на $($map.Count) компьютерах ($action)..."
        Set-Status "Применение блокировки на $($map.Count) компьютерах..."
        $label = "'$name' ($algorithm $hash)"
        try {
            $job = Start-BlockApply -Map $map -NotifyText $notifyText -LogoffSessions $logoffSessions -LockAccount $lockAccount
            Register-UiJob -Job $job -OnDone { param($j) Complete-BlockApply -Job $j -LockAccount $lockAccount -BlockLabel $label }.GetNewClosure()
        }
        catch {
            Write-Log "Не удалось запустить применение: $($_.Exception.Message)"
        }
    }
    else {
        Show-Message -Text 'Блокировка добавлена. Компьютер, на котором видели этот файл, сейчас не определён (нет данных сканирования) - применится при следующем сканировании (см. "Невод" в README.md). Пересканируйте компьютеры, чтобы проверить сразу.'
    }
}

# Complete-BlockApply - вызывается по завершении применения блокировки (закрытие процессов, уведомление,
#   по желанию - завершение сеанса): пишет в журнал по каждому компьютеру результат (сколько найдено, сколько
#   реально закрыто, сколько уведомлено), а также компьютеры, недоступные по WinRM. Если блокировка с
#   LockAccount - дополнительно отключает учётные записи пойманных пользователей в AD (Invoke-AccountLockFollowUp).
#   -Job завершённое задание; -LockAccount включена ли для этой блокировки блокировка учётной записи;
#   -BlockLabel текст для журнала ("'bad.exe' (MD5 ...)"). Локальные: $result - итог (Receive-JobResults);
#   $r - результат одного компьютера; $f - сбой.
function Complete-BlockApply {
    param($Job, [bool]$LockAccount = $false, [string]$BlockLabel = '')
    $result = Receive-JobResults -Job $Job
    foreach ($r in $result.Data) {
        $line = "[{0}] найдено запущенных: {1}; завершено: {2}; уведомлено пользователей: {3}" -f $r.Computer, $r.Found, $r.Killed, $r.Notified
        if ($r.LoggedOff -gt 0) { $line += "; завершено сеансов: {0}" -f $r.LoggedOff }
        if ($r.Found -gt $r.Killed -and $r.FailReasons) { $line += "; не завершено из-за: $($r.FailReasons)" }
        if ($r.Found -eq 0) { $line += ' (на момент применения процесс уже не был запущен)' }
        if ($r.Error) { $line += "; ошибка: $($r.Error)" }
        Write-Log $line
    }
    foreach ($f in $result.Failures) {
        Write-Log ("[{0}] не применено: {1}" -f $f.Computer, $f.Message)
    }
    if ($LockAccount) {
        Invoke-AccountLockFollowUp -Result $result -BlockLabel $BlockLabel
        # Учётная запись могла только что отключиться (Disable-AdAccount внутри Invoke-AccountLockFollowUp) -
        # обновляем вкладку "Пользователи", ЕСЛИ её уже хоть раз открывали и загружали (Nodes.Count -gt 0):
        # незачем самим лезть в AD, если администратор эту вкладку даже не открывал.
        if ($script:UsersTree.Nodes.Count -gt 0) { Update-UsersTree }
    }
    Set-Status ("Применение завершено: успешно {0}, ошибок {1}" -f $result.Succeeded, $result.Failures.Count)
    # Без этого колонки "Срабатываний"/"Последнее обнаружение"/"Последний компьютер"/"Последний пользователь"
    # на вкладке "Блокировки" не обновлялись сами - Add-BlockHit (вызванный раньше, из Invoke-BlockSweep или
    # Invoke-BlockSelected(Batch), ДО старта этого фонового задания) уже всё посчитал и сохранил на диск, но
    # $script:BlockGrid показывает снимок DataTable на момент последнего Update-BlockGrid, а не живые данные -
    # сама таблица не перерисовывается заново при изменении $script:Blocks в памяти.
    Update-BlockGrid
}

# Invoke-BlockSelectedBatch - обработчик "Заблокировать по хэшу..." при выделении НЕСКОЛЬКИХ строк: для каждого
#   уникального хэша среди них (один и тот же файл, выбранный на разных компьютерах, - это одна блокировка, не
#   несколько) выполняет те же шаги, что Invoke-BlockSelected для одной строки, но с ОДНИМ общим подтверждением
#   и ОДНИМ вопросом про завершение сеанса на весь пакет, а не по разу на каждый файл. Блокировка учётной
#   записи (чекбокс $script:LockAccountCheck) - тоже одна на весь пакет. Уже заблокированные, с некорректным
#   хэшем или защищённым путём файлы молча пропускаются (перечисляются в сообщении, почему), остальные
#   блокируются; ошибка на одном хэше не прерывает обработку остальных - каждая пишется в журнал отдельно.
#   Применение (завершение/уведомление) запускается отдельным фоновым заданием на каждый файл (переиспользует
#   Start-BlockApply без изменений), все они просто стартуют одним нажатием кнопки.
#   -Rows  выбранные строки таблицы процессов (DataRow, как у Invoke-BlockSelected).
#   Локальные: $algorithm - алгоритм хэша (общий, из $script:AlgoCombo); $lockAccount - общая для пакета;
#   $seen - хэши, уже учтённые при разборе (защита от дублей); $toBlock - файлы к блокировке (Name/Hash/Path/Size);
#   $skipped - пропущенные файлы с причиной; $row/$hash/$name/$path/$size - разбор текущей строки;
#   $message - текст общего подтверждения; $anyLocations - есть ли смысл спрашивать про завершение сеанса;
#   $logoffSessions - общий ответ про завершение сеанса; $blocked - сколько файлов реально заблокировано;
#   $item - текущий файл из $toBlock; $locations/$map/$loc/$key/$notifyText/$label/$job -
#   то же самое, что в Invoke-BlockSelected, но внутри цикла по каждому файлу из $toBlock.
function Invoke-BlockSelectedBatch {
    param([Parameter(Mandatory)][object[]]$Rows)

    $algorithm = [string]$script:AlgoCombo.SelectedItem
    $lockAccount = $script:LockAccountCheck.Checked

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

    $message = "Заблокировать запуск $($toBlock.Count) файлов по хэшу?`n`n" +
        (($toBlock | ForEach-Object { "  - $($_.Name)" }) -join "`n")
    if ($skipped.Count -gt 0) { $message += "`n`nПропущено ($($skipped.Count)):`n" + ($skipped -join "`n") }
    if ($lockAccount) {
        $message += "`n`nПРИ ОБНАРУЖЕНИИ ЗАПУЩЕННЫМ (сейчас и при каждом следующем сканировании): файлы будут " +
            "закрыты, пользователям показано уведомление, их сеанс немедленно завершён, а учётные записи ПОЛНОСТЬЮ " +
            "ОТКЛЮЧЕНЫ в домене - для возврата доступа потребуется обращение к системному администратору."
    }
    else {
        $message += "`n`nНа компьютерах, где эти файлы встречались в последнем сканировании, сразу после " +
            "добавления блокировок они будут закрыты, а пользователям показано уведомление."
    }
    if (-not (Confirm-Action -Text $message -Title "Блокировка по хэшу ($($toBlock.Count) файлов)")) { return }

    $anyLocations = $false
    foreach ($item in $toBlock) {
        if ((Get-HashLocations -Algorithm $algorithm -Hash $item.Hash).Rows.Count -gt 0) { $anyLocations = $true; break }
    }
    $logoffSessions = $lockAccount
    if ($anyLocations -and -not $lockAccount) {
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
                Add-BlockRecord -Name $item.Name -Algorithm $algorithm -Hash $item.Hash -Size $item.Size -LockAccount $lockAccount
                Write-Log "Блокировка добавлена: $($item.Name) ($algorithm $($item.Hash))$(if ($lockAccount) { ' [с блокировкой учётной записи]' })"
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
            $notifyText = if ($lockAccount) { $script:LockNotifyTemplate -f $item.Name } else { $script:NotifyTemplate -f $item.Name }
            $label = "'$($item.Name)' ($algorithm $($item.Hash))"
            $blockId = [int](Get-ActiveBlock -Algorithm $algorithm -Hash $item.Hash)['Id']
            foreach ($loc in $locations.Rows) {
                Add-BlockHit -BlockId $blockId -Computer ([string]$loc.Computer).ToUpper() -User ([string]$loc.User) -Path ([string]$loc.Path)
            }
            try {
                $job = Start-BlockApply -Map $map -NotifyText $notifyText -LogoffSessions $logoffSessions -LockAccount $lockAccount
                Register-UiJob -Job $job -OnDone { param($j) Complete-BlockApply -Job $j -LockAccount $lockAccount -BlockLabel $label }.GetNewClosure()
            }
            catch {
                Write-Log "Не удалось запустить применение для $($item.Name): $($_.Exception.Message)"
            }
        }
    }
    finally {
        $script:Form.Cursor = [System.Windows.Forms.Cursors]::Default
    }
    Update-BlockGrid
    Write-Log "Массовая блокировка завершена: добавлено $blocked из $($toBlock.Count)."
    Set-Status "Массовая блокировка: добавлено $blocked из $($toBlock.Count)."
}

# Invoke-UnblockSelected - обработчик "Снять блокировку": помечает запись в журнале снятой. Никакой GPO больше
#   нет, поэтому снятие блокировки - это просто Disable-BlockRecord; после снятия Invoke-BlockSweep перестаёт
#   реагировать на этот хэш при следующих сканированиях. $row - выбранная блокировка; $text - текст подтверждения.
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
    $text = "Снять блокировку?`n`nИмя: $($row['Name'])`n$($row['Algorithm']): $($row['Hash'])`nБлокировка учётной записи: $($row['LockAccount'])"
    if (-not (Confirm-Action -Text $text -Title 'Снятие блокировки')) { return }

    try {
        Disable-BlockRecord -Id ([int]$row['Id'])
        Write-Log "Блокировка снята: $($row['Name']) ($($row['Algorithm']) $($row['Hash']))"
        Update-BlockGrid
    }
    catch {
        Write-Log "Ошибка снятия блокировки: $($_.Exception.Message)"
        Show-Message -Text "Не удалось снять блокировку:`n$($_.Exception.Message)" -Icon Error
    }
}

# Invoke-ShowHitHistory - обработчик "История обнаружений": отдельное окно со всеми отдельными случаями
#   обнаружения выбранной блокировки запущенной (время/компьютер/пользователь/путь), а не только сводкой
#   (Срабатываний/Последнее обнаружение) с основной таблицы - см. Get-BlockHitsTable.
#   Локальные: $row - выбранная блокировка; $win - окно; $grid - таблица обнаружений.
function Invoke-ShowHitHistory {
    if (-not $script:BlockGrid.CurrentRow -or -not $script:BlockGrid.CurrentRow.DataBoundItem) {
        Show-Message -Text 'Выберите блокировку в таблице.' -Icon Warning
        return
    }
    $row = $script:BlockGrid.CurrentRow.DataBoundItem.Row
    $blockId = [int]$row['Id']

    $win = New-Object System.Windows.Forms.Form
    $win.Text = "История обнаружений - '$($row['Name'])' ($($row['Algorithm']) $($row['Hash']))"
    $win.Width = 820
    $win.Height = 480
    $win.StartPosition = 'CenterParent'

    $grid = New-Grid
    Add-GridColumn $grid 'Время' 'Time' 150
    Add-GridColumn $grid 'Компьютер' 'Computer' 130
    Add-GridColumn $grid 'Пользователь' 'User' 170
    Add-GridColumn $grid 'Путь' 'Path' 300 -Fill
    $grid.DataSource = (Get-BlockHitsTable -BlockId $blockId).DefaultView
    $win.Controls.Add($grid)

    [void]$win.ShowDialog($script:Form)
}

# ---------------------------------------------------------------------------
# Обработчики событий
# ---------------------------------------------------------------------------

# Связь кнопок и действий. $i - элемент списка компьютеров; $n - имя, введённое для ручного добавления.
#   "Остановить" останавливает $script:ScanJob; смена сканирования/алгоритма перезагружает таблицу;
#   ввод в поле поиска фильтрует таблицу; при закрытии окна таймер и все фоновые задания останавливаются;
#   при показе окна загружаются сканирования и блокировки, а в журнал пишется путь к папке данных.
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
$btnUnblock.Add_Click({ Invoke-UnblockSelected })
$btnHitHistory.Add_Click({ Invoke-ShowHitHistory })
$btnLoadUsers.Add_Click({ Update-UsersTree })
# Правый клик должен сначала выделить узел под курсором (иначе SelectedNode остаётся старым/пустым) -
# стандартный приём WinForms для контекстного меню по правой кнопке в TreeView.
$script:UsersTree.Add_NodeMouseClick({
        param($sender, $e)
        if ($e.Button -eq [System.Windows.Forms.MouseButtons]::Right) { $script:UsersTree.SelectedNode = $e.Node }
    })
# Меню показывается только для пользователя (Tag задан в Update-UsersTree) - у узла OU Tag пуст, для него
# меню просто не открывается (Cancel = $true), а не показывается с неработающим пунктом.
$script:UsersContextMenu.Add_Opening({
        param($sender, $e)
        if (-not $script:UsersTree.SelectedNode -or -not $script:UsersTree.SelectedNode.Tag) { $e.Cancel = $true }
    })
$script:RestoreUserMenuItem.Add_Click({ Invoke-RestoreSelectedUser })
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
    })

[void]$script:Form.ShowDialog()
