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
      * блокирует запуск файла с выбранным хэшем хэш-правилом SRP в доменной GPO.

    Скрипт самодостаточный (один файл), сторонних драйверов не требует.
    Подробности и требования - в README.md.

.PARAMETER SelfTest
    Не открывать окно, а проверить на этом компьютере всё, от чего зависит работа (версия PowerShell, JSON-хранилище,
    хэширование, Windows Forms, WinRM, AD, модуль GroupPolicy), и вывести [ OK ] / [WARN] / [FAIL] по каждому пункту.

.PARAMETER DataPath
    Папка для JSON-файлов с данными. По умолчанию data рядом со скриптом. Прежнее имя -DbPath работает как псевдоним.
#>
[CmdletBinding()]
param(
    [Alias('DbPath')]
    [string]$DataPath,
    [switch]$SelfTest
)

# WinForms требует STA; в Windows PowerShell 5.1 консоль обычно уже STA, но не при запуске из ISE/планировщика.
# Перезапуск возможен только если известен путь к файлу скрипта ($PSCommandPath пуст при вставке кода в консоль или F8 в ISE).
if ($PSCommandPath -and [Threading.Thread]::CurrentThread.GetApartmentState() -ne [Threading.ApartmentState]::STA) {
    $relaunch = @('-NoProfile', '-STA', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
    if ($DataPath) { $relaunch += @('-DataPath', "`"$DataPath`"") }
    if ($SelfTest) { $relaunch += '-SelfTest' }
    & powershell.exe @relaunch
    exit $LASTEXITCODE
}

# ПЕРЕМЕННЫЕ ВЕРХНЕГО УРОВНЯ
#   $SelfTest         - параметр-переключатель: выполнить самопроверку (Invoke-SelfTest) вместо открытия окна.
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
        [Parameter(Mandatory)][string]$RuleId
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
#   Поле Status: "Активна" (Active=1) или "Снята".
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
    for ($i = $script:Blocks.Count - 1; $i -ge 0; $i--) {
        $b = $script:Blocks[$i]
        $status = if ([int]$b['Active'] -eq 1) { 'Активна' } else { 'Снята' }
        [void]$table.Rows.Add([int]$b['Id'], [string]$b['BlockDate'], [string]$b['Name'], [string]$b['Algorithm'],
            [string]$b['Hash'], [string]$b['GpoName'], [string]$b['RuleId'], [int]$b['Active'], $status)
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
#   Возвращает объект { Computer, GpUpdate ("OK" или код), TerminateRequested, Found (сколько запущенных экземпляров
#   найдено - считается независимо от TerminateRequested), Killed (сколько реально завершено),
#   Notified (скольким пользователям показано уведомление), LoggedOff (сколько сеансов принудительно завершено -
#   один раз на сеанс (SessionId), даже если в нём было несколько запущенных экземпляров), FailReasons (причины
#   неудач метода Terminate, без повторов), Error }.
#   Found может быть больше Killed: причина - в FailReasons (чаще всего нет прав на завершение процесса).
#   Found = 0 при непустом $paths значит, что на момент применения процесс с таким путём уже не запущен
#   (завершился сам, или путь в данных сканирования устарел). Уведомление и завершение сеанса выполняются, только
#   если процесс реально завершён (TRUE Kill), и только один раз на пользователя/сеанс, даже если он держал
#   открытыми несколько копий файла.
#   Локальные: $res - возвращаемый результат; $paths - пути, по которым ищем запущенные экземпляры;
#   $reasonMap - код возврата Terminate() -> текст причины; $notified - кому уведомление уже отправлено;
#   $loggedOff - какие сеансы (SessionId) уже завершены в этом запуске (защита от дублей, если у пользователя
#   было несколько запущенных экземпляров в одном сеансе); $p - процесс из WMI; $owner - владелец именно этого
#   запущенного экземпляра (берётся заново через GetOwner(), а не из данных сканирования - на момент блокировки
#   им может быть уже другой пользователь); $r - результат Terminate(); $reason - текст причины для конкретного кода.
$script:ApplyBlockScript = {
    param($Map, $TerminateProcesses, $NotifyText = 'Нельзя такое запускать: этот файл заблокирован политикой безопасности.', $LogoffSessions = $false)
    $res = New-Object PSObject -Property @{
        Computer           = $env:COMPUTERNAME
        GpUpdate           = ''
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
        & "$env:windir\System32\gpupdate.exe" /target:computer /force 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) { $res.GpUpdate = 'OK' } else { $res.GpUpdate = 'код ' + $LASTEXITCODE }

        $paths = @($Map[$env:COMPUTERNAME.ToUpper()])
        if ($paths.Count -gt 0) {
            $reasons = @{}
            $notified = @{}
            $loggedOff = @{}
            foreach ($p in (Get-WmiObject -Class Win32_Process)) {
                if ($p.ExecutablePath -and ($paths -contains $p.ExecutablePath)) {
                    $res.Found = $res.Found + 1
                    if ($TerminateProcesses) {
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
    param([Parameter(Mandatory)][hashtable]$Map, [bool]$TerminateProcesses = $false, [string]$NotifyText, [bool]$LogoffSessions = $false)
    Invoke-Command -ComputerName @($Map.Keys) -ScriptBlock $script:ApplyBlockScript `
        -ArgumentList $Map, $TerminateProcesses, $NotifyText, $LogoffSessions -SessionOption (Get-RemoteSessionOption) -ThrottleLimit 32 `
        -AsJob -JobName 'ProcMon-Apply'
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

# $script:SrpBase - раздел реестра политики SRP (в GPO он пишется в Registry.pol этого раздела).
$script:SrpBase = 'HKLM\Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers'

# $script:SrpHashAlg - код алгоритма хэша для значения HashAlg правила SRP (MD5=0x8003, SHA1=0x8004, SHA256=0x800C).
$script:SrpHashAlg = @{ MD5 = 32771; SHA1 = 32772; SHA256 = 32780 }
# $script:HashLength - сколько шестнадцатеричных символов в хэше каждого алгоритма (для проверки ввода).
$script:HashLength = @{ MD5 = 32; SHA1 = 40; SHA256 = 64 }

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

# Initialize-SrpGpo - готовит GPO к хранению правил: создаёт её, если нет; записывает базовые параметры
#   SRP (если их ещё нет - существующие не перезаписываются); при необходимости привязывает к OU/домену.
#   -GpoName  имя GPO; -LinkTarget  DN контейнера для привязки (пусто - не привязывать). Возвращает GPO.
#   Локальные: $gpo - объект GPO; $hasBase - есть ли в GPO базовые настройки SRP;
#   $base - раздел реестра; $linked - уже привязана ли GPO к контейнеру.
#   Базовые значения: DefaultLevel=262144 ("Неограниченный": всё, что не запрещено, работает), TransparentEnabled=1,
#   PolicyScope=0 (все пользователи), AuthenticodeEnabled=0, ExecutableTypes (список расширений).
function Initialize-SrpGpo {
    param(
        [Parameter(Mandatory)][string]$GpoName,
        [string]$LinkTarget
    )
    Import-Module GroupPolicy -ErrorAction Stop

    $gpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
    if (-not $gpo) {
        $gpo = New-GPO -Name $GpoName -Comment 'Блокировка процессов по хэшу (создано ProcessMonitor)' -ErrorAction Stop
    }

    $hasBase = $true
    try {
        [void](Get-GPRegistryValue -Name $GpoName -Key $script:SrpBase -ValueName DefaultLevel -ErrorAction Stop)
    }
    catch {
        $hasBase = $false
    }
    if (-not $hasBase) {
        $base = $script:SrpBase
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
    return $gpo
}

# Add-SrpHashBlock - добавляет в GPO хэш-правило уровня "Запрещено". Возвращает GUID правила "{xxxxxxxx-...}".
#   -GpoName, -LinkTarget  GPO и привязка (см. Initialize-SrpGpo); -Name  имя файла (для описания правила);
#   -Algorithm и -Hash  хэш; -Size  размер файла (SRP сверяет и его).
#   Значения правила в реестре: ItemData (хэш в байтах), ItemSize (размер), HashAlg (алгоритм), SaferFlags=0,
#   LastModified (дата изменения), Description (описание).
#   Локальные: $ruleId - GUID нового правила; $key - раздел реестра правила; $bytes - хэш в байтах;
#   $description - текст описания.
function Add-SrpHashBlock {
    param(
        [Parameter(Mandatory)][string]$GpoName,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][ValidateSet('MD5', 'SHA1', 'SHA256')][string]$Algorithm,
        [Parameter(Mandatory)][string]$Hash,
        [long]$Size,
        [string]$LinkTarget
    )
    if (-not (Test-HashValue -Algorithm $Algorithm -Hash $Hash)) {
        throw "Некорректный $Algorithm-хэш: '$Hash'."
    }
    [void](Initialize-SrpGpo -GpoName $GpoName -LinkTarget $LinkTarget)

    $ruleId = [Guid]::NewGuid().ToString('B')
    $key = '{0}\0\Hashes\{1}' -f $script:SrpBase, $ruleId
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

# Remove-SrpHashBlock - удаляет правило из GPO по его GUID. -GpoName  имя GPO; -RuleId  GUID из журнала блокировок.
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
        [Parameter(Mandatory)][string]$RuleId
    )
    Import-Module GroupPolicy -ErrorAction Stop
    $key = '{0}\0\Hashes\{1}' -f $script:SrpBase, $RuleId
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
#   Локальные: $g - таблица; $num - колонка "№"; в обработчике CellFormatting $e - данные отрисовываемой ячейки.
function New-Grid {
    $g = New-Object System.Windows.Forms.DataGridView
    $g.Dock = 'Fill'
    $g.ReadOnly = $true
    $g.AllowUserToAddRows = $false
    $g.AllowUserToDeleteRows = $false
    $g.AllowUserToResizeRows = $false
    $g.SelectionMode = 'FullRowSelect'
    $g.MultiSelect = $false
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
$compBar.Controls.AddRange(@($btnLoadAd, (New-Label 'OU (DN, необязательно):'), $script:SearchBaseBox,
        $btnAll, $btnNone, (New-Label 'Добавить вручную:'), $script:ManualBox, $btnAddManual, $btnScan, $btnStop))

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
#   $btnBlock - "Заблокировать по хэшу..."; $script:ProcGrid - таблица процессов (№, время запуска процесса, Имя, Хэш, Компьютер, Пользователь, Путь).
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

$script:ProcGrid = New-Grid
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
#   $blockBar - панель инструментов; $script:GpoBox - имя GPO, в которую добавляются правила;
#   $script:LinkCombo - DN контейнера, к которому привязать GPO (необязательно); редактируемый выпадающий
#   список: можно вставить/набрать DN вручную, а можно выбрать OU из списка, который загружает $btnLoadOUs
#   (см. Import-AdOUs) - пункты показываются как "Имя OU — DN", а при блокировке используется только DN
#   (после последнего " — " в тексте поля; если разделителя нет - весь текст считается DN, как раньше).
#   На известных компьютерах (где файл встречался в последнем сканировании) блокировка автоматически: обновляет
#   политики (gpupdate), завершает уже запущенные экземпляры файла и показывает каждому затронутому пользователю
#   уведомление $script:NotifyTemplate (имя файла подставляется вместо {0}) - всё без отдельных флажков.
#   $btnUnblock - "Снять блокировку"; $script:BlockGrid - таблица всех блокировок.
$script:NotifyTemplate = 'Нельзя такое запускать: «{0}» заблокировано политикой безопасности.'
$blockBar = New-Toolbar
$script:GpoBox = New-Object System.Windows.Forms.TextBox -Property @{ Width = 260; Text = 'Process Hash Block (SRP)'; Margin = (New-Object System.Windows.Forms.Padding(2, 7, 2, 0)) }
$script:LinkCombo = New-Object System.Windows.Forms.ComboBox -Property @{ Width = 340; DropDownStyle = 'DropDown'; Margin = (New-Object System.Windows.Forms.Padding(2, 5, 2, 0)) }
$btnLoadOUs = New-Button 'Загрузить OU из AD' 160
$btnUnblock = New-Button 'Снять блокировку' 140
$blockBar.Controls.AddRange(@((New-Label 'GPO:'), $script:GpoBox, (New-Label 'Привязать к (DN, можно выбрать из списка):'), $script:LinkCombo,
        $btnLoadOUs, $btnUnblock))

$script:BlockGrid = New-Grid
Add-GridColumn $script:BlockGrid 'Дата' 'BlockDate' 140
Add-GridColumn $script:BlockGrid 'Имя' 'Name' 160
Add-GridColumn $script:BlockGrid 'Алгоритм' 'Algorithm' 70
Add-GridColumn $script:BlockGrid 'Хэш' 'Hash' 330 -Mono
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
    $gpo = $script:GpoBox.Text.Trim()
    $linkTarget = ConvertTo-LinkTargetDn -Text $script:LinkCombo.Text

    if (-not $gpo) {
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
    $message = "Заблокировать запуск файла по хэшу?`n`nИмя: $name`n${algorithm}: $hash`nРазмер: $size байт`nПример пути: $path`nНайден на компьютерах (последнее сканирование): $computerCount`n`nGPO: $gpo"
    if ($linkTarget) { $message += "`nПривязка: $linkTarget" }
    else { $message += "`nGPO будет создана/изменена; убедитесь, что она привязана к нужному OU." }
    if ($computerCount -gt 0) {
        $message += "`n`nНа этих компьютерах сразу после добавления правила: обновятся политики (gpupdate), будут" +
            " закрыты уже запущенные экземпляры файла, а их пользователям будет показано сообщение:`n`"$notifyText`""
    }
    if (-not (Confirm-Action -Text $message -Title 'Блокировка по хэшу')) { return }

    $script:Form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    try {
        $ruleId = Add-SrpHashBlock -GpoName $gpo -Name $name -Algorithm $algorithm -Hash $hash -Size $size -LinkTarget $linkTarget
        Add-BlockRecord -Name $name -Algorithm $algorithm -Hash $hash -Size $size -GpoName $gpo -RuleId $ruleId
        Write-Log "Блокировка добавлена: $name ($algorithm $hash), GPO '$gpo', правило $ruleId"
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
        $action = 'gpupdate + завершение процессов + уведомление'
        if ($logoffSessions) { $action += ' + завершение сеанса' }
        Write-Log "Применение на $($map.Count) компьютерах ($action)..."
        Set-Status "Применение блокировки на $($map.Count) компьютерах..."
        try {
            $job = Start-BlockApply -Map $map -TerminateProcesses $true -NotifyText $notifyText -LogoffSessions $logoffSessions
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
    $text = "Снять блокировку?`n`nИмя: $($row['Name'])`n$($row['Algorithm']): $($row['Hash'])`nGPO: $($row['GpoName'])"
    if (-not (Confirm-Action -Text $text -Title 'Снятие блокировки')) { return }

    $script:Form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    try {
        Remove-SrpHashBlock -GpoName ([string]$row['GpoName']) -RuleId ([string]$row['RuleId'])
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
$script:ScanCombo.Add_SelectedIndexChanged({ Update-ProcessGrid })
$script:AlgoCombo.Add_SelectedIndexChanged({ Update-ProcessGrid })
$script:FilterBox.Add_TextChanged({ Update-ProcessFilter })
$btnRefresh.Add_Click({ Update-ScanList })
$btnBlock.Add_Click({ Invoke-BlockSelected })
$btnLoadOUs.Add_Click({ Import-AdOUs })
$btnUnblock.Add_Click({ Invoke-UnblockSelected })
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
