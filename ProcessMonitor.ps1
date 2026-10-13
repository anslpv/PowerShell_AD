#requires -Version 5.1
<#
.SYNOPSIS
    Мониторинг запущенных процессов на компьютерах Active Directory с блокировкой по хэшу.

.DESCRIPTION
    Графическое приложение (WinForms):
      * берёт список компьютеров из AD;
      * по WinRM собирает запущенные процессы и их хэши (MD5 / SHA1 / SHA256);
      * показывает таблицу |№|Дата|Имя|Хэш| (плюс компьютер и путь) и хранит историю в JSON-файлах;
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
#                    .NET-словари). Для записи применяется собственный Write-JsonValue. Если JavaScriptSerializer
#                    недоступен (например, при проверке на PowerShell 7), чтение идёт через ConvertFrom-Json.
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

# Write-JsonValue - дописывает в StringBuilder значение в формате JSON. Рекурсивно обходит словари (IDictionary ->
#   объект {...}), списки и массивы (IEnumerable -> [...]); строки экранируются, числа пишутся в инвариантной культуре.
#   Это собственный сериализатор, а не JavaScriptSerializer: в Windows PowerShell 5.1 тот пытается сериализовать
#   PowerShell-обёртку (PSObject / PSParameterizedProperty) и падает с "обнаружена циклическая ссылка".
#   -Value что записать (словарь, список, строка, число, bool, $null); -Sb куда дописывать.
#   Для скорости строки и числа внутри словаря пишутся прямо в цикле, без отдельного вызова функции.
#   Локальные: $e - запись словаря; $v - её значение; $item - элемент списка; $first - "первый элемент" (для запятых).
function Write-JsonValue {
    param($Value, [System.Text.StringBuilder]$Sb)
    if ($null -eq $Value) { [void]$Sb.Append('null'); return }
    $Value = $Value.psobject.BaseObject      # снять PowerShell-обёртку (.BaseObject напрямую на списках перечислялся бы по элементам)

    if ($Value -is [string]) {
        $t = $Value.Replace('\', '\\').Replace('"', '\"').Replace("`r", '\r').Replace("`n", '\n').Replace("`t", '\t')
        if ($t -match '[\x00-\x1f]') { $t = [regex]::Replace($t, '[\x00-\x1f]', { param($m) '\u{0:x4}' -f [int][char]$m.Value }) }
        [void]$Sb.Append('"').Append($t).Append('"')
        return
    }
    if ($Value -is [bool]) { [void]$Sb.Append($(if ($Value) { 'true' } else { 'false' })); return }
    if ($Value -is [System.Collections.IDictionary]) {
        [void]$Sb.Append('{')
        $first = $true
        foreach ($e in $Value.GetEnumerator()) {
            if (-not $first) { [void]$Sb.Append(',') }
            $first = $false
            [void]$Sb.Append('"').Append(([string]$e.Key).Replace('\', '\\').Replace('"', '\"')).Append('":')     # имена полей - обычные идентификаторы
            $v = $e.Value
            if ($v -is [string]) {
                $t = $v.Replace('\', '\\').Replace('"', '\"')
                if ($t -match '[\x00-\x1f]') { Write-JsonValue -Value $v -Sb $Sb }
                else { [void]$Sb.Append('"').Append($t).Append('"') }
            }
            elseif ($v -is [long] -or $v -is [int]) { [void]$Sb.Append($v.ToString([System.Globalization.CultureInfo]::InvariantCulture)) }
            else { Write-JsonValue -Value $v -Sb $Sb }
        }
        [void]$Sb.Append('}')
        return
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        [void]$Sb.Append('[')
        $first = $true
        foreach ($item in $Value) {
            if (-not $first) { [void]$Sb.Append(',') }
            $first = $false
            Write-JsonValue -Value $item -Sb $Sb
        }
        [void]$Sb.Append(']')
        return
    }
    if ($Value -is [ValueType] -and $Value -isnot [char] -and $Value -isnot [datetime] -and $Value -isnot [enum]) {
        [void]$Sb.Append([Convert]::ToString($Value, [System.Globalization.CultureInfo]::InvariantCulture))
        return
    }
    Write-JsonValue -Value ([string]$Value) -Sb $Sb      # всё прочее (даты, символы, перечисления) - как строка
}

# ConvertTo-JsonText - превращает данные (словари, списки, строки, числа) в текст JSON через Write-JsonValue.
#   -Data что сериализовать. $sb - накапливаемый текст.
function ConvertTo-JsonText {
    param([Parameter(Mandatory)]$Data)
    $sb = New-Object System.Text.StringBuilder
    Write-JsonValue -Value $Data -Sb $sb
    return $sb.ToString()
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
#   Читает JavaScriptSerializer.DeserializeObject (быстро, возвращает чистые .NET-типы). Если его нет - ConvertFrom-Json
#   (на PowerShell 6+ с -AsHashtable, на 5.1 с преобразованием через ConvertTo-PlainData). -Text строка с JSON.
function ConvertFrom-JsonText {
    param([Parameter(Mandatory)][string]$Text)
    if ($script:JsonSerializer) { return $script:JsonSerializer.DeserializeObject($Text) }
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
    if (Test-Path -LiteralPath $Path) { [System.IO.File]::Replace($tmp, $Path, [NullString]::Value) }    # без резервной копии
    else { [System.IO.File]::Move($tmp, $Path) }
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
                Name     = [string]$r.Name
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
#   Возвращает таблицу: ScanDate, Name, Hash, Computer, Path, Size.
#   Локальные: $table - результат; $scan - сканирование из индекса; $doc - прочитанный файл сканирования;
#   $p - процесс из файла. Если файл сканирования потерян, оно пропускается.
function Get-ProcessTable {
    param(
        [int]$ScanId = 0,
        [ValidateSet('MD5', 'SHA1', 'SHA256')][string]$Algorithm = 'MD5'
    )
    $table = New-Object System.Data.DataTable
    [void]$table.Columns.Add('ScanDate', [string])
    [void]$table.Columns.Add('Name', [string])
    [void]$table.Columns.Add('Hash', [string])
    [void]$table.Columns.Add('Computer', [string])
    [void]$table.Columns.Add('Path', [string])
    [void]$table.Columns.Add('Size', [long])

    $table.BeginLoadData()
    for ($i = $script:Scans.Count - 1; $i -ge 0; $i--) {
        $scan = $script:Scans[$i]
        if ($ScanId -gt 0 -and [int]$scan['Id'] -ne $ScanId) { continue }
        $doc = Read-JsonFile -Path (Get-ScanFilePath -Id ([int]$scan['Id']))
        foreach ($p in (Get-JsonList -Document $doc -Key 'Processes')) {
            [void]$table.Rows.Add([string]$scan['ScanDate'], [string]$p['Name'], [string]$p[$Algorithm],
                [string]$p['Computer'], [string]$p['Path'], [long]$p['Size'])
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

# $script:CollectScript - скрипт, который выполняется НА УДАЛЁННОМ компьютере (передаётся в Invoke-Command).
#   Читает Win32_Process, для каждого уникального файла считает MD5/SHA1/SHA256 за один проход чтения
#   и возвращает объекты { Computer, Name, Path, Size, MD5, SHA1, SHA256 }. Работает и в PowerShell 2.0.
#   Локальные: $seen - уже обработанные пути (один файл считается один раз); $algs - три объекта хэширования;
#   $buffer - буфер чтения 1 МБ; $proc - процесс из WMI; $path - путь к exe; $key - путь в нижнем регистре;
#   $stream - открытый файл (разрешено читать запущенные файлы); $n - сколько байт прочитано;
#   $a - текущий алгоритм; $size - размер файла. Недоступные файлы пропускаются.
$script:CollectScript = {
    $ErrorActionPreference = 'Stop'
    $seen = @{}
    $algs = @{
        MD5    = [System.Security.Cryptography.MD5]::Create()
        SHA1   = [System.Security.Cryptography.SHA1]::Create()
        SHA256 = [System.Security.Cryptography.SHA256]::Create()
    }
    $buffer = New-Object byte[] 1048576

    foreach ($proc in (Get-WmiObject -Class Win32_Process)) {
        $path = $proc.ExecutablePath
        if (-not $path) { continue }
        $key = $path.ToLower()
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true

        try {
            $stream = New-Object System.IO.FileStream($path, [System.IO.FileMode]::Open,
                [System.IO.FileAccess]::Read, ([System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete))
            try {
                foreach ($a in $algs.Values) { $a.Initialize() }
                while (($n = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                    foreach ($a in $algs.Values) { [void]$a.TransformBlock($buffer, 0, $n, $null, 0) }
                }
                foreach ($a in $algs.Values) { [void]$a.TransformFinalBlock($buffer, 0, 0) }
                $size = $stream.Length
            }
            finally {
                $stream.Close()
            }
        }
        catch {
            continue    # файл недоступен или удалён - пропускаем
        }

        New-Object PSObject -Property @{
            Computer = $env:COMPUTERNAME
            Name     = $proc.Name
            Path     = $path
            Size     = $size
            MD5      = [BitConverter]::ToString($algs.MD5.Hash).Replace('-', '')
            SHA1     = [BitConverter]::ToString($algs.SHA1.Hash).Replace('-', '')
            SHA256   = [BitConverter]::ToString($algs.SHA256.Hash).Replace('-', '')
        }
    }
}

# $script:ApplyBlockScript - скрипт, который выполняется НА УДАЛЁННОМ компьютере после добавления блокировки:
#   обновляет групповые политики (gpupdate) и завершает уже запущенные экземпляры заблокированного файла.
#   $Map  - хэш-таблица "ИМЯ КОМПЬЮТЕРА (в верхнем регистре) -> массив путей к файлу".
#   Возвращает объект { Computer, GpUpdate ("OK" или код), Killed (сколько процессов завершено), Error }.
#   Локальные: $res - возвращаемый результат; $paths - пути, которые нужно завершить на этом компьютере;
#   $p - процесс из WMI; $r - результат метода Terminate().
$script:ApplyBlockScript = {
    param($Map)
    $res = New-Object PSObject -Property @{
        Computer = $env:COMPUTERNAME
        GpUpdate = ''
        Killed   = 0
        Error    = ''
    }
    try {
        & "$env:windir\System32\gpupdate.exe" /target:computer /force 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) { $res.GpUpdate = 'OK' } else { $res.GpUpdate = 'код ' + $LASTEXITCODE }

        $paths = @($Map[$env:COMPUTERNAME.ToUpper()])
        if ($paths.Count -gt 0) {
            foreach ($p in (Get-WmiObject -Class Win32_Process)) {
                if ($p.ExecutablePath -and ($paths -contains $p.ExecutablePath)) {
                    $r = $p.Terminate()
                    if ($r.ReturnValue -eq 0) { $res.Killed = $res.Killed + 1 }
                }
            }
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

# Start-BlockApply - в фоне запускает $script:ApplyBlockScript на компьютерах, где найден заблокированный файл.
#   -Map  "ИМЯ КОМПЬЮТЕРА -> пути к файлу" (ключи Map - список компьютеров). Возвращает задание.
function Start-BlockApply {
    param([Parameter(Mandatory)][hashtable]$Map)
    Invoke-Command -ComputerName @($Map.Keys) -ScriptBlock $script:ApplyBlockScript `
        -ArgumentList (, $Map) -SessionOption (Get-RemoteSessionOption) -ThrottleLimit 32 `
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
                [pscustomobject]@{ Computer = 'pc1'; Name = 'тест.exe'; Path = "C:\Прог\`"тест`"`t.exe"; Size = 5GB; MD5 = 'aa'; SHA1 = 'bb'; SHA256 = 'cc' },
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
        Assert-True ($mine.Count -eq 1) "не найден собственный процесс: $self"
        foreach ($alg in 'MD5', 'SHA1', 'SHA256') {
            $ref = (Get-FileHash -LiteralPath $self -Algorithm $alg).Hash
            Assert-True ($mine[0].$alg -eq $ref) "$alg не совпал с Get-FileHash"
        }
        'процессов с путями: ' + $collected.Count
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
    Show-Message -Text "Не удалось открыть хранилище данных:`n$($_.Exception.Message)" -Icon Error
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
                $e.Value = $e.RowIndex + 1
                $e.FormattingApplied = $true
            }
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

# Write-Log - добавляет строку "чч:мм:сс  сообщение" в журнал. -Message текст сообщения.
function Write-Log {
    param([string]$Message)
    $script:LogBox.AppendText(('{0}  {1}{2}' -f (Get-Date).ToString('HH:mm:ss'), $Message, [Environment]::NewLine))
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
#   $script:FilterBox - поиск по имени, хэшу, компьютеру и пути; $btnRefresh - "Обновить" (перечитать данные);
#   $btnBlock - "Заблокировать по хэшу..."; $script:ProcGrid - таблица процессов (№, Дата, Имя, Хэш, Компьютер, Путь).
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
Add-GridColumn $script:ProcGrid 'Дата' 'ScanDate' 140
Add-GridColumn $script:ProcGrid 'Имя' 'Name' 180
Add-GridColumn $script:ProcGrid 'Хэш' 'Hash' 330 -Mono
Add-GridColumn $script:ProcGrid 'Компьютер' 'Computer' 130
Add-GridColumn $script:ProcGrid 'Путь' 'Path' 300 -Fill

$tabProcesses.Controls.Add($script:ProcGrid)
$tabProcesses.Controls.Add($procBar)

# --- Вкладка "Блокировки" --------------------------------------------------
# Вкладка "Блокировки":
#   $blockBar - панель инструментов; $script:GpoBox - имя GPO, в которую добавляются правила;
#   $script:LinkBox - DN контейнера, к которому привязать GPO (необязательно);
#   $script:ApplyNowBox - флажок "Сразу применить" (gpupdate + завершение запущенных экземпляров);
#   $btnUnblock - "Снять блокировку"; $script:BlockGrid - таблица всех блокировок.
$blockBar = New-Toolbar
$script:GpoBox = New-Object System.Windows.Forms.TextBox -Property @{ Width = 260; Text = 'Process Hash Block (SRP)'; Margin = (New-Object System.Windows.Forms.Padding(2, 7, 2, 0)) }
$script:LinkBox = New-Object System.Windows.Forms.TextBox -Property @{ Width = 300; Margin = (New-Object System.Windows.Forms.Padding(2, 7, 2, 0)) }
$script:ApplyNowBox = New-Object System.Windows.Forms.CheckBox -Property @{ Text = 'Сразу применить (gpupdate + завершить запущенные)'; AutoSize = $true; Margin = (New-Object System.Windows.Forms.Padding(10, 8, 2, 0)) }
$btnUnblock = New-Button 'Снять блокировку' 140
$blockBar.Controls.AddRange(@((New-Label 'GPO:'), $script:GpoBox, (New-Label 'Привязать к (DN, необязательно):'), $script:LinkBox,
        $script:ApplyNowBox, $btnUnblock))

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
            try {
                if ($item.Job.State -in 'Running', 'NotStarted') {
                    if ($item.OnProgress) { & $item.OnProgress $item.Job }
                }
                else {
                    [void]$script:PendingJobs.Remove($item)
                    & $item.OnDone $item.Job
                }
            }
            catch {
                Write-Log "Ошибка обработки задания: $($_.Exception.Message)"
                [void]$script:PendingJobs.Remove($item)
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
        $script:ProcView.RowFilter = "Name LIKE '%$like%' OR Hash LIKE '%$like%' OR Computer LIKE '%$like%' OR Path LIKE '%$like%'"
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
#      блокировка ещё не действует); 2) окно подтверждения; 3) правило добавляется в GPO и в журнал;
#   4) при флажке "Сразу применить" запускается gpupdate и завершение процессов на найденных компьютерах.
#   Локальные: $row - выбранная строка таблицы; $algorithm / $hash / $name / $path / $size - данные файла;
#   $gpo - имя GPO; $linkTarget - DN для привязки; $locations - где хэш найден; $computerCount - на скольких
#   компьютерах; $applyNow - флажок "Сразу применить"; $message - текст подтверждения; $ruleId - GUID
#   созданного правила; $map - "компьютер -> пути" для применения; $loc, $key - элемент и ключ при его
#   построении; $job - фоновое задание применения.
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
    $linkTarget = $script:LinkBox.Text.Trim()

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

    $locations = Get-HashLocations -Algorithm $algorithm -Hash $hash
    $computerCount = @($locations.Rows | ForEach-Object { $_.Computer } | Select-Object -Unique).Count
    $applyNow = $script:ApplyNowBox.Checked
    $message = "Заблокировать запуск файла по хэшу?`n`nИмя: $name`n${algorithm}: $hash`nРазмер: $size байт`nПример пути: $path`nНайден на компьютерах (последнее сканирование): $computerCount`n`nGPO: $gpo"
    if ($linkTarget) { $message += "`nПривязка: $linkTarget" }
    else { $message += "`nGPO будет создана/изменена; убедитесь, что она привязана к нужному OU." }
    if ($applyNow) { $message += "`n`nНа найденных компьютерах будет выполнен gpupdate, запущенные экземпляры файла будут завершены." }
    if (-not (Confirm-Action -Text $message -Title 'Блокировка по хэшу')) { return }

    $script:Form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    try {
        $ruleId = Add-SrpHashBlock -GpoName $gpo -Name $name -Algorithm $algorithm -Hash $hash -Size $size -LinkTarget $linkTarget
        Add-BlockRecord -Name $name -Algorithm $algorithm -Hash $hash -Size $size -GpoName $gpo -RuleId $ruleId
        Write-Log "Блокировка добавлена: $name ($algorithm $hash), GPO '$gpo', правило $ruleId"
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

    if ($applyNow -and $locations.Rows.Count -gt 0) {
        $map = @{}
        foreach ($loc in $locations.Rows) {
            $key = ([string]$loc.Computer).ToUpper()
            if (-not $map.ContainsKey($key)) { $map[$key] = @() }
            $map[$key] += [string]$loc.Path
        }
        Write-Log "Применение на $($map.Count) компьютерах (gpupdate + завершение процессов)..."
        Set-Status "Применение блокировки на $($map.Count) компьютерах..."
        try {
            $job = Start-BlockApply -Map $map
            Register-UiJob -Job $job -OnDone { param($j) Complete-BlockApply -Job $j }
        }
        catch {
            Write-Log "Не удалось запустить применение: $($_.Exception.Message)"
        }
    }
    else {
        Show-Message -Text 'Правило добавлено в GPO. Клиенты получат его при ближайшем обновлении политик (по умолчанию до 90 минут) или после gpupdate. Уже запущенные процессы не завершаются.'
    }
}

# Complete-BlockApply - вызывается по завершении применения блокировки: пишет в журнал по каждому
#   компьютеру результат gpupdate и число завершённых процессов, а также компьютеры с ошибками.
#   -Job завершённое задание; $result - итог (Receive-JobResults); $r - результат одного компьютера; $f - сбой.
function Complete-BlockApply {
    param($Job)
    $result = Receive-JobResults -Job $Job
    foreach ($r in $result.Data) {
        Write-Log ("[{0}] gpupdate: {1}; завершено процессов: {2}{3}" -f $r.Computer, $r.GpUpdate, $r.Killed,
            $(if ($r.Error) { "; ошибка: $($r.Error)" } else { '' }))
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
$btnUnblock.Add_Click({ Invoke-UnblockSelected })

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
        Write-Log "Данные: $DataPath"
        if (-not (Test-GroupPolicyModule)) {
            Write-Log 'Внимание: модуль GroupPolicy (RSAT) не найден - блокировка будет недоступна.'
        }
    })

[void]$script:Form.ShowDialog()
