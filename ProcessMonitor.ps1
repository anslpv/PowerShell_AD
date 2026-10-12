#requires -Version 5.1
<#
.SYNOPSIS
    Мониторинг запущенных процессов на компьютерах Active Directory с блокировкой по хэшу.

.DESCRIPTION
    Графическое приложение (WinForms):
      * берёт список компьютеров из AD;
      * по WinRM собирает запущенные процессы и их хэши (MD5 / SHA1 / SHA256);
      * показывает таблицу |№|Дата|Имя|Хэш| (плюс компьютер и путь) и хранит историю в SQLite;
      * блокирует запуск файла с выбранным хэшем хэш-правилом SRP в доменной GPO.

    Скрипт самодостаточный (один файл). Драйвер SQLite скачивается при первом запуске.
    Подробности и требования - в README.md.

.PARAMETER DbPath
    Путь к файлу базы SQLite. По умолчанию data\processes.db рядом со скриптом.
#>
[CmdletBinding()]
param(
    [string]$DbPath
)

# WinForms требует STA; в Windows PowerShell 5.1 консоль обычно уже STA, но не при запуске из ISE/планировщика.
if ([Threading.Thread]::CurrentThread.GetApartmentState() -ne [Threading.ApartmentState]::STA) {
    $relaunch = @('-NoProfile', '-STA', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
    if ($DbPath) { $relaunch += @('-DbPath', "`"$DbPath`"") }
    & powershell.exe @relaunch
    exit $LASTEXITCODE
}

$script:AppRoot = $PSScriptRoot
if (-not $DbPath) { $DbPath = Join-Path $script:AppRoot 'data\processes.db' }

# ===========================================================================
# Хранилище SQLite
# ===========================================================================

# ---------------------------------------------------------------------------
# Драйвер SQLite: System.Data.SQLite скачивается с nuget.org при первом запуске
# ---------------------------------------------------------------------------

function Install-SQLiteDriver {
    param(
        [string]$Version = '1.0.118',
        [string]$Framework = 'net45'    # работает везде, где есть PowerShell 5.1
    )
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Add-Type -AssemblyName System.IO.Compression.FileSystem

    $target = Join-Path $script:AppRoot 'lib\sqlite'
    $package = Join-Path ([IO.Path]::GetTempPath()) ('sqlite-{0}.nupkg' -f [Guid]::NewGuid().ToString('N'))
    $id = 'stub.system.data.sqlite.core.netframework'
    $url = 'https://api.nuget.org/v3-flatcontainer/{0}/{1}/{0}.{1}.nupkg' -f $id, $Version
    $files = @{
        ('lib/{0}/System.Data.SQLite.dll' -f $Framework)   = 'System.Data.SQLite.dll'
        ('build/{0}/x64/SQLite.Interop.dll' -f $Framework) = 'x64\SQLite.Interop.dll'
        ('build/{0}/x86/SQLite.Interop.dll' -f $Framework) = 'x86\SQLite.Interop.dll'
    }

    Invoke-WebRequest -Uri $url -OutFile $package -UseBasicParsing
    $extracted = 0
    $zip = [IO.Compression.ZipFile]::OpenRead($package)
    try {
        foreach ($entry in $zip.Entries) {
            if (-not $files.ContainsKey($entry.FullName)) { continue }
            $dest = Join-Path $target $files[$entry.FullName]
            $destDir = Split-Path -Parent $dest
            if (-not (Test-Path -LiteralPath $destDir)) { New-Item -ItemType Directory -Path $destDir | Out-Null }
            [IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $dest, $true)
            $extracted++
        }
    }
    finally {
        $zip.Dispose()
        Remove-Item -LiteralPath $package -Force -ErrorAction SilentlyContinue
    }
    if ($extracted -ne $files.Count) {
        throw "В пакете $url найдено файлов: $extracted из $($files.Count)."
    }
}

# Хранилище SQLite: результаты сканирований и журнал блокировок.
# Требует $script:AppRoot (папка приложения) и lib\sqlite\System.Data.SQLite.dll.

$script:DbPath = $null
$script:SQLiteLoaded = $false

function Import-SQLite {
    if ($script:SQLiteLoaded) { return }
    $dll = Join-Path $script:AppRoot 'lib\sqlite\System.Data.SQLite.dll'
    if (-not (Test-Path -LiteralPath $dll)) {
        $answer = [System.Windows.Forms.MessageBox]::Show(
            "Не найден драйвер SQLite:`n$dll`n`nСкачать System.Data.SQLite с nuget.org сейчас?",
            'Process Monitor', [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Question)
        if ($answer -ne [System.Windows.Forms.DialogResult]::Yes) {
            throw "Драйвер SQLite не установлен. Положите System.Data.SQLite.dll (+ x64\x86 SQLite.Interop.dll) в $(Split-Path -Parent $dll)."
        }
        Install-SQLiteDriver
    }
    Add-Type -Path $dll
    $script:SQLiteLoaded = $true
}

function Open-Db {
    $conn = New-Object System.Data.SQLite.SQLiteConnection("Data Source=$($script:DbPath);Version=3;")
    $conn.Open()
    return $conn
}

function Add-DbParameters {
    param($Command, [hashtable]$Params)
    if (-not $Params) { return }
    foreach ($key in $Params.Keys) {
        $value = $Params[$key]
        if ($null -eq $value) { $value = [DBNull]::Value }
        [void]$Command.Parameters.AddWithValue("@$key", $value)
    }
}

function Invoke-DbNonQuery {
    param(
        [Parameter(Mandatory)][string]$Sql,
        [hashtable]$Params,
        [object]$Connection
    )
    $own = -not $Connection
    if ($own) { $Connection = Open-Db }
    try {
        $cmd = $Connection.CreateCommand()
        $cmd.CommandText = $Sql
        Add-DbParameters -Command $cmd -Params $Params
        return $cmd.ExecuteNonQuery()
    }
    finally {
        if ($own) { $Connection.Dispose() }
    }
}

function Invoke-DbScalar {
    param(
        [Parameter(Mandatory)][string]$Sql,
        [hashtable]$Params,
        [object]$Connection
    )
    $own = -not $Connection
    if ($own) { $Connection = Open-Db }
    try {
        $cmd = $Connection.CreateCommand()
        $cmd.CommandText = $Sql
        Add-DbParameters -Command $cmd -Params $Params
        return $cmd.ExecuteScalar()
    }
    finally {
        if ($own) { $Connection.Dispose() }
    }
}

function Invoke-DbQuery {
    param(
        [Parameter(Mandatory)][string]$Sql,
        [hashtable]$Params
    )
    $conn = Open-Db
    try {
        $cmd = $conn.CreateCommand()
        $cmd.CommandText = $Sql
        Add-DbParameters -Command $cmd -Params $Params
        $adapter = New-Object System.Data.SQLite.SQLiteDataAdapter($cmd)
        $table = New-Object System.Data.DataTable
        [void]$adapter.Fill($table)
        return , $table
    }
    finally {
        $conn.Dispose()
    }
}

function Initialize-Database {
    param([Parameter(Mandatory)][string]$Path)

    Import-SQLite
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir | Out-Null
    }
    $script:DbPath = $Path

    $schema = @(
        'CREATE TABLE IF NOT EXISTS Scans (
            Id        INTEGER PRIMARY KEY AUTOINCREMENT,
            ScanDate  TEXT    NOT NULL,
            Requested INTEGER NOT NULL DEFAULT 0,
            Succeeded INTEGER NOT NULL DEFAULT 0,
            Failed    INTEGER NOT NULL DEFAULT 0
        )',
        'CREATE TABLE IF NOT EXISTS Processes (
            Id       INTEGER PRIMARY KEY AUTOINCREMENT,
            ScanId   INTEGER NOT NULL REFERENCES Scans(Id),
            ScanDate TEXT    NOT NULL,
            Computer TEXT    NOT NULL,
            Name     TEXT    NOT NULL,
            Path     TEXT,
            Size     INTEGER,
            MD5      TEXT,
            SHA1     TEXT,
            SHA256   TEXT
        )',
        'CREATE INDEX IF NOT EXISTS IX_Processes_Scan     ON Processes (ScanId)',
        'CREATE INDEX IF NOT EXISTS IX_Processes_Computer ON Processes (Computer, ScanId)',
        'CREATE INDEX IF NOT EXISTS IX_Processes_MD5      ON Processes (MD5)',
        'CREATE INDEX IF NOT EXISTS IX_Processes_SHA1     ON Processes (SHA1)',
        'CREATE INDEX IF NOT EXISTS IX_Processes_SHA256   ON Processes (SHA256)',
        'CREATE TABLE IF NOT EXISTS Blocks (
            Id        INTEGER PRIMARY KEY AUTOINCREMENT,
            BlockDate TEXT    NOT NULL,
            Name      TEXT,
            Algorithm TEXT    NOT NULL,
            Hash      TEXT    NOT NULL,
            Size      INTEGER,
            GpoName   TEXT    NOT NULL,
            RuleId    TEXT    NOT NULL,
            Active    INTEGER NOT NULL DEFAULT 1
        )'
    )
    $conn = Open-Db
    try {
        foreach ($sql in $schema) {
            [void](Invoke-DbNonQuery -Sql $sql -Connection $conn)
        }
    }
    finally {
        $conn.Dispose()
    }
}

# ---- Сканирования и процессы -------------------------------------------------

function New-Scan {
    param([int]$Requested)
    $date = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $conn = Open-Db
    try {
        [void](Invoke-DbNonQuery -Connection $conn -Params @{ d = $date; r = $Requested } `
            -Sql 'INSERT INTO Scans (ScanDate, Requested) VALUES (@d, @r)')
        $id = [int](Invoke-DbScalar -Connection $conn -Sql 'SELECT last_insert_rowid()')
    }
    finally {
        $conn.Dispose()
    }
    return [pscustomobject]@{ Id = $id; Date = $date }
}

function Save-Processes {
    param(
        [Parameter(Mandatory)][int]$ScanId,
        [Parameter(Mandatory)][string]$ScanDate,
        [object[]]$Rows,
        [int]$Succeeded,
        [int]$Failed
    )
    $conn = Open-Db
    try {
        $tx = $conn.BeginTransaction()
        try {
            $cmd = $conn.CreateCommand()
            $cmd.Transaction = $tx
            $cmd.CommandText = 'INSERT INTO Processes (ScanId, ScanDate, Computer, Name, Path, Size, MD5, SHA1, SHA256)
                                VALUES (@scan, @date, @comp, @name, @path, @size, @md5, @sha1, @sha256)'
            $p = @{}
            foreach ($n in 'scan', 'date', 'comp', 'name', 'path', 'size', 'md5', 'sha1', 'sha256') {
                $p[$n] = $cmd.Parameters.AddWithValue("@$n", [DBNull]::Value)
            }
            foreach ($r in $Rows) {
                $p.scan.Value = $ScanId
                $p.date.Value = $ScanDate
                $p.comp.Value = ([string]$r.Computer).ToUpper()
                $p.name.Value = [string]$r.Name
                $p.path.Value = [string]$r.Path
                $p.size.Value = [long]$r.Size
                $p.md5.Value = ([string]$r.MD5).ToUpper()
                $p.sha1.Value = ([string]$r.SHA1).ToUpper()
                $p.sha256.Value = ([string]$r.SHA256).ToUpper()
                [void]$cmd.ExecuteNonQuery()
            }
            [void](Invoke-DbNonQuery -Connection $conn -Params @{ id = $ScanId; ok = $Succeeded; bad = $Failed } `
                -Sql 'UPDATE Scans SET Succeeded = @ok, Failed = @bad WHERE Id = @id')
            $tx.Commit()
        }
        catch {
            $tx.Rollback()
            throw
        }
    }
    finally {
        $conn.Dispose()
    }
}

function Get-Scans {
    Invoke-DbQuery -Sql "SELECT Id,
            ScanDate || '  (ПК: ' || Succeeded || ' из ' || Requested || ')' AS Title
        FROM Scans ORDER BY Id DESC"
}

function Get-ProcessTable {
    param(
        [int]$ScanId = 0,
        [ValidateSet('MD5', 'SHA1', 'SHA256')][string]$Algorithm = 'MD5'
    )
    # $Algorithm прошёл ValidateSet, поэтому подставлять его в SQL безопасно.
    $sql = "SELECT ScanDate, Name, $Algorithm AS Hash, Computer, Path, Size FROM Processes"
    $params = @{}
    if ($ScanId -gt 0) {
        $sql += ' WHERE ScanId = @scan'
        $params.scan = $ScanId
    }
    $sql += ' ORDER BY ScanDate DESC, Computer, Name'
    Invoke-DbQuery -Sql $sql -Params $params
}

# Где хэш встречался в последнем сканировании каждого компьютера.
function Get-HashLocations {
    param(
        [Parameter(Mandatory)][ValidateSet('MD5', 'SHA1', 'SHA256')][string]$Algorithm,
        [Parameter(Mandatory)][string]$Hash
    )
    Invoke-DbQuery -Params @{ h = $Hash.ToUpper() } -Sql "SELECT DISTINCT p.Computer, p.Path FROM Processes p
        WHERE p.$Algorithm = @h
          AND p.ScanId = (SELECT MAX(ScanId) FROM Processes WHERE Computer = p.Computer)"
}

# ---- Блокировки ------------------------------------------------------------

function Add-BlockRecord {
    param(
        [string]$Name,
        [Parameter(Mandatory)][string]$Algorithm,
        [Parameter(Mandatory)][string]$Hash,
        [long]$Size,
        [Parameter(Mandatory)][string]$GpoName,
        [Parameter(Mandatory)][string]$RuleId
    )
    [void](Invoke-DbNonQuery -Params @{
            d = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'); n = $Name; a = $Algorithm
            h = $Hash.ToUpper(); s = $Size; g = $GpoName; r = $RuleId
        } -Sql 'INSERT INTO Blocks (BlockDate, Name, Algorithm, Hash, Size, GpoName, RuleId)
                VALUES (@d, @n, @a, @h, @s, @g, @r)')
}

function Get-BlockTable {
    Invoke-DbQuery -Sql "SELECT Id, BlockDate, Name, Algorithm, Hash, GpoName, RuleId, Active,
            CASE Active WHEN 1 THEN 'Активна' ELSE 'Снята' END AS Status
        FROM Blocks ORDER BY Id DESC"
}

function Get-ActiveBlock {
    param([string]$Algorithm, [string]$Hash)
    $t = Invoke-DbQuery -Params @{ a = $Algorithm; h = $Hash.ToUpper() } `
        -Sql 'SELECT * FROM Blocks WHERE Active = 1 AND Algorithm = @a AND Hash = @h LIMIT 1'
    if ($t.Rows.Count -gt 0) { return $t.Rows[0] }
    return $null
}

function Disable-BlockRecord {
    param([Parameter(Mandatory)][int]$Id)
    [void](Invoke-DbNonQuery -Params @{ id = $Id } -Sql 'UPDATE Blocks SET Active = 0 WHERE Id = @id')
}

# ===========================================================================
# Компьютеры AD и удалённый сбор
# ===========================================================================

# Список компьютеров из AD и удалённый сбор запущенных процессов через WinRM.

# Компьютеры домена через ADSI: не требует модуля ActiveDirectory (RSAT),
# поэтому работает и на рабочих станциях, и на контроллерах 2008/2012.
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

# Выполняется на удалённом компьютере. Должен работать в PowerShell 2.0
# (на Windows Server 2008 R2 без WMF 5.1), поэтому только базовый синтаксис.
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

# Применить блокировку сразу: gpupdate и завершение уже запущенных экземпляров.
# $Map: имя компьютера (в верхнем регистре) -> массив путей к файлу.
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

function Get-RemoteSessionOption {
    New-PSSessionOption -OpenTimeout 20000 -OperationTimeout 900000 -NoMachineProfile
}

function Start-Collection {
    param(
        [Parameter(Mandatory)][string[]]$ComputerName,
        [int]$ThrottleLimit = 32
    )
    Invoke-Command -ComputerName $ComputerName -ScriptBlock $script:CollectScript `
        -SessionOption (Get-RemoteSessionOption) -ThrottleLimit $ThrottleLimit `
        -AsJob -JobName 'ProcMon-Collect'
}

function Start-BlockApply {
    param([Parameter(Mandatory)][hashtable]$Map)
    Invoke-Command -ComputerName @($Map.Keys) -ScriptBlock $script:ApplyBlockScript `
        -ArgumentList (, $Map) -SessionOption (Get-RemoteSessionOption) -ThrottleLimit 32 `
        -AsJob -JobName 'ProcMon-Apply'
}

# Сколько дочерних заданий (по одному на компьютер) уже завершилось.
function Get-JobProgress {
    param([Parameter(Mandatory)]$Job)
    $children = @($Job.ChildJobs)
    $done = @($children | Where-Object { $_.State -notin 'Running', 'NotStarted' }).Count
    [pscustomobject]@{ Done = $done; Total = $children.Count }
}

# Забирает результат задания: данные успешных компьютеров и причины сбоев остальных.
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

$script:SrpBase = 'HKLM\Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers'

# Идентификаторы алгоритмов (CALG_*), которые SRP хранит в значении HashAlg.
$script:SrpHashAlg = @{ MD5 = 32771; SHA1 = 32772; SHA256 = 32780 }
$script:HashLength = @{ MD5 = 32; SHA1 = 40; SHA256 = 64 }

# Типы файлов, которые SRP проверяет по умолчанию.
$script:SrpExecutableTypes = @(
    'ADE', 'ADP', 'BAS', 'BAT', 'CHM', 'CMD', 'COM', 'CPL', 'CRT', 'EXE', 'HLP', 'HTA', 'INF', 'INS', 'ISP',
    'LNK', 'MDB', 'MDE', 'MSC', 'MSI', 'MSP', 'MST', 'OCX', 'PCD', 'PIF', 'REG', 'SCR', 'SHS', 'URL', 'VB', 'WSC'
)

function Test-GroupPolicyModule {
    [bool](Get-Module -ListAvailable -Name GroupPolicy)
}

# Системные файлы Windows блокировать нельзя: правило по хэшу svchost.exe или
# explorer.exe выведет из строя весь домен.
function Test-ProtectedPath {
    param([string]$Path)
    if (-not $Path) { return $false }
    return [bool]($Path -match '(?i)^[a-z]:\\windows\\')
}

function ConvertFrom-HexString {
    param([Parameter(Mandatory)][string]$Hex)
    $bytes = New-Object byte[] ($Hex.Length / 2)
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        $bytes[$i] = [Convert]::ToByte($Hex.Substring($i * 2, 2), 16)
    }
    , $bytes
}

function Test-HashValue {
    param([string]$Algorithm, [string]$Hash)
    return [bool]($Hash -match '^[0-9A-Fa-f]+$' -and $Hash.Length -eq $script:HashLength[$Algorithm])
}

# Создаёт GPO (если её нет), задаёт базовые параметры SRP и при необходимости
# привязывает GPO к контейнеру. Существующие значения SRP не перезаписываются.
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

# Добавляет хэш-правило "Запрещено". Возвращает GUID правила в виде {xxxxxxxx-...}.
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

function Remove-SrpHashBlock {
    param(
        [Parameter(Mandatory)][string]$GpoName,
        [Parameter(Mandatory)][string]$RuleId
    )
    Import-Module GroupPolicy -ErrorAction Stop
    $key = '{0}\0\Hashes\{1}' -f $script:SrpBase, $RuleId
    [void](Remove-GPRegistryValue -Name $GpoName -Key $key -ErrorAction Stop)
}


Add-Type -AssemblyName System.Windows.Forms, System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

function Show-Message {
    param(
        [string]$Text,
        [string]$Title = 'Process Monitor',
        [System.Windows.Forms.MessageBoxIcon]$Icon = [System.Windows.Forms.MessageBoxIcon]::Information
    )
    [void][System.Windows.Forms.MessageBox]::Show($Text, $Title, [System.Windows.Forms.MessageBoxButtons]::OK, $Icon)
}

function Confirm-Action {
    param([string]$Text, [string]$Title = 'Подтверждение')
    $answer = [System.Windows.Forms.MessageBox]::Show($Text, $Title,
        [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning,
        [System.Windows.Forms.MessageBoxDefaultButton]::Button2)
    return ($answer -eq [System.Windows.Forms.DialogResult]::Yes)
}

try {
    Initialize-Database -Path $DbPath
}
catch {
    Show-Message -Text "Не удалось открыть базу данных:`n$($_.Exception.Message)" -Icon Error
    exit 1
}

# ---------------------------------------------------------------------------
# Элементы интерфейса
# ---------------------------------------------------------------------------

function New-Label {
    param([string]$Text)
    $l = New-Object System.Windows.Forms.Label
    $l.Text = $Text
    $l.AutoSize = $true
    $l.Margin = New-Object System.Windows.Forms.Padding(8, 8, 2, 0)
    return $l
}

function New-Button {
    param([string]$Text, [int]$Width = 150)
    $b = New-Object System.Windows.Forms.Button
    $b.Text = $Text
    $b.Width = $Width
    $b.Height = 27
    $b.Margin = New-Object System.Windows.Forms.Padding(4, 4, 4, 4)
    return $b
}

function New-Toolbar {
    $p = New-Object System.Windows.Forms.FlowLayoutPanel
    $p.Dock = 'Top'
    $p.AutoSize = $true
    $p.WrapContents = $true
    return $p
}

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
$status = New-Object System.Windows.Forms.StatusStrip
$script:StatusLabel = New-Object System.Windows.Forms.ToolStripStatusLabel -Property @{ Text = 'Готово'; Spring = $true; TextAlign = 'MiddleLeft' }
$script:Progress = New-Object System.Windows.Forms.ToolStripProgressBar -Property @{ Width = 220; Visible = $false }
[void]$status.Items.Add($script:StatusLabel)
[void]$status.Items.Add($script:Progress)

# --- Журнал ----------------------------------------------------------------
$script:LogBox = New-Object System.Windows.Forms.TextBox -Property @{
    Multiline = $true; ReadOnly = $true; ScrollBars = 'Vertical'; Dock = 'Fill'
    Font = (New-Object System.Drawing.Font('Consolas', 9)); BackColor = [System.Drawing.Color]::White
}
$tabLog.Controls.Add($script:LogBox)

function Write-Log {
    param([string]$Message)
    $script:LogBox.AppendText(('{0}  {1}{2}' -f (Get-Date).ToString('HH:mm:ss'), $Message, [Environment]::NewLine))
}

function Set-Status {
    param([string]$Text)
    $script:StatusLabel.Text = $Text
}

# --- Вкладка "Компьютеры" --------------------------------------------------
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

$script:PendingJobs = New-Object System.Collections.ArrayList
$script:ScanJob = $null

function Register-UiJob {
    param($Job, [scriptblock]$OnProgress, [scriptblock]$OnDone)
    [void]$script:PendingJobs.Add(@{ Job = $Job; OnProgress = $OnProgress; OnDone = $OnDone })
}

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
    Save-Processes -ScanId $scan.Id -ScanDate $scan.Date -Rows $result.Data.ToArray() `
        -Succeeded $result.Succeeded -Failed $result.Failures.Count
    Write-Log ("Сбор завершён: компьютеров {0} из {1}, записей {2}" -f $result.Succeeded, $requested, $result.Data.Count)
    Set-Status ("Сбор завершён: компьютеров {0} из {1}, записей {2}" -f $result.Succeeded, $requested, $result.Data.Count)

    Update-ScanList -SelectScanId $scan.Id
    $tabs.SelectedTab = $tabProcesses
}

# ---------------------------------------------------------------------------
# Таблица процессов
# ---------------------------------------------------------------------------

$script:Loading = $false
$script:ProcView = $null

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

function Update-BlockGrid {
    $script:BlockGrid.DataSource = (Get-BlockTable).DefaultView
}

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
        Write-Log "База данных: $DbPath"
        if (-not (Test-GroupPolicyModule)) {
            Write-Log 'Внимание: модуль GroupPolicy (RSAT) не найден - блокировка будет недоступна.'
        }
    })

[void]$script:Form.ShowDialog()
