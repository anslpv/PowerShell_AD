# Хранилище SQLite: результаты сканирований и журнал блокировок.
# Требует $script:AppRoot (папка приложения) и lib\sqlite\System.Data.SQLite.dll.

$script:DbPath = $null
$script:SQLiteLoaded = $false

function Import-SQLite {
    if ($script:SQLiteLoaded) { return }
    $dll = Join-Path $script:AppRoot 'lib\sqlite\System.Data.SQLite.dll'
    if (-not (Test-Path -LiteralPath $dll)) {
        throw "Не найден $dll. Запустите Install-SQLite.ps1 (см. README.md)."
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
