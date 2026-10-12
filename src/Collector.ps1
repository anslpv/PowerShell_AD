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
