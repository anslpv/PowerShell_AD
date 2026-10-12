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
