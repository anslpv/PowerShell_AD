<#
.SYNOPSIS
    Скачивает System.Data.SQLite (NuGet) в папку lib\sqlite рядом со скриптом.

.DESCRIPTION
    ProcessMonitor.ps1 хранит данные в SQLite, а в PowerShell 5.1 / .NET Framework
    встроенного драйвера SQLite нет. Скрипт берёт пакет
    Stub.System.Data.SQLite.Core.NetFramework с nuget.org и раскладывает файлы так:

        lib\sqlite\System.Data.SQLite.dll
        lib\sqlite\x64\SQLite.Interop.dll
        lib\sqlite\x86\SQLite.Interop.dll

    Запускать нужно один раз, на машине с доступом к nuget.org. Если доступа нет,
    скачайте пакет вручную на другой машине и скопируйте папку lib\sqlite целиком.

.PARAMETER Version
    Версия пакета на nuget.org.

.PARAMETER Framework
    Сборка под какую версию .NET брать (net40, net45, net451, net46).
    net45 работает на любой системе, где есть PowerShell 5.1.
#>
[CmdletBinding()]
param(
    [string]$Version = '1.0.118',
    [ValidateSet('net40', 'net45', 'net451', 'net46')]
    [string]$Framework = 'net45'
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Add-Type -AssemblyName System.IO.Compression.FileSystem

$target = Join-Path $PSScriptRoot 'lib\sqlite'
$package = Join-Path ([IO.Path]::GetTempPath()) ('sqlite-{0}.nupkg' -f [Guid]::NewGuid().ToString('N'))
$id = 'stub.system.data.sqlite.core.netframework'
$url = 'https://api.nuget.org/v3-flatcontainer/{0}/{1}/{0}.{1}.nupkg' -f $id, $Version

$files = @{
    ('lib/{0}/System.Data.SQLite.dll' -f $Framework)       = 'System.Data.SQLite.dll'
    ('build/{0}/x64/SQLite.Interop.dll' -f $Framework)     = 'x64\SQLite.Interop.dll'
    ('build/{0}/x86/SQLite.Interop.dll' -f $Framework)     = 'x86\SQLite.Interop.dll'
}

Write-Host "Скачиваю $url"
Invoke-WebRequest -Uri $url -OutFile $package -UseBasicParsing

$extracted = 0
$zip = [IO.Compression.ZipFile]::OpenRead($package)
try {
    foreach ($entry in $zip.Entries) {
        if (-not $files.ContainsKey($entry.FullName)) { continue }
        $dest = Join-Path $target $files[$entry.FullName]
        $destDir = Split-Path -Parent $dest
        if (-not (Test-Path -LiteralPath $destDir)) {
            New-Item -ItemType Directory -Path $destDir | Out-Null
        }
        [IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $dest, $true)
        Write-Host "  -> $dest"
        $extracted++
    }
}
finally {
    $zip.Dispose()
    Remove-Item -LiteralPath $package -Force -ErrorAction SilentlyContinue
}

if ($extracted -ne $files.Count) {
    throw "В пакете найдено $extracted файлов из $($files.Count) ожидаемых. Проверьте -Version / -Framework."
}
Write-Host 'Готово. Теперь можно запускать ProcessMonitor.ps1.'
