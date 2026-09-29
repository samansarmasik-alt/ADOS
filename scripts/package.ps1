$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'start.ps1') -ValidateOnly
if ($LASTEXITCODE -ne 0) { throw 'Runtime package validation failed.' }
$staging = Join-Path $projectRoot ('.tools/package-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $staging -Force | Out-Null
try {
    $files = @('config.json','README.md','THIRD-PARTY.md','VERIFICATION.md',
        'scripts/start.ps1','scripts/dashboard.ps1','scripts/runtime-manifest.json',
        'dist/ados.exe','dist/WinDivert.dll','dist/WinDivert64.sys','dist/WinDivert-LICENSE.txt',
        'models/model.json','models/model.h')
    foreach ($relative in $files) {
        $destination = Join-Path $staging $relative
        New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force | Out-Null
        Copy-Item -LiteralPath (Join-Path $projectRoot $relative) -Destination $destination
    }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = Join-Path $projectRoot ('.tools/payload-' + [Guid]::NewGuid().ToString('N') + '.zip')
    [System.IO.Compression.ZipFile]::CreateFromDirectory($staging, $archive)
    $payload = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($archive))
    $payloadHash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    $bootstrap = (Get-Content -LiteralPath (Join-Path $PSScriptRoot 'bootstrap.ps1.template') -Raw).Replace('__PAYLOAD_BASE64__',$payload).Replace('__PAYLOAD_SHA256__',$payloadHash)
    $encoded = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($bootstrap))
    $lines = [regex]::Matches($encoded, '.{1,128}') | ForEach-Object { $_.Value }
    $header = @'
@echo off
setlocal DisableDelayedExpansion
set "ADOS_PACKAGE_PATH=%~f0"
set "ADOS_VALIDATE_ONLY="
if /i "%~1"=="--check" set "ADOS_VALIDATE_ONLY=1"
set "ADOS_DEMO="
if /i "%~1"=="--demo" set "ADOS_DEMO=1"
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "$p=[IO.File]::ReadAllText($env:ADOS_PACKAGE_PATH);$m=':ADOS_BOOTSTRAP';$i=$p.LastIndexOf($m);if($i -lt 0){throw 'Package missing'};$s=$p.Substring($i+$m.Length);&([scriptblock]::Create([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($s))))"
set "result=%errorlevel%"
if not "%result%"=="0" pause
exit /b %result%
:ADOS_BOOTSTRAP
'@
    $bat = Join-Path $projectRoot 'ADOS.bat'
    [System.IO.File]::WriteAllText($bat, $header + "`r`n" + ($lines -join "`r`n") + "`r`n", [System.Text.Encoding]::ASCII)
    Get-Item -LiteralPath $bat | Select-Object Name, Length
    Write-Output "Embedded runtime SHA256: $payloadHash"
} finally {
    $resolvedStaging = [System.IO.Path]::GetFullPath($staging)
    $allowedRoot = [System.IO.Path]::GetFullPath((Join-Path $projectRoot '.tools')) + [System.IO.Path]::DirectorySeparatorChar
    if (!$resolvedStaging.StartsWith($allowedRoot, [System.StringComparison]::OrdinalIgnoreCase)) { throw 'Package cleanup path outside .tools.' }
    if (Test-Path -LiteralPath $resolvedStaging) { Remove-Item -LiteralPath $resolvedStaging -Recurse -Force }
    if ($archive -and (Test-Path -LiteralPath $archive)) {
        $resolvedArchive = [System.IO.Path]::GetFullPath($archive)
        if (!$resolvedArchive.StartsWith($allowedRoot, [System.StringComparison]::OrdinalIgnoreCase)) { throw 'Payload cleanup path outside .tools.' }
        Remove-Item -LiteralPath $resolvedArchive -Force
    }
}
