$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $projectRoot
$parseFailed = $false
Get-ChildItem -LiteralPath $PSScriptRoot -Filter '*.ps1' -File | ForEach-Object {
    $tokens = $null
    $parseErrors = $null
    [System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$tokens, [ref]$parseErrors) | Out-Null
    if ($parseErrors.Count -gt 0) {
        $parseFailed = $true
        $parseErrors | ForEach-Object { Write-Output $_.Message }
    }
}
if ($parseFailed) { throw 'PowerShell syntax validation failed.' }
Write-Output 'PowerShell syntax validation: passed.'
& powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'start.ps1') -ValidateOnly
if ($LASTEXITCODE -ne 0) { throw 'Runtime package validation failed.' }
$executable = Join-Path $projectRoot 'dist/ados.exe'
foreach ($argument in @('--check', '--self-test', '--benchmark', '--status')) {
    & $executable $argument
    if ($LASTEXITCODE -ne 0) { throw "Native validation failed: $argument" }
}
$scratch = Join-Path $projectRoot ('.tools/verification-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path (Join-Path $scratch 'scripts'), (Join-Path $scratch 'dist') -Force | Out-Null
try {
    foreach ($relative in @('scripts/start.ps1','scripts/runtime-manifest.json','dist/ados.exe','dist/WinDivert.dll','dist/WinDivert64.sys','config.json')) {
        Copy-Item -LiteralPath (Join-Path $projectRoot $relative) -Destination (Join-Path $scratch $relative)
    }
    $scratchManifest = Join-Path $scratch 'scripts/runtime-manifest.json'
    $scratchConfig = Join-Path $scratch 'config.json'
    $originalManifest = Get-Content -LiteralPath $scratchManifest -Raw
    $originalConfig = Get-Content -LiteralPath $scratchConfig -Raw
    function Assert-PackageRejected([string]$reason) {
        $ErrorActionPreference = 'Continue'
        $messages = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $scratch 'scripts/start.ps1') -ValidateOnly 2>&1
        if ($LASTEXITCODE -eq 0) { throw "Unsafe package accepted: $reason" }
        Write-Output "Negative validation passed: $reason"
    }
    $dll = Join-Path $scratch 'dist/WinDivert.dll'
    $stream = [System.IO.File]::OpenWrite($dll)
    try { $stream.WriteByte(0) } finally { $stream.Dispose() }
    Assert-PackageRejected 'changed DLL bytes'
    Copy-Item -LiteralPath (Join-Path $projectRoot 'dist/WinDivert.dll') -Destination $dll -Force
    $manifest = $originalManifest | ConvertFrom-Json
    $manifest.files[1] = $manifest.files[0]
    $manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $scratchManifest -Encoding UTF8
    Assert-PackageRejected 'duplicate manifest entries'
    $originalManifest | Set-Content -LiteralPath $scratchManifest -Encoding UTF8
    $config = $originalConfig | ConvertFrom-Json
    $config.synLimit = 1.5
    $config | ConvertTo-Json | Set-Content -LiteralPath $scratchConfig -Encoding UTF8
    Assert-PackageRejected 'fractional rate limit'
    $config.synLimit = 1000001
    $config | ConvertTo-Json | Set-Content -LiteralPath $scratchConfig -Encoding UTF8
    Assert-PackageRejected 'rate limit above bound'
    $originalConfig | Set-Content -LiteralPath $scratchConfig -Encoding UTF8
    $manifest = $originalManifest | ConvertFrom-Json
    $manifest.driverThumbprint = '0000000000000000000000000000000000000000'
    $manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $scratchManifest -Encoding UTF8
    Assert-PackageRejected 'wrong driver certificate pin'
} finally {
    $resolvedScratch = [System.IO.Path]::GetFullPath($scratch)
    $allowedRoot = [System.IO.Path]::GetFullPath((Join-Path $projectRoot '.tools')) + [System.IO.Path]::DirectorySeparatorChar
    if (!$resolvedScratch.StartsWith($allowedRoot, [System.StringComparison]::OrdinalIgnoreCase)) { throw 'Verification cleanup path outside .tools.' }
    if (Test-Path -LiteralPath $resolvedScratch) { Remove-Item -LiteralPath $resolvedScratch -Recurse -Force }
}
Write-Output 'Offline verification passed. Live network activation was not performed by this script.'
