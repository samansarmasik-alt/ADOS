$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$exe = Join-Path $root 'dist\ados.exe'
if (!(Test-Path -LiteralPath $exe -PathType Leaf)) { Write-Output 'state=stopped'; exit 0 }
$before = & $exe --status 2>$null
if ($LASTEXITCODE -ne 0 -or ($before -join "`n") -notmatch '(?m)^state=active\s*$') { Write-Output 'state=stopped'; exit 0 }
& $exe --stop
if ($LASTEXITCODE -ne 0) { Write-Error 'Could not send the scoped stop event.'; exit 2 }
$deadline = [DateTime]::UtcNow.AddSeconds(8)
do {
    Start-Sleep -Milliseconds 200
    $status = & $exe --status 2>$null
    if (($status -join "`n") -match '(?m)^state=stopped\s*$') { Write-Output 'state=stopped'; exit 0 }
} while ([DateTime]::UtcNow -lt $deadline)
Write-Error 'Stop was requested, but the runtime mutex remains active after 8 seconds.'
exit 2
