param([switch]$ValidateOnly,[switch]$Elevated)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$exe = Join-Path $root 'dist\ados.exe'
$manifestPath = Join-Path $PSScriptRoot 'runtime-manifest.json'
$configPath = Join-Path $root 'config.json'

function Test-RuntimePackage {
    if (!(Test-Path -LiteralPath $exe -PathType Leaf)) { throw 'dist\ados.exe missing; run scripts\build.ps1.' }
    if (!(Test-Path -LiteralPath $manifestPath -PathType Leaf)) { throw 'scripts\runtime-manifest.json missing.' }
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $expected = @('dist/ados.exe','dist/WinDivert.dll','dist/WinDivert64.sys')
    if ($manifest.files.Count -ne $expected.Count) { throw 'Manifest file list does not match the package.' }
    $seen = @{}
    foreach ($item in $manifest.files) {
        $relative = ([string]$item.path).Replace('\','/')
        if ($expected -notcontains $relative) { throw "Unexpected manifest path: $relative" }
        if ($seen.ContainsKey($relative)) { throw "Duplicate manifest path: $relative" }
        $seen[$relative] = $true
        if ([string]$item.sha256 -notmatch '^[0-9a-fA-F]{64}$') { throw "Invalid SHA-256: $relative" }
        $path = Join-Path $root $relative.Replace('/','\')
        if (!(Test-Path -LiteralPath $path -PathType Leaf)) { throw "Package file missing: $relative" }
        if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ine [string]$item.sha256) { throw "SHA-256 mismatch: $relative" }
    }
    foreach ($relative in $expected) { if (!$seen.ContainsKey($relative)) { throw "Manifest entry missing: $relative" } }
    if (!$manifest.driverThumbprint -or !$manifest.driverSigner) { throw 'Manifest must pin the driver signer and certificate thumbprint.' }
    $driver = Join-Path $root 'dist\WinDivert64.sys'
    $signature = Get-AuthenticodeSignature -LiteralPath $driver
    if ($signature.Status -ne 'Valid') { throw "WinDivert driver signature is not valid: $($signature.Status)" }
    if ($signature.SignerCertificate.Thumbprint -ine [string]$manifest.driverThumbprint) { throw 'Driver certificate thumbprint differs from manifest.' }
    if ($signature.SignerCertificate.Subject -cne [string]$manifest.driverSigner) { throw 'Driver signer differs from manifest.' }
    if (!(Test-Path -LiteralPath $configPath -PathType Leaf)) { throw 'config.json missing.' }
    $config = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
    foreach ($name in @('synLimit','udpLimit','globalSynLimit','globalUdpLimit')) {
        $value = [string]$config.$name
        if ($value -notmatch '^[0-9]+$') { throw "config.$name must be an integer." }
        $number = [long]$value
        if ($number -lt 1 -or $number -gt 1000000) { throw "config.$name must be between 1 and 1000000." }
    }
    return $config
}

try { $config = Test-RuntimePackage } catch { Write-Error $_; exit 2 }
if ($ValidateOnly) { Write-Output 'validation=passed package_hashes=valid driver_signature=valid config=bounds_valid'; exit 0 }

# Avoid replacing logs or mistaking a stale status file for a live runtime.
$existing = & $exe --status 2>$null
$existingText = $existing -join "`n"
if ($LASTEXITCODE -eq 0 -and $existingText -match '(?m)^state=active\s*$') { Write-Output $existingText; exit 0 }

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (!$isAdmin -and !$Elevated) {
    $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $child = Start-Process -FilePath $ps -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"{0}"' -f $PSCommandPath),'-Elevated') -Verb RunAs -WindowStyle Hidden -Wait -PassThru
    exit $child.ExitCode
}
if (!$isAdmin) { Write-Error 'Administrator rights are required.'; exit 2 }

$runtimeArgs = @('--syn-limit',[string]$config.synLimit,'--udp-limit',[string]$config.udpLimit,'--global-syn-limit',[string]$config.globalSynLimit,'--global-udp-limit',[string]$config.globalUdpLimit)
$stdout = Join-Path $root 'dist\runtime.stdout.log'
$stderr = Join-Path $root 'dist\runtime.stderr.log'
$process = Start-Process -FilePath $exe -ArgumentList $runtimeArgs -WindowStyle Hidden -WorkingDirectory (Join-Path $root 'dist') -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru
$statusFile = Join-Path $root 'dist\ados-status.txt'
$deadline = [DateTime]::UtcNow.AddSeconds(8)
do {
    Start-Sleep -Milliseconds 200
    $process.Refresh()
    if ($process.HasExited) {
        if ($process.ExitCode -eq 3) {
            $text = & $exe --status 2>$null
            if (($text -join "`n") -match '(?m)^state=active\s*$') { Write-Output ($text -join "`n"); exit 0 }
        }
        $reason = if (Test-Path -LiteralPath $stderr) { Get-Content -LiteralPath $stderr -Raw } else { 'runtime exited before activation' }
        Write-Error $reason; exit 2
    }
    if (Test-Path -LiteralPath $statusFile) {
        $text = Get-Content -LiteralPath $statusFile -Raw
        if ($text -match '(?m)^state=active\s*$' -and $text -match "(?m)^pid=$($process.Id)\s*$" -and !$process.HasExited) { Write-Output 'state=active; WinDivert handle verified'; exit 0 }
        if ($text -match '(?m)^state=error\s*$' -and $text -match "(?m)^pid=$($process.Id)\s*$") { Write-Error $text; exit 2 }
    }
} while ([DateTime]::UtcNow -lt $deadline)
Write-Error 'Runtime did not confirm an active handle within 8 seconds. Check dist\runtime.stderr.log.'
exit 2
