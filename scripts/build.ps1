param([switch]$FetchCompiler)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $projectRoot
$zigVersion = '0.15.2'
$zigHash = '3a0ed1e8799a2f8ce2a6e6290a9ff22e6906f8227865911fb7ddedc3cc14cb0c'
$compiler = Join-Path $projectRoot '.tools/zig-x86_64-windows-0.15.2/zig.exe'
if (-not (Test-Path -LiteralPath $compiler)) {
    if (-not $FetchCompiler) { throw 'Compiler missing. Run scripts/build.ps1 -FetchCompiler once on the development machine.' }
    New-Item -ItemType Directory -Force -Path (Join-Path $projectRoot '.tools') | Out-Null
    $archive = Join-Path $projectRoot '.tools/zig.zip'
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest -Uri "https://ziglang.org/download/$zigVersion/zig-x86_64-windows-$zigVersion.zip" -OutFile $archive
    if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $zigHash) { throw 'Compiler SHA256 mismatch.' }
    Expand-Archive -LiteralPath $archive -DestinationPath (Join-Path $projectRoot '.tools') -Force
}
if (-not (Test-Path -LiteralPath 'models/model.h')) { throw 'Model missing. See training/README.md for training instructions.' }
New-Item -ItemType Directory -Force -Path 'dist' | Out-Null
& $compiler cc -std=c11 -O2 -Wall -Wextra -target x86_64-windows-gnu -I vendor/windivert/include -I models src/ados.c -o dist/ados.exe -L vendor/windivert/x64 -lWinDivert -ladvapi32 -lws2_32
if ($LASTEXITCODE -ne 0) { throw 'Native build failed.' }
function Copy-RuntimeIfChanged([string]$source, [string]$destination) {
    if ((Test-Path -LiteralPath $destination -PathType Leaf) -and
        (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash -eq (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash) { return }
    Copy-Item -LiteralPath $source -Destination $destination -Force
}
Copy-RuntimeIfChanged 'vendor/windivert/x64/WinDivert.dll' 'dist/WinDivert.dll'
Copy-RuntimeIfChanged 'vendor/windivert/x64/WinDivert64.sys' 'dist/WinDivert64.sys'
Copy-Item -LiteralPath 'vendor/windivert/LICENSE' -Destination 'dist/WinDivert-LICENSE.txt' -Force
$signature = Get-AuthenticodeSignature -LiteralPath 'dist/WinDivert64.sys'
if ($signature.Status -ne 'Valid') { throw "Driver signature validation failed: $($signature.Status)" }
$runtimeFiles = @('dist/ados.exe', 'dist/WinDivert.dll', 'dist/WinDivert64.sys')
$manifest = [ordered]@{
    driverVersion = '2.2.2-A'
    driverSigner = $signature.SignerCertificate.Subject
    driverThumbprint = $signature.SignerCertificate.Thumbprint
    buildUtc = [DateTime]::UtcNow.ToString('o')
    files = @($runtimeFiles | ForEach-Object { [ordered]@{path=$_; sha256=(Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash.ToLowerInvariant()} })
}
$manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath 'scripts/runtime-manifest.json' -Encoding UTF8
Write-Output 'Native application built. Runtime hashes recorded. Driver Authenticode signature: Valid.'
