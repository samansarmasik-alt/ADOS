param([switch]$Elevated,[ValidateRange(0,60)][int]$SmokeTestSeconds=0,[switch]$Observe,[switch]$Demo)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$root = Split-Path -Parent $PSScriptRoot
$exe = Join-Path $root 'dist\ados.exe'
$statusPath = Join-Path $root 'dist\ados-status.txt'
$stdoutPath = Join-Path $root 'dist\runtime.stdout.log'
$stderrPath = Join-Path $root 'dist\runtime.stderr.log'
$configPath = Join-Path $root 'config.json'
$psExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$process = $null
$jobHandle = [IntPtr]::Zero
$ownedPid = 0
$running = $true
$exitCode = 0
$userStopped = $false
$restoreControlC = $false
$previousControlCInput = $false
$script:cancelRequested = $false

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Hide-CurrentConsole([bool]$hide) {
    if (-not ('AdosConsoleWindow' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class AdosConsoleWindow {
    [DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow();
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
}
'@
    }
    $window = [AdosConsoleWindow]::GetConsoleWindow()
    if ($window -ne [IntPtr]::Zero) {
        if ($hide) { [void][AdosConsoleWindow]::ShowWindow($window, 0) }
        else { [void][AdosConsoleWindow]::ShowWindow($window, 5) }
    }
}

function Get-StatusMap {
    for ($attempt = 0; $attempt -lt 2; $attempt++) {
        $map = @{}
        try {
            if (!(Test-Path -LiteralPath $statusPath -PathType Leaf)) { throw 'status not ready' }
            foreach ($line in [IO.File]::ReadAllLines($statusPath)) {
                $at = $line.IndexOf('=')
                if ($at -gt 0) { $map[$line.Substring(0, $at)] = $line.Substring($at + 1).Trim() }
            }
            return $map
        } catch {
            if ($attempt -eq 0) { Start-Sleep -Milliseconds 75 }
        }
    }
    return @{}
}

function Get-LiveStatusText {
    if (!(Test-Path -LiteralPath $exe -PathType Leaf)) { return '' }
    $lines = & $exe --status 2>$null
    if ($LASTEXITCODE -ne 0) { return '' }
    return ($lines -join "`n")
}

function Get-LastLogEvents {
    $items = @()
    foreach ($path in @($stdoutPath, $stderrPath)) {
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            try {
                $items += [IO.File]::ReadAllLines($path) | Where-Object { ![string]::IsNullOrWhiteSpace($_) }
            } catch { }
        }
    }
    if ($items.Count -eq 0) { return @('Kayit yok', 'Kayit yok') }
    $tail = @($items | Select-Object -Last 2)
    if ($tail.Count -eq 1) { return @('Kayit yok', [string]$tail[0]) }
    return @([string]$tail[0], [string]$tail[1])
}

function Convert-EventText([string]$event) {
    switch ($event) {
        'capture_active' { return 'Paket katmani acildi' }
        'tcp_syn_rate_cap' { return 'TCP SYN hiz siniri uygulandi' }
        'udp_rate_cap' { return 'UDP hiz siniri uygulandi' }
        'capture_stopped' { return 'Paket katmani durduruldu' }
        'runtime_error' { return 'Runtime hatasi olustu' }
        'reinject_capacity_error' { return 'Paket kuyrugu limiti asildi' }
        'runtime_starting' { return 'Koruma baslatiliyor' }
        'stop_requested' { return 'Koruma durduruluyor' }
        'parent_process_exit' { return 'Dashboard kapandi, koruma durduruluyor' }
        'duration_elapsed' { return 'Sinirli test suresi tamamlandi' }
        'watchdog_wait_error' { return 'Koruma izleme hatasi olustu' }
        'none' { return 'Kayit yok' }
        default { return 'Ag guvenlik olayi kaydedildi' }
    }
}

function Get-EventText($status, [int]$index) {
    $name = if ($index -eq 0) { 'last_event' } else { 'previous_event' }
    $value = [string]$status[$name]
    if ([string]::IsNullOrWhiteSpace($value) -or $value -eq 'none') {
        $fallback = Get-LastLogEvents
        return Convert-EventText ([string]$fallback[$index])
    }
    return Convert-EventText ($value -replace '[\r\n\t]', ' ')
}

function Write-Dashboard($lines, [string]$stateLabel) {
    if ([Console]::IsOutputRedirected) {
        Write-Output ($lines -join "`n")
        return
    }
    $width = [Math]::Max(1, [Console]::WindowWidth - 1)
    $rowLimit = [Math]::Max(1, [Console]::WindowHeight - 1)
    $displayLines = @($lines | Select-Object -First $rowLimit)
    for ($row = 0; $row -lt $displayLines.Count; $row++) {
        $line = $displayLines[$row]
        $text = [string]$line
        if ($text.Length -gt $width) { $text = $text.Substring(0, $width) }
        [Console]::SetCursorPosition(0, $row)
        if ($row -eq 0) { [Console]::ForegroundColor = [ConsoleColor]::Cyan }
        elseif ($row -eq 1 -and $stateLabel -eq 'AKTIF') { [Console]::ForegroundColor = [ConsoleColor]::Green }
        elseif ($row -eq 1) { [Console]::ForegroundColor = [ConsoleColor]::Yellow }
        elseif ($row -ge 5) { [Console]::ForegroundColor = [ConsoleColor]::DarkGray }
        else { [Console]::ForegroundColor = [ConsoleColor]::Gray }
        [Console]::Write($text.PadRight($width))
    }
    [Console]::ResetColor()
}

function Invoke-AdosDemo {
    $started = [DateTime]::UtcNow
    $tick = 0
    $controlCInput = $false
    $previousControlC = $false
    try {
        if (-not [Console]::IsInputRedirected) {
            try { $previousControlC = [Console]::TreatControlCAsInput; [Console]::TreatControlCAsInput = $true; $controlCInput = $true } catch { }
        }
        try { [Console]::CursorVisible = $false } catch { }
        while ($true) {
            $tick++
            $uptime = [TimeSpan]::FromSeconds(([DateTime]::UtcNow - $started).TotalSeconds)
            $phase = $tick % 4
            if ($phase -eq 0) { $eventNew = 'Demo: UDP hiz siniri'; $eventOld = 'Demo: TCP SYN yuksek hiz' }
            elseif ($phase -eq 1) { $eventNew = 'Demo: TCP SYN yuksek hiz'; $eventOld = 'Demo: UDP hiz siniri' }
            elseif ($phase -eq 2) { $eventNew = 'Demo: paket siniri uygulandi'; $eventOld = 'Demo: TCP SYN yuksek hiz' }
            else { $eventNew = 'Demo: UDP hiz siniri'; $eventOld = 'Demo: paket siniri uygulandi' }
            $seen = $tick * 2487
            $dropped = $tick * 193
            $lines = @(
                'ADOS AI / GUVENLI TRAFIK DEMOSU',
                ('Durum: DEMO - Ag trafigi gonderilmiyor | Sure: {0}' -f $uptime.ToString('dd\.hh\:mm\:ss')),
                ('Simule gorulen: {0,12} | Simule engellenen: {1,12}' -f $seen, $dropped),
                ('Son olay: ' + $eventNew),
                ('Onceki olay: ' + $eventOld),
                'Gercek ag trafigi yok | Q: cikis | Pencereyi kapat: cikis'
            )
            Write-Dashboard $lines 'DEMO'
            if (-not [Console]::IsInputRedirected -and [Console]::KeyAvailable) {
                $key = [Console]::ReadKey($true)
                $isCtrlC = ($key.Key -eq [ConsoleKey]::C -and (($key.Modifiers -band [ConsoleModifiers]::Control) -ne 0))
                if ($key.Key -eq [ConsoleKey]::Q -or $isCtrlC) { break }
            }
            if ($SmokeTestSeconds -gt 0 -and ([DateTime]::UtcNow - $started).TotalSeconds -ge $SmokeTestSeconds) { break }
            Start-Sleep -Seconds 1
        }
    } finally {
        if ($controlCInput) { [Console]::TreatControlCAsInput = $previousControlC }
        try { [Console]::CursorVisible = $true } catch { }
    }
}

function New-AdosJob {
    if (-not ('AdosJobNative' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class AdosJobNative {
    [StructLayout(LayoutKind.Sequential)] public struct BasicLimitInformation {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }
    [StructLayout(LayoutKind.Sequential)] public struct IoCounters {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }
    [StructLayout(LayoutKind.Sequential)] public struct ExtendedLimitInformation {
        public BasicLimitInformation BasicLimitInformation;
        public IoCounters IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern IntPtr CreateJobObject(IntPtr attributes, string name);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool SetInformationJobObject(IntPtr job, int infoClass, ref ExtendedLimitInformation info, uint length);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern bool CloseHandle(IntPtr handle);
}
'@
    }
    $handle = [AdosJobNative]::CreateJobObject([IntPtr]::Zero, $null)
    if ($handle -eq [IntPtr]::Zero) { throw 'Job object could not be created.' }
    $info = New-Object -TypeName 'AdosJobNative+ExtendedLimitInformation'
    $basic = $info.BasicLimitInformation
    $basic.LimitFlags = 0x2000
    $info.BasicLimitInformation = $basic
    $length = [uint32][Runtime.InteropServices.Marshal]::SizeOf($info)
    if (-not [AdosJobNative]::SetInformationJobObject($handle, 9, [ref]$info, $length)) {
        $code = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        [void][AdosJobNative]::CloseHandle($handle)
        throw "Job object shutdown policy failed (Win32 $code)."
    }
    return $handle
}

function Get-OwnStatus($status) {
    return ($null -ne $status -and [string]$status['pid'] -eq [string]$ownedPid)
}

function Stop-OwnedRuntime {
    if ($ownedPid -le 0 -or $null -eq $process -or !(Test-Path -LiteralPath $exe -PathType Leaf)) { return }
    $process.Refresh()
    if ($process.HasExited) { return }
    $status = Get-StatusMap
    if (Get-OwnStatus $status) {
        try { $null = & $exe --stop 2>$null } catch { }
        $deadline = [DateTime]::UtcNow.AddSeconds(4)
        do {
            Start-Sleep -Milliseconds 150
            if ($null -ne $process) { $process.Refresh() }
            $status = Get-StatusMap
            if (($null -ne $process -and $process.HasExited) -or -not (Get-OwnStatus $status)) { break }
        } while ([DateTime]::UtcNow -lt $deadline)
    }
}

if (-not $Demo -and -not (Test-Administrator)) {
    Hide-CurrentConsole $true
    try {
        $argLine = '-NoProfile -ExecutionPolicy Bypass -File "{0}" -Elevated' -f $PSCommandPath
        if ($SmokeTestSeconds -gt 0) { $argLine += ' -SmokeTestSeconds ' + $SmokeTestSeconds }
        if ($Observe) { $argLine += ' -Observe' }
        $elevated = Start-Process -FilePath $psExe -ArgumentList $argLine -Verb RunAs -WindowStyle Normal -Wait -PassThru
        exit $elevated.ExitCode
    } catch {
        Hide-CurrentConsole $false
        Write-Host 'UAC iptal edildi. Koruma baslatilmadi.' -ForegroundColor Yellow
        Read-Host 'Cikmak icin Enter'
        exit 2
    }
}

try {
    if ($Demo) { Invoke-AdosDemo; exit 0 }
    if ($Observe -and $SmokeTestSeconds -eq 0) { throw '-Observe only supports bounded smoke runs; use -SmokeTestSeconds 1..60.' }
    $preflight = & $psExe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'start.ps1') -ValidateOnly 2>&1
    if ($LASTEXITCODE -ne 0) { throw ('Paket dogrulamasi basarisiz: ' + ($preflight -join ' ')) }
    $config = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json

    $existing = Get-LiveStatusText
    if ($existing -match '(?m)^state=active\s*$') {
        $existingPid = 'bilinmiyor'
        if ($existing -match '(?m)^pid=(\d+)\s*$') { $existingPid = $Matches[1] }
        throw "Baska bir ADOS koruma sureci aktif (PID $existingPid). Bu pencere onu durdurmayacak."
    }

    $jobHandle = New-AdosJob
    $runtimeArgs = @('--parent-pid', [string]$PID, '--syn-limit', [string]$config.synLimit,
        '--udp-limit', [string]$config.udpLimit, '--global-syn-limit', [string]$config.globalSynLimit,
        '--global-udp-limit', [string]$config.globalUdpLimit)
    if ($Observe) { $runtimeArgs += '--observe' }
    $process = Start-Process -FilePath $exe -ArgumentList $runtimeArgs -WindowStyle Hidden `
        -WorkingDirectory (Join-Path $root 'dist') -RedirectStandardOutput $stdoutPath `
        -RedirectStandardError $stderrPath -PassThru
    $ownedPid = $process.Id
    if (-not [AdosJobNative]::AssignProcessToJobObject($jobHandle, $process.Handle)) {
        $code = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        try { $process.Kill() } catch { }
        throw "Runtime job assignment failed; child was stopped (Win32 $code)."
    }

    $activationDeadline = [DateTime]::UtcNow.AddSeconds(10)
    $active = $false
    do {
        $process.Refresh()
        $status = Get-StatusMap
        if ((Get-OwnStatus $status) -and [string]$status['state'] -eq 'active') { $active = $true; break }
        if ($process.HasExited) { break }
        Start-Sleep -Milliseconds 200
    } while ([DateTime]::UtcNow -lt $activationDeadline)
    if (-not $active) {
        $detail = if (Test-Path -LiteralPath $stderrPath) { (Get-Content -LiteralPath $stderrPath -Tail 5) -join ' ' } else { 'Durum dosyasinda kendi PID icin aktif onayi yok.' }
        throw "Koruma aktiflesmedi: $detail"
    }

    $dashboardStart = [DateTime]::UtcNow
    $missedOwnStatus = 0
    try { [Console]::CursorVisible = $false } catch { }
    if (-not [Console]::IsInputRedirected) {
        try {
            $previousControlCInput = [Console]::TreatControlCAsInput
            [Console]::TreatControlCAsInput = $true
            $restoreControlC = $true
        } catch { }
    }
    while ($running) {
        $process.Refresh()
        $status = Get-StatusMap
        if ($process.HasExited) { break }
        if ((Get-OwnStatus $status) -and [string]$status['state'] -eq 'active') { $missedOwnStatus = 0 }
        else { $missedOwnStatus++ }
        if ($missedOwnStatus -ge 3) { break }
        $uptime = [TimeSpan]::FromSeconds([Math]::Max(0, ([DateTime]::UtcNow - $process.StartTime.ToUniversalTime()).TotalSeconds))
        $eventNew = Get-EventText $status 0
        $eventOld = Get-EventText $status 1
        $stateLabel = 'AKTIF'
        $heartbeat = [DateTimeOffset]::MinValue
        if ([DateTimeOffset]::TryParse([string]$status['heartbeat_utc'], [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$heartbeat)) {
            if (([DateTimeOffset]::UtcNow - $heartbeat.ToUniversalTime()).TotalSeconds -gt 3) { $stateLabel = 'YANIT BEKLENIYOR' }
        }
        $lines = @(
            'ADOS AI / CANLI KORUMA',
            ('Durum: {0} | Sure: {1}' -f $stateLabel, $uptime.ToString('dd\.hh\:mm\:ss')),
            ('Gorulen: {0,12} | Engellenen: {1,12}' -f $(if ($status['seen']) { $status['seen'] } else { '0' }), $(if ($status['dropped']) { $status['dropped'] } else { '0' })),
            ('Son olay: ' + $eventNew),
            ('Onceki olay: ' + $eventOld),
            'Pencereyi kapat = koruma durur | Q: cikis'
        )
        Write-Dashboard $lines $stateLabel
        if (-not [Console]::IsInputRedirected -and [Console]::KeyAvailable) {
            $key = [Console]::ReadKey($true)
            $isCtrlC = ($key.Key -eq [ConsoleKey]::C -and (($key.Modifiers -band [ConsoleModifiers]::Control) -ne 0))
            if ($key.Key -eq [ConsoleKey]::Q -or $isCtrlC) { $running = $false; $userStopped = $true }
        }
        if ($SmokeTestSeconds -gt 0 -and ([DateTime]::UtcNow - $dashboardStart).TotalSeconds -ge $SmokeTestSeconds) { $running = $false }
        if ($running) { Start-Sleep -Seconds 1 }
    }
    if (-not $userStopped -and $SmokeTestSeconds -eq 0) {
        $exitCode = 2
        Write-Host ''
        Write-Host 'Runtime beklenmedik sekilde durdu veya sahiplik durumu kayboldu.' -ForegroundColor Yellow
        Read-Host 'Cikmak icin Enter'
    }
} catch {
    $exitCode = 2
    try { [Console]::CursorVisible = $true } catch { }
    Write-Host ''
    Write-Host ('ADOS baslatilamadi: ' + $_.Exception.Message) -ForegroundColor Red
    if ($ownedPid -le 0) { Write-Host 'Mevcut baska bir runtime bu pencereden durdurulmadi.' }
    Read-Host 'Cikmak icin Enter'
} finally {
    Stop-OwnedRuntime
    if ($jobHandle -ne [IntPtr]::Zero) {
        [void][AdosJobNative]::CloseHandle($jobHandle)
        $jobHandle = [IntPtr]::Zero
    }
    if ($null -ne $process) { $process.Dispose() }
    if ($restoreControlC) { [Console]::TreatControlCAsInput = $previousControlCInput }
    try { [Console]::CursorVisible = $true } catch { }
}
exit $exitCode
