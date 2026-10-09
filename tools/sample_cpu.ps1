# Poor-man's sampling profiler for MuMuNxMain.exe.
#
# Answers "which code is burning the CPU" without a debugger attached: it
# enumerates the process's threads, ranks them by user-mode CPU time, then
# repeatedly suspends the hottest one and reads its instruction pointer.
# Aggregating the RIP samples gives the hot address directly, which can then be
# mapped back to an RVA and looked up in the IDB.
#
# Usage (from a Windows PowerShell):
#   powershell -NoProfile -ExecutionPolicy Bypass -File tools\sample_cpu.ps1
#   powershell -NoProfile -ExecutionPolicy Bypass -File tools\sample_cpu.ps1 -Name MuMuNxMain -Samples 60
#
# Nothing is written to the target process and no breakpoint is installed, so it
# is safe to run against a live emulator.  Suspend/resume is held only for the
# few microseconds it takes to read the context.

[CmdletBinding()]
param(
    [string] $Name = "MuMuNxMain",
    [int]    $Samples = 40,
    [int]    $DelayMs = 25,
    [int]    $TopThreads = 5
)

Add-Type @"
using System;
using System.Runtime.InteropServices;

public static class Nt {
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr OpenProcess(int access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr CreateToolhelp32Snapshot(int flags, int pid);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool Thread32First(IntPtr snap, ref THREADENTRY32 te);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool Thread32Next(IntPtr snap, ref THREADENTRY32 te);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr OpenThread(int access, bool inherit, int tid);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern int SuspendThread(IntPtr h);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern int ResumeThread(IntPtr h);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool GetThreadContext(IntPtr h, byte[] ctx);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool GetThreadTimes(IntPtr h, out long created, out long exited, out long kernel, out long user);

    [StructLayout(LayoutKind.Sequential)]
    public struct THREADENTRY32 {
        public uint dwSize; public uint cntUsage; public uint th32ThreadID;
        public uint th32OwnerProcessID; public int tpBasePri; public int tpDeltaPri;
        public uint dwFlags;
    }
}
"@

$PROCESS_QUERY_INFORMATION = 0x0400
$PROCESS_VM_READ           = 0x0010
$TH32CS_SNAPTHREAD         = 0x00000004
$THREAD_SUSPEND_RESUME     = 0x0002
$THREAD_GET_CONTEXT        = 0x0008
$THREAD_QUERY_INFORMATION  = 0x0040
$CONTEXT_CONTROL           = 0x00100001   # CONTEXT_AMD64 | CONTEXT_CONTROL
$CONTEXT_SIZE              = 1232         # sizeof(CONTEXT) on x64
$RIP_OFFSET                = 0xF8         # offsetof(CONTEXT, Rip)
$CONTEXT_FLAGS_OFFSET      = 0x30

$proc = Get-Process -Name $Name -ErrorAction SilentlyContinue |
        Sort-Object -Property CPU -Descending | Select-Object -First 1
if (-not $proc) { Write-Error "process '$Name' is not running"; exit 1 }

$pid_ = $proc.Id
$base = $proc.MainModule.BaseAddress.ToInt64()
Write-Host ("process : {0} (pid {1})" -f $proc.ProcessName, $pid_)
Write-Host ("base    : 0x{0:X}" -f $base)
Write-Host ("threads : {0}" -f $proc.Threads.Count)
Write-Host ""

$hProc = [Nt]::OpenProcess(($PROCESS_QUERY_INFORMATION -bor $PROCESS_VM_READ), $false, $pid_)
if ($hProc -eq [IntPtr]::Zero) { Write-Error "OpenProcess failed"; exit 1 }

# ---- enumerate the process's threads ------------------------------------- #
$snap = [Nt]::CreateToolhelp32Snapshot($TH32CS_SNAPTHREAD, 0)
$te = New-Object Nt+THREADENTRY32
$te.dwSize = [System.Runtime.InteropServices.Marshal]::SizeOf($te)
$tids = New-Object System.Collections.Generic.List[int]
if ([Nt]::Thread32First($snap, [ref]$te)) {
    do {
        if ($te.th32OwnerProcessID -eq $pid_) { $tids.Add([int]$te.th32ThreadID) }
        $te.dwSize = [System.Runtime.InteropServices.Marshal]::SizeOf($te)
    } while ([Nt]::Thread32Next($snap, [ref]$te))
}
[Nt]::CloseHandle($snap) | Out-Null

# ---- rank by user-mode CPU time ------------------------------------------ #
$rows = @()
foreach ($tid in $tids) {
    $h = [Nt]::OpenThread(($THREAD_QUERY_INFORMATION -bor $THREAD_SUSPEND_RESUME -bor $THREAD_GET_CONTEXT), $false, $tid)
    if ($h -eq [IntPtr]::Zero) { continue }
    $c = 0L; $e = 0L; $k = 0L; $u = 0L
    if ([Nt]::GetThreadTimes($h, [ref]$c, [ref]$e, [ref]$k, [ref]$u)) {
        $rows += [pscustomobject]@{ Tid = $tid; Handle = $h; UserMs = [math]::Round($u / 10000.0, 1); KernelMs = [math]::Round($k / 10000.0, 1) }
    } else { [Nt]::CloseHandle($h) | Out-Null }
}

$rows = $rows | Sort-Object -Property UserMs -Descending
Write-Host "top threads by user-mode CPU time:"
$rows | Select-Object -First $TopThreads | Format-Table -AutoSize | Out-String -Width 100 | Write-Host

# ---- sample the RIP of the hottest threads ------------------------------- #
$ctx = New-Object byte[] $CONTEXT_SIZE
foreach ($row in ($rows | Select-Object -First $TopThreads)) {
    if ($row.UserMs -le 0) { continue }
    $hits = @{}
    $ok = 0
    for ($i = 0; $i -lt $Samples; $i++) {
        if ([Nt]::SuspendThread($row.Handle) -eq -1) { continue }
        try {
            [Array]::Clear($ctx, 0, $CONTEXT_SIZE)
            [BitConverter]::GetBytes([int]$CONTEXT_CONTROL).CopyTo($ctx, $CONTEXT_FLAGS_OFFSET)
            if ([Nt]::GetThreadContext($row.Handle, $ctx)) {
                $rip = [BitConverter]::ToInt64($ctx, $RIP_OFFSET)
                $key = "0x{0:X}" -f $rip
                if ($hits.ContainsKey($key)) { $hits[$key]++ } else { $hits[$key] = 1 }
                $ok++
            }
        } finally { [Nt]::ResumeThread($row.Handle) | Out-Null }
        Start-Sleep -Milliseconds $DelayMs
    }
    Write-Host ("--- tid {0}  user={1}ms  kernel={2}ms  ({3}/{4} samples read)" -f $row.Tid, $row.UserMs, $row.KernelMs, $ok, $Samples)
    if ($ok -eq 0) { Write-Host "    (could not read context)"; continue }
    $hits.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First 12 | ForEach-Object {
        $addr = [int64]$_.Key
        $rva = $addr - $base
        $pct = [math]::Round(100.0 * $_.Value / $ok, 1)
        if ($rva -ge 0 -and $rva -lt 0x2000000) {
            Write-Host ("    {0,4}x  {1,5}%  rip={2}  RVA=0x{3:X}" -f $_.Value, $pct, $_.Key, $rva)
        } else {
            Write-Host ("    {0,4}x  {1,5}%  rip={2}  (outside module)" -f $_.Value, $pct, $_.Key)
        }
    }
}

foreach ($row in $rows) { [Nt]::CloseHandle($row.Handle) | Out-Null }
[Nt]::CloseHandle($hProc) | Out-Null
