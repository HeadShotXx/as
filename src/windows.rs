#![allow(non_camel_case_types, non_snake_case)]

use std::ffi::c_void;

// Basic Types
pub type HANDLE = *mut c_void;
pub type HMODULE = *mut c_void;
pub type PVOID = *mut c_void;
pub type LPVOID = *mut c_void;
pub type LPCSTR = *const i8;
pub type LPCWSTR = *const u16;
pub type LPWSTR = *mut u16;
pub type DWORD = u32;
pub type ULONG = u32;
pub type NTSTATUS = i32;

// Constants
pub const CREATE_SUSPENDED: DWORD = 0x00000004;
pub const CREATE_NEW_CONSOLE: DWORD = 0x00000010;

// Structs
#[repr(C)]
pub struct UNICODE_STRING {
    pub Length: u16,
    pub MaximumLength: u16,
    pub Buffer: LPWSTR,
}

#[repr(C)]
pub struct PEB {
    pub Reserved1: [u8; 2],
    pub BeingDebugged: u8,
    pub Reserved2: [u8; 1],
    pub Reserved3: [PVOID; 2],
    pub Ldr: PVOID,
    pub ProcessParameters: PVOID,
    pub Reserved4: [PVOID; 3],
    pub AtlThunkSListPtr: PVOID,
    pub Reserved5: PVOID,
    pub Reserved6: u32,
    pub Reserved7: PVOID,
    pub Reserved8: u32,
    pub AtlThunkSListPtr32: u32,
    pub Reserved9: [PVOID; 45],
    pub Reserved10: [u8; 96],
    pub PostProcessInitRoutine: PVOID,
    pub Reserved11: [u8; 128],
    pub Reserved12: [PVOID; 1],
    pub SessionId: u32,
}

#[repr(C)]
pub struct PROCESS_BASIC_INFORMATION {
    pub ExitStatus: NTSTATUS,
    pub PebBaseAddress: *mut PEB,
    pub AffinityMask: usize,
    pub BasePriority: i32,
    pub UniqueProcessId: usize,
    pub InheritedFromUniqueProcessId: usize,
}

#[repr(C)]
pub struct SECURITY_ATTRIBUTES {
    pub nLength: DWORD,
    pub lpSecurityDescriptor: LPVOID,
    pub bInheritHandle: i32,
}

#[repr(C)]
pub struct STARTUPINFOW {
    pub cb: DWORD,
    pub lpReserved: LPWSTR,
    pub lpDesktop: LPWSTR,
    pub lpTitle: LPWSTR,
    pub dwX: DWORD,
    pub dwY: DWORD,
    pub dwXSize: DWORD,
    pub dwYSize: DWORD,
    pub dwXCountChars: DWORD,
    pub dwYCountChars: DWORD,
    pub dwFillAttribute: DWORD,
    pub dwFlags: DWORD,
    pub wShowWindow: u16,
    pub cbReserved2: u16,
    pub lpReserved2: *mut u8,
    pub hStdInput: HANDLE,
    pub hStdOutput: HANDLE,
    pub hStdError: HANDLE,
}

#[repr(C)]
pub struct PROCESS_INFORMATION {
    pub hProcess: HANDLE,
    pub hThread: HANDLE,
    pub dwProcessId: DWORD,
    pub dwThreadId: DWORD,
}

extern "system" {
    pub fn CreateProcessW(
        lpApplicationName: LPCWSTR,
        lpCommandLine: LPWSTR,
        lpProcessAttributes: *mut SECURITY_ATTRIBUTES,
        lpThreadAttributes: *mut SECURITY_ATTRIBUTES,
        bInheritHandles: i32,
        dwCreationFlags: DWORD,
        lpEnvironment: LPVOID,
        lpCurrentDirectory: LPCWSTR,
        lpStartupInfo: *mut STARTUPINFOW,
        lpProcessInformation: *mut PROCESS_INFORMATION,
    ) -> i32;

    pub fn GetModuleHandleA(lpModuleName: LPCSTR) -> HMODULE;

    pub fn GetProcAddress(hModule: HMODULE, lpProcName: LPCSTR) -> PVOID;
}
