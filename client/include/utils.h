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

// Hybrid Encryption
#define RSA_PUB_KEY "-----BEGIN PUBLIC KEY-----\n"\
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAodtLRibwDvbVQRWVVs2Y\n"\
"Tl2ynE34ZhuMxKSdCxnW2glWgMkpSIDLZfWRR6XzJz8W20r/c6Xm2Uzxjy+N/eYQ\n"\
"d+LWaUCT3syDZqz8YXxs6oLCJkuDsska2gKGJ3HqdAoDBFsIqFBjBrukpug6swoi\n"\
"wMABHvz9Ou/O8IpaeJtsyawMhjWbAIvH0fWO53ydjMqjIAiRmN2MkQoL7PqhaqG9\n"\
"fMIBmkxzZIrIvLGGll/NzmxjrgF6SyOiHcEGdQhm9XxbfBT0PTzgJz5Buw+YXmTv\n"\
"sKJGiBAc/BAeMhUFZXIt4RErJql2GSwdeBXynxPQ4QEevujkE3FHGTrLmsRILH/k\n"\
"FwIDAQAB\n"\
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

#endif
