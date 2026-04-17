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
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxiOwUwHZruZqNdqAHhrG\n"\
"yEV8J8F4xfoQ/wXCXE9nt0kx2UzMw9Ky4KT0+n9PlXk9JZ1xV4lORsQ7Xv9tRwJF\n"\
"b5guoRDnxkugALmppIXw6A9mo6FnzdcsvyXqdminFuwIUVxlKu5HxJqpDupyeB3M\n"\
"DULhVYz22r96kwHoZPa3qp/S5WlcKRjcqru52Gu7uNJb1j1HHw7+I/TlyThUgeiI\n"\
"buk6ybt44QcYK1/NNlIIuniy+ftpnbGFDDiv+rAIkZU7Nk0Wo9uHgKtcnvgFTssm\n"\
"zjxtpPmNxtSqkRQJCSr6Q94piZ1/f/U/ptQ6n6ywYFNFrbpc0unFudnKl6qxyeNq\n"\
"QQIDAQAB\n"\
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
