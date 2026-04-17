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
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAt73DfbFQ1mKLi1vhbDsC\n"\
"AZHQJ06d3Gm0xK2iT750NHf58Q9ZyL3vTbHH30jWBz9Wbeqsb+mnPDKeG2h90w4G\n"\
"snfybvC6lIwaFWJaYZOhMw8AumjnadVuQx23ohrDCgw1ub8CTboGSOSXpPkFc+mk\n"\
"FVj9/m1DD7AlWH+/bKq25KLrG6ozolDzGhyMr4QSEOq8JDU8DXVukzOehdH7tf0A\n"\
"eRkkgnT2o+4QR4sL00It40cYb0qcuD6i6ypylFNiXGYOSy4YNkbStbIDZoAAKseV\n"\
"zuY9B9GoSXrY6drdrIO2hHWcqZxSjMEIsQSB0Vtrmpyw+Z/nSR/RzIYfU8UhUeyc\n"\
"7wIDAQAB\n"\
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
