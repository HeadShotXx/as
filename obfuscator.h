#ifndef OBFUSCATOR_H
#define OBFUSCATOR_H

#include <stddef.h>

// Yardımcı makrolar
#define OBF_CONCAT_IMPL(a, b) a##b
#define OBF_CONCAT(a, b) OBF_CONCAT_IMPL(a, b)

// Her string için benzersiz bir key üretmek için LCG benzeri bir yapı
#define OBF_SEED 0x1337BEEF
#define OBF_GET_KEY(c) ((unsigned char)(((c + 1) * 0x1105 + (OBF_SEED >> 8)) & 0xFF))

#define OBF_CH(s, i, key) ((unsigned char)((i < sizeof(s)) ? (s[i] ^ key) : 0))

#define OBF_STR_128(s, key) \
    OBF_CH(s, 0, key), OBF_CH(s, 1, key), OBF_CH(s, 2, key), OBF_CH(s, 3, key), \
    OBF_CH(s, 4, key), OBF_CH(s, 5, key), OBF_CH(s, 6, key), OBF_CH(s, 7, key), \
    OBF_CH(s, 8, key), OBF_CH(s, 9, key), OBF_CH(s, 10, key), OBF_CH(s, 11, key), \
    OBF_CH(s, 12, key), OBF_CH(s, 13, key), OBF_CH(s, 14, key), OBF_CH(s, 15, key), \
    OBF_CH(s, 16, key), OBF_CH(s, 17, key), OBF_CH(s, 18, key), OBF_CH(s, 19, key), \
    OBF_CH(s, 20, key), OBF_CH(s, 21, key), OBF_CH(s, 22, key), OBF_CH(s, 23, key), \
    OBF_CH(s, 24, key), OBF_CH(s, 25, key), OBF_CH(s, 26, key), OBF_CH(s, 27, key), \
    OBF_CH(s, 28, key), OBF_CH(s, 29, key), OBF_CH(s, 30, key), OBF_CH(s, 31, key), \
    OBF_CH(s, 32, key), OBF_CH(s, 33, key), OBF_CH(s, 34, key), OBF_CH(s, 35, key), \
    OBF_CH(s, 36, key), OBF_CH(s, 37, key), OBF_CH(s, 38, key), OBF_CH(s, 39, key), \
    OBF_CH(s, 40, key), OBF_CH(s, 41, key), OBF_CH(s, 42, key), OBF_CH(s, 43, key), \
    OBF_CH(s, 44, key), OBF_CH(s, 45, key), OBF_CH(s, 46, key), OBF_CH(s, 47, key), \
    OBF_CH(s, 48, key), OBF_CH(s, 49, key), OBF_CH(s, 50, key), OBF_CH(s, 51, key), \
    OBF_CH(s, 52, key), OBF_CH(s, 53, key), OBF_CH(s, 54, key), OBF_CH(s, 55, key), \
    OBF_CH(s, 56, key), OBF_CH(s, 57, key), OBF_CH(s, 58, key), OBF_CH(s, 59, key), \
    OBF_CH(s, 60, key), OBF_CH(s, 61, key), OBF_CH(s, 62, key), OBF_CH(s, 63, key), \
    OBF_CH(s, 64, key), OBF_CH(s, 65, key), OBF_CH(s, 66, key), OBF_CH(s, 67, key), \
    OBF_CH(s, 68, key), OBF_CH(s, 69, key), OBF_CH(s, 70, key), OBF_CH(s, 71, key), \
    OBF_CH(s, 72, key), OBF_CH(s, 73, key), OBF_CH(s, 74, key), OBF_CH(s, 75, key), \
    OBF_CH(s, 76, key), OBF_CH(s, 77, key), OBF_CH(s, 78, key), OBF_CH(s, 79, key), \
    OBF_CH(s, 80, key), OBF_CH(s, 81, key), OBF_CH(s, 82, key), OBF_CH(s, 83, key), \
    OBF_CH(s, 84, key), OBF_CH(s, 85, key), OBF_CH(s, 86, key), OBF_CH(s, 87, key), \
    OBF_CH(s, 88, key), OBF_CH(s, 89, key), OBF_CH(s, 90, key), OBF_CH(s, 91, key), \
    OBF_CH(s, 92, key), OBF_CH(s, 93, key), OBF_CH(s, 94, key), OBF_CH(s, 95, key), \
    OBF_CH(s, 96, key), OBF_CH(s, 97, key), OBF_CH(s, 98, key), OBF_CH(s, 99, key), \
    OBF_CH(s, 100, key), OBF_CH(s, 101, key), OBF_CH(s, 102, key), OBF_CH(s, 103, key), \
    OBF_CH(s, 104, key), OBF_CH(s, 105, key), OBF_CH(s, 106, key), OBF_CH(s, 107, key), \
    OBF_CH(s, 108, key), OBF_CH(s, 109, key), OBF_CH(s, 110, key), OBF_CH(s, 111, key), \
    OBF_CH(s, 112, key), OBF_CH(s, 113, key), OBF_CH(s, 114, key), OBF_CH(s, 115, key), \
    OBF_CH(s, 116, key), OBF_CH(s, 117, key), OBF_CH(s, 118, key), OBF_CH(s, 119, key), \
    OBF_CH(s, 120, key), OBF_CH(s, 121, key), OBF_CH(s, 122, key), OBF_CH(s, 123, key), \
    OBF_CH(s, 124, key), OBF_CH(s, 125, key), OBF_CH(s, 126, key), OBF_CH(s, 127, key)

#define OBF_STR(s) OBF_STR_INTERNAL(s, __COUNTER__)

#define OBF_STR_INTERNAL(s, c) ({ \
    _Static_assert(sizeof(s) <= 128, "String too long for OBF_STR (max 128 chars)"); \
    enum { OBF_CONCAT(key_, c) = OBF_GET_KEY(c) }; \
    static unsigned char data[] = { OBF_STR_128(s, OBF_CONCAT(key_, c)) }; \
    static int decrypted = 0; \
    auto void OBF_CONCAT(decoder_, c)(void) { \
        for (size_t i = 0; i < sizeof(s); i++) data[i] ^= OBF_CONCAT(key_, c); \
    } \
    if (!decrypted) { \
        OBF_CONCAT(decoder_, c)(); \
        decrypted = 1; \
    } \
    (char*)data; \
})

#endif
