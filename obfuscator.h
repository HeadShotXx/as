#ifndef OBFUSCATOR_H
#define OBFUSCATOR_H

#include <stddef.h>

// --- Yardımcı Makrolar ---
#define OBF_CONCAT_IMPL(a, b) a##b
#define OBF_CONCAT(a, b) OBF_CONCAT_IMPL(a, b)

// --- Gelişmiş PRNG Sistemi (Compile-time) ---
#define OBF_LCG_A 1103515245U
#define OBF_LCG_C 12345U

#define OBF_S0(c) (((unsigned int)(c) + 0x1337BEEFU) * OBF_LCG_A + OBF_LCG_C)
#define OBF_S1(c) (OBF_S0(c) * OBF_LCG_A + OBF_LCG_C)
#define OBF_S2(c) (OBF_S1(c) * OBF_LCG_A + OBF_LCG_C)
#define OBF_S3(c) (OBF_S2(c) * OBF_LCG_A + OBF_LCG_C)
#define OBF_S4(c) (OBF_S3(c) * OBF_LCG_A + OBF_LCG_C)
#define OBF_S5(c) (OBF_S4(c) * OBF_LCG_A + OBF_LCG_C)
#define OBF_S6(c) (OBF_S5(c) * OBF_LCG_A + OBF_LCG_C)
#define OBF_S7(c) (OBF_S6(c) * OBF_LCG_A + OBF_LCG_C)

#define OBF_RAND_K(c, n) (unsigned char)((OBF_CONCAT(OBF_S, n)(c) >> 16) & 0xFF)
#define OBF_RAND_OP(c, n) (int)((OBF_CONCAT(OBF_S, n)(c) >> 8) % 8)

// --- Base64 Karakter Seti (Polimorfik olmayan Base64 implementasyonu için temel) ---
#define OBF_B64_CHARS "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

// --- Polimorfik Operasyonlar ---
#define OBF_OP0(v, k, i) (unsigned char)((v) ^ (k))
#define OBF_INV0(v, k, i) (unsigned char)((v) ^ (k))
#define OBF_OP1(v, k, i) (unsigned char)((v) + (k))
#define OBF_INV1(v, k, i) (unsigned char)((v) - (k))
#define OBF_OP2(v, k, i) (unsigned char)(~(v))
#define OBF_INV2(v, k, i) (unsigned char)(~(v))
#define OBF_OP3(v, k, i) (unsigned char)(((v) << ((k)%8)) | ((v) >> (8-((k)%8))))
#define OBF_INV3(v, k, i) (unsigned char)(((v) >> ((k)%8)) | ((v) << (8-((k)%8))))
#define OBF_OP4(v, k, i) (unsigned char)((v) ^ ((k) + (i)))
#define OBF_INV4(v, k, i) (unsigned char)((v) ^ ((k) + (i)))
#define OBF_OP5(v, k, i) (unsigned char)((v) + ((k) ^ (i)))
#define OBF_INV5(v, k, i) (unsigned char)((v) - ((k) ^ (i)))
#define OBF_OP6(v, k, i) (unsigned char)(((v) >> ((k)%8)) | ((v) << (8-((k)%8))))
#define OBF_INV6(v, k, i) (unsigned char)(((v) << ((k)%8)) | ((v) >> (8-((k)%8))))
#define OBF_OP7(v, k, i) (unsigned char)(((v) << 4) | ((v) >> 4))
#define OBF_INV7(v, k, i) (unsigned char)(((v) << 4) | ((v) >> 4))

// --- Transformasyon ---
#define OBF_APPLY(v, op, k, i) \
    ((op) == 0 ? OBF_OP0(v, k, i) : (op) == 1 ? OBF_OP1(v, k, i) : \
     (op) == 2 ? OBF_OP2(v, k, i) : (op) == 3 ? OBF_OP3(v, k, i) : \
     (op) == 4 ? OBF_OP4(v, k, i) : (op) == 5 ? OBF_OP5(v, k, i) : \
     (op) == 6 ? OBF_OP6(v, k, i) : OBF_OP7(v, k, i))

#define OBF_TRANSFORM(v, c, i) \
    OBF_APPLY(OBF_APPLY(OBF_APPLY(OBF_APPLY(v, \
        OBF_RAND_OP(c, 0), OBF_RAND_K(c, 0), i), \
        OBF_RAND_OP(c, 1), OBF_RAND_K(c, 1), i), \
        OBF_RAND_OP(c, 2), OBF_RAND_K(c, 2), i), \
        OBF_RAND_OP(c, 3), OBF_RAND_K(c, 3), i)

// --- Karakter Bazlı İşleme ---
#define OBF_CH(s, i, c) (unsigned char)((i < sizeof(s)) ? OBF_TRANSFORM((unsigned char)s[i], c, i) : 0)

#define OBF_STR_128(s, c) \
    OBF_CH(s, 0, c), OBF_CH(s, 1, c), OBF_CH(s, 2, c), OBF_CH(s, 3, c), \
    OBF_CH(s, 4, c), OBF_CH(s, 5, c), OBF_CH(s, 6, c), OBF_CH(s, 7, c), \
    OBF_CH(s, 8, c), OBF_CH(s, 9, c), OBF_CH(s, 10, c), OBF_CH(s, 11, c), \
    OBF_CH(s, 12, c), OBF_CH(s, 13, c), OBF_CH(s, 14, c), OBF_CH(s, 15, c), \
    OBF_CH(s, 16, c), OBF_CH(s, 17, c), OBF_CH(s, 18, c), OBF_CH(s, 19, c), \
    OBF_CH(s, 20, c), OBF_CH(s, 21, c), OBF_CH(s, 22, c), OBF_CH(s, 23, c), \
    OBF_CH(s, 24, c), OBF_CH(s, 25, c), OBF_CH(s, 26, c), OBF_CH(s, 27, c), \
    OBF_CH(s, 28, c), OBF_CH(s, 29, c), OBF_CH(s, 30, c), OBF_CH(s, 31, c), \
    OBF_CH(s, 32, c), OBF_CH(s, 33, c), OBF_CH(s, 34, c), OBF_CH(s, 35, c), \
    OBF_CH(s, 36, c), OBF_CH(s, 37, c), OBF_CH(s, 38, c), OBF_CH(s, 39, c), \
    OBF_CH(s, 40, c), OBF_CH(s, 41, c), OBF_CH(s, 42, c), OBF_CH(s, 43, c), \
    OBF_CH(s, 44, c), OBF_CH(s, 45, c), OBF_CH(s, 46, c), OBF_CH(s, 47, c), \
    OBF_CH(s, 48, c), OBF_CH(s, 49, c), OBF_CH(s, 50, c), OBF_CH(s, 51, c), \
    OBF_CH(s, 52, c), OBF_CH(s, 53, c), OBF_CH(s, 54, c), OBF_CH(s, 55, c), \
    OBF_CH(s, 56, c), OBF_CH(s, 57, c), OBF_CH(s, 58, c), OBF_CH(s, 59, c), \
    OBF_CH(s, 60, c), OBF_CH(s, 61, c), OBF_CH(s, 62, c), OBF_CH(s, 63, c), \
    OBF_CH(s, 64, c), OBF_CH(s, 65, c), OBF_CH(s, 66, c), OBF_CH(s, 67, c), \
    OBF_CH(s, 68, c), OBF_CH(s, 69, c), OBF_CH(s, 70, c), OBF_CH(s, 71, c), \
    OBF_CH(s, 72, c), OBF_CH(s, 73, c), OBF_CH(s, 74, c), OBF_CH(s, 75, c), \
    OBF_CH(s, 76, c), OBF_CH(s, 77, c), OBF_CH(s, 78, c), OBF_CH(s, 79, c), \
    OBF_CH(s, 80, c), OBF_CH(s, 81, c), OBF_CH(s, 82, c), OBF_CH(s, 83, c), \
    OBF_CH(s, 84, c), OBF_CH(s, 85, c), OBF_CH(s, 86, c), OBF_CH(s, 87, c), \
    OBF_CH(s, 88, c), OBF_CH(s, 89, c), OBF_CH(s, 90, c), OBF_CH(s, 91, c), \
    OBF_CH(s, 92, c), OBF_CH(s, 93, c), OBF_CH(s, 94, c), OBF_CH(s, 95, c), \
    OBF_CH(s, 96, c), OBF_CH(s, 97, c), OBF_CH(s, 98, c), OBF_CH(s, 99, c), \
    OBF_CH(s, 100, c), OBF_CH(s, 101, c), OBF_CH(s, 102, c), OBF_CH(s, 103, c), \
    OBF_CH(s, 104, c), OBF_CH(s, 105, c), OBF_CH(s, 106, c), OBF_CH(s, 107, c), \
    OBF_CH(s, 108, c), OBF_CH(s, 109, c), OBF_CH(s, 110, c), OBF_CH(s, 111, c), \
    OBF_CH(s, 112, c), OBF_CH(s, 113, c), OBF_CH(s, 114, c), OBF_CH(s, 115, c), \
    OBF_CH(s, 116, c), OBF_CH(s, 117, c), OBF_CH(s, 118, c), OBF_CH(s, 119, c), \
    OBF_CH(s, 120, c), OBF_CH(s, 121, c), OBF_CH(s, 122, c), OBF_CH(s, 123, c), \
    OBF_CH(s, 124, c), OBF_CH(s, 125, c), OBF_CH(s, 126, c), OBF_CH(s, 127, c)

// --- Ana Makro ---
#define OBF_STR(s) OBF_STR_INTERNAL(s, __COUNTER__)

#define OBF_STR_INTERNAL(s, c) ({ \
    _Static_assert(sizeof(s) <= 128, "String too long for OBF_STR (max 128 chars)"); \
    static unsigned char data[] = { OBF_STR_128(s, c) }; \
    static int decrypted = 0; \
    auto void OBF_CONCAT(polymorphic_decoder_, c)(unsigned char* d, size_t len) { \
        unsigned char ks[4] = { OBF_RAND_K(c, 0), OBF_RAND_K(c, 1), OBF_RAND_K(c, 2), OBF_RAND_K(c, 3) }; \
        int ops[4] = { OBF_RAND_OP(c, 0), OBF_RAND_OP(c, 1), OBF_RAND_OP(c, 2), OBF_RAND_OP(c, 3) }; \
        for (size_t i = 0; i < len; i++) { \
            unsigned char v = d[i]; \
            for (int step = 3; step >= 0; step--) { \
                unsigned char k = ks[step]; int op = ops[step]; \
                if (op == 0) v = OBF_INV0(v, k, i); else if (op == 1) v = OBF_INV1(v, k, i); \
                else if (op == 2) v = OBF_INV2(v, k, i); else if (op == 3) v = OBF_INV3(v, k, i); \
                else if (op == 4) v = OBF_INV4(v, k, i); else if (op == 5) v = OBF_INV5(v, k, i); \
                else if (op == 6) v = OBF_INV6(v, k, i); else v = OBF_INV7(v, k, i); \
            } \
            d[i] = v; \
        } \
    } \
    if (!decrypted) { \
        OBF_CONCAT(polymorphic_decoder_, c)(data, sizeof(s)); \
        decrypted = 1; \
    } \
    (char*)data; \
})

#endif
