#ifndef OBFUSCATOR_H
#define OBFUSCATOR_H

#include <stddef.h>

// Her derlemede farklı bir key isterseniz bunu __TIME__ ile harmanlayabilirsiniz
// ama şimdilik sabit bir key kullanalım.
#define OBF_KEY 0xAD

#define OBF_CH(s, i) ((unsigned char)((i < sizeof(s)) ? (s[i] ^ OBF_KEY) : 0))

#define OBF_STR_128(s) \
    OBF_CH(s, 0), OBF_CH(s, 1), OBF_CH(s, 2), OBF_CH(s, 3), \
    OBF_CH(s, 4), OBF_CH(s, 5), OBF_CH(s, 6), OBF_CH(s, 7), \
    OBF_CH(s, 8), OBF_CH(s, 9), OBF_CH(s, 10), OBF_CH(s, 11), \
    OBF_CH(s, 12), OBF_CH(s, 13), OBF_CH(s, 14), OBF_CH(s, 15), \
    OBF_CH(s, 16), OBF_CH(s, 17), OBF_CH(s, 18), OBF_CH(s, 19), \
    OBF_CH(s, 20), OBF_CH(s, 21), OBF_CH(s, 22), OBF_CH(s, 23), \
    OBF_CH(s, 24), OBF_CH(s, 25), OBF_CH(s, 26), OBF_CH(s, 27), \
    OBF_CH(s, 28), OBF_CH(s, 29), OBF_CH(s, 30), OBF_CH(s, 31), \
    OBF_CH(s, 32), OBF_CH(s, 33), OBF_CH(s, 34), OBF_CH(s, 35), \
    OBF_CH(s, 36), OBF_CH(s, 37), OBF_CH(s, 38), OBF_CH(s, 39), \
    OBF_CH(s, 40), OBF_CH(s, 41), OBF_CH(s, 42), OBF_CH(s, 43), \
    OBF_CH(s, 44), OBF_CH(s, 45), OBF_CH(s, 46), OBF_CH(s, 47), \
    OBF_CH(s, 48), OBF_CH(s, 49), OBF_CH(s, 50), OBF_CH(s, 51), \
    OBF_CH(s, 52), OBF_CH(s, 53), OBF_CH(s, 54), OBF_CH(s, 55), \
    OBF_CH(s, 56), OBF_CH(s, 57), OBF_CH(s, 58), OBF_CH(s, 59), \
    OBF_CH(s, 60), OBF_CH(s, 61), OBF_CH(s, 62), OBF_CH(s, 63), \
    OBF_CH(s, 64), OBF_CH(s, 65), OBF_CH(s, 66), OBF_CH(s, 67), \
    OBF_CH(s, 68), OBF_CH(s, 69), OBF_CH(s, 70), OBF_CH(s, 71), \
    OBF_CH(s, 72), OBF_CH(s, 73), OBF_CH(s, 74), OBF_CH(s, 75), \
    OBF_CH(s, 76), OBF_CH(s, 77), OBF_CH(s, 78), OBF_CH(s, 79), \
    OBF_CH(s, 80), OBF_CH(s, 81), OBF_CH(s, 82), OBF_CH(s, 83), \
    OBF_CH(s, 84), OBF_CH(s, 85), OBF_CH(s, 86), OBF_CH(s, 87), \
    OBF_CH(s, 88), OBF_CH(s, 89), OBF_CH(s, 90), OBF_CH(s, 91), \
    OBF_CH(s, 92), OBF_CH(s, 93), OBF_CH(s, 94), OBF_CH(s, 95), \
    OBF_CH(s, 96), OBF_CH(s, 97), OBF_CH(s, 98), OBF_CH(s, 99), \
    OBF_CH(s, 100), OBF_CH(s, 101), OBF_CH(s, 102), OBF_CH(s, 103), \
    OBF_CH(s, 104), OBF_CH(s, 105), OBF_CH(s, 106), OBF_CH(s, 107), \
    OBF_CH(s, 108), OBF_CH(s, 109), OBF_CH(s, 110), OBF_CH(s, 111), \
    OBF_CH(s, 112), OBF_CH(s, 113), OBF_CH(s, 114), OBF_CH(s, 115), \
    OBF_CH(s, 116), OBF_CH(s, 117), OBF_CH(s, 118), OBF_CH(s, 119), \
    OBF_CH(s, 120), OBF_CH(s, 121), OBF_CH(s, 122), OBF_CH(s, 123), \
    OBF_CH(s, 124), OBF_CH(s, 125), OBF_CH(s, 126), OBF_CH(s, 127)

#define OBF_STR(s) ({ \
    _Static_assert(sizeof(s) <= 128, "String too long for OBF_STR (max 128 chars)"); \
    static unsigned char data[] = { OBF_STR_128(s) }; \
    static int decrypted = 0; \
    if (!decrypted) { \
        for (size_t i = 0; i < sizeof(s); i++) \
            data[i] ^= OBF_KEY; \
        decrypted = 1; \
    } \
    (char*)data; \
})

#endif
