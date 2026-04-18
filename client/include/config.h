#ifndef CONFIG_H
#define CONFIG_H

#define CONFIG_RESOURCE_ID 101

#define XOR_MARKER "\xFE\xED\xFA\xCE"
#define XOR_PROCESSED_MARKER "\xCE\xFA\xED\xFE"
#define XOR_KEY_MARKER "\xAA\xBB\xCC\xDD"

#define _S(x) XOR_MARKER "\x00" x

#define CONFIG_KEY "B4A7E9C2D5F8A1B3C6E9D2F5A8B1C4D7"
#define CONFIG_IV "A1B2C3D4E5F6A7B8"

// Marker: DE AD BE EF 11 22 33 44 55 66 77 88 99 AA BB CC
// Using volatile and byte-by-byte assignment in a block to prevent compiler from emitting the literal 16-byte sequence in the code section.
#define SET_MARKER(m) do { \
    volatile unsigned char* p = (volatile unsigned char*)(m); \
    p[0] = 0xDE - 1; p[0]++; \
    p[1] = 0xAD - 1; p[1]++; \
    p[2] = 0xBE - 1; p[2]++; \
    p[3] = 0xEF - 1; p[3]++; \
    p[4] = 0x11 - 1; p[4]++; \
    p[5] = 0x22 - 1; p[5]++; \
    p[6] = 0x33 - 1; p[6]++; \
    p[7] = 0x44 - 1; p[7]++; \
    p[8] = 0x55 - 1; p[8]++; \
    p[9] = 0x66 - 1; p[9]++; \
    p[10] = 0x77 - 1; p[10]++; \
    p[11] = 0x88 - 1; p[11]++; \
    p[12] = 0x99 - 1; p[12]++; \
    p[13] = 0xAA - 1; p[13]++; \
    p[14] = 0xBB - 1; p[14]++; \
    p[15] = 0xCC - 1; p[15]++; \
} while(0)

#endif
