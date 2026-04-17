#ifndef CONFIG_H
#define CONFIG_H

#include <string.h>

#define IDR_CONFIG 101

// AES key and IV for configuration encryption (32-byte key, 16-byte IV)
#define CONFIG_KEY "B4A7E9C2D5F8A1B3C6E9D2F5A8B1C4D7"
#define CONFIG_IV  "A1B2C3D4E5F6A7B8"
#define CONFIG_RES_SIZE 2048

// Obfuscated marker setup to avoid literal matches in code section
// Marker: {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x13, 0x37, 0x99, 0x99, 0x88, 0x88, 0x77, 0x77}
#define SET_MARKER(m) do { \
    m[0]=0xDF-1; m[1]=0xAE-1; m[2]=0xBF-1; m[3]=0xF0-1; \
    m[4]=0xCB-1; m[5]=0xFF-1; m[6]=0xBB-1; m[7]=0xBF-1; \
    m[8]=0x14-1; m[9]=0x38-1; m[10]=0x9A-1; m[11]=0x9A-1; \
    m[12]=0x89-1; m[13]=0x89-1; m[14]=0x78-1; m[15]=0x78-1; \
} while(0)

#endif // CONFIG_H
