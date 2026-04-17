#ifndef CONFIG_H
#define CONFIG_H

#define SET_MARKER(m) \
    m[0] = 0xDF - 1; m[1] = 0xAE - 1; m[2] = 0xBF - 1; m[3] = 0xF0 - 1; \
    m[4] = 0x05 - 1; m[5] = 0x06 - 1; m[6] = 0x07 - 1; m[7] = 0x08 - 1; \
    m[8] = 0x09 - 1; m[9] = 0x0A - 1; m[10] = 0x0B - 1; m[11] = 0x0C - 1; \
    m[12] = 0x0D - 1; m[13] = 0x0E - 1; m[14] = 0x0F - 1; m[15] = 0x10 - 1;

void load_config();

#endif
