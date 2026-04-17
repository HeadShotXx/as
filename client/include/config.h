#ifndef CONFIG_H
#define CONFIG_H

#define SET_MARKER(m) \
    m[0] = 0xDE; m[1] = 0xAD; m[2] = 0xBE; m[3] = 0xEF; \
    m[4] = 0x11; m[5] = 0x22; m[6] = 0x33; m[7] = 0x44; \
    m[8] = 0x55; m[9] = 0x66; m[10] = 0x77; m[11] = 0x88; \
    m[12] = 0x99; m[13] = 0xAA; m[14] = 0xBB; m[15] = 0xCC;

void load_config();

#endif
