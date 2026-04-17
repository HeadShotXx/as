#ifndef CONFIG_H
#define CONFIG_H

#define CONFIG_RES_ID 101

// Marker: DE AD BE EF 11 22 33 44 55 66 77 88 99 AA BB CC
#define SET_MARKER(m) \
    m[0]=0xDE-1; m[0]++; m[1]=0xAD-1; m[1]++; m[2]=0xBE-1; m[2]++; m[3]=0xEF-1; m[3]++; \
    m[4]=0x11-1; m[4]++; m[5]=0x22-1; m[5]++; m[6]=0x33-1; m[6]++; m[7]=0x44-1; m[7]++; \
    m[8]=0x55-1; m[8]++; m[9]=0x66-1; m[9]++; m[10]=0x77-1; m[10]++; m[11]=0x88-1; m[11]++; \
    m[12]=0x99-1; m[12]++; m[13]=0xAA-1; m[13]++; m[14]=0xBB-1; m[14]++; m[15]=0xCC-1; m[15]++;

#define CONFIG_ENCRYPTION_KEY "B4A7E9C2D5F8A1B3C6E9D2F5A8B1C4D7"
#define CONFIG_ENCRYPTION_IV  "A1B2C3D4E5F6A7B8"

#endif
