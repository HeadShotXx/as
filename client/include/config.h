#ifndef CONFIG_H
#define CONFIG_H

#define IDR_CONFIG 101

// AES key and IV for configuration encryption (32-byte key, 16-byte IV)
#define CONFIG_KEY "B4A7E9C2D5F8A1B3C6E9D2F5A8B1C4D7"
#define CONFIG_IV  "A1B2C3D4E5F6A7B8"
#define CONFIG_MARKER "CONF_DATA_START:"
#define CONFIG_RES_SIZE 2048

typedef struct {
    char host[256];
    int port;
} ClientConfig;

#endif // CONFIG_H
