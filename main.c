#include <stdio.h>
#include "obfuscator.h"

int main() {
    printf("Decrypted: %s\n", OBF_STR("Hello, World!"));
    printf("Decrypted: %s\n", OBF_STR("This is an obfuscated string."));
    printf("Decrypted: %s\n", OBF_STR("Another test with numbers 1234567890"));

    // Testing same string multiple times
    const char* str1 = OBF_STR("Repeat");
    const char* str2 = OBF_STR("Repeat");
    printf("Repeat 1: %s\n", str1);
    printf("Repeat 2: %s\n", str2);

    return 0;
}
