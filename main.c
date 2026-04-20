#include <stdio.h>
#include "obfuscator.h"

int main() {
    printf("Decrypted 1: %s\n", OBF_STR("First unique string"));
    printf("Decrypted 2: %s\n", OBF_STR("Second unique string"));
    printf("Decrypted 3: %s\n", OBF_STR("Third unique string"));

    const char* repeat = OBF_STR("Repeatable");
    printf("Repeat 1: %s\n", repeat);
    printf("Repeat 2: %s\n", repeat);

    return 0;
}
