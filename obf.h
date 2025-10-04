#ifndef OBF_H
#define OBF_H

#include <string>
#include <array>
#include <utility>

// Compile-time string obfuscation using XOR encryption.
// This makes it much harder for static analysis tools to find and extract strings from the binary.

namespace Obfuscation {

    // A simple compile-time and runtime seed for the XOR key.
    // This makes the key less predictable.
    constexpr int time_seed() {
        return __TIME__[7] + __TIME__[6] * 10 + __TIME__[4] * 60 + __TIME__[3] * 600;
    }
    constexpr char XOR_KEY = static_cast<char>(time_seed() % 255 + 1); // Ensure key is not 0

    // `XorStr` struct to hold the obfuscated string.
    template <std::size_t N>
    struct XorStr {
        std::array<char, N> data;

        // Decrypts the string at runtime.
        // This is marked `inline` to encourage the compiler to place the decryption logic
        // directly where the string is used, avoiding a single, easily-findable decryption function.
        inline const char* decrypt() const {
            // The string is decrypted in-place in a mutable buffer.
            char* decrypted_data = const_cast<char*>(data.data());
            for (std::size_t i = 0; i < N - 1; ++i) {
                decrypted_data[i] ^= XOR_KEY;
            }
            return decrypted_data;
        }
    };

    // `make_xor_str` function to create an obfuscated string at compile-time.
    template <std::size_t N>
    constexpr auto make_xor_str(const char(&s)[N]) {
        XorStr<N> obfuscated_str{};
        for (std::size_t i = 0; i < N; ++i) {
            obfuscated_str.data[i] = s[i] ^ XOR_KEY;
        }
        return obfuscated_str;
    }

} // namespace Obfuscation

// The OBF_STR macro to be used in the code.
// It creates a static, obfuscated string and decrypts it on-the-fly when accessed.
// The lambda function helps ensure that the decryption happens at the point of use.
#define OBF_STR(s) []{ \
    constexpr auto obfuscated = Obfuscation::make_xor_str(s); \
    return std::string(obfuscated.decrypt()); \
}()

#endif // OBF_H