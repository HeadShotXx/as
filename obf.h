// obf.h - C++ only: compile-time ascii85 + simple XOR obfuscation
#pragma once

#include <cstddef>
#include <cstdint>
#include <random>
#include <string>

#if defined(__GNUC__) || defined(__clang__)
#define OBF_NOINLINE __attribute__((noinline))
#else
#define OBF_NOINLINE
#endif

#if defined(_WIN32) || defined(_WIN64)
#include <windows.h>
static void obf_secure_zero(void *p, size_t n) { SecureZeroMemory(p, n); }
#else
static void obf_secure_zero(void *p, size_t n) {
    volatile unsigned char *q = (volatile unsigned char*)p;
    while (n--) *q++ = 0;
}
#endif

#ifndef OBF__COUNTER
#if defined(__COUNTER__)
#define OBF__COUNTER __COUNTER__
#else
#define OBF__COUNTER __LINE__
#endif
#endif

namespace obf_priv {

/* ---------- ASCII85 compile-time helpers ---------- */
constexpr std::size_t enc_len_from_plain(std::size_t n) { return ((n + 3) / 4) * 5; }

template<std::size_t N>
struct enc_buf { char data[N+1]; constexpr enc_buf(): data{} {} };

constexpr uint32_t pack4(const char *p, std::size_t i, std::size_t n) {
    uint32_t v = 0;
    for (std::size_t j = 0; j < 4; ++j) {
        std::size_t idx = i + j;
        uint8_t byte = (idx < n) ? static_cast<uint8_t>(p[idx]) : 0;
        v = (v << 8) | byte;
    }
    return v;
}

constexpr void encode5(uint32_t v, char *out, std::size_t pos) {
    char tmp[5] = {};
    for (int i = 4; i >= 0; --i) { tmp[i] = static_cast<char>((v % 85u) + 33); v /= 85u; }
    for (int i = 0; i < 5; ++i) out[pos + i] = tmp[i];
}

template<std::size_t Nplain>
constexpr auto ascii85_encode_const(const char (&plain)[Nplain]) -> enc_buf<enc_len_from_plain(Nplain)> {
    constexpr std::size_t N = Nplain;
    constexpr std::size_t outN = enc_len_from_plain(N);
    enc_buf<outN> out{};
    std::size_t outpos = 0;
    char tmp[N] = {};
    for (std::size_t i = 0; i < N; ++i) tmp[i] = plain[i];
    for (std::size_t i = 0; i < N; i += 4) {
        uint32_t v = pack4(tmp, i, N);
        encode5(v, out.data, outpos);
        outpos += 5;
    }
    out.data[outN] = '\0';
    return out;
}

static inline void ascii85_decode_rt(const char *enc, size_t enc_len, char *dest, size_t dest_len) {
    size_t outpos = 0;
    for (size_t i = 0; i < enc_len; i += 5) {
        uint32_t v = 0;
        for (size_t j = 0; j < 5; ++j) {
            char c = enc[i + j];
            uint32_t d = (uint32_t)(static_cast<unsigned char>(c) - 33);
            v = v * 85u + d;
        }
        for (int b = 3; b >= 0; --b)
            if (outpos < dest_len) dest[outpos++] = static_cast<char>((v >> (8 * b)) & 0xFFu);
    }
}

/* ---------- Compile-time key derivation ---------- */
constexpr uint32_t compile_part_a(unsigned long long base) {
    uint64_t x = base + 0x9E3779B97F4A7C15ULL;
    x = (x ^ (x >> 23)) * 0x2127599bf4325c37ULL;
    return static_cast<uint32_t>((x >> 16) & 0xFFFFFFFFu);
}

constexpr uint32_t compile_part_b(unsigned long long base) {
    uint64_t x = base * 0x9E3779B97F4A7C15ULL + 0xC6BC279692B5C323ULL;
    x = (x ^ (x >> 17)) * 0x7C1592C9UL;
    return static_cast<uint32_t>((x >> 8) & 0xFFFFFFFFu);
}

constexpr uint64_t reconstruct_compile_key(uint32_t a, uint32_t b) {
    uint64_t v = (static_cast<uint64_t>(a) << 32) | b;
    v ^= 0xA5A5A5A5A5A5A5A5ULL;
    return (v << 13) | (v >> (64 - 13));
}

/* ---------- Random junk code generator ---------- */
static inline uint32_t junk_hash(uint32_t x) {
    x ^= x >> 16;
    x *= 0x85ebca6b;
    x ^= x >> 13;
    x *= 0xc2b2ae35;
    x ^= x >> 16;
    return x;
}

#define OBF_JUNK_1(seed) \
    do { \
        volatile uint32_t __junk_a = (seed); \
        __junk_a = obf_priv::junk_hash(__junk_a); \
        __junk_a ^= 0xDEADBEEF; \
        (void)__junk_a; \
    } while(0)

#define OBF_JUNK_2(seed) \
    do { \
        volatile uint64_t __junk_b = (seed) * 0x9E3779B97F4A7C15ULL; \
        __junk_b = (__junk_b << 13) ^ (__junk_b >> 7); \
        __junk_b += 0xC6BC279692B5C323ULL; \
        (void)__junk_b; \
    } while(0)

#define OBF_JUNK_3(seed) \
    do { \
        volatile int __junk_c = static_cast<int>(seed); \
        for (int __i = 0; __i < 3; ++__i) { \
            __junk_c = (__junk_c * 1103515245 + 12345) & 0x7fffffff; \
        } \
        (void)__junk_c; \
    } while(0)

#define OBF_JUNK_4(seed) \
    do { \
        volatile uint32_t __junk_d[4]; \
        __junk_d[0] = (seed); \
        __junk_d[1] = __junk_d[0] ^ 0x12345678; \
        __junk_d[2] = __junk_d[1] + 0x9ABCDEF0; \
        __junk_d[3] = __junk_d[2] * 0xFEDCBA98; \
        (void)__junk_d[3]; \
    } while(0)

#define OBF_JUNK_BLOCK(seed) \
    do { \
        uint32_t __junk_selector = (seed) % 4; \
        switch(__junk_selector) { \
            case 0: OBF_JUNK_1(seed); break; \
            case 1: OBF_JUNK_2(seed); break; \
            case 2: OBF_JUNK_3(seed); break; \
            case 3: OBF_JUNK_4(seed); break; \
        } \
    } while(0)

/* ---------- Compile-time literal encoding ---------- */
template <std::size_t Nplain>
constexpr auto obf_encode_literal(const char (&lit)[Nplain], uint32_t part_a, uint32_t part_b)
-> enc_buf<enc_len_from_plain(Nplain)> {
    char tmp[Nplain] = {};
    uint64_t ck = reconstruct_compile_key(part_a, part_b);
    for (std::size_t i = 0; i < Nplain; ++i) {
        unsigned char kb = static_cast<unsigned char>((ck >> ((i & 7) * 8)) & 0xFFu);
        tmp[i] = static_cast<char>(static_cast<unsigned char>(lit[i]) ^ kb);
    }
    return ascii85_encode_const(tmp);
}

} // namespace obf_priv

#ifndef OBF_KEY_FROM_COUNTER_BASE
#define OBF_KEY_FROM_COUNTER_BASE() (static_cast<unsigned long long>(OBF__COUNTER) + 0x1337ABCDULL)
#endif

/* ---------- Block-style macro with junk code ---------- */
#define OBF_DO(str_literal, code_block) \
do { \
    OBF_JUNK_BLOCK(OBF__COUNTER * 0x1234); \
    constexpr unsigned long long __obf_base = OBF_KEY_FROM_COUNTER_BASE(); \
    constexpr uint32_t __obf_part_a = obf_priv::compile_part_a(__obf_base); \
    constexpr uint32_t __obf_part_b = obf_priv::compile_part_b(__obf_base); \
    OBF_JUNK_BLOCK(__obf_part_a); \
    constexpr auto __obf_enc = obf_priv::obf_encode_literal<sizeof(str_literal)>(str_literal, __obf_part_a, __obf_part_b); \
    constexpr std::size_t __obf_enc_size = obf_priv::enc_len_from_plain(sizeof(str_literal)); \
    constexpr std::size_t __obf_plain_size = sizeof(str_literal); \
    char buf[__obf_plain_size]; \
    OBF_JUNK_BLOCK(__obf_part_b); \
    obf_priv::ascii85_decode_rt(__obf_enc.data, __obf_enc_size, buf, __obf_plain_size); \
    uint64_t __obf_compile_key = obf_priv::reconstruct_compile_key(__obf_part_a, __obf_part_b); \
    OBF_JUNK_BLOCK(__obf_compile_key >> 32); \
    for (std::size_t __obf_i = 0; __obf_i < __obf_plain_size; ++__obf_i) { \
        unsigned char kb = static_cast<unsigned char>((__obf_compile_key >> ((__obf_i & 7) * 8)) & 0xFFu); \
        buf[__obf_i] = static_cast<char>(static_cast<unsigned char>(buf[__obf_i]) ^ kb); \
    } \
    OBF_JUNK_BLOCK(__obf_compile_key & 0xFFFFFFFF); \
    code_block; \
    obf_secure_zero(buf, __obf_plain_size); \
} while (0)

/* ---------- Expression-style with junk code ---------- */
#define OBF_STR(str_literal) \
([&]() -> std::string { \
    OBF_JUNK_BLOCK(OBF__COUNTER * 0x5678); \
    constexpr unsigned long long __obf_base = OBF_KEY_FROM_COUNTER_BASE(); \
    constexpr uint32_t __obf_part_a = obf_priv::compile_part_a(__obf_base); \
    constexpr uint32_t __obf_part_b = obf_priv::compile_part_b(__obf_base); \
    OBF_JUNK_BLOCK(__obf_part_a ^ __obf_part_b); \
    constexpr auto __obf_enc = obf_priv::obf_encode_literal<sizeof(str_literal)>(str_literal, __obf_part_a, __obf_part_b); \
    constexpr std::size_t __obf_enc_size = obf_priv::enc_len_from_plain(sizeof(str_literal)); \
    constexpr std::size_t __obf_plain_size = sizeof(str_literal); \
    char __obf_buf[__obf_plain_size]; \
    OBF_JUNK_BLOCK(__obf_plain_size * 0xABCD); \
    obf_priv::ascii85_decode_rt(__obf_enc.data, __obf_enc_size, __obf_buf, __obf_plain_size); \
    uint64_t __obf_compile_key = obf_priv::reconstruct_compile_key(__obf_part_a, __obf_part_b); \
    OBF_JUNK_BLOCK(__obf_compile_key >> 16); \
    for (std::size_t __obf_i = 0; __obf_i < __obf_plain_size; ++__obf_i) { \
        unsigned char kb = static_cast<unsigned char>((__obf_compile_key >> ((__obf_i & 7) * 8)) & 0xFFu); \
        __obf_buf[__obf_i] = static_cast<char>(static_cast<unsigned char>(__obf_buf[__obf_i]) ^ kb); \
    } \
    OBF_JUNK_BLOCK(__obf_compile_key & 0xFFFF); \
    std::string __obf_ret(__obf_buf, __obf_plain_size ? __obf_plain_size - 1 : 0); \
    obf_secure_zero(__obf_buf, __obf_plain_size); \
    return __obf_ret; \
}())

/* end of header */