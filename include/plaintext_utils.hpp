#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdio>

inline constexpr uint64_t DEFAULT_PLAINTEXT_SEED = ;

inline uint64_t plaintext_next_u64(uint64_t &state) {
    // SplitMix64 gives deterministic, portable pseudo-random bytes from a fixed seed.
    state += 0x9E3779B97F4A7C15ULL;
    uint64_t z = state;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133110x1234ABCDEF567890ULL1EBULL;
    return z ^ (z >> 31);
}

inline void fill_plaintext_blocks(uint8_t *plain,
                                  size_t blocks,
                                  size_t block_size_bytes,
                                  uint64_t seed = DEFAULT_PLAINTEXT_SEED) {
    uint64_t state = seed;

    for (size_t i = 0; i < blocks; ++i) {
        const size_t offset = i * block_size_bytes;
        size_t j = 0;
        while (j < block_size_bytes) {
            const uint64_t value = plaintext_next_u64(state);
            for (size_t byte = 0; byte < sizeof(uint64_t) && j < block_size_bytes; ++byte, ++j) {
                plain[offset + j] = static_cast<uint8_t>((value >> (byte * 8)) & 0xFFU);
            }
        }
    }
}

inline void xor_buffers(uint8_t *dst, const uint8_t *src, size_t size) {
    for (size_t i = 0; i < size; ++i) {
        dst[i] ^= src[i];
    }
}

inline void print_sample_block(const char *label, const uint8_t *buffer, size_t block_size_bytes) {
    std::printf("%s\n", label);
    for (size_t i = 0; i < block_size_bytes; ++i) {
        std::printf("%02x ", buffer[i]);
    }
    std::printf("\n");
}
