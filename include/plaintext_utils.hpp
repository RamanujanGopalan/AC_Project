#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdio>

inline void fill_plaintext_blocks(uint8_t *plain, size_t blocks, size_t block_size_bytes) {
    for (size_t i = 0; i < blocks; ++i) {
        const size_t offset = i * block_size_bytes;
        const uint64_t value = static_cast<uint64_t>(i);

        for (size_t j = 0; j < block_size_bytes; ++j) {
            plain[offset + j] = 0;
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
