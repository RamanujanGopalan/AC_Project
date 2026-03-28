#include <common_header.hpp>

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <omp.h>

namespace {

constexpr size_t FRAMEWORK_BLOCK_SIZE = 16;
constexpr int CHACHA_ROUNDS = 20;

static inline uint32_t rotl32(uint32_t value, int amount) {
    return (value << amount) | (value >> (32 - amount));
}

static inline uint32_t load_le32(const uint8_t *input) {
    return static_cast<uint32_t>(input[0]) |
           (static_cast<uint32_t>(input[1]) << 8) |
           (static_cast<uint32_t>(input[2]) << 16) |
           (static_cast<uint32_t>(input[3]) << 24);
}

static inline void store_le32(uint8_t *output, uint32_t value) {
    output[0] = static_cast<uint8_t>(value & 0xFFU);
    output[1] = static_cast<uint8_t>((value >> 8) & 0xFFU);
    output[2] = static_cast<uint8_t>((value >> 16) & 0xFFU);
    output[3] = static_cast<uint8_t>((value >> 24) & 0xFFU);
}

static inline void quarter_round(uint32_t &a, uint32_t &b, uint32_t &c, uint32_t &d) {
    a += b;
    d ^= a;
    d = rotl32(d, 16);

    c += d;
    b ^= c;
    b = rotl32(b, 12);

    a += b;
    d ^= a;
    d = rotl32(d, 8);

    c += d;
    b ^= c;
    b = rotl32(b, 7);
}

static inline void chacha20_block(const uint32_t input[16], uint32_t output[16]) {
    uint32_t working[16];
    for (int i = 0; i < 16; ++i) {
        working[i] = input[i];
    }

    for (int round = 0; round < CHACHA_ROUNDS; round += 2) {
        quarter_round(working[0], working[4], working[8], working[12]);
        quarter_round(working[1], working[5], working[9], working[13]);
        quarter_round(working[2], working[6], working[10], working[14]);
        quarter_round(working[3], working[7], working[11], working[15]);

        quarter_round(working[0], working[5], working[10], working[15]);
        quarter_round(working[1], working[6], working[11], working[12]);
        quarter_round(working[2], working[7], working[8], working[13]);
        quarter_round(working[3], working[4], working[9], working[14]);
    }

    for (int i = 0; i < 16; ++i) {
        output[i] = working[i] + input[i];
    }
}

static inline void write_first_16_bytes(uint8_t *output, const uint32_t state[16]) {
    store_le32(output + 0, state[0]);
    store_le32(output + 4, state[1]);
    store_le32(output + 8, state[2]);
    store_le32(output + 12, state[3]);
}

} // namespace

uint32_t* chacha_cpu_get_key() {
    uint32_t *state = static_cast<uint32_t*>(std::malloc(16 * sizeof(uint32_t)));

    state[0] = 0x61707865U;
    state[1] = 0x3320646eU;
    state[2] = 0x79622d32U;
    state[3] = 0x6b206574U;

    for (int i = 0; i < 8; ++i) {
        state[4 + i] = 0x03020100U + static_cast<uint32_t>(i) * 0x04040404U;
    }

    state[12] = 0U;
    state[13] = 0U;
    state[14] = 0U;
    state[15] = 0U;

    return state;
}

void chacha_cpu_encrypt(uint8_t *input, uint8_t *output, uint32_t *key, size_t blocks) {
    #pragma omp parallel for
    for (long long block = 0; block < static_cast<long long>(blocks); ++block) {
        uint32_t state[16];
        uint32_t keystream[16];
        const size_t offset = static_cast<size_t>(block) * FRAMEWORK_BLOCK_SIZE;

        for (int i = 0; i < 16; ++i) {
            state[i] = key[i];
        }

        state[12] = load_le32(input + offset + 0);
        state[13] = load_le32(input + offset + 4);
        state[14] = load_le32(input + offset + 8);
        state[15] = load_le32(input + offset + 12);

        chacha20_block(state, keystream);
        write_first_16_bytes(output + offset, keystream);
    }
}

void chacha_cpu_encrypt_ctr(uint8_t *output, uint32_t *key, size_t blocks, uint64_t ctr) {
    #pragma omp parallel for
    for (long long block = 0; block < static_cast<long long>(blocks); ++block) {
        uint32_t state[16];
        uint32_t keystream[16];
        const uint64_t counter = ctr + static_cast<uint64_t>(block);
        const size_t offset = static_cast<size_t>(block) * FRAMEWORK_BLOCK_SIZE;

        for (int i = 0; i < 16; ++i) {
            state[i] = key[i];
        }

        state[12] = static_cast<uint32_t>(counter & 0xFFFFFFFFULL);
        state[13] = static_cast<uint32_t>(counter >> 32);

        chacha20_block(state, keystream);
        write_first_16_bytes(output + offset, keystream);
    }
}
