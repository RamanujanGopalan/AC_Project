#include <cstddef>
#include <cstdint>
#include <cstdlib>

namespace {

constexpr int SALSA_ROUNDS = 20;

static inline uint32_t rotl32(uint32_t value, int amount) {
    return (value << amount) | (value >> (32 - amount));
}

static inline void store_le32(uint8_t *output, uint32_t value) {
    output[0] = static_cast<uint8_t>(value & 0xFFU);
    output[1] = static_cast<uint8_t>((value >> 8) & 0xFFU);
    output[2] = static_cast<uint8_t>((value >> 16) & 0xFFU);
    output[3] = static_cast<uint8_t>((value >> 24) & 0xFFU);
}

static inline void quarter_round(uint32_t &a, uint32_t &b, uint32_t &c, uint32_t &d) {
    b ^= rotl32(a + d, 7);
    c ^= rotl32(b + a, 9);
    d ^= rotl32(c + b, 13);
    a ^= rotl32(d + c, 18);
}

static inline void salsa20_block(const uint32_t input[16], uint32_t output[16]) {
    uint32_t working[16];
    for (int i = 0; i < 16; ++i) {
        working[i] = input[i];
    }

    for (int round = 0; round < SALSA_ROUNDS; round += 2) {
        quarter_round(working[0], working[4], working[8], working[12]);
        quarter_round(working[5], working[9], working[13], working[1]);
        quarter_round(working[10], working[14], working[2], working[6]);
        quarter_round(working[15], working[3], working[7], working[11]);

        quarter_round(working[0], working[1], working[2], working[3]);
        quarter_round(working[5], working[6], working[7], working[4]);
        quarter_round(working[10], working[11], working[8], working[9]);
        quarter_round(working[15], working[12], working[13], working[14]);
    }

    for (int i = 0; i < 16; ++i) {
        output[i] = working[i] + input[i];
    }
}

} // namespace

extern "C" void* salsa20_cpu_get_key_native() {
    uint32_t *state = static_cast<uint32_t*>(std::malloc(16 * sizeof(uint32_t)));

    state[0] = 0x61707865U;
    state[5] = 0x3320646eU;
    state[10] = 0x79622d32U;
    state[15] = 0x6b206574U;

    for (int i = 0; i < 4; ++i) {
        state[1 + i] = 0x03020100U + static_cast<uint32_t>(i) * 0x04040404U;
        state[11 + i] = 0x13121110U + static_cast<uint32_t>(i) * 0x04040404U;
    }

    state[6] = 0U;
    state[7] = 0U;
    state[8] = 0U;
    state[9] = 0U;

    return state;
}

extern "C" void salsa20_cpu_free_key_native(void *key) {
    std::free(key);
}

extern "C" void salsa20_cpu_crypt_ctr_native(const uint8_t *input,
                                              uint8_t *output,
                                              void *key,
                                              size_t blocks,
                                              uint64_t ctr) {
    auto *base_state = static_cast<uint32_t*>(key);

    for (size_t block = 0; block < blocks; ++block) {
        uint32_t state[16];
        uint32_t keystream[16];
        const size_t offset = block * 64;
        const uint64_t counter = ctr + block;

        for (int i = 0; i < 16; ++i) {
            state[i] = base_state[i];
        }

        state[8] = static_cast<uint32_t>(counter & 0xFFFFFFFFULL);
        state[9] = static_cast<uint32_t>(counter >> 32);

        salsa20_block(state, keystream);

        for (int i = 0; i < 16; ++i) {
            store_le32(output + offset + i * 4, keystream[i]);
        }

        if (input != nullptr) {
            for (int i = 0; i < 64; ++i) {
                output[offset + i] ^= input[offset + i];
            }
        }
    }
}
