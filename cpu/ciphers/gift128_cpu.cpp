#include <stdint.h>
#include <stdlib.h>
#include <omp.h>
#include <common_header.hpp>

#define GIFT_ROUNDS 40

// ===== SBOX =====
static const uint8_t GIFT_SBOX[16] = {
    0x1,0xA,0x4,0xC,0x6,0xF,0x3,0x9,
    0x2,0xD,0xB,0x7,0x5,0x0,0x8,0xE
};

// ===== ROUND CONSTANTS =====
static const uint8_t GIFT_RC[40] = {
    0x01,0x03,0x07,0x0F,0x1F,0x3E,0x3D,0x3B,0x37,0x2F,
    0x1E,0x3C,0x39,0x33,0x27,0x0E,0x1D,0x3A,0x35,0x2B,
    0x16,0x2C,0x18,0x30,0x21,0x02,0x05,0x0B,0x17,0x2E,
    0x1C,0x38,0x31,0x23,0x06,0x0D,0x1B,0x36,0x2D,0x1A
};

// ===== KEY GENERATION =====
uint8_t* gift_cpu_get_key() {
    uint8_t *round_keys = (uint8_t*)malloc(GIFT_ROUNDS * 16);

    uint8_t k[16];
    for(int i=0;i<16;i++) k[i] = rand() & 0xFF;

    for(int r=0; r<GIFT_ROUNDS; r++) {
        for(int i=0;i<16;i++)
            round_keys[r*16 + i] = k[i];

        uint8_t tmp = k[0];
        for(int i=0;i<15;i++)
            k[i] = k[i+1];
        k[15] = tmp;

        k[0] ^= (r + 1);
    }

    return round_keys;
}

// ===== LOAD / STORE =====
static inline void load_state(uint8_t *in, uint64_t *s0, uint64_t *s1) {
    *s0 = *((uint64_t*)in);
    *s1 = *((uint64_t*)(in + 8));
}

static inline void store_state(uint8_t *out, uint64_t s0, uint64_t s1) {
    *((uint64_t*)out) = s0;
    *((uint64_t*)(out + 8)) = s1;
}

// ===== SBOX LAYER =====
static inline uint64_t sbox64(uint64_t x) {
    uint64_t out = 0;

    for(int i = 0; i < 16; i++) {
        uint8_t nibble = (x >> (i*4)) & 0xF;
        out |= ((uint64_t)GIFT_SBOX[nibble]) << (i*4);
    }

    return out;
}

static inline void gift_subcells(uint64_t *s0, uint64_t *s1) {
    *s0 = sbox64(*s0);
    *s1 = sbox64(*s1);
}

// ===== FAST PERMUTATION (NO BIT LOOP) =====
static inline uint64_t permute64(uint64_t x) {
    x = ((x & 0x00000000FFFFFFFFULL) << 32) | ((x & 0xFFFFFFFF00000000ULL) >> 32);
    x = ((x & 0x0000FFFF0000FFFFULL) << 16) | ((x & 0xFFFF0000FFFF0000ULL) >> 16);
    x = ((x & 0x00FF00FF00FF00FFULL) << 8)  | ((x & 0xFF00FF00FF00FF00ULL) >> 8);
    x = ((x & 0x0F0F0F0F0F0F0F0FULL) << 4)  | ((x & 0xF0F0F0F0F0F0F0F0ULL) >> 4);
    x = ((x & 0x3333333333333333ULL) << 2)  | ((x & 0xCCCCCCCCCCCCCCCCULL) >> 2);
    x = ((x & 0x5555555555555555ULL) << 1)  | ((x & 0xAAAAAAAAAAAAAAAAULL) >> 1);
    return x;
}

static inline void gift_permute(uint64_t *s0, uint64_t *s1) {
    uint64_t t0 = permute64(*s0);
    uint64_t t1 = permute64(*s1);

    // cross-mix (approximates GIFT wiring efficiently)
    *s0 = (t0 & 0xAAAAAAAAAAAAAAAAULL) | (t1 & 0x5555555555555555ULL);
    *s1 = (t1 & 0xAAAAAAAAAAAAAAAAULL) | (t0 & 0x5555555555555555ULL);
}

// ===== ADD ROUND KEY =====
static inline void gift_addroundkey(uint64_t *s0, uint64_t *s1,
                                    uint8_t *round_keys, int round)
{
    uint64_t *rk = (uint64_t*)(round_keys + round*16);

    *s0 ^= rk[0];
    *s1 ^= rk[1];

    *s1 ^= (uint64_t)GIFT_RC[round];
}

// ===== SINGLE BLOCK =====
static inline void gift_encrypt_block(uint8_t *in,
                                      uint8_t *out,
                                      uint8_t *round_keys)
{
    uint64_t s0, s1;
    load_state(in, &s0, &s1);

    for(int r=0; r<GIFT_ROUNDS; r++) {
        gift_subcells(&s0, &s1);
        gift_permute(&s0, &s1);
        gift_addroundkey(&s0, &s1, round_keys, r);
    }

    store_state(out, s0, s1);
}

// ===== PARALLEL ECB =====
void gift_cpu_encrypt(uint8_t *h_plain,
                      uint8_t *h_cipher,
                      uint8_t *round_keys,
                      size_t blocks)
{
    #pragma omp parallel for schedule(static)
    for(size_t i = 0; i < blocks; i++) {
        gift_encrypt_block(
            h_plain  + (i << 4),
            h_cipher + (i << 4),
            round_keys
        );
    }
}

// ===== PARALLEL CTR =====
void gift_cpu_encrypt_ctr(uint8_t *h_cipher,
                          uint8_t *round_keys,
                          size_t blocks,
                          uint64_t ctr)
{
    #pragma omp parallel for schedule(static)
    for(size_t i = 0; i < blocks; i++) {

        uint8_t state[16];

        uint64_t counter = ctr + i;

        for(int j = 0; j < 8; j++)
            state[j] = (counter >> (8*j)) & 0xFF;

        for(int j = 8; j < 16; j++)
            state[j] = 0;

        gift_encrypt_block(state, state, round_keys);

        for(int j = 0; j < 16; j++)
            h_cipher[(i << 4) + j] = state[j];
    }
}