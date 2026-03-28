#include <stdint.h>
#include <stdlib.h>
#include <omp.h>

#define GIFT_ROUNDS 40

// ===== SBOX =====
static const uint8_t GIFT_SBOX[16] = {
    0x1,0xA,0x4,0xC,0x6,0xF,0x3,0x9,
    0x2,0xD,0xB,0x7,0x5,0x0,0x8,0xE
};

// ===== PERMUTATION =====
static const uint8_t GIFT_PBOX[128] = {
     0,33,66,99,96,1,34,67,64,97,2,35,32,65,98,3,
     4,37,70,103,100,5,38,71,68,101,6,39,36,69,102,7,
     8,41,74,107,104,9,42,75,72,105,10,43,40,73,106,11,
     12,45,78,111,108,13,46,79,76,109,14,47,44,77,110,15,
     16,49,82,115,112,17,50,83,80,113,18,51,48,81,114,19,
     20,53,86,119,116,21,54,87,84,117,22,55,52,85,118,23,
     24,57,90,123,120,25,58,91,88,121,26,59,56,89,122,27,
     28,61,94,127,124,29,62,95,92,125,30,63,60,93,126,31
};

// ===== ROUND CONSTANTS =====
static const uint8_t GIFT_RC[40] = {
    0x01,0x03,0x07,0x0F,0x1F,0x3E,0x3D,0x3B,0x37,0x2F,
    0x1E,0x3C,0x39,0x33,0x27,0x0E,0x1D,0x3A,0x35,0x2B,
    0x16,0x2C,0x18,0x30,0x21,0x02,0x05,0x0B,0x17,0x2E,
    0x1C,0x38,0x31,0x23,0x06,0x0D,0x1B,0x36,0x2D,0x1A
};

// ===== KEY GENERATION =====
// returns pointer to round keys [40 * 16 bytes]
uint8_t* gift_cpu_get_key() {
    uint8_t *round_keys = (uint8_t*)malloc(GIFT_ROUNDS * 16);

    uint8_t k[16];
    for(int i=0;i<16;i++) k[i] = rand() & 0xFF;

    for(int r=0; r<GIFT_ROUNDS; r++) {
        // store round key
        for(int i=0;i<16;i++)
            round_keys[r*16 + i] = k[i];

        // simple rotation
        uint8_t tmp = k[0];
        for(int i=0;i<15;i++)
            k[i] = k[i+1];
        k[15] = tmp;

        // small variation
        k[0] ^= (r + 1);
    }

    return round_keys;
}

// ===== SBOX LAYER =====
static inline void gift_subcells(uint8_t *state) {
    for(int i=0;i<16;i++) {
        uint8_t hi = state[i] >> 4;
        uint8_t lo = state[i] & 0xF;
        state[i] = (GIFT_SBOX[hi] << 4) | GIFT_SBOX[lo];
    }
}

// ===== PERMUTATION =====
static inline void gift_permute(uint8_t *state) {
    uint8_t tmp[16] = {0};

    for(int i=0;i<128;i++) {
        int src_byte = i >> 3;
        int src_bit  = i & 7;

        int dst = GIFT_PBOX[i];
        int dst_byte = dst >> 3;
        int dst_bit  = dst & 7;

        uint8_t bit = (state[src_byte] >> src_bit) & 1;
        tmp[dst_byte] |= (bit << dst_bit);
    }

    for(int i=0;i<16;i++)
        state[i] = tmp[i];
}

// ===== ADD ROUND KEY =====
static inline void gift_addroundkey(uint8_t *state,
                                    uint8_t *round_keys,
                                    int round)
{
    uint8_t *rk = round_keys + round*16;

    for(int i=0;i<16;i++)
        state[i] ^= rk[i];

    state[15] ^= GIFT_RC[round];
}

// ===== SINGLE BLOCK =====
static inline void gift_encrypt_block(uint8_t *in,
                                      uint8_t *out,
                                      uint8_t *round_keys)
{
    uint8_t state[16];

    for(int i=0;i<16;i++)
        state[i] = in[i];

    for(int r=0; r<GIFT_ROUNDS; r++) {
        gift_subcells(state);
        gift_permute(state);
        gift_addroundkey(state, round_keys, r);
    }

    for(int i=0;i<16;i++)
        out[i] = state[i];
}

// ===== PARALLEL ENCRYPT =====
void gift_cpu_encrypt(uint8_t *h_plain, uint8_t *h_cipher,uint8_t *round_keys,size_t blocks)
{
    #pragma omp parallel for
    for(size_t i = 0; i < blocks; i++) {
        gift_encrypt_block(
            h_plain  + (i << 4),
            h_cipher + (i << 4),
            round_keys
        );
    }
}

void gift_cpu_encrypt(uint8_t *h_cipher, uint8_t *round_keys, size_t blocks, uint64_t ctr){
    #pragma omp parallel for
    for(size_t i = 0; i < blocks; i++) {

        uint8_t state[16];

        // ===== Construct counter block =====
        uint64_t counter = ctr + i;

        // lower 64 bits
        for(int j = 0; j < 8; j++)
            state[j] = (counter >> (8*j)) & 0xFF;

        // upper 64 bits = 0
        for(int j = 8; j < 16; j++)
            state[j] = 0;

        // ===== ENCRYPT =====
        gift_encrypt_block(state, state, round_keys);

        // ===== OUTPUT =====
        for(int j = 0; j < 16; j++)
            h_cipher[(i << 4) + j] = state[j];
    }
}