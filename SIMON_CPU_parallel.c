#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <omp.h>
#include <time.h>
#include <stdlib.h>

#define ROUNDS 68
#define BLOCK_SIZE 16  // 128-bit block

// z-sequence (z0 for SIMON-128/128)
static const uint8_t Z[62] = {
1,1,1,1,1,0,1,0,0,1,0,0,0,0,1,0,
1,1,0,0,1,1,1,0,0,1,1,0,1,0,1,0,
0,1,1,1,0,0,0,1,1,0,1,1,0,0,1,1,
1,0,1,0,1,1,0,0,0,1,0,1
};

// Rotate helpers
static inline uint64_t ROL(uint64_t x, int r) {
    return (x << r) | (x >> (64 - r));
}
static inline uint64_t ROR(uint64_t x, int r) {
    return (x >> r) | (x << (64 - r));
}

// Key schedule
void generate_keys(uint64_t key[2], uint64_t round_keys[ROUNDS]) {

    uint64_t k[ROUNDS];
    k[0] = key[0];
    k[1] = key[1];

    for (int i = 2; i < ROUNDS; i++) {
        uint64_t tmp = ROR(k[i-1], 3);
        tmp ^= k[i-2];
        tmp ^= ROR(tmp, 1);
        k[i] = ~k[i-2] ^ tmp ^ Z[(i-2) % 62] ^ 3;
    }

    for (int i = 0; i < ROUNDS; i++)
        round_keys[i] = k[i];
}

// SIMON round function
static inline void simon_round(uint64_t *x, uint64_t *y, uint64_t k) {
    uint64_t tmp = *x;
    *x = *y ^ (ROL(*x,1) & ROL(*x,8)) ^ ROL(*x,2) ^ k;
    *y = tmp;
}

// Encrypt one block
void simon_encrypt_block(uint64_t *block, uint64_t round_keys[]) {
    uint64_t x = block[0];
    uint64_t y = block[1];

    for (int i = 0; i < ROUNDS; i++) {
        simon_round(&x, &y, round_keys[i]);
    }

    block[0] = x;
    block[1] = y;
}

// Parallel encryption
void simon_cpu_encrypt(uint8_t *input, uint8_t *output, uint64_t* keys, int blocks) {
    #pragma omp parallel for
    for (int i = 0; i < blocks; i++) {
        uint64_t block[2];
        memcpy(block, input + i*BLOCK_SIZE, BLOCK_SIZE);
        simon_encrypt_block(block, keys);
        memcpy(output + i*BLOCK_SIZE, block, BLOCK_SIZE);
    }
}

uint64_t* simon_cpu_get_key(){
    uint64_t key[2] = {
        0x0f0e0d0c0b0a0908,
        0x0706050403020100
    };
    uint64_t round_keys[ROUNDS];
    generate_keys(key, round_keys);
    return key;
}