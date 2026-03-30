// simon_cipher.cu
#include <stdio.h>
#include <stdint.h>
#include <cuda.h>
#include <random>

#define SIMON_ROUNDS 68
#define SIMON_BLOCK_SIZE 16

__constant__ uint64_t d_simon_round_keys[SIMON_ROUNDS];  // renamed

__device__ __forceinline__ uint64_t ROL(uint64_t x, int r) {
    return (x << r) | (x >> (64 - r));
}

__device__ __forceinline__ void simon_round(uint64_t &x, uint64_t &y, uint64_t k) {
    uint64_t tmp = x;
    x = y ^ (ROL(x,1) & ROL(x,8)) ^ ROL(x,2) ^ k;
    y = tmp;
}

__device__ void simon_encrypt_block(uint64_t &x, uint64_t &y) {
    #pragma unroll
    for (int i = 0; i < SIMON_ROUNDS; i++)
        simon_round(x, y, d_simon_round_keys[i]);
}

__global__ void simon_ecb_kernel(uint8_t *out, uint8_t *in, size_t blocks) {
    size_t i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= blocks) return;

    uint64_t *in64  = (uint64_t*)(in  + i * SIMON_BLOCK_SIZE);
    uint64_t *out64 = (uint64_t*)(out + i * SIMON_BLOCK_SIZE);

    uint64_t x = in64[0], y = in64[1];
    simon_encrypt_block(x, y);
    out64[0] = x;
    out64[1] = y;
}
// ── CTR ──────────────────────────────────────────────────────────────────────

__global__ void simon_ctr_kernel(uint8_t *out, const uint8_t *in,
                                  size_t blocks, uint64_t nonce, uint64_t counter_start)
{
    size_t i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= blocks) return;

    uint64_t ctr = counter_start + i;

    // Counter block: x = nonce, y = counter  (two 64-bit words = 16 bytes)
    uint64_t x = nonce;
    uint64_t y = ctr;

    // Encrypt the counter block using Simon round function
    #pragma unroll
    for (int r = 0; r < SIMON_ROUNDS; r++)
        simon_round(x, y, d_simon_round_keys[r]);

    // Reinterpret keystream as bytes and XOR with plaintext
    uint8_t keystream[16];
    for (int b = 7; b >= 0; b--) {
        keystream[b]   = (x >> (8 * (7 - b))) & 0xFF;
        keystream[8+b] = (y >> (8 * (7 - b))) & 0xFF;
    }

    #pragma unroll
    for (int j = 0; j < 16; j++)
        out[i * SIMON_BLOCK_SIZE + j] = in[i * SIMON_BLOCK_SIZE + j] ^ keystream[j];
}


static inline uint64_t ROR(uint64_t x, int r) {
    return (x >> r) | (x << (64 - r));
}

static const uint8_t Z[62] = {
    1,1,1,1,1,0,1,0,0,1,0,0,0,0,1,0,
    1,1,0,0,1,1,1,0,0,1,1,0,1,0,1,0,
    0,1,1,1,0,0,0,1,1,0,1,1,0,0,1,1,
    1,0,1,0,1,1,0,0,0,1,0,1
};

static void simon_keyExpansion(uint64_t key[2], uint64_t round_keys[SIMON_ROUNDS]) {
    uint64_t k[SIMON_ROUNDS];
    k[0] = key[0]; k[1] = key[1];
    for (int i = 2; i < SIMON_ROUNDS; i++) {
        uint64_t tmp = ROR(k[i-1], 3);
        tmp ^= k[i-2];
        tmp ^= ROR(tmp, 1);
        k[i] = ~k[i-2] ^ tmp ^ Z[(i-2) % 62] ^ 3;
    }
    for (int i = 0; i < SIMON_ROUNDS; i++)
        round_keys[i] = k[i];
}

// ── public entry points ───────────────────────────────────────────────────────

void cipher_simon_setup(const uint8_t *key) {
    uint64_t round_keys[SIMON_ROUNDS];
    // reinterpret the 16-byte key as two uint64_t words
    uint64_t k[2];
    k[0] = ((const uint64_t*)key)[0];
    k[1] = ((const uint64_t*)key)[1];
    simon_keyExpansion(k, round_keys);
    cudaMemcpyToSymbol(d_simon_round_keys, round_keys, sizeof(uint64_t) * SIMON_ROUNDS);
}

void cipher_simon_launch(uint8_t *d_in, uint8_t *d_out, int blocks, int threads) {
    int grid = (blocks + threads - 1) / threads;
    simon_ecb_kernel<<<grid, threads>>>(d_out, d_in, blocks);
}

void cipher_simon_launch_ctr(uint8_t *d_in, uint8_t *d_out,
                              int blocks, int threads,
                              uint64_t nonce, uint64_t counter_start){
    int grid = (blocks + threads - 1) / threads;
    simon_ctr_kernel<<<grid, threads>>>(d_out, d_in, blocks, nonce, counter_start);
}