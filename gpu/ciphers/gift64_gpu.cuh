#pragma once

#include "../modes/gpu_chunk_runner.cuh"

#define GIFT_ROUNDS 40
#define GIFT_BLOCK_SIZE 16



// ── device constants (private to this TU) ────────────────────────────────────
__constant__ uint8_t d_gift_round_keys[GIFT_ROUNDS * 16];
__constant__ uint8_t d_gift_sbox[16];
__constant__ uint8_t d_gift_pbox[128];
__constant__ uint8_t d_gift_rc[GIFT_ROUNDS];

// ── device helpers ────────────────────────────────────────────────────────────
__device__ __forceinline__ void gift_subcells(uint8_t *state) {
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        uint8_t hi = state[i] >> 4;
        uint8_t lo = state[i] & 0xF;
        state[i] = (d_gift_sbox[hi] << 4) | d_gift_sbox[lo];
    }
}

__device__ void gift_permute(uint8_t *state) {
    uint8_t tmp[16] = {0};
    #pragma unroll
    for (int i = 0; i < 128; i++) {
        int src_byte = i >> 3;
        int src_bit  = i & 7;
        int dst      = d_gift_pbox[i];
        int dst_byte = dst >> 3;
        int dst_bit  = dst & 7;
        uint8_t bit  = (state[src_byte] >> src_bit) & 1;
        tmp[dst_byte] |= (bit << dst_bit);
    }
    #pragma unroll
    for (int i = 0; i < 16; i++) state[i] = tmp[i];
}

__device__ __forceinline__ void gift_addroundkey(uint8_t *state, int round) {
    const uint8_t *rk = d_gift_round_keys + round * 16;
    #pragma unroll
    for (int i = 0; i < 16; i++) state[i] ^= rk[i];
    state[15] ^= d_gift_rc[round];
}

__device__ void gift_encrypt_block(uint8_t *state) {
    #pragma unroll
    for (int r = 0; r < GIFT_ROUNDS; r++) {
        gift_subcells(state);
        gift_permute(state);
        gift_addroundkey(state, r);
    }
}

// ── kernel ────────────────────────────────────────────────────────────────────
__global__ void gift_ecb_kernel(uint8_t *out, uint8_t *in, size_t blocks) {
    size_t i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= blocks) return;

    uint8_t state[16];
    #pragma unroll
    for (int j = 0; j < 16; j++) state[j] = in[i * GIFT_BLOCK_SIZE + j];

    gift_encrypt_block(state);

    #pragma unroll
    for (int j = 0; j < 16; j++) out[i * GIFT_BLOCK_SIZE + j] = state[j];
}

// ── host key schedule ─────────────────────────────────────────────────────────
// Takes an explicit 16-byte key instead of rand(), so it's deterministic.
static uint8_t* gift_keyExpansion(const uint8_t *key) {
    uint8_t *round_keys = (uint8_t*)malloc(GIFT_ROUNDS * 16);

    uint8_t k[16];
    for (int i = 0; i < 16; i++) k[i] = key[i];

    for (int r = 0; r < GIFT_ROUNDS; r++) {
        for (int i = 0; i < 16; i++) round_keys[r * 16 + i] = k[i];

        uint8_t tmp = k[0];
        for (int i = 0; i < 15; i++) k[i] = k[i+1];
        k[15] = tmp;
        k[0] ^= (r + 1);
    }

    return round_keys;
}

// ── public entry points ───────────────────────────────────────────────────────

static const uint8_t h_gift_sbox[16] = {
    0x1,0xA,0x4,0xC,0x6,0xF,0x3,0x9,
    0x2,0xD,0xB,0x7,0x5,0x0,0x8,0xE
};

static const uint8_t h_gift_pbox[128] = {
     0,33,66,99,96,1,34,67,64,97,2,35,32,65,98,3,
     4,37,70,103,100,5,38,71,68,101,6,39,36,69,102,7,
     8,41,74,107,104,9,42,75,72,105,10,43,40,73,106,11,
     12,45,78,111,108,13,46,79,76,109,14,47,44,77,110,15,
     16,49,82,115,112,17,50,83,80,113,18,51,48,81,114,19,
     20,53,86,119,116,21,54,87,84,117,22,55,52,85,118,23,
     24,57,90,123,120,25,58,91,88,121,26,59,56,89,122,27,
     28,61,94,127,124,29,62,95,92,125,30,63,60,93,126,31
};

static const uint8_t h_gift_rc[GIFT_ROUNDS] = {
    0x01,0x03,0x07,0x0F,0x1F,0x3E,0x3D,0x3B,0x37,0x2F,
    0x1E,0x3C,0x39,0x33,0x27,0x0E,0x1D,0x3A,0x35,0x2B,
    0x16,0x2C,0x18,0x30,0x21,0x02,0x05,0x0B,0x17,0x2E,
    0x1C,0x38,0x31,0x23,0x06,0x0D,0x1B,0x36,0x2D,0x1A
};

void cipher_gift_setup(const uint8_t *key) {
    uint8_t *round_keys = gift_keyExpansion(key);
    cudaMemcpyToSymbol(d_gift_round_keys, round_keys, GIFT_ROUNDS * 16);
    cudaMemcpyToSymbol(d_gift_sbox,       h_gift_sbox,  16);
    cudaMemcpyToSymbol(d_gift_pbox,       h_gift_pbox,  128);
    cudaMemcpyToSymbol(d_gift_rc,         h_gift_rc,    GIFT_ROUNDS);
    free(round_keys);
}


// ── CTR ──────────────────────────────────────────────────────────────────────

__device__ void gift_encrypt_ctr_block(uint8_t *state)
{
    // Identical to gift_encrypt_block — inlined separately so the
    // CTR path is independent of any future changes to the ECB path.
    #pragma unroll
    for (int r = 0; r < GIFT_ROUNDS; r++) {
        gift_subcells(state);
        gift_permute(state);
        gift_addroundkey(state, r);
    }
}

__global__ void gift_ctr_kernel(uint8_t *out, const uint8_t *in,
                                 size_t blocks, uint64_t nonce, uint64_t counter_start){
    size_t i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= blocks) return;

    uint64_t ctr = counter_start + i;

    // Build counter block: bytes 0-7 = nonce, bytes 8-15 = counter (big-endian)
    uint8_t ctr_block[16];
    for (int b = 7; b >= 0; b--) {
        ctr_block[b]   = (nonce >> (8 * (7 - b))) & 0xFF;
        ctr_block[8+b] = (ctr   >> (8 * (7 - b))) & 0xFF;
    }

    // Encrypt the counter block to produce keystream
    gift_encrypt_ctr_block(ctr_block);

    // XOR keystream with plaintext
    #pragma unroll
    for (int j = 0; j < 16; j++)
        out[i * GIFT_BLOCK_SIZE + j] = in[i * GIFT_BLOCK_SIZE + j] ^ ctr_block[j];
}

namespace gift_gpu{

inline cudaError_t launch_ecb(const uint8_t *d_input,
                             uint8_t *d_output,
                             size_t blocks) {
    const int grid = gpu_grid_for_blocks(blocks);
    gift_ecb_kernel<<<grid, GPU_THREADS_PER_BLOCK>>>(
        d_output, d_input, blocks
    );
    return cudaGetLastError();
}

inline cudaError_t launch_ctr(const uint8_t *d_input,
                             uint8_t *d_output,
                             size_t blocks,
                             uint64_t nonce,
                             uint64_t counter_start) {
    const int grid = gpu_grid_for_blocks(blocks);
    gift_ctr_kernel<<<grid, GPU_THREADS_PER_BLOCK>>>(
        d_output, d_input, blocks, nonce, counter_start
    );
    return cudaGetLastError();
}

}