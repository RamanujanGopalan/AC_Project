#pragma once

#include "../modes/gpu_chunk_runner.cuh"

<<<<<<< HEAD
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
=======
#include <cstdint>

namespace simon128_gpu {

inline constexpr CipherDescriptor descriptor = {"simon", "SIMON-128/128", 16};
constexpr int SIMON_ROUNDS = 68;
constexpr int SIMON_BLOCK_SIZE = 16;

__device__ __constant__ uint64_t d_round_keys[SIMON_ROUNDS];

__device__ __forceinline__ uint64_t rol(uint64_t x, int r) {
    return (x << r) | (x >> (64 - r));
}

__device__ __forceinline__ void round_fn(uint64_t &x, uint64_t &y, uint64_t round_key) {
    const uint64_t temp = x;
    x = y ^ (rol(x, 1) & rol(x, 8)) ^ rol(x, 2) ^ round_key;
    y = temp;
}

__device__ __forceinline__ void encrypt_block(uint64_t &x, uint64_t &y) {
    #pragma unroll
    for (int i = 0; i < SIMON_ROUNDS; ++i) {
        round_fn(x, y, d_round_keys[i]);
    }
}

__global__ void ecb_kernel(const uint8_t *input, uint8_t *output, size_t blocks) {
    const size_t stride = static_cast<size_t>(blockDim.x) * gridDim.x;
    for (size_t idx = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x; idx < blocks; idx += stride) {
        const size_t offset = idx * SIMON_BLOCK_SIZE;
        const uint64_t *input64 = reinterpret_cast<const uint64_t*>(input + offset);
        uint64_t x = input64[0];
        uint64_t y = input64[1];
        encrypt_block(x, y);

        uint64_t *output64 = reinterpret_cast<uint64_t*>(output + offset);
        output64[0] = x;
        output64[1] = y;
    }
}

__global__ void ctr_kernel(uint8_t *output, size_t blocks, uint64_t ctr) {
    const size_t stride = static_cast<size_t>(blockDim.x) * gridDim.x;
    constexpr uint64_t nonce = 0x123456789ABCDEF0ULL;

    for (size_t idx = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x; idx < blocks; idx += stride) {
        uint64_t x = nonce;
        uint64_t y = ctr + idx;
        encrypt_block(x, y);

        const size_t offset = idx * SIMON_BLOCK_SIZE;
        uint8_t *out = output + offset;
        for (int b = 0; b < 8; ++b) {
            out[b] = static_cast<uint8_t>((x >> (8 * (7 - b))) & 0xFFU);
            out[8 + b] = static_cast<uint8_t>((y >> (8 * (7 - b))) & 0xFFU);
        }
    }
}

inline uint64_t ror(uint64_t x, int r) {
    return (x >> r) | (x << (64 - r));
}

inline constexpr uint8_t z_sequence[62] = {
>>>>>>> cb2958b (corrected gpu ciphers)
    1,1,1,1,1,0,1,0,0,1,0,0,0,0,1,0,
    1,1,0,0,1,1,1,0,0,1,1,0,1,0,1,0,
    0,1,1,1,0,0,0,1,1,0,1,1,0,0,1,1,
    1,0,1,0,1,1,0,0,0,1,0,1
};

<<<<<<< HEAD
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
namespace simon_gpu {

inline cudaError_t launch_ecb(const uint8_t *d_input,
                             uint8_t *d_output,
                             size_t blocks) {
    const int grid = gpu_grid_for_blocks(blocks);
    simon_ecb_kernel<<<grid, GPU_THREADS_PER_BLOCK>>>(
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
    simon_ctr_kernel<<<grid, GPU_THREADS_PER_BLOCK>>>(
        d_output, d_input, blocks, nonce, counter_start
    );
    return cudaGetLastError();
}

} // namespace simon_gpu
=======
inline void key_expansion(uint64_t key[2], uint64_t round_keys[SIMON_ROUNDS]) {
    uint64_t expanded[SIMON_ROUNDS];
    expanded[0] = key[0];
    expanded[1] = key[1];

    for (int i = 2; i < SIMON_ROUNDS; ++i) {
        uint64_t temp = ror(expanded[i - 1], 3);
        temp ^= expanded[i - 2];
        temp ^= ror(temp, 1);
        expanded[i] = ~expanded[i - 2] ^ temp ^ z_sequence[(i - 2) % 62] ^ 3ULL;
    }

    for (int i = 0; i < SIMON_ROUNDS; ++i) {
        round_keys[i] = expanded[i];
    }
}

inline cudaError_t setup_key() {
    static constexpr uint64_t key[2] = {
        0x0f0e0d0c0b0a0908ULL,
        0x0706050403020100ULL
    };

    uint64_t round_keys[SIMON_ROUNDS];
    key_expansion(const_cast<uint64_t*>(key), round_keys);
    return cudaMemcpyToSymbol(d_round_keys, round_keys, sizeof(round_keys));
}

inline cudaError_t launch_ecb(const uint8_t *d_input, uint8_t *d_output, size_t blocks) {
    cudaError_t err = setup_key();
    if (err != cudaSuccess) {
        return err;
    }

    const int grid = gpu_grid_for_blocks(blocks);
    ecb_kernel<<<grid, GPU_THREADS_PER_BLOCK>>>(d_input, d_output, blocks);
    return cudaGetLastError();
}

inline cudaError_t launch_ctr(uint8_t *d_output, size_t blocks, uint64_t ctr) {
    cudaError_t err = setup_key();
    if (err != cudaSuccess) {
        return err;
    }

    const int grid = gpu_grid_for_blocks(blocks);
    ctr_kernel<<<grid, GPU_THREADS_PER_BLOCK>>>(d_output, blocks, ctr);
    return cudaGetLastError();
}

} // namespace simon128_gpu
>>>>>>> cb2958b (corrected gpu ciphers)
