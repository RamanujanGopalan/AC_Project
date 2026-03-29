#pragma once

#include "../modes/gpu_chunk_runner.cuh"

namespace chacha20_gpu {

inline constexpr CipherDescriptor descriptor = {"chacha", "ChaCha20", 64};
constexpr int CHACHA_ROUNDS = 20;

__host__ __device__ __forceinline__ uint32_t rotl32(uint32_t value, int amount) {
    return (value << amount) | (value >> (32 - amount));
}

__host__ __device__ __forceinline__ void store_le32(uint8_t *output, uint32_t value) {
    output[0] = static_cast<uint8_t>(value & 0xFFU);
    output[1] = static_cast<uint8_t>((value >> 8) & 0xFFU);
    output[2] = static_cast<uint8_t>((value >> 16) & 0xFFU);
    output[3] = static_cast<uint8_t>((value >> 24) & 0xFFU);
}

__device__ __forceinline__ void quarter_round(uint32_t &a, uint32_t &b, uint32_t &c, uint32_t &d) {
    a += b; d ^= a; d = rotl32(d, 16);
    c += d; b ^= c; b = rotl32(b, 12);
    a += b; d ^= a; d = rotl32(d, 8);
    c += d; b ^= c; b = rotl32(b, 7);
}

__device__ __forceinline__ void block(const uint32_t input[16], uint32_t output[16]) {
    uint32_t working[16];
    for (int i = 0; i < 16; ++i) working[i] = input[i];
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
    for (int i = 0; i < 16; ++i) output[i] = working[i] + input[i];
}

__device__ __forceinline__ void init_state(uint32_t state[16], uint64_t ctr) {
    state[0] = 0x61707865U;
    state[1] = 0x3320646eU;
    state[2] = 0x79622d32U;
    state[3] = 0x6b206574U;
    for (int i = 0; i < 8; ++i) state[4 + i] = 0x03020100U + static_cast<uint32_t>(i) * 0x04040404U;
    state[12] = static_cast<uint32_t>(ctr & 0xFFFFFFFFULL);
    state[13] = static_cast<uint32_t>(ctr >> 32);
    state[14] = 0U;
    state[15] = 0U;
}

__global__ void ctr_kernel(const uint8_t *input, uint8_t *output, size_t blocks, uint64_t ctr) {
    const size_t stride = static_cast<size_t>(blockDim.x) * gridDim.x;
    for (size_t idx = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x; idx < blocks; idx += stride) {
        uint32_t state[16], keystream[16];
        const size_t offset = idx * 64;
        init_state(state, ctr + idx);
        block(state, keystream);
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

inline cudaError_t launch_ctr(const uint8_t *d_input, uint8_t *d_output, size_t blocks, uint64_t ctr) {
    const int grid = gpu_grid_for_blocks(blocks);
    ctr_kernel<<<grid, GPU_THREADS_PER_BLOCK>>>(d_input, d_output, blocks, ctr);
    return cudaGetLastError();
}

} // namespace chacha20_gpu
