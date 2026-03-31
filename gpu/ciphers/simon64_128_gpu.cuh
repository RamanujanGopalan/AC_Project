#pragma once

#include "../modes/gpu_chunk_runner.cuh"

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
    1,1,1,1,1,0,1,0,0,1,0,0,0,0,1,0,
    1,1,0,0,1,1,1,0,0,1,1,0,1,0,1,0,
    0,1,1,1,0,0,0,1,1,0,1,1,0,0,1,1,
    1,0,1,0,1,1,0,0,0,1,0,1
};

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
