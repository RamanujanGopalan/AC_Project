#pragma once

#include "../modes/gpu_chunk_runner.cuh"

#include <cstdint>
#include <cstdlib>

namespace gift128_gpu {

inline constexpr CipherDescriptor descriptor = {"gift", "GIFT-128", 16};
constexpr int GIFT_ROUNDS = 40;
constexpr int GIFT_BLOCK_SIZE = 16;

__device__ __constant__ uint8_t d_gift_round_keys[GIFT_ROUNDS * GIFT_BLOCK_SIZE];
__device__ __constant__ uint8_t d_gift_sbox[16];
__device__ __constant__ uint8_t d_gift_pbox[128];
__device__ __constant__ uint8_t d_gift_rc[GIFT_ROUNDS];

__device__ __forceinline__ void subcells(uint8_t *state) {
    #pragma unroll
    for (int i = 0; i < GIFT_BLOCK_SIZE; ++i) {
        const uint8_t hi = state[i] >> 4;
        const uint8_t lo = state[i] & 0x0FU;
        state[i] = static_cast<uint8_t>((d_gift_sbox[hi] << 4) | d_gift_sbox[lo]);
    }
}

__device__ __forceinline__ void permute(uint8_t *state) {
    uint8_t tmp[GIFT_BLOCK_SIZE] = {0};

    #pragma unroll
    for (int i = 0; i < 128; ++i) {
        const int src_byte = i >> 3;
        const int src_bit = i & 7;
        const int dst = d_gift_pbox[i];
        const int dst_byte = dst >> 3;
        const int dst_bit = dst & 7;
        const uint8_t bit = static_cast<uint8_t>((state[src_byte] >> src_bit) & 1U);
        tmp[dst_byte] |= static_cast<uint8_t>(bit << dst_bit);
    }

    #pragma unroll
    for (int i = 0; i < GIFT_BLOCK_SIZE; ++i) {
        state[i] = tmp[i];
    }
}

__device__ __forceinline__ void add_round_key(uint8_t *state, int round) {
    const uint8_t *round_key = d_gift_round_keys + round * GIFT_BLOCK_SIZE;

    #pragma unroll
    for (int i = 0; i < GIFT_BLOCK_SIZE; ++i) {
        state[i] ^= round_key[i];
    }

    state[15] ^= d_gift_rc[round];
}

__device__ __forceinline__ void encrypt_block(uint8_t *state) {
    #pragma unroll
    for (int round = 0; round < GIFT_ROUNDS; ++round) {
        subcells(state);
        permute(state);
        add_round_key(state, round);
    }
}

__global__ void ecb_kernel(const uint8_t *input, uint8_t *output, size_t blocks) {
    const size_t stride = static_cast<size_t>(blockDim.x) * gridDim.x;
    for (size_t idx = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x; idx < blocks; idx += stride) {
        uint8_t state[GIFT_BLOCK_SIZE];
        const size_t offset = idx * GIFT_BLOCK_SIZE;

        #pragma unroll
        for (int i = 0; i < GIFT_BLOCK_SIZE; ++i) {
            state[i] = input[offset + i];
        }

        encrypt_block(state);

        #pragma unroll
        for (int i = 0; i < GIFT_BLOCK_SIZE; ++i) {
            output[offset + i] = state[i];
        }
    }
}

__global__ void ctr_kernel(uint8_t *output, size_t blocks, uint64_t ctr) {
    const size_t stride = static_cast<size_t>(blockDim.x) * gridDim.x;
    constexpr uint64_t nonce = 0x123456789ABCDEF0ULL;

    for (size_t idx = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x; idx < blocks; idx += stride) {
        const uint64_t counter = ctr + idx;
        uint8_t state[GIFT_BLOCK_SIZE];

        for (int b = 0; b < 8; ++b) {
            state[b] = static_cast<uint8_t>((nonce >> (8 * (7 - b))) & 0xFFU);
            state[8 + b] = static_cast<uint8_t>((counter >> (8 * (7 - b))) & 0xFFU);
        }

        encrypt_block(state);

        const size_t offset = idx * GIFT_BLOCK_SIZE;
        #pragma unroll
        for (int i = 0; i < GIFT_BLOCK_SIZE; ++i) {
            output[offset + i] = state[i];
        }
    }
}

inline uint8_t* key_expansion(const uint8_t *key) {
    uint8_t *round_keys = static_cast<uint8_t*>(std::malloc(GIFT_ROUNDS * GIFT_BLOCK_SIZE));
    if (round_keys == nullptr) {
        return nullptr;
    }

    uint8_t local_key[GIFT_BLOCK_SIZE];
    for (int i = 0; i < GIFT_BLOCK_SIZE; ++i) {
        local_key[i] = key[i];
    }

    for (int round = 0; round < GIFT_ROUNDS; ++round) {
        for (int i = 0; i < GIFT_BLOCK_SIZE; ++i) {
            round_keys[round * GIFT_BLOCK_SIZE + i] = local_key[i];
        }

        const uint8_t first = local_key[0];
        for (int i = 0; i < GIFT_BLOCK_SIZE - 1; ++i) {
            local_key[i] = local_key[i + 1];
        }
        local_key[GIFT_BLOCK_SIZE - 1] = first;
        local_key[0] ^= static_cast<uint8_t>(round + 1);
    }

    return round_keys;
}

inline constexpr uint8_t h_gift_sbox[16] = {
    0x1,0xA,0x4,0xC,0x6,0xF,0x3,0x9,
    0x2,0xD,0xB,0x7,0x5,0x0,0x8,0xE
};

inline constexpr uint8_t h_gift_pbox[128] = {
     0,33,66,99,96,1,34,67,64,97,2,35,32,65,98,3,
     4,37,70,103,100,5,38,71,68,101,6,39,36,69,102,7,
     8,41,74,107,104,9,42,75,72,105,10,43,40,73,106,11,
     12,45,78,111,108,13,46,79,76,109,14,47,44,77,110,15,
     16,49,82,115,112,17,50,83,80,113,18,51,48,81,114,19,
     20,53,86,119,116,21,54,87,84,117,22,55,52,85,118,23,
     24,57,90,123,120,25,58,91,88,121,26,59,56,89,122,27,
     28,61,94,127,124,29,62,95,92,125,30,63,60,93,126,31
};

inline constexpr uint8_t h_gift_rc[GIFT_ROUNDS] = {
    0x01,0x03,0x07,0x0F,0x1F,0x3E,0x3D,0x3B,0x37,0x2F,
    0x1E,0x3C,0x39,0x33,0x27,0x0E,0x1D,0x3A,0x35,0x2B,
    0x16,0x2C,0x18,0x30,0x21,0x02,0x05,0x0B,0x17,0x2E,
    0x1C,0x38,0x31,0x23,0x06,0x0D,0x1B,0x36,0x2D,0x1A
};

inline cudaError_t setup_key() {
    static constexpr uint8_t key[GIFT_BLOCK_SIZE] = {
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
        0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff
    };

    uint8_t *round_keys = key_expansion(key);
    if (round_keys == nullptr) {
        return cudaErrorMemoryAllocation;
    }

    cudaError_t err = cudaMemcpyToSymbol(d_gift_round_keys, round_keys, GIFT_ROUNDS * GIFT_BLOCK_SIZE);
    if (err == cudaSuccess) {
        err = cudaMemcpyToSymbol(d_gift_sbox, h_gift_sbox, sizeof(h_gift_sbox));
    }
    if (err == cudaSuccess) {
        err = cudaMemcpyToSymbol(d_gift_pbox, h_gift_pbox, sizeof(h_gift_pbox));
    }
    if (err == cudaSuccess) {
        err = cudaMemcpyToSymbol(d_gift_rc, h_gift_rc, sizeof(h_gift_rc));
    }

    std::free(round_keys);
    return err;
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

} // namespace gift128_gpu
