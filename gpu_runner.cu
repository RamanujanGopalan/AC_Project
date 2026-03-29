#include <cuda_runtime.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <string>

namespace {

constexpr size_t FRAMEWORK_BLOCK_SIZE = 16;
constexpr size_t DES_BLOCK_SIZE = 8;
constexpr int DES_ROUNDS = 16;
constexpr int CHACHA_ROUNDS = 20;
constexpr int SALSA_ROUNDS = 20;
constexpr int THREADS_PER_BLOCK = 256;
constexpr size_t CHUNK_BLOCKS = 1ULL << 20;

#define CUDA_CHECK(call)                                                            \
    do {                                                                            \
        cudaError_t err__ = (call);                                                 \
        if (err__ != cudaSuccess) {                                                 \
            fprintf(stderr, "CUDA error: %s (%s:%d)\n", cudaGetErrorString(err__),  \
                    __FILE__, __LINE__);                                            \
            return 1;                                                               \
        }                                                                           \
    } while (0)

struct PerfStats {
    double total_ms = 0.0;
    double kernel_ms = 0.0;
    double h2d_ms = 0.0;
    double d2h_ms = 0.0;
};

void print_usage(const char *program) {
    printf("Usage:\n");
    printf("  %s <cipher> <mode> <blocks>\n", program);
    printf("  %s gpu <cipher> <mode> <blocks>\n", program);
    printf("\nGPU ciphers: des, chacha, salsa\n");
    printf("Modes: ecb, ctr\n");
}

void fill_plaintext(uint8_t *plain, size_t blocks, size_t block_offset) {
    for (size_t i = 0; i < blocks; ++i) {
        const size_t offset = i * FRAMEWORK_BLOCK_SIZE;
        const uint64_t value = static_cast<uint64_t>(block_offset + i);
        for (int j = 0; j < 8; ++j) {
            plain[offset + j] = static_cast<uint8_t>((value >> (8 * j)) & 0xFFU);
            plain[offset + 8 + j] = static_cast<uint8_t>((value >> (8 * j)) & 0xFFU);
        }
    }
}

void xor_buffers(uint8_t *dst, const uint8_t *src, size_t size) {
    for (size_t i = 0; i < size; ++i) {
        dst[i] ^= src[i];
    }
}

void print_block(const char *label, const uint8_t *block) {
    printf("%s\n", label);
    for (size_t i = 0; i < FRAMEWORK_BLOCK_SIZE; ++i) {
        printf("%02x ", block[i]);
    }
    printf("\n");
}

void print_perf(const PerfStats &stats, size_t total_blocks) {
    const double total_seconds = stats.total_ms / 1000.0;
    const double blocks_per_sec = total_seconds > 0.0 ? total_blocks / total_seconds : 0.0;
    const double gb_per_sec =
        total_seconds > 0.0
            ? ((total_blocks * FRAMEWORK_BLOCK_SIZE) / (1024.0 * 1024.0 * 1024.0)) / total_seconds
            : 0.0;

    printf("\n===== PERFORMANCE =====\n");
    printf("Total Time: %.3f ms\n", stats.total_ms);
    printf("Kernel Time: %.3f ms\n", stats.kernel_ms);
    printf("H2D Time: %.3f ms\n", stats.h2d_ms);
    printf("D2H Time: %.3f ms\n", stats.d2h_ms);
    printf("\nThroughput:\n");
    printf("Blocks/sec: %.2f\n", blocks_per_sec);
    printf("GB/sec: %.2f\n", gb_per_sec);
}

__device__ __constant__ int d_ip[64] = {
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
};

__device__ __constant__ int d_fp[64] = {
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
};

__device__ __constant__ int d_e[48] = {
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1
};

__device__ __constant__ int d_p[32] = {
    16, 7, 20, 21, 29, 12, 28, 17,
    1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9,
    19, 13, 30, 6, 22, 11, 4, 25
};

__device__ __constant__ int d_pc1[56] = {
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4
};

__device__ __constant__ int d_pc2[48] = {
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
};

__device__ __constant__ int d_shifts[DES_ROUNDS] = {
    1, 1, 2, 2, 2, 2, 2, 2,
    1, 2, 2, 2, 2, 2, 2, 1
};

__device__ __constant__ int d_sbox[8][4][16] = {
    {
        {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
        {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
        {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
        {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
    },
    {
        {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
        {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
        {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
        {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}
    },
    {
        {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
        {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
        {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
        {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}
    },
    {
        {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
        {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
        {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
        {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}
    },
    {
        {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
        {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
        {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
        {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}
    },
    {
        {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
        {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
        {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
        {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}
    },
    {
        {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
        {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
        {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
        {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}
    },
    {
        {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
        {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
        {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
        {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
    }
};

__device__ __forceinline__ uint64_t permute_bits(uint64_t input, const int *table, int count, int width) {
    uint64_t output = 0;
    for (int i = 0; i < count; ++i) {
        output = (output << 1) | ((input >> (width - table[i])) & 1ULL);
    }
    return output;
}

__device__ __forceinline__ uint64_t load_be64(const uint8_t *input) {
    uint64_t value = 0;
    for (int i = 0; i < 8; ++i) {
        value = (value << 8) | input[i];
    }
    return value;
}

__device__ __forceinline__ void store_be64(uint8_t *output, uint64_t value) {
    for (int i = 7; i >= 0; --i) {
        output[i] = static_cast<uint8_t>(value & 0xFFU);
        value >>= 8;
    }
}

__device__ __forceinline__ uint32_t feistel_round(uint32_t half_block, uint64_t round_key) {
    const uint64_t expanded = permute_bits(half_block, d_e, 48, 32) ^ round_key;
    uint32_t substituted = 0;
    for (int box = 0; box < 8; ++box) {
        const uint32_t chunk = static_cast<uint32_t>((expanded >> (42 - 6 * box)) & 0x3FU);
        const int row = ((chunk & 0x20U) >> 4) | (chunk & 0x01U);
        const int col = (chunk >> 1) & 0x0F;
        substituted = (substituted << 4) | static_cast<uint32_t>(d_sbox[box][row][col]);
    }
    return static_cast<uint32_t>(permute_bits(substituted, d_p, 32, 32));
}

__device__ __forceinline__ void des_generate_round_keys(uint64_t key, uint64_t round_keys[DES_ROUNDS]) {
    const uint64_t permuted = permute_bits(key, d_pc1, 56, 64);
    uint32_t c = static_cast<uint32_t>((permuted >> 28) & 0x0FFFFFFFUL);
    uint32_t d = static_cast<uint32_t>(permuted & 0x0FFFFFFFUL);
    for (int round = 0; round < DES_ROUNDS; ++round) {
        c = ((c << d_shifts[round]) | (c >> (28 - d_shifts[round]))) & 0x0FFFFFFFUL;
        d = ((d << d_shifts[round]) | (d >> (28 - d_shifts[round]))) & 0x0FFFFFFFUL;
        const uint64_t combined = (static_cast<uint64_t>(c) << 28) | d;
        round_keys[round] = permute_bits(combined, d_pc2, 48, 56);
    }
}

__device__ __forceinline__ uint64_t des_encrypt_block(uint64_t block, const uint64_t round_keys[DES_ROUNDS]) {
    block = permute_bits(block, d_ip, 64, 64);
    uint32_t left = static_cast<uint32_t>(block >> 32);
    uint32_t right = static_cast<uint32_t>(block & 0xFFFFFFFFULL);
    for (int round = 0; round < DES_ROUNDS; ++round) {
        const uint32_t next_left = right;
        right = left ^ feistel_round(right, round_keys[round]);
        left = next_left;
    }
    const uint64_t pre_output = (static_cast<uint64_t>(right) << 32) | static_cast<uint64_t>(left);
    return permute_bits(pre_output, d_fp, 64, 64);
}

__host__ __device__ __forceinline__ uint32_t rotl32(uint32_t value, int amount) {
    return (value << amount) | (value >> (32 - amount));
}

__host__ __device__ __forceinline__ uint32_t load_le32(const uint8_t *input) {
    return static_cast<uint32_t>(input[0]) |
           (static_cast<uint32_t>(input[1]) << 8) |
           (static_cast<uint32_t>(input[2]) << 16) |
           (static_cast<uint32_t>(input[3]) << 24);
}

__host__ __device__ __forceinline__ void store_le32(uint8_t *output, uint32_t value) {
    output[0] = static_cast<uint8_t>(value & 0xFFU);
    output[1] = static_cast<uint8_t>((value >> 8) & 0xFFU);
    output[2] = static_cast<uint8_t>((value >> 16) & 0xFFU);
    output[3] = static_cast<uint8_t>((value >> 24) & 0xFFU);
}

__device__ __forceinline__ void chacha_quarter_round(uint32_t &a, uint32_t &b, uint32_t &c, uint32_t &d) {
    a += b; d ^= a; d = rotl32(d, 16);
    c += d; b ^= c; b = rotl32(b, 12);
    a += b; d ^= a; d = rotl32(d, 8);
    c += d; b ^= c; b = rotl32(b, 7);
}

__device__ __forceinline__ void chacha20_block(const uint32_t input[16], uint32_t output[16]) {
    uint32_t working[16];
    for (int i = 0; i < 16; ++i) working[i] = input[i];
    for (int round = 0; round < CHACHA_ROUNDS; round += 2) {
        chacha_quarter_round(working[0], working[4], working[8], working[12]);
        chacha_quarter_round(working[1], working[5], working[9], working[13]);
        chacha_quarter_round(working[2], working[6], working[10], working[14]);
        chacha_quarter_round(working[3], working[7], working[11], working[15]);
        chacha_quarter_round(working[0], working[5], working[10], working[15]);
        chacha_quarter_round(working[1], working[6], working[11], working[12]);
        chacha_quarter_round(working[2], working[7], working[8], working[13]);
        chacha_quarter_round(working[3], working[4], working[9], working[14]);
    }
    for (int i = 0; i < 16; ++i) output[i] = working[i] + input[i];
}

__device__ __forceinline__ void salsa_quarter_round(uint32_t &a, uint32_t &b, uint32_t &c, uint32_t &d) {
    b ^= rotl32(a + d, 7);
    c ^= rotl32(b + a, 9);
    d ^= rotl32(c + b, 13);
    a ^= rotl32(d + c, 18);
}

__device__ __forceinline__ void salsa20_block(const uint32_t input[16], uint32_t output[16]) {
    uint32_t working[16];
    for (int i = 0; i < 16; ++i) working[i] = input[i];
    for (int round = 0; round < SALSA_ROUNDS; round += 2) {
        salsa_quarter_round(working[0], working[4], working[8], working[12]);
        salsa_quarter_round(working[5], working[9], working[13], working[1]);
        salsa_quarter_round(working[10], working[14], working[2], working[6]);
        salsa_quarter_round(working[15], working[3], working[7], working[11]);
        salsa_quarter_round(working[0], working[1], working[2], working[3]);
        salsa_quarter_round(working[5], working[6], working[7], working[4]);
        salsa_quarter_round(working[10], working[11], working[8], working[9]);
        salsa_quarter_round(working[15], working[12], working[13], working[14]);
    }
    for (int i = 0; i < 16; ++i) output[i] = working[i] + input[i];
}

__device__ __forceinline__ void write_first_16_bytes(uint8_t *output, const uint32_t state[16]) {
    store_le32(output + 0, state[0]);
    store_le32(output + 4, state[1]);
    store_le32(output + 8, state[2]);
    store_le32(output + 12, state[3]);
}

__device__ __forceinline__ void init_chacha_state(uint32_t state[16]) {
    state[0] = 0x61707865U;
    state[1] = 0x3320646eU;
    state[2] = 0x79622d32U;
    state[3] = 0x6b206574U;
    for (int i = 0; i < 8; ++i) state[4 + i] = 0x03020100U + static_cast<uint32_t>(i) * 0x04040404U;
    state[12] = 0U; state[13] = 0U; state[14] = 0U; state[15] = 0U;
}

__device__ __forceinline__ void init_salsa_state(uint32_t state[16]) {
    state[0] = 0x61707865U;
    state[5] = 0x3320646eU;
    state[10] = 0x79622d32U;
    state[15] = 0x6b206574U;
    for (int i = 0; i < 4; ++i) {
        state[1 + i] = 0x03020100U + static_cast<uint32_t>(i) * 0x04040404U;
        state[11 + i] = 0x13121110U + static_cast<uint32_t>(i) * 0x04040404U;
    }
    state[6] = 0U; state[7] = 0U; state[8] = 0U; state[9] = 0U;
}

__global__ void des_ecb_kernel(const uint8_t *input, uint8_t *output, uint64_t key, size_t blocks) {
    const size_t stride = static_cast<size_t>(blockDim.x) * gridDim.x;
    uint64_t round_keys[DES_ROUNDS];
    des_generate_round_keys(key, round_keys);
    for (size_t idx = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x; idx < blocks; idx += stride) {
        const size_t offset = idx * FRAMEWORK_BLOCK_SIZE;
        const uint64_t left = load_be64(input + offset);
        const uint64_t right = load_be64(input + offset + DES_BLOCK_SIZE);
        store_be64(output + offset, des_encrypt_block(left, round_keys));
        store_be64(output + offset + DES_BLOCK_SIZE, des_encrypt_block(right, round_keys));
    }
}

__global__ void des_ctr_kernel(uint8_t *output, uint64_t key, size_t blocks, uint64_t ctr) {
    const size_t stride = static_cast<size_t>(blockDim.x) * gridDim.x;
    uint64_t round_keys[DES_ROUNDS];
    des_generate_round_keys(key, round_keys);
    for (size_t idx = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x; idx < blocks; idx += stride) {
        const size_t offset = idx * FRAMEWORK_BLOCK_SIZE;
        const uint64_t counter0 = ctr + idx * 2ULL;
        const uint64_t counter1 = counter0 + 1ULL;
        store_be64(output + offset, des_encrypt_block(counter0, round_keys));
        store_be64(output + offset + DES_BLOCK_SIZE, des_encrypt_block(counter1, round_keys));
    }
}

__global__ void chacha_ecb_kernel(const uint8_t *input, uint8_t *output, size_t blocks) {
    const size_t stride = static_cast<size_t>(blockDim.x) * gridDim.x;
    for (size_t idx = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x; idx < blocks; idx += stride) {
        uint32_t state[16], keystream[16];
        const size_t offset = idx * FRAMEWORK_BLOCK_SIZE;
        init_chacha_state(state);
        state[12] = load_le32(input + offset + 0);
        state[13] = load_le32(input + offset + 4);
        state[14] = load_le32(input + offset + 8);
        state[15] = load_le32(input + offset + 12);
        chacha20_block(state, keystream);
        write_first_16_bytes(output + offset, keystream);
    }
}

__global__ void chacha_ctr_kernel(uint8_t *output, size_t blocks, uint64_t ctr) {
    const size_t stride = static_cast<size_t>(blockDim.x) * gridDim.x;
    for (size_t idx = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x; idx < blocks; idx += stride) {
        uint32_t state[16], keystream[16];
        const size_t offset = idx * FRAMEWORK_BLOCK_SIZE;
        const uint64_t counter = ctr + idx;
        init_chacha_state(state);
        state[12] = static_cast<uint32_t>(counter & 0xFFFFFFFFULL);
        state[13] = static_cast<uint32_t>(counter >> 32);
        chacha20_block(state, keystream);
        write_first_16_bytes(output + offset, keystream);
    }
}

__global__ void salsa_ecb_kernel(const uint8_t *input, uint8_t *output, size_t blocks) {
    const size_t stride = static_cast<size_t>(blockDim.x) * gridDim.x;
    for (size_t idx = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x; idx < blocks; idx += stride) {
        uint32_t state[16], keystream[16];
        const size_t offset = idx * FRAMEWORK_BLOCK_SIZE;
        init_salsa_state(state);
        state[6] = load_le32(input + offset + 0);
        state[7] = load_le32(input + offset + 4);
        state[8] = load_le32(input + offset + 8);
        state[9] = load_le32(input + offset + 12);
        salsa20_block(state, keystream);
        write_first_16_bytes(output + offset, keystream);
    }
}

__global__ void salsa_ctr_kernel(uint8_t *output, size_t blocks, uint64_t ctr) {
    const size_t stride = static_cast<size_t>(blockDim.x) * gridDim.x;
    for (size_t idx = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x; idx < blocks; idx += stride) {
        uint32_t state[16], keystream[16];
        const size_t offset = idx * FRAMEWORK_BLOCK_SIZE;
        const uint64_t counter = ctr + idx;
        init_salsa_state(state);
        state[8] = static_cast<uint32_t>(counter & 0xFFFFFFFFULL);
        state[9] = static_cast<uint32_t>(counter >> 32);
        salsa20_block(state, keystream);
        write_first_16_bytes(output + offset, keystream);
    }
}

enum class GpuCipher {
    Des,
    Chacha,
    Salsa
};

int run_gpu_cipher(GpuCipher cipher, const std::string &mode, size_t total_blocks) {
    const size_t max_bytes = CHUNK_BLOCKS * FRAMEWORK_BLOCK_SIZE;
    uint8_t *h_plain = static_cast<uint8_t*>(malloc(max_bytes));
    uint8_t *h_out = static_cast<uint8_t*>(malloc(max_bytes));
    uint8_t *d_plain = nullptr;
    uint8_t *d_out = nullptr;
    if (h_plain == nullptr || h_out == nullptr) {
        fprintf(stderr, "memory allocation failed\n");
        free(h_plain);
        free(h_out);
        return 1;
    }

    if (mode == "ecb") {
        CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&d_plain), max_bytes));
    }
    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&d_out), max_bytes));

    cudaEvent_t start_event, stop_event;
    CUDA_CHECK(cudaEventCreate(&start_event));
    CUDA_CHECK(cudaEventCreate(&stop_event));

    PerfStats stats;
    uint8_t first_plain[FRAMEWORK_BLOCK_SIZE] = {0};
    uint8_t first_cipher[FRAMEWORK_BLOCK_SIZE] = {0};
    bool first_saved = false;

    for (size_t processed = 0; processed < total_blocks; processed += CHUNK_BLOCKS) {
        const size_t current_blocks = (total_blocks - processed < CHUNK_BLOCKS) ? (total_blocks - processed) : CHUNK_BLOCKS;
        const size_t current_bytes = current_blocks * FRAMEWORK_BLOCK_SIZE;
        fill_plaintext(h_plain, current_blocks, processed);

        if (mode == "ecb") {
            CUDA_CHECK(cudaEventRecord(start_event));
            CUDA_CHECK(cudaMemcpy(d_plain, h_plain, current_bytes, cudaMemcpyHostToDevice));
            CUDA_CHECK(cudaEventRecord(stop_event));
            CUDA_CHECK(cudaEventSynchronize(stop_event));
            float ms = 0.0f;
            CUDA_CHECK(cudaEventElapsedTime(&ms, start_event, stop_event));
            stats.h2d_ms += ms;
        }

        int grid = static_cast<int>((current_blocks + THREADS_PER_BLOCK - 1) / THREADS_PER_BLOCK);
        if (grid > 65535) grid = 65535;
        if (grid == 0) grid = 1;

        CUDA_CHECK(cudaEventRecord(start_event));
        if (cipher == GpuCipher::Des) {
            const uint64_t key = 0x133457799BBCDFF1ULL;
            const uint64_t ctr = 0xABCDEF1234567890ULL + processed * 2ULL;
            if (mode == "ecb") des_ecb_kernel<<<grid, THREADS_PER_BLOCK>>>(d_plain, d_out, key, current_blocks);
            else des_ctr_kernel<<<grid, THREADS_PER_BLOCK>>>(d_out, key, current_blocks, ctr);
        } else if (cipher == GpuCipher::Chacha) {
            const uint64_t ctr = 0x1020304050607080ULL + processed;
            if (mode == "ecb") chacha_ecb_kernel<<<grid, THREADS_PER_BLOCK>>>(d_plain, d_out, current_blocks);
            else chacha_ctr_kernel<<<grid, THREADS_PER_BLOCK>>>(d_out, current_blocks, ctr);
        } else {
            const uint64_t ctr = 0x0F1E2D3C4B5A6978ULL + processed;
            if (mode == "ecb") salsa_ecb_kernel<<<grid, THREADS_PER_BLOCK>>>(d_plain, d_out, current_blocks);
            else salsa_ctr_kernel<<<grid, THREADS_PER_BLOCK>>>(d_out, current_blocks, ctr);
        }
        CUDA_CHECK(cudaGetLastError());
        CUDA_CHECK(cudaEventRecord(stop_event));
        CUDA_CHECK(cudaEventSynchronize(stop_event));
        float ms = 0.0f;
        CUDA_CHECK(cudaEventElapsedTime(&ms, start_event, stop_event));
        stats.kernel_ms += ms;

        CUDA_CHECK(cudaEventRecord(start_event));
        CUDA_CHECK(cudaMemcpy(h_out, d_out, current_bytes, cudaMemcpyDeviceToHost));
        CUDA_CHECK(cudaEventRecord(stop_event));
        CUDA_CHECK(cudaEventSynchronize(stop_event));
        CUDA_CHECK(cudaEventElapsedTime(&ms, start_event, stop_event));
        stats.d2h_ms += ms;

        if (mode == "ctr") {
            xor_buffers(h_out, h_plain, current_bytes);
        }

        if (!first_saved && current_blocks > 0) {
            memcpy(first_plain, h_plain, FRAMEWORK_BLOCK_SIZE);
            memcpy(first_cipher, h_out, FRAMEWORK_BLOCK_SIZE);
            first_saved = true;
        }
    }

    stats.total_ms = stats.h2d_ms + stats.kernel_ms + stats.d2h_ms;

    printf("Device: gpu\n");
    if (cipher == GpuCipher::Des) printf("Cipher: des\n");
    else if (cipher == GpuCipher::Chacha) printf("Cipher: chacha\n");
    else printf("Cipher: salsa\n");
    printf("Mode: %s\n", mode.c_str());
    printf("Blocks(N): %zu\n", total_blocks);
    print_block("First plaintext block:", first_plain);
    print_block("First ciphertext block:", first_cipher);
    print_perf(stats, total_blocks);

    CUDA_CHECK(cudaEventDestroy(start_event));
    CUDA_CHECK(cudaEventDestroy(stop_event));
    if (d_plain != nullptr) CUDA_CHECK(cudaFree(d_plain));
    CUDA_CHECK(cudaFree(d_out));
    free(h_plain);
    free(h_out);
    return 0;
}

} // namespace

int main(int argc, char **argv) {
    if (argc != 4 && argc != 5) {
        print_usage(argv[0]);
        return 1;
    }

    int arg_index = 1;
    if (argc == 5) {
        if (std::string(argv[1]) != "gpu") {
            fprintf(stderr, "only gpu is supported in this runner\n");
            return 1;
        }
        arg_index = 2;
    }

    const std::string cipher = argv[arg_index];
    const std::string mode = argv[arg_index + 1];
    const size_t blocks = static_cast<size_t>(strtoull(argv[arg_index + 2], nullptr, 10));

    if (blocks == 0) {
        fprintf(stderr, "blocks must be greater than 0\n");
        return 1;
    }
    if (mode != "ecb" && mode != "ctr") {
        fprintf(stderr, "unsupported mode: %s\n", mode.c_str());
        return 1;
    }

    if (cipher == "des") return run_gpu_cipher(GpuCipher::Des, mode, blocks);
    if (cipher == "chacha") return run_gpu_cipher(GpuCipher::Chacha, mode, blocks);
    if (cipher == "salsa") return run_gpu_cipher(GpuCipher::Salsa, mode, blocks);

    fprintf(stderr, "unsupported gpu cipher: %s\n", cipher.c_str());
    fprintf(stderr, "supported gpu ciphers are: des, chacha, salsa\n");
    return 1;
}
