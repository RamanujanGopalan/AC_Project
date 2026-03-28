#include <cuda_runtime.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

namespace {

constexpr size_t FRAMEWORK_BLOCK_SIZE = 16;
constexpr size_t DES_BLOCK_SIZE = 8;
constexpr int DES_ROUNDS = 16;
constexpr int THREADS_PER_BLOCK = 256;
constexpr size_t DEFAULT_TOTAL_BLOCKS = 100ULL * 1024ULL * 1024ULL;
constexpr size_t CHUNK_BLOCKS = 1ULL << 20;

#define CUDA_CHECK(call)                                                            \
    do {                                                                            \
        cudaError_t err__ = (call);                                                 \
        if (err__ != cudaSuccess) {                                                 \
            fprintf(stderr, "CUDA error: %s (%s:%d)\n", cudaGetErrorString(err__),  \
                    __FILE__, __LINE__);                                            \
            exit(EXIT_FAILURE);                                                     \
        }                                                                           \
    } while (0)

struct PerfStats {
    double total_ms = 0.0;
    double kernel_ms = 0.0;
    double h2d_ms = 0.0;
    double d2h_ms = 0.0;
};

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

__device__ __forceinline__ uint64_t permute_bits(uint64_t input,
                                                 const int *table,
                                                 int count,
                                                 int width) {
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

__device__ __forceinline__ void generate_round_keys(uint64_t key, uint64_t round_keys[DES_ROUNDS]) {
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

    const uint64_t pre_output =
        (static_cast<uint64_t>(right) << 32) | static_cast<uint64_t>(left);
    return permute_bits(pre_output, d_fp, 64, 64);
}

__global__ void des_ecb_kernel(const uint8_t *input, uint8_t *output, uint64_t key, size_t blocks) {
    const size_t stride = static_cast<size_t>(blockDim.x) * gridDim.x;
    uint64_t round_keys[DES_ROUNDS];
    generate_round_keys(key, round_keys);

    for (size_t idx = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
         idx < blocks;
         idx += stride) {
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
    generate_round_keys(key, round_keys);

    for (size_t idx = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
         idx < blocks;
         idx += stride) {
        const size_t offset = idx * FRAMEWORK_BLOCK_SIZE;
        const uint64_t counter0 = ctr + idx * 2ULL;
        const uint64_t counter1 = counter0 + 1ULL;

        store_be64(output + offset, des_encrypt_block(counter0, round_keys));
        store_be64(output + offset + DES_BLOCK_SIZE, des_encrypt_block(counter1, round_keys));
    }
}

static void fill_input_chunk(uint8_t *buffer, size_t blocks, size_t block_offset) {
    const size_t bytes = blocks * FRAMEWORK_BLOCK_SIZE;
    const size_t base = block_offset * FRAMEWORK_BLOCK_SIZE;
    for (size_t i = 0; i < bytes; ++i) {
        buffer[i] = static_cast<uint8_t>((base + i) & 0xFFU);
    }
}

static void print_sample(const uint8_t *buffer) {
    printf("Sample Output: ");
    for (size_t i = 0; i < FRAMEWORK_BLOCK_SIZE; ++i) {
        printf("%02x", buffer[i]);
    }
    printf("\n");
}

static void print_perf(const PerfStats &stats, size_t total_blocks) {
    const double total_seconds = stats.total_ms / 1000.0;
    const double blocks_per_sec = total_seconds > 0.0 ? total_blocks / total_seconds : 0.0;
    const double gb_per_sec =
        total_seconds > 0.0
            ? ((total_blocks * FRAMEWORK_BLOCK_SIZE) / (1024.0 * 1024.0 * 1024.0)) / total_seconds
            : 0.0;

    printf("===== PERFORMANCE =====\n");
    printf("Total Time: %.3f ms\n", stats.total_ms);
    printf("Kernel Time: %.3f ms\n", stats.kernel_ms);
    printf("H2D Time: %.3f ms\n", stats.h2d_ms);
    printf("D2H Time: %.3f ms\n", stats.d2h_ms);
    printf("\nThroughput:\n");
    printf("Blocks/sec: %.2f\n", blocks_per_sec);
    printf("GB/sec: %.2f\n", gb_per_sec);
}

static PerfStats run_ecb(uint64_t key, size_t total_blocks) {
    uint8_t *h_input = static_cast<uint8_t*>(malloc(CHUNK_BLOCKS * FRAMEWORK_BLOCK_SIZE));
    uint8_t *h_output = static_cast<uint8_t*>(malloc(CHUNK_BLOCKS * FRAMEWORK_BLOCK_SIZE));
    uint8_t *d_input = nullptr;
    uint8_t *d_output = nullptr;

    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&d_input), CHUNK_BLOCKS * FRAMEWORK_BLOCK_SIZE));
    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&d_output), CHUNK_BLOCKS * FRAMEWORK_BLOCK_SIZE));

    cudaEvent_t start_event;
    cudaEvent_t stop_event;
    CUDA_CHECK(cudaEventCreate(&start_event));
    CUDA_CHECK(cudaEventCreate(&stop_event));

    PerfStats stats;

    for (size_t processed = 0; processed < total_blocks; processed += CHUNK_BLOCKS) {
        const size_t current_blocks =
            (total_blocks - processed < CHUNK_BLOCKS) ? (total_blocks - processed) : CHUNK_BLOCKS;
        const size_t current_bytes = current_blocks * FRAMEWORK_BLOCK_SIZE;
        fill_input_chunk(h_input, current_blocks, processed);

        CUDA_CHECK(cudaEventRecord(start_event));
        CUDA_CHECK(cudaMemcpy(d_input, h_input, current_bytes, cudaMemcpyHostToDevice));
        CUDA_CHECK(cudaEventRecord(stop_event));
        CUDA_CHECK(cudaEventSynchronize(stop_event));
        float ms = 0.0f;
        CUDA_CHECK(cudaEventElapsedTime(&ms, start_event, stop_event));
        stats.h2d_ms += ms;

        int blocks = static_cast<int>((current_blocks + THREADS_PER_BLOCK - 1) / THREADS_PER_BLOCK);
        if (blocks > 65535) {
            blocks = 65535;
        }
        if (blocks == 0) {
            blocks = 1;
        }

        CUDA_CHECK(cudaEventRecord(start_event));
        des_ecb_kernel<<<blocks, THREADS_PER_BLOCK>>>(d_input, d_output, key, current_blocks);
        CUDA_CHECK(cudaGetLastError());
        CUDA_CHECK(cudaEventRecord(stop_event));
        CUDA_CHECK(cudaEventSynchronize(stop_event));
        CUDA_CHECK(cudaEventElapsedTime(&ms, start_event, stop_event));
        stats.kernel_ms += ms;

        CUDA_CHECK(cudaEventRecord(start_event));
        CUDA_CHECK(cudaMemcpy(h_output, d_output, current_bytes, cudaMemcpyDeviceToHost));
        CUDA_CHECK(cudaEventRecord(stop_event));
        CUDA_CHECK(cudaEventSynchronize(stop_event));
        CUDA_CHECK(cudaEventElapsedTime(&ms, start_event, stop_event));
        stats.d2h_ms += ms;
    }

    stats.total_ms = stats.h2d_ms + stats.kernel_ms + stats.d2h_ms;
    print_sample(h_output);

    CUDA_CHECK(cudaEventDestroy(start_event));
    CUDA_CHECK(cudaEventDestroy(stop_event));
    CUDA_CHECK(cudaFree(d_input));
    CUDA_CHECK(cudaFree(d_output));
    free(h_input);
    free(h_output);
    return stats;
}

static PerfStats run_ctr(uint64_t key, uint64_t ctr, size_t total_blocks) {
    uint8_t *h_output = static_cast<uint8_t*>(malloc(CHUNK_BLOCKS * FRAMEWORK_BLOCK_SIZE));
    uint8_t *d_output = nullptr;

    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&d_output), CHUNK_BLOCKS * FRAMEWORK_BLOCK_SIZE));

    cudaEvent_t start_event;
    cudaEvent_t stop_event;
    CUDA_CHECK(cudaEventCreate(&start_event));
    CUDA_CHECK(cudaEventCreate(&stop_event));

    PerfStats stats;

    for (size_t processed = 0; processed < total_blocks; processed += CHUNK_BLOCKS) {
        const size_t current_blocks =
            (total_blocks - processed < CHUNK_BLOCKS) ? (total_blocks - processed) : CHUNK_BLOCKS;
        const size_t current_bytes = current_blocks * FRAMEWORK_BLOCK_SIZE;

        int blocks = static_cast<int>((current_blocks + THREADS_PER_BLOCK - 1) / THREADS_PER_BLOCK);
        if (blocks > 65535) {
            blocks = 65535;
        }
        if (blocks == 0) {
            blocks = 1;
        }

        CUDA_CHECK(cudaEventRecord(start_event));
        des_ctr_kernel<<<blocks, THREADS_PER_BLOCK>>>(
            d_output, key, current_blocks, ctr + processed * 2ULL);
        CUDA_CHECK(cudaGetLastError());
        CUDA_CHECK(cudaEventRecord(stop_event));
        CUDA_CHECK(cudaEventSynchronize(stop_event));
        float ms = 0.0f;
        CUDA_CHECK(cudaEventElapsedTime(&ms, start_event, stop_event));
        stats.kernel_ms += ms;

        CUDA_CHECK(cudaEventRecord(start_event));
        CUDA_CHECK(cudaMemcpy(h_output, d_output, current_bytes, cudaMemcpyDeviceToHost));
        CUDA_CHECK(cudaEventRecord(stop_event));
        CUDA_CHECK(cudaEventSynchronize(stop_event));
        CUDA_CHECK(cudaEventElapsedTime(&ms, start_event, stop_event));
        stats.d2h_ms += ms;
    }

    stats.total_ms = stats.h2d_ms + stats.kernel_ms + stats.d2h_ms;
    print_sample(h_output);

    CUDA_CHECK(cudaEventDestroy(start_event));
    CUDA_CHECK(cudaEventDestroy(stop_event));
    CUDA_CHECK(cudaFree(d_output));
    free(h_output);
    return stats;
}

} // namespace

int main(int argc, char **argv) {
    size_t total_blocks = DEFAULT_TOTAL_BLOCKS;
    if (argc > 1) {
        total_blocks = static_cast<size_t>(strtoull(argv[1], nullptr, 10));
    }

    const uint64_t key = 0x133457799BBCDFF1ULL;
    const uint64_t ctr = 0xABCDEF1234567890ULL;

    printf("DES GPU ECB\n");
    const PerfStats ecb_stats = run_ecb(key, total_blocks);
    print_perf(ecb_stats, total_blocks);

    printf("\nDES GPU CTR\n");
    const PerfStats ctr_stats = run_ctr(key, ctr, total_blocks);
    print_perf(ctr_stats, total_blocks);

    return 0;
}
