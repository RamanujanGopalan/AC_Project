#include <cuda_runtime.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

namespace {

constexpr size_t FRAMEWORK_BLOCK_SIZE = 16;
constexpr int SALSA_ROUNDS = 20;
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

__device__ __forceinline__ void quarter_round(uint32_t &a, uint32_t &b, uint32_t &c, uint32_t &d) {
    b ^= rotl32(a + d, 7);
    c ^= rotl32(b + a, 9);
    d ^= rotl32(c + b, 13);
    a ^= rotl32(d + c, 18);
}

__device__ __forceinline__ void salsa20_block(const uint32_t input[16], uint32_t output[16]) {
    uint32_t working[16];
    for (int i = 0; i < 16; ++i) {
        working[i] = input[i];
    }

    for (int round = 0; round < SALSA_ROUNDS; round += 2) {
        quarter_round(working[0], working[4], working[8], working[12]);
        quarter_round(working[5], working[9], working[13], working[1]);
        quarter_round(working[10], working[14], working[2], working[6]);
        quarter_round(working[15], working[3], working[7], working[11]);

        quarter_round(working[0], working[1], working[2], working[3]);
        quarter_round(working[5], working[6], working[7], working[4]);
        quarter_round(working[10], working[11], working[8], working[9]);
        quarter_round(working[15], working[12], working[13], working[14]);
    }

    for (int i = 0; i < 16; ++i) {
        output[i] = working[i] + input[i];
    }
}

__device__ __forceinline__ void write_first_16_bytes(uint8_t *output, const uint32_t state[16]) {
    store_le32(output + 0, state[0]);
    store_le32(output + 4, state[1]);
    store_le32(output + 8, state[2]);
    store_le32(output + 12, state[3]);
}

__device__ __forceinline__ void init_key_state(uint32_t state[16]) {
    state[0] = 0x61707865U;
    state[5] = 0x3320646eU;
    state[10] = 0x79622d32U;
    state[15] = 0x6b206574U;

    for (int i = 0; i < 4; ++i) {
        state[1 + i] = 0x03020100U + static_cast<uint32_t>(i) * 0x04040404U;
        state[11 + i] = 0x13121110U + static_cast<uint32_t>(i) * 0x04040404U;
    }

    state[6] = 0U;
    state[7] = 0U;
    state[8] = 0U;
    state[9] = 0U;
}

__global__ void salsa_ecb_kernel(const uint8_t *input, uint8_t *output, size_t blocks) {
    const size_t stride = static_cast<size_t>(blockDim.x) * gridDim.x;

    for (size_t idx = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
         idx < blocks;
         idx += stride) {
        uint32_t state[16];
        uint32_t keystream[16];
        const size_t offset = idx * FRAMEWORK_BLOCK_SIZE;

        init_key_state(state);
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

    for (size_t idx = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
         idx < blocks;
         idx += stride) {
        uint32_t state[16];
        uint32_t keystream[16];
        const size_t offset = idx * FRAMEWORK_BLOCK_SIZE;
        const uint64_t counter = ctr + idx;

        init_key_state(state);
        state[8] = static_cast<uint32_t>(counter & 0xFFFFFFFFULL);
        state[9] = static_cast<uint32_t>(counter >> 32);

        salsa20_block(state, keystream);
        write_first_16_bytes(output + offset, keystream);
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

static PerfStats run_ecb(size_t total_blocks) {
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
        salsa_ecb_kernel<<<blocks, THREADS_PER_BLOCK>>>(d_input, d_output, current_blocks);
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

static PerfStats run_ctr(size_t total_blocks, uint64_t ctr) {
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
        salsa_ctr_kernel<<<blocks, THREADS_PER_BLOCK>>>(d_output, current_blocks, ctr + processed);
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

    const uint64_t ctr = 0x0F1E2D3C4B5A6978ULL;

    printf("Salsa20 GPU ECB\n");
    const PerfStats ecb_stats = run_ecb(total_blocks);
    print_perf(ecb_stats, total_blocks);

    printf("\nSalsa20 GPU CTR\n");
    const PerfStats ctr_stats = run_ctr(total_blocks, ctr);
    print_perf(ctr_stats, total_blocks);

    return 0;
}
