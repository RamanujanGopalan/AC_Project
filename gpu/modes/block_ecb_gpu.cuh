#pragma once

#include "gpu_chunk_runner.cuh"

#include <cstdlib>
#include <cstring>

template <typename Launcher>
int run_gpu_block_ecb_mode(const CipherDescriptor &descriptor, size_t blocks, Launcher launch_ecb) {
    const size_t block_size = descriptor.block_size_bytes;
    const size_t chunk_bytes = GPU_CHUNK_BLOCKS * block_size;

    uint8_t *h_plain = static_cast<uint8_t*>(std::malloc(chunk_bytes));
    uint8_t *h_out = static_cast<uint8_t*>(std::malloc(chunk_bytes));
    uint8_t *d_plain = nullptr;
    uint8_t *d_out = nullptr;

    if (h_plain == nullptr || h_out == nullptr) {
        std::fprintf(stderr, "memory allocation failed\n");
        std::free(h_plain);
        std::free(h_out);
        return 1;
    }

    GPU_CHECK(cudaMalloc(reinterpret_cast<void**>(&d_plain), chunk_bytes));
    GPU_CHECK(cudaMalloc(reinterpret_cast<void**>(&d_out), chunk_bytes));

    cudaEvent_t start_event, stop_event;
    GPU_CHECK(cudaEventCreate(&start_event));
    GPU_CHECK(cudaEventCreate(&stop_event));

    PerfStats stats;
    uint8_t first_plain[64] = {0};
    uint8_t first_cipher[64] = {0};
    bool first_saved = false;

    for (size_t processed = 0; processed < blocks; processed += GPU_CHUNK_BLOCKS) {
        const size_t current_blocks = (blocks - processed < GPU_CHUNK_BLOCKS) ? (blocks - processed) : GPU_CHUNK_BLOCKS;
        const size_t current_bytes = current_blocks * block_size;

        fill_plaintext_blocks(h_plain, current_blocks, block_size);

        GPU_CHECK(cudaEventRecord(start_event));
        GPU_CHECK(cudaMemcpy(d_plain, h_plain, current_bytes, cudaMemcpyHostToDevice));
        GPU_CHECK(cudaEventRecord(stop_event));
        GPU_CHECK(cudaEventSynchronize(stop_event));
        float ms = 0.0f;
        GPU_CHECK(cudaEventElapsedTime(&ms, start_event, stop_event));
        stats.h2d_ms += ms;

        GPU_CHECK(cudaEventRecord(start_event));
        GPU_CHECK(launch_ecb(d_plain, d_out, current_blocks));
        GPU_CHECK(cudaEventRecord(stop_event));
        GPU_CHECK(cudaEventSynchronize(stop_event));
        GPU_CHECK(cudaEventElapsedTime(&ms, start_event, stop_event));
        stats.kernel_ms += ms;

        GPU_CHECK(cudaEventRecord(start_event));
        GPU_CHECK(cudaMemcpy(h_out, d_out, current_bytes, cudaMemcpyDeviceToHost));
        GPU_CHECK(cudaEventRecord(stop_event));
        GPU_CHECK(cudaEventSynchronize(stop_event));
        GPU_CHECK(cudaEventElapsedTime(&ms, start_event, stop_event));
        stats.d2h_ms += ms;

        if (!first_saved && current_blocks > 0) {
            std::memcpy(first_plain, h_plain, block_size);
            std::memcpy(first_cipher, h_out, block_size);
            first_saved = true;
        }
    }

    stats.total_ms = stats.h2d_ms + stats.kernel_ms + stats.d2h_ms;

    std::printf("Device: gpu\n");
    std::printf("Cipher: %s\n", descriptor.name);
    std::printf("Variant: %s\n", descriptor.variant);
    std::printf("Mode: ecb\n");
    std::printf("Blocks(N): %zu\n", blocks);
    print_sample_block("First plaintext block:", first_plain, block_size);
    print_sample_block("First ciphertext block:", first_cipher, block_size);
    print_perf(stats, blocks, block_size);

    GPU_CHECK(cudaEventDestroy(start_event));
    GPU_CHECK(cudaEventDestroy(stop_event));
    GPU_CHECK(cudaFree(d_plain));
    GPU_CHECK(cudaFree(d_out));
    std::free(h_plain);
    std::free(h_out);
    return 0;
}
