#pragma once

#include "../../include/cipher_descriptor.hpp"
#include "../../include/perf_utils.hpp"
#include "../../include/plaintext_utils.hpp"

#include <cuda_runtime.h>

#include <cstdio>

constexpr int GPU_THREADS_PER_BLOCK = 256;
constexpr size_t GPU_CHUNK_BLOCKS = 1ULL << 20;

#define GPU_CHECK(call)                                                             \
    do {                                                                            \
        cudaError_t err__ = (call);                                                 \
        if (err__ != cudaSuccess) {                                                 \
            std::fprintf(stderr, "CUDA error: %s (%s:%d)\n",                        \
                         cudaGetErrorString(err__), __FILE__, __LINE__);            \
            return 1;                                                               \
        }                                                                           \
    } while (0)

inline int gpu_grid_for_blocks(size_t blocks) {
    int grid = static_cast<int>((blocks + GPU_THREADS_PER_BLOCK - 1) / GPU_THREADS_PER_BLOCK);
    if (grid > 65535) {
        grid = 65535;
    }
    if (grid == 0) {
        grid = 1;
    }
    return grid;
}
