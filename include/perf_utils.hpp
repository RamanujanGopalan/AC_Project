#pragma once

#include <cstdio>

struct PerfStats {
    double total_ms = 0.0;
    double kernel_ms = 0.0;
    double h2d_ms = 0.0;
    double d2h_ms = 0.0;
};

inline void print_perf(const PerfStats &stats, size_t total_blocks, size_t block_size_bytes) {
    const double total_seconds = stats.total_ms / 1000.0;
    const double blocks_per_sec = total_seconds > 0.0 ? total_blocks / total_seconds : 0.0;
    const double gb_per_sec =
        total_seconds > 0.0
            ? ((total_blocks * block_size_bytes) / (1024.0 * 1024.0 * 1024.0)) / total_seconds
            : 0.0;

    std::printf("\n===== PERFORMANCE =====\n");
    std::printf("Total Time: %.3f ms\n", stats.total_ms);
    std::printf("Kernel Time: %.3f ms\n", stats.kernel_ms);
    std::printf("H2D Time: %.3f ms\n", stats.h2d_ms);
    std::printf("D2H Time: %.3f ms\n", stats.d2h_ms);
    std::printf("\nThroughput:\n");
    std::printf("Blocks/sec: %.2f\n", blocks_per_sec);
    std::printf("GB/sec: %.2f\n", gb_per_sec);
}
