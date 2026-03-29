#pragma once

#include "cipher_descriptor.hpp"

#include <cstddef>
#include <cstdint>

struct GpuBlockCipherApi {
    CipherDescriptor descriptor;
    int (*run_ecb)(size_t blocks);
    int (*run_ctr)(size_t blocks, uint64_t ctr);
    bool supports_ctr;
};

struct GpuStreamCipherApi {
    CipherDescriptor descriptor;
    int (*run_ctr)(size_t blocks, uint64_t ctr);
};

const GpuBlockCipherApi* get_gpu_block_cipher(const char *name);
const GpuStreamCipherApi* get_gpu_stream_cipher(const char *name);
