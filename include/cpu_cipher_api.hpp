#pragma once

#include "cipher_descriptor.hpp"

#include <cstddef>
#include <cstdint>

struct CpuBlockCipherApi {
    CipherDescriptor descriptor;
    void* (*get_key)();
    void (*free_key)(void *key);
    void (*encrypt_ecb)(const uint8_t *input, uint8_t *output, void *key, size_t blocks);
    void (*encrypt_ctr_keystream)(uint8_t *output, void *key, size_t blocks, uint64_t ctr);
    bool supports_ctr;
};

struct CpuStreamCipherApi {
    CipherDescriptor descriptor;
    void* (*get_key)();
    void (*free_key)(void *key);
    void (*crypt_ctr)(const uint8_t *input, uint8_t *output, void *key, size_t blocks, uint64_t ctr);
};

const CpuBlockCipherApi* get_cpu_block_cipher(const char *name);
const CpuStreamCipherApi* get_cpu_stream_cipher(const char *name);

int run_cpu_block_ecb(const CpuBlockCipherApi &cipher, size_t blocks);
int run_cpu_block_ctr(const CpuBlockCipherApi &cipher, size_t blocks);
int run_cpu_stream_ctr(const CpuStreamCipherApi &cipher, size_t blocks);
