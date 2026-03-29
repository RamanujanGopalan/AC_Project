#include "../include/cpu_cipher_api.hpp"
#include "../include/common_header.hpp"

#include <cstdlib>
#include <cstring>
#include <string_view>

extern "C" void* chacha20_cpu_get_key_native();
extern "C" void chacha20_cpu_free_key_native(void *key);
extern "C" void chacha20_cpu_crypt_ctr_native(const uint8_t *input,
                                               uint8_t *output,
                                               void *key,
                                               size_t blocks,
                                               uint64_t ctr);

extern "C" void* salsa20_cpu_get_key_native();
extern "C" void salsa20_cpu_free_key_native(void *key);
extern "C" void salsa20_cpu_crypt_ctr_native(const uint8_t *input,
                                              uint8_t *output,
                                              void *key,
                                              size_t blocks,
                                              uint64_t ctr);

namespace {

void free_heap_key(void *key) {
    std::free(key);
}

void* aes_get_key_void() {
    return static_cast<void*>(aes_cpu_get_key());
}

void* des_get_key_boxed() {
    auto *boxed = static_cast<uint64_t*>(std::malloc(sizeof(uint64_t)));
    *boxed = des_cpu_get_key();
    return boxed;
}

void des_free_key_boxed(void *key) {
    std::free(key);
}

void des_encrypt_ecb_native(const uint8_t *input, uint8_t *output, void *key, size_t blocks) {
    const uint64_t des_key = *static_cast<uint64_t*>(key);
    const size_t packed_blocks = (blocks + 1) / 2;
    uint8_t *packed_in = static_cast<uint8_t*>(std::calloc(packed_blocks, 16));
    uint8_t *packed_out = static_cast<uint8_t*>(std::calloc(packed_blocks, 16));

    for (size_t i = 0; i < blocks; ++i) {
        const size_t packed_index = i / 2;
        const size_t packed_offset = packed_index * 16 + ((i % 2) * 8);
        std::memcpy(packed_in + packed_offset, input + i * 8, 8);
    }

    des_cpu_encrypt(packed_in, packed_out, des_key, packed_blocks);

    for (size_t i = 0; i < blocks; ++i) {
        const size_t packed_index = i / 2;
        const size_t packed_offset = packed_index * 16 + ((i % 2) * 8);
        std::memcpy(output + i * 8, packed_out + packed_offset, 8);
    }

    std::free(packed_in);
    std::free(packed_out);
}

void des_encrypt_ctr_native(uint8_t *output, void *key, size_t blocks, uint64_t ctr) {
    const uint64_t des_key = *static_cast<uint64_t*>(key);
    const size_t packed_blocks = (blocks + 1) / 2;
    uint8_t *packed_out = static_cast<uint8_t*>(std::calloc(packed_blocks, 16));

    des_cpu_encrypt_ctr(packed_out, des_key, packed_blocks, ctr);

    for (size_t i = 0; i < blocks; ++i) {
        const size_t packed_index = i / 2;
        const size_t packed_offset = packed_index * 16 + ((i % 2) * 8);
        std::memcpy(output + i * 8, packed_out + packed_offset, 8);
    }

    std::free(packed_out);
}

void* kalyna_get_key_void() {
    return static_cast<void*>(kalyna_cpu_get_key());
}

void* simon_get_key_void() {
    return static_cast<void*>(simon_cpu_get_key());
}

void* gift_get_key_void() {
    return static_cast<void*>(gift_cpu_get_key());
}

void aes_encrypt_ecb(const uint8_t *input, uint8_t *output, void *key, size_t blocks) {
    aes_cpu_encrypt(const_cast<uint8_t*>(input), output, static_cast<uint8_t*>(key), blocks);
}

void aes_encrypt_ctr(uint8_t *output, void *key, size_t blocks, uint64_t ctr) {
    aes_cpu_encrypt_ctr(output, static_cast<uint8_t*>(key), blocks, ctr);
}

void kalyna_encrypt_ecb(const uint8_t *input, uint8_t *output, void *key, size_t blocks) {
    kalyna_cpu_encrypt(const_cast<uint8_t*>(input), output, static_cast<uint8_t*>(key), blocks);
}

void kalyna_encrypt_ctr(uint8_t *output, void *key, size_t blocks, uint64_t ctr) {
    kalyna_cpu_encrypt_ctr(output, static_cast<uint8_t*>(key), blocks, ctr);
}

void simon_encrypt_ecb(const uint8_t *input, uint8_t *output, void *key, size_t blocks) {
    simon_cpu_encrypt(const_cast<uint8_t*>(input), output, static_cast<uint64_t*>(key), blocks);
}

void simon_encrypt_ctr(uint8_t *output, void *key, size_t blocks, uint64_t ctr) {
    simon_cpu_encrypt_ctr(output, static_cast<uint64_t*>(key), blocks, ctr);
}

void gift_encrypt_ecb(const uint8_t *input, uint8_t *output, void *key, size_t blocks) {
    gift_cpu_encrypt(const_cast<uint8_t*>(input), output, static_cast<uint8_t*>(key), blocks);
}

const CpuBlockCipherApi BLOCK_CIPHERS[] = {
    {{"aes", "AES-128", 16}, aes_get_key_void, free_heap_key, aes_encrypt_ecb, aes_encrypt_ctr, true},
    {{"des", "DES", 8}, des_get_key_boxed, des_free_key_boxed, des_encrypt_ecb_native, des_encrypt_ctr_native, true},
    {{"kalyna", "Kalyna-128/128 (current repo core)", 16}, kalyna_get_key_void, free_heap_key, kalyna_encrypt_ecb, kalyna_encrypt_ctr, true},
    {{"simon", "SIMON-128/128 (current repo core)", 16}, simon_get_key_void, free_heap_key, simon_encrypt_ecb, simon_encrypt_ctr, true},
    {{"gift", "GIFT-128 (current repo core)", 16}, gift_get_key_void, free_heap_key, gift_encrypt_ecb, nullptr, false},
};

const CpuStreamCipherApi STREAM_CIPHERS[] = {
    {{"chacha", "ChaCha20", 64}, chacha20_cpu_get_key_native, chacha20_cpu_free_key_native, chacha20_cpu_crypt_ctr_native},
    {{"salsa", "Salsa20", 64}, salsa20_cpu_get_key_native, salsa20_cpu_free_key_native, salsa20_cpu_crypt_ctr_native},
};

} // namespace

const CpuBlockCipherApi* get_cpu_block_cipher(const char *name) {
    for (const auto &cipher : BLOCK_CIPHERS) {
        if (std::string_view(cipher.descriptor.name) == name) {
            return &cipher;
        }
    }
    return nullptr;
}

const CpuStreamCipherApi* get_cpu_stream_cipher(const char *name) {
    for (const auto &cipher : STREAM_CIPHERS) {
        if (std::string_view(cipher.descriptor.name) == name) {
            return &cipher;
        }
    }
    return nullptr;
}
