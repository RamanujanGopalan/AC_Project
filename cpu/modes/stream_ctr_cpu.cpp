#include "../../include/cpu_cipher_api.hpp"
#include "../../include/output_utils.hpp"
#include "../../include/perf_utils.hpp"
#include "../../include/plaintext_utils.hpp"

#include <chrono>
#include <cstdio>
#include <cstdlib>

int run_cpu_stream_ctr(const CpuStreamCipherApi &cipher, size_t blocks) {
    const size_t size = blocks * cipher.descriptor.block_size_bytes;
    uint8_t *plain = static_cast<uint8_t*>(std::malloc(size));
    uint8_t *cipher_out = static_cast<uint8_t*>(std::malloc(size));
    void *key = cipher.get_key();

    fill_plaintext_blocks(plain, blocks, cipher.descriptor.block_size_bytes);

    const uint64_t ctr = 0x123456789ABCDEF0ULL;
    auto start = std::chrono::high_resolution_clock::now();
    cipher.crypt_ctr(plain, cipher_out, key, blocks, ctr);
    auto end = std::chrono::high_resolution_clock::now();

    const double elapsed_sec = std::chrono::duration<double>(end - start).count();
    PerfStats stats;
    stats.total_ms = elapsed_sec * 1000.0;
    stats.kernel_ms = stats.total_ms;

    std::printf("Device: cpu\n");
    std::printf("Cipher: %s\n", cipher.descriptor.name);
    std::printf("Variant: %s\n", cipher.descriptor.variant);
    std::printf("Mode: ctr\n");
    std::printf("Blocks(N): %zu\n", blocks);
    print_sample_block("First plaintext block:", plain, cipher.descriptor.block_size_bytes);
    print_sample_block("First ciphertext block:", cipher_out, cipher.descriptor.block_size_bytes);
    print_perf(stats, blocks, cipher.descriptor.block_size_bytes);
    output_utils::OutputRecorder recorder;
    if (output_utils::open_output(recorder, "cpu_out.bin")) {
        output_utils::append_output(recorder, cipher_out, size);
    }
    output_utils::finish_output(recorder, "CPU output");
    output_utils::print_match_status();
    output_utils::print_hash_compare_hint();

    cipher.free_key(key);
    std::free(plain);
    std::free(cipher_out);
    return 0;
}
