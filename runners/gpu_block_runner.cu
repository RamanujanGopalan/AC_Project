#include "../gpu/ciphers/aes128_gpu.cuh"
#include "../gpu/ciphers/des_gpu.cuh"
#include "../gpu/ciphers/gift64_gpu.cuh"
#include "../gpu/ciphers/kalyna128_128_gpu.cuh"
#include "../gpu/ciphers/simon64_128_gpu.cuh"
#include "../gpu/modes/block_ctr_gpu.cuh"
#include "../gpu/modes/block_ecb_gpu.cuh"

#include "../include/cipher_descriptor.hpp"
#include "../include/gpu_cipher_api.cuh"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>

namespace {

void print_usage(const char *program) {
    std::printf("Usage:\n");
    std::printf("  %s <cipher> <mode> <blocks>\n", program);
    std::printf("\nGPU block ciphers currently available: aes, des, gift, kalyna, simon\n");
    std::printf("Modes: ecb, ctr\n");
}

}// namespace

int main(int argc, char **argv) {
    if (argc != 4) {
        print_usage(argv[0]);
        return 1;
    }

    const std::string cipher = argv[1];
    const std::string mode = argv[2];
    const size_t blocks = static_cast<size_t>(std::strtoull(argv[3], nullptr, 10));

    const GpuBlockCipherApi *cipher = get_gpu_block_cipher(cipher_name.c_str());
    if (cipher == nullptr) {
        std::fprintf(stderr, "unsupported gpu block cipher: %s\n", cipher_name.c_str());
    if (cipher == "aes") {
        if (mode == "ecb") {
            return run_gpu_block_ecb_mode(aes128_gpu::descriptor, blocks, aes128_gpu::launch_ecb);
        }
        if (mode == "ctr") {
            return run_gpu_block_ctr_mode(aes128_gpu::descriptor, blocks, 0xABCDEF1234567890ULL, aes128_gpu::launch_ctr);
        }
    } else if (cipher == "des") {
        if (mode == "ecb") {
            return run_gpu_block_ecb_mode(des_gpu::descriptor, blocks, des_gpu::launch_ecb);
        }
        if (mode == "ctr") {
            return run_gpu_block_ctr_mode(des_gpu::descriptor, blocks, 0xABCDEF1234567890ULL, des_gpu::launch_ctr);
        }
    } else if (cipher == "gift") {
        if (mode == "ecb") {
            return run_gpu_block_ecb_mode(gift128_gpu::descriptor, blocks, gift128_gpu::launch_ecb);
        }
        if (mode == "ctr") {
            return run_gpu_block_ctr_mode(gift128_gpu::descriptor, blocks, 0xABCDEF1234567890ULL, gift128_gpu::launch_ctr);
        }
    } else if (cipher == "kalyna") {
        if (mode == "ecb") {
            return run_gpu_block_ecb_mode(kalyna128_gpu::descriptor, blocks, kalyna128_gpu::launch_ecb);
        }
        if (mode == "ctr") {
            return run_gpu_block_ctr_mode(kalyna128_gpu::descriptor, blocks, 0xABCDEF1234567890ULL, kalyna128_gpu::launch_ctr);
        }
    } else if (cipher == "simon") {
        if (mode == "ecb") {
            return run_gpu_block_ecb_mode(simon128_gpu::descriptor, blocks, simon128_gpu::launch_ecb);
        }
        if (mode == "ctr") {
            return run_gpu_block_ctr_mode(simon128_gpu::descriptor, blocks, 0xABCDEF1234567890ULL, simon128_gpu::launch_ctr);
        }
    } else {
        std::fprintf(stderr, "unsupported gpu block cipher: %s\n", cipher.c_str());
        return 1;
    }

    std::fprintf(stderr, "unsupported mode: %s\n", mode.c_str());
    return 1;
    }
}
