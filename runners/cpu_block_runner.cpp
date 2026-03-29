#include "../include/cpu_cipher_api.hpp"

#include <cstdlib>
#include <cstdio>
#include <string>

namespace {

void print_usage(const char *program) {
    std::printf("Usage:\n");
    std::printf("  %s <cipher> <mode> <blocks>\n", program);
    std::printf("\nBlock ciphers: aes, des, kalyna, simon, gift\n");
    std::printf("Modes: ecb, ctr\n");
}

} // namespace

int main(int argc, char **argv) {
    if (argc != 4) {
        print_usage(argv[0]);
        return 1;
    }

    const std::string cipher_name = argv[1];
    const std::string mode = argv[2];
    const size_t blocks = static_cast<size_t>(std::strtoull(argv[3], nullptr, 10));

    const CpuBlockCipherApi *cipher = get_cpu_block_cipher(cipher_name.c_str());
    if (cipher == nullptr) {
        std::fprintf(stderr, "unsupported cpu block cipher: %s\n", cipher_name.c_str());
        return 1;
    }

    if (mode == "ecb") {
        return run_cpu_block_ecb(*cipher, blocks);
    }
    if (mode == "ctr") {
        return run_cpu_block_ctr(*cipher, blocks);
    }

    std::fprintf(stderr, "unsupported mode: %s\n", mode.c_str());
    return 1;
}
