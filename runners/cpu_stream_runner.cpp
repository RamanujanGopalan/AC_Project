#include "../include/cpu_cipher_api.hpp"

#include <cstdlib>
#include <cstdio>
#include <string>

namespace {

void print_usage(const char *program) {
    std::printf("Usage:\n");
    std::printf("  %s <cipher> ctr <blocks>\n", program);
    std::printf("\nStream ciphers: chacha, salsa\n");
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

    if (mode != "ctr") {
        std::fprintf(stderr, "stream runner only supports ctr/native stream mode\n");
        return 1;
    }

    const CpuStreamCipherApi *cipher = get_cpu_stream_cipher(cipher_name.c_str());
    if (cipher == nullptr) {
        std::fprintf(stderr, "unsupported cpu stream cipher: %s\n", cipher_name.c_str());
        return 1;
    }

    return run_cpu_stream_ctr(*cipher, blocks);
}
