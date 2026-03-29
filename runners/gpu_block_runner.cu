#include "../gpu/ciphers/des_gpu.cuh"
#include "../gpu/modes/block_ctr_gpu.cuh"
#include "../gpu/modes/block_ecb_gpu.cuh"

#include <cstdio>
#include <cstdlib>
#include <string>

namespace {

void print_usage(const char *program) {
    std::printf("Usage:\n");
    std::printf("  %s des <mode> <blocks>\n", program);
    std::printf("\nGPU block ciphers currently available: des\n");
    std::printf("Modes: ecb, ctr\n");
}

} // namespace

int main(int argc, char **argv) {
    if (argc != 4) {
        print_usage(argv[0]);
        return 1;
    }

    const std::string cipher = argv[1];
    const std::string mode = argv[2];
    const size_t blocks = static_cast<size_t>(std::strtoull(argv[3], nullptr, 10));

    if (cipher != "des") {
        std::fprintf(stderr, "unsupported gpu block cipher: %s\n", cipher.c_str());
        return 1;
    }

    if (mode == "ecb") {
        return run_gpu_block_ecb_mode(des_gpu::descriptor, blocks, des_gpu::launch_ecb);
    }
    if (mode == "ctr") {
        return run_gpu_block_ctr_mode(des_gpu::descriptor, blocks, 0xABCDEF1234567890ULL, des_gpu::launch_ctr);
    }

    std::fprintf(stderr, "unsupported mode: %s\n", mode.c_str());
    return 1;
}
