#pragma once

#include <cstdint>
#include <cstdio>
#include <cstring>

namespace output_utils {

struct Sha256State {
    uint64_t bit_length = 0;
    uint32_t state[8] = {
        0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
        0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U
    };
    uint8_t buffer[64] = {0};
    size_t buffer_size = 0;
};

inline constexpr uint32_t k_constants[64] = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
};

inline uint32_t rotr(uint32_t value, uint32_t shift) {
    return (value >> shift) | (value << (32U - shift));
}

inline void sha256_transform(Sha256State &ctx, const uint8_t block[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; ++i) {
        w[i] = (static_cast<uint32_t>(block[i * 4]) << 24)
             | (static_cast<uint32_t>(block[i * 4 + 1]) << 16)
             | (static_cast<uint32_t>(block[i * 4 + 2]) << 8)
             | static_cast<uint32_t>(block[i * 4 + 3]);
    }
    for (int i = 16; i < 64; ++i) {
        const uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        const uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = ctx.state[0];
    uint32_t b = ctx.state[1];
    uint32_t c = ctx.state[2];
    uint32_t d = ctx.state[3];
    uint32_t e = ctx.state[4];
    uint32_t f = ctx.state[5];
    uint32_t g = ctx.state[6];
    uint32_t h = ctx.state[7];

    for (int i = 0; i < 64; ++i) {
        const uint32_t s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        const uint32_t ch = (e & f) ^ ((~e) & g);
        const uint32_t temp1 = h + s1 + ch + k_constants[i] + w[i];
        const uint32_t s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        const uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        const uint32_t temp2 = s0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    ctx.state[0] += a;
    ctx.state[1] += b;
    ctx.state[2] += c;
    ctx.state[3] += d;
    ctx.state[4] += e;
    ctx.state[5] += f;
    ctx.state[6] += g;
    ctx.state[7] += h;
}

inline void sha256_update(Sha256State &ctx, const uint8_t *data, size_t length) {
    ctx.bit_length += static_cast<uint64_t>(length) * 8ULL;
    while (length > 0) {
        const size_t copy_size = (64 - ctx.buffer_size < length) ? (64 - ctx.buffer_size) : length;
        std::memcpy(ctx.buffer + ctx.buffer_size, data, copy_size);
        ctx.buffer_size += copy_size;
        data += copy_size;
        length -= copy_size;
        if (ctx.buffer_size == 64) {
            sha256_transform(ctx, ctx.buffer);
            ctx.buffer_size = 0;
        }
    }
}

inline void sha256_finalize(Sha256State &ctx, uint8_t digest[32]) {
    ctx.buffer[ctx.buffer_size++] = 0x80U;
    if (ctx.buffer_size > 56) {
        while (ctx.buffer_size < 64) {
            ctx.buffer[ctx.buffer_size++] = 0;
        }
        sha256_transform(ctx, ctx.buffer);
        ctx.buffer_size = 0;
    }
    while (ctx.buffer_size < 56) {
        ctx.buffer[ctx.buffer_size++] = 0;
    }
    for (int i = 7; i >= 0; --i) {
        ctx.buffer[ctx.buffer_size++] = static_cast<uint8_t>((ctx.bit_length >> (i * 8)) & 0xFFU);
    }
    sha256_transform(ctx, ctx.buffer);

    for (int i = 0; i < 8; ++i) {
        digest[i * 4] = static_cast<uint8_t>((ctx.state[i] >> 24) & 0xFFU);
        digest[i * 4 + 1] = static_cast<uint8_t>((ctx.state[i] >> 16) & 0xFFU);
        digest[i * 4 + 2] = static_cast<uint8_t>((ctx.state[i] >> 8) & 0xFFU);
        digest[i * 4 + 3] = static_cast<uint8_t>(ctx.state[i] & 0xFFU);
    }
}

struct OutputRecorder {
    const char *path = nullptr;
    FILE *file = nullptr;
    Sha256State sha;
    bool ok = false;
};

inline bool open_output(OutputRecorder &recorder, const char *path) {
    recorder.path = path;
    recorder.file = std::fopen(path, "wb");
    recorder.ok = recorder.file != nullptr;
    if (!recorder.ok) {
        std::fprintf(stderr, "failed to open output file: %s\n", path);
    }
    return recorder.ok;
}

inline bool append_output(OutputRecorder &recorder, const uint8_t *data, size_t size) {
    if (!recorder.ok) {
        return false;
    }
    if (size > 0 && std::fwrite(data, 1, size, recorder.file) != size) {
        std::fprintf(stderr, "failed to write output file: %s\n", recorder.path);
        recorder.ok = false;
        return false;
    }
    sha256_update(recorder.sha, data, size);
    return true;
}

inline void finish_output(OutputRecorder &recorder, const char *label) {
    if (recorder.file != nullptr) {
        std::fclose(recorder.file);
        recorder.file = nullptr;
    }
    if (!recorder.ok) {
        return;
    }

    uint8_t digest[32];
    sha256_finalize(recorder.sha, digest);

    std::printf("%s: %s\n", label, recorder.path);
    std::printf("%s SHA-256: ", label);
    for (uint8_t byte : digest) {
        std::printf("%02x", byte);
    }
    std::printf("\n");
}

inline void print_hash_compare_hint() {
    std::printf("Compare hashes with: sha256sum cpu_out.bin gpu_out.bin\n");
    std::printf("Compare bytes with: cmp cpu_out.bin gpu_out.bin\n");
}

inline void print_match_status() {
    FILE *cpu_file = std::fopen("cpu_out.bin", "rb");
    FILE *gpu_file = std::fopen("gpu_out.bin", "rb");

    if (cpu_file == nullptr || gpu_file == nullptr) {
        if (cpu_file != nullptr) {
            std::fclose(cpu_file);
        }
        if (gpu_file != nullptr) {
            std::fclose(gpu_file);
        }
        std::printf("CPU/GPU comparison pending: generate both cpu_out.bin and gpu_out.bin first.\n");
        return;
    }

    bool matches = true;
    while (true) {
        const int cpu_byte = std::fgetc(cpu_file);
        const int gpu_byte = std::fgetc(gpu_file);
        if (cpu_byte != gpu_byte) {
            matches = false;
            break;
        }
        if (cpu_byte == EOF || gpu_byte == EOF) {
            break;
        }
    }

    std::fclose(cpu_file);
    std::fclose(gpu_file);

    if (matches) {
        std::printf("CPU and GPU outputs matched correctly.\n");
    } else {
        std::printf("CPU and GPU outputs did not match correctly.\n");
    }
}

} // namespace output_utils
