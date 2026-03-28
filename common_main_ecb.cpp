#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <omp.h>
#include <chrono>
#include <random>
#include <common_header.hpp>

using namespace std;

int main(){
    std::mt19937 rng(42);  // fixed seed

    auto start = chrono::high_resolution_clock::now();

    size_t blocks = 100 * 1024 * 1024;
    size_t size = blocks * 16;

    uint8_t *h_plain  = (uint8_t*)malloc(size);
    uint8_t *h_cipher = (uint8_t*)malloc(size);

    std::uniform_int_distribution<uint16_t> dist(0, 255);

    for (size_t i = 0; i < size; i++) {
        h_plain[i] = (uint8_t)dist(rng);
    }

    // ===== ENCRYPTION =====
    #if defined(CIPHER_AES)
        auto key = aes_cpu_get_key();
        aes_cpu_encrypt(h_plain, h_cipher, key, blocks);
    #elif defined(CIPHER_DES)
        auto key = des_cpu_get_key();
        des_cpu_encrypt(h_plain, h_cipher, key, blocks);
    #elif defined(CIPHER_CHACHA)
        auto key = chacha_cpu_get_key();
        chacha_cpu_encrypt(h_plain, h_cipher, key, blocks);
    #elif defined(CIPHER_SALSA)
        auto key = salsa_cpu_get_key();
        salsa_cpu_encrypt(h_plain, h_cipher, key, blocks);
    #elif defined(CIPHER_KALYNA)
        auto key = kalyna_cpu_get_key();
        kalyna_cpu_encrypt(h_plain, h_cipher, key, blocks);
    #elif defined(CIPHER_SIMON)
        auto key = simon_cpu_get_key();
        simon_cpu_encrypt(h_plain, h_cipher, key, blocks);
    #elif defined(CIPHER_GIFT)
        auto key = gift_cpu_get_key();
        gift_cpu_encrypt(h_plain, h_cipher, key, blocks);
    #else
        #error "Define one CPU cipher macro such as CIPHER_AES, CIPHER_DES, CIPHER_CHACHA, CIPHER_SALSA, CIPHER_KALYNA, CIPHER_SIMON, or CIPHER_GIFT."
    #endif

    auto end = chrono::high_resolution_clock::now();

    // ===== TIME CALCULATION =====
    double elapsed_sec = chrono::duration<double>(end - start).count();

    double totalTime  = elapsed_sec * 1000.0; // ms
    double kernelTime = totalTime;            // CPU = kernel
    double h2dTime    = 0.0;
    double d2hTime    = 0.0;

    // ===== THROUGHPUT =====
    double blocksPerSec = blocks / elapsed_sec;
    double gbPerSec     = (size / (1024.0 * 1024.0 * 1024.0)) / elapsed_sec;

    // ===== OUTPUT =====
    printf("First block ciphertext:\n");
    for(int i = 0; i < 16; i++)
        printf("%02x ", h_cipher[i]);
    printf("\n");

    // ===== PERFORMANCE PRINT =====
    printf("\n===== PERFORMANCE =====\n");
    printf("Total Time: %.3f ms\n", totalTime);
    printf("Kernel Time: %.3f ms\n", kernelTime);
    printf("H2D Time: %.3f ms\n", h2dTime);
    printf("D2H Time: %.3f ms\n", d2hTime);

    printf("\nThroughput:\n");
    printf("Blocks/sec: %.2f\n", blocksPerSec);
    printf("GB/sec: %.2f\n", gbPerSec);

    // ===== SAMPLE OUTPUT =====
    printf("\nSample Output: ");
    for (int i = 0; i < 16; i++){
        printf("%02x", h_cipher[i]);
    }
    printf("\n");

    free(h_plain);
    free(h_cipher);

    return 0;
}
