#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <omp.h>
#include <chrono>
#include <common_header.hpp>
#include <random>

using namespace std;

int main(){
    std::mt19937_64 rng(42);

    auto start = chrono::high_resolution_clock::now();

    size_t blocks = 100 * 1024 * 1024;
    size_t size = blocks * 16;

    uint8_t *h_plain  = (uint8_t*)malloc(size);
    uint8_t *h_cipher = (uint8_t*)malloc(size);

    std::uniform_int_distribution<uint16_t> dist(0, 255);

    for (size_t i = 0; i < size; i++) {
        h_plain[i] = (uint8_t)dist(rng);
    }
    
    uint64_t ctr = rng();

    // ===== ENCRYPTION =====
    // auto key = aes_cpu_get_key(); 
    // aes_cpu_encrypt_ctr(h_cipher,key,blocks, ctr);

    // auto key = des_cpu_get_key(); 
    // des_cpu_encrypt_ctr(h_cipher, key, blocks, ctr); 

    // auto key = des_cpu_get_key(); 
    // des_cpu_encrypt_ctr(h_cipher, key, blocks, ctr); 

    // auto key = kalyna_cpu_get_key(); 
    // kalyna_cpu_encrypt_ctr(h_cipher, key, blocks, ctr);

    auto key = simon_cpu_get_key(); 
    simon_cpu_encrypt_ctr(h_cipher, key, blocks, ctr);

    for (size_t i = 0; i < size; i++) {
        h_cipher[i] ^= h_plain[i];
    }

    auto end = chrono::high_resolution_clock::now();

    // ===== TIME CALCULATION =====
    double elapsed_sec = chrono::duration<double>(end - start).count();

    double totalTime  = elapsed_sec * 1000.0; // ms

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
    printf("Kernel Time: N.A\n");
    printf("H2D Time: N.A\n");
    printf("D2H Time: N.A\n");

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