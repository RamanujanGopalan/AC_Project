#include <stdio.h>
#include <stdint.h>
// #include <iostream>
#include <stdlib.h>
#include <omp.h>
#include <time.h>
#include <common_header.hpp>

int main(){
    struct timespec start, end;
    
    clock_gettime(CLOCK_MONOTONIC, &start);

    size_t blocks = 100*1024*1024;
    size_t size = blocks*16;

    uint8_t *h_plain = (uint8_t*)malloc(size);
    uint8_t *h_cipher = (uint8_t*)malloc(size);

    // ===== ENCRYTPION =====
    // auto key = aes_cpu_get_key();
    // aes_cpu_ecrypt(h_plain,h_cipher,key,blocks);

    // auto key = des_cpu_get_key();
    // des_cpu_encrypt(h_plain, h_cipher, key, blocks);

    // auto key = des_cpu_get_key();
    // des_cpu_encrypt(h_plain, h_cipher, key, blocks);

    // auto key = kalyna_cpu_get_key();
    // kalyna_cpu_encrypt(h_plain, h_cipher, key, blocks);

    auto key = simon_cpu_get_key();
    simon_cpu_encrypt(h_plain, h_cipher, key, blocks);

    printf("First block ciphertext:\n");
    printf("RESULT\n");
    for(int i=0;i<16;i++) printf("%02x ",h_cipher[i]);

    printf("\n");

    clock_gettime(CLOCK_MONOTONIC, &end);
    double elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;  
    printf("==================================================\n");
    printf("Execution Time: %f\n", elapsed);

    free(h_plain);
    free(h_cipher);

    return 0;
}