#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <cuda.h>

#define ROUNDS 68
#define BLOCK_SIZE 16

// z-sequence
__constant__ uint8_t d_Z[62] = {
1,1,1,1,1,0,1,0,0,1,0,0,0,0,1,0,
1,1,0,0,1,1,1,0,0,1,1,0,1,0,1,0,
0,1,1,1,0,0,0,1,1,0,1,1,0,0,1,1,
1,0,1,0,1,1,0,0,0,1,0,1
};

// Rotate helpers (device)
__device__ __forceinline__ uint64_t ROL(uint64_t x, long long int r) {
    return (x << r) | (x >> (64 - r));
}
__device__ __forceinline__ uint64_t ROR(uint64_t x, long long int r) {
    return (x >> r) | (x << (64 - r));
}

// SIMON round
__device__ __forceinline__ void simon_round(uint64_t *x, uint64_t *y, uint64_t k) {
    uint64_t tmp = *x;
    *x = *y ^ (ROL(*x,1) & ROL(*x,8)) ^ ROL(*x,2) ^ k;
    *y = tmp;
}

// Kernel: each thread encrypts one block
__global__ void simon_encrypt_kernel(uint8_t *input, uint8_t *output, long long int nblocks, uint64_t *round_keys) {

    long long int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= nblocks) return;

    uint64_t x, y;

    // Load block (unaligned-safe)
    memcpy(&x, input + i*BLOCK_SIZE, 8);
    memcpy(&y, input + i*BLOCK_SIZE + 8, 8);

    for (long long int r = 0; r < ROUNDS; r++) {
        simon_round(&x, &y, round_keys[r]);
    }

    memcpy(output + i*BLOCK_SIZE, &x, 8);
    memcpy(output + i*BLOCK_SIZE + 8, &y, 8);
}

// CPU key schedule (unchanged)
static inline uint64_t ROR_host(uint64_t x, long long int r) {
    return (x >> r) | (x << (64 - r));
}

void generate_keys(uint64_t key[2], uint64_t round_keys[ROUNDS]) {

    uint64_t k[ROUNDS];
    k[0] = key[0];
    k[1] = key[1];

    static const uint8_t Z[62] = {
    1,1,1,1,1,0,1,0,0,1,0,0,0,0,1,0,
    1,1,0,0,1,1,1,0,0,1,1,0,1,0,1,0,
    0,1,1,1,0,0,0,1,1,0,1,1,0,0,1,1,
    1,0,1,0,1,1,0,0,0,1,0,1
    };

    for (long long int i = 2; i < ROUNDS; i++) {
        uint64_t tmp = ROR_host(k[i-1], 3);
        tmp ^= k[i-2];
        tmp ^= ROR_host(tmp, 1);
        k[i] = ~k[i-2] ^ tmp ^ Z[(i-2) % 62] ^ 3;
    }

    for (long long int i = 0; i < ROUNDS; i++)
        round_keys[i] = k[i];
}

// Driver
long long int main(){

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    long long int blocks = 100*1024*1024;
    long long int size = blocks * BLOCK_SIZE;

    uint8_t *h_plain = (uint8_t*)malloc(size);
    uint8_t *h_cipher = (uint8_t*)malloc(size);

    for(long long int i=0;i<size;i++)
        h_plain[i] = i % 256;

    uint64_t key[2] = {
        0x0f0e0d0c0b0a0908,
        0x0706050403020100
    };

    uint64_t h_round_keys[ROUNDS];
    generate_keys(key, h_round_keys);

    // Device memory
    uint8_t *d_plain, *d_cipher;
    uint64_t *d_round_keys;

    cudaMalloc(&d_plain, size);
    cudaMalloc(&d_cipher, size);
    cudaMalloc(&d_round_keys, ROUNDS * sizeof(uint64_t));

    cudaMemcpy(d_plain, h_plain, size, cudaMemcpyHostToDevice);
    cudaMemcpy(d_round_keys, h_round_keys, ROUNDS * sizeof(uint64_t), cudaMemcpyHostToDevice);

    // Launch kernel
    long long int threads = 256;
    long long int blocks_grid = (blocks + threads - 1) / threads;

    simon_encrypt_kernel<<<blocks_grid, threads>>>(d_plain, d_cipher, blocks, d_round_keys);

    cudaMemcpy(h_cipher, d_cipher, size, cudaMemcpyDeviceToHost);

    printf("First block ciphertext:\n");
    for(long long int i=0;i<16;i++) printf("%02x ", h_cipher[i]);
    printf("\n");

    clock_gettime(CLOCK_MONOTONIC, &end);
    double elapsed = (end.tv_sec - start.tv_sec) +
                     (end.tv_nsec - start.tv_nsec) / 1e9;

    printf("==================================================\n");
    printf("Execution Time: %f\n", elapsed);

    cudaFree(d_plain);
    cudaFree(d_cipher);
    cudaFree(d_round_keys);

    free(h_plain);
    free(h_cipher);

    return 0;
}