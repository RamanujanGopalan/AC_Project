#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <cuda.h>

#define BLOCK_SIZE 16
#define ROUNDS 10

// --- SBOX in constant memory ---
__constant__ uint8_t d_SBOX[4][256];

// --- Galois multiplication ---
__device__ uint8_t gf_mul(uint8_t a, uint8_t b)
{
    uint8_t res = 0;
    for(int i=0;i<8;i++){
        if(b & 1) res ^= a;
        uint8_t hi = a & 0x80;
        a <<= 1;
        if(hi) a ^= 0x1d;
        b >>= 1;
    }
    return res;
}

// --- SubBytes ---
__device__ void subBytes(uint8_t *state)
{
    for(int i=0;i<16;i++)
        state[i] = d_SBOX[i%4][state[i]];
}

// --- ShiftRows ---
__device__ void shiftRows(uint8_t *s)
{
    uint8_t tmp[16];
    for(int i=0;i<16;i++)
        tmp[i] = s[i];

    for(int r=0;r<4;r++)
        for(int c=0;c<4;c++)
            s[r + 4*c] = tmp[r + 4*((c+r)%4)];
}

// --- MixColumns ---
__device__ void mixColumns(uint8_t *s)
{
    uint8_t tmp[16];

    for(int c=0;c<4;c++)
    {
        int i = 4*c;

        tmp[i+0] = gf_mul(2,s[i]) ^ gf_mul(1,s[i+1]) ^ gf_mul(1,s[i+2]) ^ gf_mul(3,s[i+3]);
        tmp[i+1] = gf_mul(3,s[i]) ^ gf_mul(2,s[i+1]) ^ gf_mul(1,s[i+2]) ^ gf_mul(1,s[i+3]);
        tmp[i+2] = gf_mul(1,s[i]) ^ gf_mul(3,s[i+1]) ^ gf_mul(2,s[i+2]) ^ gf_mul(1,s[i+3]);
        tmp[i+3] = gf_mul(1,s[i]) ^ gf_mul(1,s[i+1]) ^ gf_mul(3,s[i+2]) ^ gf_mul(2,s[i+3]);
    }

    for(int i=0;i<16;i++)
        s[i] = tmp[i];
}

// --- AddRoundKey ---
__device__ void addRoundKey(uint8_t *state, uint8_t *key)
{
    for(int i=0;i<16;i++)
        state[i] ^= key[i];
}

// --- GPU Kernel ---
__global__ void kalyna_encrypt_gpu(uint8_t *in, uint8_t *out, uint8_t *roundKeys, int blocks)
{
    int id = blockIdx.x * blockDim.x + threadIdx.x;
    if(id >= blocks) return;

    uint8_t state[16];

    for(int i=0;i<16;i++)
        state[i] = in[id*16+i];

    addRoundKey(state, roundKeys);

    for(int r=1;r<ROUNDS;r++)
    {
        subBytes(state);
        shiftRows(state);
        mixColumns(state);
        addRoundKey(state, roundKeys + r*16);
    }

    subBytes(state);
    shiftRows(state);
    addRoundKey(state, roundKeys + ROUNDS*16);

    for(int i=0;i<16;i++)
        out[id*16+i] = state[i];
}

// --- Key Expansion (CPU unchanged) ---
void keyExpansion(uint8_t *key, uint8_t *roundKeys)
{
    for(int i=0;i<16;i++)
        roundKeys[i] = key[i];

    for(int r=1;r<=ROUNDS;r++)
        for(int i=0;i<16;i++)
            roundKeys[r*16+i] = roundKeys[(r-1)*16+i] ^ (uint8_t)(r+i);
}

// --- MAIN ---
int main(){
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    int blocks = 100*1024*1024;
    int size = blocks*16;

    uint8_t *h_plain = (uint8_t*)malloc(size);
    uint8_t *h_cipher = (uint8_t*)malloc(size);

    for(int i=0;i<size;i++)
        h_plain[i] = i%256;

    uint8_t key[16];
    for(int i=0;i<16;i++)
        key[i] = i;

    uint8_t roundKeys[(ROUNDS+1)*16];
    keyExpansion(key, roundKeys);

    // --- Device memory ---
    uint8_t *d_plain, *d_cipher, *d_roundKeys;

    cudaMalloc(&d_plain, size);
    cudaMalloc(&d_cipher, size);
    cudaMalloc(&d_roundKeys, (ROUNDS+1)*16);

    cudaMemcpy(d_plain, h_plain, size, cudaMemcpyHostToDevice);
    cudaMemcpy(d_roundKeys, roundKeys, (ROUNDS+1)*16, cudaMemcpyHostToDevice);

    // Copy SBOX to constant memory
    cudaMemcpyToSymbol(d_SBOX, SBOX, sizeof(SBOX));

    // --- Kernel launch ---
    int threads = 256;
    int blocksGrid = (blocks + threads - 1) / threads;

    kalyna_encrypt_gpu<<<blocksGrid, threads>>>(d_plain, d_cipher, d_roundKeys, blocks);

    cudaDeviceSynchronize();

    cudaMemcpy(h_cipher, d_cipher, size, cudaMemcpyDeviceToHost);

    printf("First block ciphertext:\n");
    printf("RESULT\n");
    for(int i=0;i<16;i++) printf("%02x ",h_cipher[i]);
    printf("\n");

    clock_gettime(CLOCK_MONOTONIC, &end);
    double elapsed = (end.tv_sec - start.tv_sec) +
                     (end.tv_nsec - start.tv_nsec) / 1e9;

    printf("==================================================\n");
    printf("Execution Time: %f\n", elapsed);

    cudaFree(d_plain);
    cudaFree(d_cipher);
    cudaFree(d_roundKeys);

    free(h_plain);
    free(h_cipher);

    return 0;
}