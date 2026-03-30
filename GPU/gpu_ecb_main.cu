#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <cuda.h>
#include <chrono>
#include <iostream>

// ── tuneable constants ────────────────────────────────────────────────────────
#define NUM_BLOCKS   (100 * 1024 * 1024)   // 100 M blocks  (~1.6 GB)
#define BLOCK_BYTES  16                    // bytes per cipher block (128-bit)
#define THREADS      256                   // CUDA threads per block


// ── AES ──────────────────────────────────────────────────────────────────────
void cipher_aes_setup (const uint8_t *key);                      // copies round keys to __constant__
void cipher_aes_launch(uint8_t *d_in, uint8_t *d_out,int blocks, int threads);

void cipher_kalyna_setup (const uint8_t *key);
void cipher_kalyna_launch(uint8_t *d_in, uint8_t *d_out,int blocks, int threads);

void cipher_simon_setup (const uint8_t *key);
void cipher_simon_launch(uint8_t *d_in, uint8_t *d_out, int blocks, int threads);

void cipher_gift_setup (const uint8_t *key);
void cipher_gift_launch(uint8_t *d_in, uint8_t *d_out, int blocks, int threads);


// =============================================================================
//  Descriptor table
// =============================================================================
struct CipherDesc {
    const char *name;                                   // CLI selector
    uint8_t     default_key[16];                        // 128-bit test key
    void      (*setup) (const uint8_t *key);
    void      (*launch)(uint8_t *d_in, uint8_t *d_out, int blocks, int threads);
};

static const CipherDesc ciphers[] = {
    {
        "aes",
        {0x2b,0x7e,0x15,0x16, 0x28,0xae,0xd2,0xa6,
         0xab,0xf7,0x15,0x88, 0x09,0xcf,0x4f,0x3c},
        cipher_aes_setup,
        cipher_aes_launch
    },
    {
        "kalyna",
        {0x00,0x01,0x02,0x03, 0x04,0x05,0x06,0x07,
         0x08,0x09,0x0a,0x0b, 0x0c,0x0d,0x0e,0x0f},
        cipher_kalyna_setup,
        cipher_kalyna_launch
    },
    {
        "simon",
        {0x00,0x01,0x02,0x03, 0x04,0x05,0x06,0x07,
         0x08,0x09,0x0a,0x0b, 0x0c,0x0d,0x0e,0x0f},
        cipher_simon_setup,
        cipher_simon_launch
    },
    {
        "gift",
        {0x00,0x01,0x02,0x03, 0x04,0x05,0x06,0x07,
         0x08,0x09,0x0a,0x0b, 0x0c,0x0d,0x0e,0x0f},
        cipher_gift_setup,
        cipher_gift_launch
    }
};

static const int NUM_CIPHERS = (int)(sizeof(ciphers) / sizeof(ciphers[0]));


static void run_benchmark(const CipherDesc &c){
    const size_t size = (size_t)NUM_BLOCKS * BLOCK_BYTES;

    printf("\n===== Cipher: %s =====\n", c.name);
    printf("Data: %d blocks x %d bytes = %.2f GB\n\n",
           NUM_BLOCKS, BLOCK_BYTES, (double)size / 1e9);

    // ── host buffers ─────────────────────────────────────────────────────────
    uint8_t *h_in  = (uint8_t*)malloc(size);
    uint8_t *h_out = (uint8_t*)malloc(size);
    for (size_t i = 0; i < size; i++) h_in[i] = (uint8_t)(i % 256);

    // ── device buffers ───────────────────────────────────────────────────────
    uint8_t *d_in, *d_out;
    cudaMalloc(&d_in,  size);
    cudaMalloc(&d_out, size);

    // ── CUDA events ──────────────────────────────────────────────────────────
    cudaEvent_t h2dStart, h2dStop, kernelStart, kernelStop, d2hStart, d2hStop;
    cudaEventCreate(&h2dStart);    cudaEventCreate(&h2dStop);
    cudaEventCreate(&kernelStart); cudaEventCreate(&kernelStop);
    cudaEventCreate(&d2hStart);    cudaEventCreate(&d2hStop);

    int grid = (NUM_BLOCKS + THREADS - 1) / THREADS;

    // ── H2D (data + key/sbox setup) ──────────────────────────────────────────
    cudaEventRecord(h2dStart);
    c.setup(c.default_key);                                // uploads __constant__ data
    cudaMemcpy(d_in, h_in, size, cudaMemcpyHostToDevice); // uploads plaintext
    cudaEventRecord(h2dStop);
    cudaEventSynchronize(h2dStop);

    // ── warm-up (not timed) ───────────────────────────────────────────────────
    c.launch(d_in, d_out, NUM_BLOCKS, THREADS);
    cudaDeviceSynchronize();

    // ── kernel timing ─────────────────────────────────────────────────────────
    cudaEventRecord(kernelStart);
    c.launch(d_in, d_out, NUM_BLOCKS, THREADS);
    cudaEventRecord(kernelStop);
    cudaEventSynchronize(kernelStop);

    // ── D2H ──────────────────────────────────────────────────────────────────
    cudaEventRecord(d2hStart);
    cudaMemcpy(h_out, d_out, size, cudaMemcpyDeviceToHost);
    cudaEventRecord(d2hStop);
    cudaEventSynchronize(d2hStop);

    // ── timings ───────────────────────────────────────────────────────────────
    float ms_h2d, ms_kernel, ms_d2h;
    cudaEventElapsedTime(&ms_h2d,    h2dStart,    h2dStop);
    cudaEventElapsedTime(&ms_kernel, kernelStart, kernelStop);
    cudaEventElapsedTime(&ms_d2h,    d2hStart,    d2hStop);

    double total_ms    = ms_h2d + ms_kernel + ms_d2h;
    double kernel_sec  = ms_kernel * 1e-3;
    double total_sec   = total_ms  * 1e-3;
    double size_gb     = (double)size / 1e9;

    printf("-- Timing --\n");
    printf("  H2D transfer      : %8.3f ms\n", ms_h2d);
    printf("  Kernel execution  : %8.3f ms\n", ms_kernel);
    printf("  D2H transfer      : %8.3f ms\n", ms_d2h);
    printf("  Total             : %8.3f ms\n", total_ms);

    printf("\n-- Throughput --\n");
    printf("  Kernel GB/s       : %.4f\n", size_gb / kernel_sec);
    printf("  Effective GB/s    : %.4f\n", 2.0 * size_gb / total_sec);
    printf("  Blocks/sec        : %.3e\n", NUM_BLOCKS / kernel_sec);

    printf("\n-- First encrypted block --\n  ");
    for (int i = 0; i < 16; i++) printf("%02x ", h_out[i]);
    printf("\n");

    // ── cleanup ───────────────────────────────────────────────────────────────
    cudaEventDestroy(h2dStart);    cudaEventDestroy(h2dStop);
    cudaEventDestroy(kernelStart); cudaEventDestroy(kernelStop);
    cudaEventDestroy(d2hStart);    cudaEventDestroy(d2hStop);
    cudaFree(d_in); cudaFree(d_out);
    free(h_in);     free(h_out);
}

// =============================================================================
//  main
// =============================================================================
int main(int argc, char **argv)
{
    // ── list available ciphers if no argument ────────────────────────────────
    if (argc < 2) {
        printf("Usage: %s <cipher> [cipher2 ...]\n\n", argv[0]);
        printf("Available ciphers:\n");
        for (int i = 0; i < NUM_CIPHERS; i++)
            printf("  %s\n", ciphers[i].name);
        printf("\nUse 'all' to run every cipher.\n");
        return 0;
    }

    bool run_all = (strcmp(argv[1], "all") == 0);

    for (int a = 1; a < argc; a++) {
        bool found = false;
        for (int i = 0; i < NUM_CIPHERS; i++) {
            if (run_all || strcmp(argv[a], ciphers[i].name) == 0) {
                run_benchmark(ciphers[i]);
                found = true;
                if (!run_all) break;
            }
        }
        if (!run_all && !found)
            fprintf(stderr, "Unknown cipher '%s' — skipped.\n", argv[a]);
    }

    return 0;
}
