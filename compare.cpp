#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <omp.h>
#include <chrono>
#include <common_header.hpp>
#include <random>

// Can alternatively use cmp cpu_out.bin gpu_out.bin OR cmp -l cpu_out.bin gpu_out.bin | head (For position)
int main(){
    FILE *f1 = fopen("cpu_out.bin", "rb");
    FILE *f2 = fopen("gpu_out.bin", "rb");

    size_t i = 0;
    int b1, b2;

    while ((b1 = fgetc(f1)) != EOF && (b2 = fgetc(f2)) != EOF) {
        if (b1 != b2) {
            printf("Mismatch at byte %zu: %02x vs %02x\n", i, b1, b2);
            break;
        }
        i++;
    }
    return 0;
}