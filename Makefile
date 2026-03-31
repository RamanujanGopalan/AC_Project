CXX = g++
NVCC = nvcc

CXXFLAGS = -O3 -fopenmp -std=c++17 -I. -Iinclude
NVCCFLAGS = -O3 -I. -Iinclude

CPU_TARGETS = cpu_block_runner cpu_stream_runner
GPU_TARGETS = gpu_block_runner gpu_stream_runner
TARGETS = $(CPU_TARGETS) $(GPU_TARGETS)

.PHONY: all cpu gpu clean

all: $(TARGETS)

cpu: $(CPU_TARGETS)

gpu: $(GPU_TARGETS)

cpu_block_runner: runners/cpu_block_runner.cpp cpu/cipher_registry.cpp cpu/modes/block_ecb_cpu.cpp cpu/modes/block_ctr_cpu.cpp cpu/ciphers/aes128_cpu.cpp cpu/ciphers/des_cpu.cpp cpu/ciphers/simon64_128_cpu.cpp cpu/ciphers/kalyna128_128_cpu.cpp cpu/ciphers/gift64_cpu.cpp
	$(CXX) $(CXXFLAGS) -o $@ runners/cpu_block_runner.cpp cpu/cipher_registry.cpp cpu/modes/block_ecb_cpu.cpp cpu/modes/block_ctr_cpu.cpp cpu/ciphers/aes128_cpu.cpp cpu/ciphers/des_cpu.cpp cpu/ciphers/simon64_128_cpu.cpp cpu/ciphers/kalyna128_128_cpu.cpp cpu/ciphers/gift64_cpu.cpp cpu/streams/chacha20_cpu.cpp cpu/streams/salsa20_cpu.cpp

cpu_stream_runner: runners/cpu_stream_runner.cpp cpu/cipher_registry.cpp cpu/modes/stream_ctr_cpu.cpp cpu/streams/chacha20_cpu.cpp cpu/streams/salsa20_cpu.cpp
	$(CXX) $(CXXFLAGS) -o $@ runners/cpu_stream_runner.cpp cpu/cipher_registry.cpp cpu/modes/stream_ctr_cpu.cpp cpu/streams/chacha20_cpu.cpp cpu/streams/salsa20_cpu.cpp cpu/ciphers/aes128_cpu.cpp cpu/ciphers/des_cpu.cpp cpu/ciphers/simon64_128_cpu.cpp cpu/ciphers/kalyna128_128_cpu.cpp cpu/ciphers/gift64_cpu.cpp

gpu_block_runner: runners/gpu_block_runner.cu gpu/ciphers/des_gpu.cuh gpu/modes/gpu_chunk_runner.cuh gpu/modes/block_ecb_gpu.cuh gpu/modes/block_ctr_gpu.cuh
	$(NVCC) $(NVCCFLAGS) -o $@ runners/gpu_block_runner.cu

gpu_stream_runner: runners/gpu_stream_runner.cu gpu/streams/chacha20_gpu.cuh gpu/streams/salsa20_gpu.cuh gpu/modes/gpu_chunk_runner.cuh
	$(NVCC) $(NVCCFLAGS) -o $@ runners/gpu_stream_runner.cu

clean:
	rm -f $(TARGETS) $(TARGETS:=.exe)
