CXX = g++
NVCC = nvcc

CXXFLAGS = -O3 -fopenmp -std=c++17 -I.
NVCCFLAGS = -O3

ECB_TARGETS = aes_ecb des_ecb chacha_ecb salsa_ecb kalyna_ecb simon_ecb gift_ecb
CTR_TARGETS = aes_ctr des_ctr chacha_ctr salsa_ctr kalyna_ctr simon_ctr
GPU_TARGETS = des_gpu chacha20_gpu salsa20_gpu
TARGETS = $(ECB_TARGETS) $(CTR_TARGETS) $(GPU_TARGETS)

.PHONY: all clean cpu gpu ecb ctr

all: $(TARGETS)

cpu: $(ECB_TARGETS) $(CTR_TARGETS)

gpu: $(GPU_TARGETS)

ecb: $(ECB_TARGETS)

ctr: $(CTR_TARGETS)

aes_ecb: common_main_ecb.cpp AES_CPU_parallel.cpp common_header.hpp
	$(CXX) $(CXXFLAGS) -DCIPHER_AES -o $@ common_main_ecb.cpp AES_CPU_parallel.cpp

des_ecb: common_main_ecb.cpp DES_CPU_parallel.cpp common_header.hpp
	$(CXX) $(CXXFLAGS) -DCIPHER_DES -o $@ common_main_ecb.cpp DES_CPU_parallel.cpp

chacha_ecb: common_main_ecb.cpp CHACHA20_CPU_parallel.cpp common_header.hpp
	$(CXX) $(CXXFLAGS) -DCIPHER_CHACHA -o $@ common_main_ecb.cpp CHACHA20_CPU_parallel.cpp

salsa_ecb: common_main_ecb.cpp SALSA20_CPU_parallel.cpp common_header.hpp
	$(CXX) $(CXXFLAGS) -DCIPHER_SALSA -o $@ common_main_ecb.cpp SALSA20_CPU_parallel.cpp

kalyna_ecb: common_main_ecb.cpp KALYNA_CPU_parallel.cpp common_header.hpp
	$(CXX) $(CXXFLAGS) -DCIPHER_KALYNA -o $@ common_main_ecb.cpp KALYNA_CPU_parallel.cpp

simon_ecb: common_main_ecb.cpp SIMON_CPU_parallel.cpp common_header.hpp
	$(CXX) $(CXXFLAGS) -DCIPHER_SIMON -o $@ common_main_ecb.cpp SIMON_CPU_parallel.cpp

gift_ecb: common_main_ecb.cpp GIFT_CPU_parallel.cpp common_header.hpp
	$(CXX) $(CXXFLAGS) -DCIPHER_GIFT -o $@ common_main_ecb.cpp GIFT_CPU_parallel.cpp

aes_ctr: common_main_ctr.cpp AES_CPU_parallel.cpp common_header.hpp
	$(CXX) $(CXXFLAGS) -DCIPHER_AES -o $@ common_main_ctr.cpp AES_CPU_parallel.cpp

des_ctr: common_main_ctr.cpp DES_CPU_parallel.cpp common_header.hpp
	$(CXX) $(CXXFLAGS) -DCIPHER_DES -o $@ common_main_ctr.cpp DES_CPU_parallel.cpp

chacha_ctr: common_main_ctr.cpp CHACHA20_CPU_parallel.cpp common_header.hpp
	$(CXX) $(CXXFLAGS) -DCIPHER_CHACHA -o $@ common_main_ctr.cpp CHACHA20_CPU_parallel.cpp

salsa_ctr: common_main_ctr.cpp SALSA20_CPU_parallel.cpp common_header.hpp
	$(CXX) $(CXXFLAGS) -DCIPHER_SALSA -o $@ common_main_ctr.cpp SALSA20_CPU_parallel.cpp

kalyna_ctr: common_main_ctr.cpp KALYNA_CPU_parallel.cpp common_header.hpp
	$(CXX) $(CXXFLAGS) -DCIPHER_KALYNA -o $@ common_main_ctr.cpp KALYNA_CPU_parallel.cpp

simon_ctr: common_main_ctr.cpp SIMON_CPU_parallel.cpp common_header.hpp
	$(CXX) $(CXXFLAGS) -DCIPHER_SIMON -o $@ common_main_ctr.cpp SIMON_CPU_parallel.cpp

des_gpu: DES_GPU.cu
	$(NVCC) $(NVCCFLAGS) -o $@ DES_GPU.cu

chacha20_gpu: CHACHA20_GPU.cu
	$(NVCC) $(NVCCFLAGS) -o $@ CHACHA20_GPU.cu

salsa20_gpu: SALSA20_GPU.cu
	$(NVCC) $(NVCCFLAGS) -o $@ SALSA20_GPU.cu

clean:
	rm -f $(TARGETS) $(TARGETS:=.exe)
