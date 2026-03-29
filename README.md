# AC_Project

This repository is organized into:

- `include/`: shared descriptors, APIs, plaintext utilities, and performance utilities
- `cpu/ciphers/`: CPU block-cipher implementations
- `cpu/modes/`: generic CPU ECB/CTR mode runners
- `cpu/streams/`: CPU stream-cipher implementations
- `gpu/ciphers/`: GPU block-cipher cores
- `gpu/modes/`: generic GPU mode/chunking helpers
- `gpu/streams/`: GPU stream-cipher cores
- `runners/`: final runtime entrypoints

Build targets:

- `cpu_block_runner`
- `cpu_stream_runner`
- `gpu_block_runner`
- `gpu_stream_runner`

Example local runs:

```bash
make cpu_block_runner
./cpu_block_runner des ecb 1000

make cpu_stream_runner
./cpu_stream_runner chacha ctr 1000

make gpu_block_runner
./gpu_block_runner des ctr 1000

make gpu_stream_runner
./gpu_stream_runner salsa ctr 1000
```

## Colab

### 1. Start a GPU runtime

In Colab, go to:

- `Runtime -> Change runtime type -> GPU`

Then confirm the GPU is attached:

```bash
!nvidia-smi
```

### 2. Upload the project

If the GitHub repo is private, the easiest option is to upload a zip of `AC_Project`.

Run:

```python
from google.colab import files
files.upload()
```

Upload `AC_Project.zip`, then extract it:

```bash
!unzip AC_Project.zip -d /content
%cd /content/AC_Project
```

If the repo is public, you can clone it directly:

```bash
!git clone -b SAKSHAM https://github.com/RamanujanGopalan/AC_Project.git
%cd /content/AC_Project
```

### 3. Build the runners

```bash
!make cpu_block_runner
!make cpu_stream_runner
!make gpu_block_runner
!make gpu_stream_runner
```

If `make` is unavailable in your Colab session, compile manually:

```bash
!g++ -O3 -fopenmp -std=c++17 -I. -Iinclude -o cpu_block_runner runners/cpu_block_runner.cpp cpu/cipher_registry.cpp cpu/modes/block_ecb_cpu.cpp cpu/modes/block_ctr_cpu.cpp cpu/ciphers/aes128_cpu.cpp cpu/ciphers/des_cpu.cpp cpu/ciphers/simon64_128_cpu.cpp cpu/ciphers/kalyna128_128_cpu.cpp cpu/ciphers/gift64_cpu.cpp cpu/streams/chacha20_cpu.cpp cpu/streams/salsa20_cpu.cpp
!g++ -O3 -fopenmp -std=c++17 -I. -Iinclude -o cpu_stream_runner runners/cpu_stream_runner.cpp cpu/cipher_registry.cpp cpu/modes/stream_ctr_cpu.cpp cpu/streams/chacha20_cpu.cpp cpu/streams/salsa20_cpu.cpp cpu/ciphers/aes128_cpu.cpp cpu/ciphers/des_cpu.cpp cpu/ciphers/simon64_128_cpu.cpp cpu/ciphers/kalyna128_128_cpu.cpp cpu/ciphers/gift64_cpu.cpp
!nvcc -O3 -I. -Iinclude -o gpu_block_runner runners/gpu_block_runner.cu
!nvcc -O3 -I. -Iinclude -o gpu_stream_runner runners/gpu_stream_runner.cu
```

### 4. Run tests

CPU block ciphers:

```bash
!./cpu_block_runner des ecb 1000
!./cpu_block_runner aes ctr 1000
```

CPU stream ciphers:

```bash
!./cpu_stream_runner chacha ctr 1000
!./cpu_stream_runner salsa ctr 1000
```

GPU block ciphers:

```bash
!./gpu_block_runner des ecb 1000
!./gpu_block_runner des ctr 1000
```

GPU stream ciphers:

```bash
!./gpu_stream_runner chacha ctr 1000
!./gpu_stream_runner salsa ctr 1000
```

### 5. Notes

- `N` is the number of plaintext blocks for the selected cipher.
- Block ciphers use their native block sizes.
- Stream ciphers (`chacha`, `salsa`) are run through their native CTR-style keystream path.
- In the current refactor, GPU DES is implemented in the new runner path; other GPU block-cipher core headers are placeholders for future work.
