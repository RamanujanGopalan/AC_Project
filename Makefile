# Compiler
CC = gcc

# Flags
CFLAGS = -O3 -fopenmp -std=c11

# Targets
TARGETS = aes_cpu des_cpu kalyna_cpu simon_cpu

all: $(TARGETS)

aes_cpu: AES_CPU_parallel.c
	$(CC) $(CFLAGS) -o aes_cpu AES_CPU_parallel.c

des_cpu: DES_CPU_parallel.c
	$(CC) $(CFLAGS) -o des_cpu DES_CPU_parallel.c

kalyna_cpu: KALYNA_CPU_parallel.c
	$(CC) $(CFLAGS) -o kalyna_cpu KALYNA_CPU_parallel.c

simon_cpu: SIMON_CPU_parallel.c
	$(CC) $(CFLAGS) -o simon_cpu SIMON_CPU_parallel.c

clean:
	rm -f $(TARGETS)