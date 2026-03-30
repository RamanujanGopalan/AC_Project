#!/bin/bash

# ===== INPUT VALIDATION =====
if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <blocks> <cipher> <mode>"
    echo "Example: $0 65536 AES ctr"
    exit 1
fi

BLOCKS=$1
CIPHER=$(echo "$2" | tr '[:lower:]' '[:upper:]')
MODE=$(echo "$3" | tr '[:lower:]' '[:upper:]')

# ===== SELECT SOURCE FILE =====
case $CIPHER in
    AES)       SRC="AES_CPU_parallel.cpp" ;;
    CHACHA20)  SRC="CHACHA20_CPU_parallel.cpp" ;;
    DES)       SRC="DES_CPU_parallel.cpp" ;;
    GIFT)      SRC="GIFT_CPU_parallel.cpp" ;;
    KALYNA)    SRC="KALYNA_CPU_parallel.cpp" ;;
    SALSA20)   SRC="SALSA20_CPU_parallel.cpp" ;;
    SIMON)     SRC="SIMON_CPU_parallel.cpp" ;;
    *)
        echo "❌ Unknown cipher: $CIPHER"
        exit 1
        ;;
esac

# ===== SELECT MODE =====
case $MODE in
    ECB) MAIN="common_main_ecb.cpp" ;;
    CTR) MAIN="common_main_ctr.cpp" ;;
    *)
        echo "❌ Unknown mode: $MODE (use ecb or ctr)"
        exit 1
        ;;
esac

# ===== BUILD =====
echo "Compiling $CIPHER ($MODE)..."
g++ -O3 -fopenmp -march=native -I. $MAIN $SRC -o crypto -D$CIPHER
if [ $? -ne 0 ]; then
    echo "❌ Compilation failed"
    exit 1
fi

# ===== RUN =====
echo "🚀 Running with $BLOCKS blocks..."
./crypto $BLOCKS