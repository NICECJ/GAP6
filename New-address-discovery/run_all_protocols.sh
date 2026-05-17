#!/bin/bash
set -e

BIN="./bin/main"
PROTOCOL_DIR="./protocols"
LOG_DIR="./logs"

INTERFACE_NAME="ens17f0"
SOURCE_MAC="80:61:5f:2b:cb:9b"
SOURCE_IP="2402:f000:6:1e00::233"
GATEWAY_MAC="74:ea:c8:b4:24:d4"
INPUT_FILENAME="input/BGP_prefixes.txt"

mkdir -p "$LOG_DIR"

# 获取协议列表（协议目录名）
PROTOCOLS=$(ls -d "$PROTOCOL_DIR"/*/ | xargs -n 1 basename)

echo "Running all protocols..."

for proto in $PROTOCOLS; do
    echo "=== Running $proto ==="
    LOG_FILE="$LOG_DIR/${proto}.log"

    # 执行带参数的 main
    sudo $BIN "$proto" "$INTERFACE_NAME" "$SOURCE_MAC" "$SOURCE_IP" "$GATEWAY_MAC" "$INPUT_FILENAME" "$LOG_FILE" || \
        echo "⚠ $proto failed. See log: $LOG_FILE"
    
    echo "Output saved to $LOG_FILE"
done

echo "All protocols processed. Logs are in $LOG_DIR/"