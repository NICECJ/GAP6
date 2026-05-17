#!/bin/bash

PROTOCOL=$1
INPUT_FILENAME=${2:-input/test.txt}
OUTPUT_FILENAME=${3:-output/test.log}

INTERFACE_NAME="ens17f0"
SOURCE_MAC="80:61:5f:2b:cb:9b"
SOURCE_IP="2402:f000:6:1e00::233"
GATEWAY_MAC="74:ea:c8:b4:24:d4"

OUTPUT_DIR=$(dirname "$OUTPUT_FILENAME")

if [ ! -d "$OUTPUT_DIR" ]; then
    mkdir -p "$OUTPUT_DIR"
fi

if [ ! -f "bin/main" ]; then
    echo "Executable not found. Please compile the project first using 'make'."
    exit 1
fi

if [ -z "$PROTOCOL" ]; then
    echo "Usage: ./run.sh <protocol> [input_file] [output_file]"
    exit 1
fi

echo "Running protocol: $PROTOCOL"
echo "Input : $INPUT_FILENAME"
echo "Output: $OUTPUT_FILENAME"

sudo bin/main "$PROTOCOL" "$INTERFACE_NAME" "$SOURCE_MAC" "$SOURCE_IP" "$GATEWAY_MAC" "$INPUT_FILENAME" "$OUTPUT_FILENAME"