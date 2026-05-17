#include "config.h"
#include <arpa/inet.h>

void processAndParseCIDR() {
    FILE* file = fopen(input_filename, "r");
    if (!file) {
        perror("Failed to open file");
        exit(EXIT_FAILURE);
    }

    char line[256];
    size_t lineCount = 0;

    while (fgets(line, sizeof(line), file)) {
        char* newline = strchr(line, '\n');
        if (newline) {
            *newline = '\0';
        }

        if (line[0] == '\0') {
            continue;
        }

        struct in6_addr ip6;

        char* slashPos = strchr(line, '/');

        // =========================
        // Case 1: exact IPv6 address
        // =========================
        if (!slashPos) {
            if (inet_pton(AF_INET6, line, &ip6) != 1) {
                fprintf(stderr, "Invalid IPv6 address: %s\n", line);
                continue;
            }

            exact_addr_flags[prefix_table_size] = 1;
            exact_addr_table[prefix_table_size] = ip6;

            prefix_table[prefix_table_size].prefix_stub = 0;
            prefix_table[prefix_table_size].mask_suffix = 0;
            prefix_table[prefix_table_size].prefix_length = 128;
            prefix_table[prefix_table_size].sent_packets = 0;
            prefix_table[prefix_table_size].received_packets = 0;
            prefix_table[prefix_table_size].sent_packets_this_round = 0;
            prefix_table[prefix_table_size].received_packets_this_round = 0;

            prefix_table_size++;
            lineCount++;

            if (lineCount == MAX_PREFIX_TABLE_SIZE) {
                fprintf(stderr, "Reached the maximum limit of lines to process.\n");
                break;
            }

            continue;
        }

        // =========================
        // Case 2: IPv6 prefix
        // =========================
        char ipStr[128];
        strncpy(ipStr, line, slashPos - line);
        ipStr[slashPos - line] = '\0';

        int prefixLen = atoi(slashPos + 1);
        if (prefixLen < 0 || prefixLen > 128) {
            fprintf(stderr, "Invalid prefix length: %s\n", line);
            continue;
        }

        if (inet_pton(AF_INET6, ipStr, &ip6) != 1) {
            fprintf(stderr, "Invalid IPv6 address: %s\n", line);
            continue;
        }

        exact_addr_flags[prefix_table_size] = 0;

        uint64_t stub = htonll(*(uint64_t*)(&ip6.s6_addr[0]));
        uint64_t mask = 0;

        if (prefixLen <= 64) {
            mask = (~0ULL >> prefixLen) & 0xFFFFFFFFFFFFFFFF;
        } else {
            // 目前你的生成逻辑主要基于前64位，先保守处理
            mask = 0;
        }

        prefix_table[prefix_table_size].prefix_stub = stub;
        prefix_table[prefix_table_size].mask_suffix = mask;
        prefix_table[prefix_table_size].prefix_length = prefixLen;
        prefix_table[prefix_table_size].sent_packets = 0;
        prefix_table[prefix_table_size].received_packets = 0;
        prefix_table[prefix_table_size].sent_packets_this_round = 0;
        prefix_table[prefix_table_size].received_packets_this_round = 0;

        prefix_table_size++;
        lineCount++;

        if (lineCount == MAX_PREFIX_TABLE_SIZE) {
            fprintf(stderr, "Reached the maximum limit of lines to process.\n");
            break;
        }
    }

    fclose(file);
}