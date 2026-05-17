#include "http_probe.h"
#include "../../include/config.h"
#include "../../include/protocol.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/udp.h>
#include <netinet/ip6.h>
#include <netinet/if_ether.h>
#include <unistd.h>

/* 随机生成 32bit */
static uint32_t rand32(void) {
    return ((uint32_t)rand() << 16) | (uint32_t)rand();
}

/* 构建目标 IPv6 地址（prefix 或 exact address） */
static void build_target_ip(struct ip6_hdr *ip6, int index) {
    if (exact_addr_flags[index]) {
        ip6->ip6_dst = exact_addr_table[index];
    } else {
        PrefixInfo *pcs = &prefix_table[index];
        unsigned char addr[16] = {0};

        uint64_t rand_val = rand32();
        uint64_t dst_prefix = pcs->prefix_stub + (pcs->mask_suffix & rand_val);
        dst_prefix = htonll(dst_prefix);
        memcpy(addr, &dst_prefix, 8);

        uint32_t rand_suffix = rand32();
        memcpy(addr+8, &rand_suffix, 4);

        /* 内嵌 checksum，可选 */
        uint32_t checksum = murmur3(addr, 12, 0x11112222);
        checksum = htonl(checksum);
        memcpy(addr+12, &checksum, 4);

        memcpy(ip6->ip6_dst.s6_addr, addr, 16);
    }
}

/* 构建 HTTP 探测包（TCP 或 UDP header） */
int http_probe_build_probe(struct ethhdr *eth,
                           struct ip6_hdr *ip6,
                           void *l4,
                           int index) {
    struct udphdr *udp = (struct udphdr *)l4;

    if (!ip6) return -1;

    memset(ip6, 0, sizeof(struct ip6_hdr));
    if (udp) memset(udp, 0, sizeof(struct udphdr));

    /* 构建目标地址 */
    build_target_ip(ip6, index);

    /* 构造端口 */
    if (udp) {
        udp->source = htons(40000 + (index % 20000));
        udp->dest   = htons(80); /* 默认 HTTP 端口 */
        udp->len    = htons(sizeof(struct udphdr));
        udp->check  = 0;
    }

    /* 更新统计 */
    prefix_table[index].sent_packets++;

    return 0;
}

/* 解析 HTTP 响应：收到响应就算命中 */
int http_probe_parse_response(uint8_t *buffer,
                              ssize_t received_bytes,
                              struct in6_addr *target_ip,
                              uint64_t *prefix_index) {
    if (!buffer || !target_ip || !prefix_index) return 0;
    if (received_bytes <= 0) return 0;

    /* 这里假设 buffer 已经是 TCP payload 或 HTTP 响应数据 */
    buffer[received_bytes-1] = '\0';
    if (strstr((char*)buffer, "HTTP/1.1 200") ||
        strstr((char*)buffer, "HTTP/1.1 301") ||
        strstr((char*)buffer, "HTTP/1.1 302") ||
        strstr((char*)buffer, "HTTP/1.1 403") ||
        strstr((char*)buffer, "HTTP/1.1 404")) {
        /* 简单命中 */
        return 1;
    }
    return 0;
}

/* 注册协议到框架 */
protocol_t http_probe_protocol = {
    .name = "http_probe",
    .build_probe = http_probe_build_probe,
    .parse_response = http_probe_parse_response
};

__attribute__((constructor))
static void register_http_probe(void) {
    register_protocol(&http_probe_protocol);
}