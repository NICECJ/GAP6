#include "tcp_syn_ack.h"
#include "../../include/config.h"
#include "../../include/protocol.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <unistd.h>

/* 随机生成 32bit */
static uint32_t rand32(void) {
    return ((uint32_t)rand() << 16) | (uint32_t)rand();
}

/* 构建目标 IPv6 地址，使用系统已有前缀生成逻辑 */
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

        /* 可选 checksum */
        uint32_t checksum = murmur3(addr, 12, 0x11112222);
        checksum = htonl(checksum);
        memcpy(addr+12, &checksum, 4);

        memcpy(ip6->ip6_dst.s6_addr, addr, 16);
    }
}

/* 构建 TCP SYN 探测包 */
int tcp_syn_ack_build_probe(struct ethhdr *eth,
                            struct ip6_hdr *ip6,
                            void *l4,
                            int index) {
    struct tcphdr *tcp = (struct tcphdr *)l4;

    if (!ip6) return -1;

    if (eth) memset(eth, 0, sizeof(struct ethhdr));
    memset(ip6, 0, sizeof(struct ip6_hdr));
    if (tcp) memset(tcp, 0, sizeof(struct tcphdr));

    /* 构建目标 IPv6 */
    build_target_ip(ip6, index);

    /* 构建 TCP SYN */
    if (tcp) {
        tcp->source = htons(40000 + (index % 20000));
        tcp->dest   = htons(80);  // 默认 HTTP/SYN 端口，可改
        tcp->seq    = htonl(rand32());
        tcp->syn    = 1;
        tcp->doff   = 5;  // TCP header length
        tcp->window = htons(1024);
        tcp->check  = 0;
    }

    prefix_table[index].sent_packets++;
    return 0;
}

/* 解析 TCP 响应，返回是否命中活跃地址 */
int tcp_syn_ack_parse_response(uint8_t *buffer,
                               ssize_t len,
                               struct in6_addr *target_ip,
                               uint64_t *prefix_index) {
    if (!buffer || !target_ip || !prefix_index) return 0;
    if (len < sizeof(struct ethhdr) + sizeof(struct ip6_hdr) + sizeof(struct tcphdr)) return 0;

    struct ethhdr *eth = (struct ethhdr *)buffer;
    if (ntohs(eth->h_proto) != ETH_P_IPV6) return 0;

    struct ip6_hdr *ip6 = (struct ip6_hdr *)(buffer + sizeof(struct ethhdr));

    struct tcphdr *tcp = (struct tcphdr *)(buffer + sizeof(struct ethhdr) + sizeof(struct ip6_hdr));

    /* 判断 TCP RST / SYN-ACK 或 ICMPv6 unreachable */
    if (tcp->rst || tcp->syn) {
        *target_ip = ip6->ip6_src;
        *prefix_index = ((ntohs(tcp->dest) - 40000) % prefix_table_size);
        return 1;
    }

    /* TODO: 如果框架支持 ICMPv6，需要在这里解析 ICMPv6 unreachable */

    return 0;
}

/* 注册协议 */
protocol_t tcp_syn_ack_protocol = {
    .name = "tcp_syn_ack",
    .build_probe = tcp_syn_ack_build_probe,
    .parse_response = tcp_syn_ack_parse_response
};

__attribute__((constructor))
static void register_tcp_syn_ack(void) {
    register_protocol(&tcp_syn_ack_protocol);
}