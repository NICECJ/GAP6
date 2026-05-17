#include "icmp_echo_request_for_default_gateway.h"
#include "../../include/config.h"
#include "../../include/protocol.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/if_ether.h>
#include <unistd.h>

/* 随机生成32bit */
static uint32_t rand32(void) { return ((uint32_t)rand() << 16) | (uint32_t)rand(); }

/* 构建目标 IPv6 地址，使用系统前缀生成逻辑 */
static void build_target_ip(struct ip6_hdr *ip6, int index) {
    if (exact_addr_flags[index]) {
        ip6->ip6_dst = exact_addr_table[index];
    } else {
        PrefixInfo *pcs = &prefix_table[index];
        unsigned char addr[16] = {0};

        uint64_t dst_prefix = pcs->prefix_stub + (pcs->mask_suffix & rand32());
        dst_prefix = htonll(dst_prefix);
        memcpy(addr, &dst_prefix, 8);

        uint32_t rand_suffix = rand32();
        memcpy(addr + 8, &rand_suffix, 4);

        uint32_t checksum = htonl(murmur3(addr, 12, 0x11112222));
        memcpy(addr + 12, &checksum, 4);

        memcpy(ip6->ip6_dst.s6_addr, addr, 16);
    }
}

/* 构建 ICMPv6 Echo Request probe */
int icmp_echo_build_probe(struct ethhdr *eth,
                          struct ip6_hdr *ip6,
                          void *l4,
                          int index,
                          int seq) {
    struct icmp6_hdr *icmp = (struct icmp6_hdr *)l4;

    if (!ip6) return -1;

    if (eth) memset(eth, 0, sizeof(struct ethhdr));
    memset(ip6, 0, sizeof(struct ip6_hdr));
    if (icmp) memset(icmp, 0, sizeof(struct icmp6_hdr));

    build_target_ip(ip6, index);

    if (icmp) {
        icmp->icmp6_type = ICMP6_ECHO_REQUEST;
        icmp->icmp6_code = 0;
        /* 使用 prefix_index + seq 构造唯一 icmp6_id */
        icmp->icmp6_id = htons(40000 + (index % 20000));
        icmp->icmp6_seq = htons(seq & 0xFFFF);
        icmp->icmp6_cksum = 0;
    }

    prefix_table[index].sent_packets++;
    return 0;
}

/* 解析 ICMPv6 响应，映射回 probe */
int icmp_echo_parse_response(uint8_t *buffer,
                             ssize_t len,
                             struct in6_addr *target_ip,
                             uint64_t *prefix_index,
                             int *seq) {
    if (!buffer || !target_ip || !prefix_index || !seq) return 0;
    if (len < sizeof(struct ethhdr) + sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr))
        return 0;

    struct ethhdr *eth = (struct ethhdr *)buffer;
    if (ntohs(eth->h_proto) != ETH_P_IPV6) return 0;

    struct ip6_hdr *ip6 = (struct ip6_hdr *)(buffer + sizeof(struct ethhdr));
    struct icmp6_hdr *icmp = (struct icmp6_hdr *)(buffer + sizeof(struct ethhdr) + sizeof(struct ip6_hdr));

    /* 只把 Echo Reply 当作活跃主机 */
    if (icmp->icmp6_type == ICMP6_ECHO_REPLY) {
        *target_ip = ip6->ip6_src;
        *prefix_index = (ntohs(icmp->icmp6_id) - 40000) % prefix_table_size;
        *seq = ntohs(icmp->icmp6_seq);
        return 1;
    }

    return 0;
}

/* 注册插件 */
protocol_t icmp_echo_protocol = {
    .name = "icmp_echo_request_for_default_gateway",
    .build_probe = icmp_echo_build_probe,
    .parse_response = icmp_echo_parse_response
};

__attribute__((constructor))
static void register_icmp_echo(void){
    register_protocol(&icmp_echo_protocol);
}