#include "dns_probe.h"
#include "../../include/config.h"
#include "../../include/protocol.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <unistd.h>
#include <time.h>

/* 随机生成32bit */
static uint32_t rand32(void) { return ((uint32_t)rand()<<16) | (uint32_t)rand(); }

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
        memcpy(addr+8, &rand_suffix, 4);

        uint32_t checksum = htonl(murmur3(addr,12,0x11112222));
        memcpy(addr+12, &checksum, 4);

        memcpy(ip6->ip6_dst.s6_addr, addr,16);
    }
}

/* 构建 DNS 探测包 */
int dns_probe_build_probe(struct ethhdr *eth,
                          struct ip6_hdr *ip6,
                          void *l4,
                          int index,
                          int seq) {
    struct udphdr *udp = (struct udphdr*)l4;

    if(!ip6) return -1;

    if(eth) memset(eth,0,sizeof(struct ethhdr));
    memset(ip6,0,sizeof(struct ip6_hdr));
    if(udp) memset(udp,0,sizeof(struct udphdr));

    build_target_ip(ip6,index);

    if(udp) {
        udp->source = htons(40000 + (index % 20000));
        udp->dest   = htons(53); /* DNS 默认端口 */
        udp->len    = htons(sizeof(struct udphdr));
        udp->check  = 0;
    }

    prefix_table[index].sent_packets++;
    return 0;
}

/* 解析 DNS 响应，映射回 probe */
int dns_probe_parse_response(uint8_t *buffer,
                             ssize_t len,
                             struct in6_addr *target_ip,
                             uint64_t *prefix_index,
                             int *seq) {
    if(!buffer || !target_ip || !prefix_index || !seq) return 0;
    if(len < sizeof(struct ethhdr)+sizeof(struct ip6_hdr)+sizeof(struct udphdr)) return 0;

    struct ethhdr *eth = (struct ethhdr*)buffer;
    if(ntohs(eth->h_proto) != ETH_P_IPV6) return 0;

    struct ip6_hdr *ip6 = (struct ip6_hdr*)(buffer + sizeof(struct ethhdr));
    struct udphdr *udp = (struct udphdr*)(buffer + sizeof(struct ethhdr)+sizeof(struct ip6_hdr));

    /* 判断目标端口返回响应即可 */
    if(ntohs(udp->source) == 53){
        *target_ip = ip6->ip6_src;
        *prefix_index = (ntohs(udp->dest)-40000) % prefix_table_size;
        *seq = ntohs(udp->dest); /* 可用来区分 probe */
        return 1;
    }

    return 0;
}

/* 注册协议 */
protocol_t dns_probe_protocol = {
    .name = "dns_probe",
    .build_probe = dns_probe_build_probe,
    .parse_response = dns_probe_parse_response
};

__attribute__((constructor))
static void register_dns_probe(void){
    register_protocol(&dns_probe_protocol);
}