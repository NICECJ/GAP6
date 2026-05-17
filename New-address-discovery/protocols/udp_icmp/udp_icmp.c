#include "udp_icmp.h"
#include "../../include/config.h"
#include "../../include/hash.h"
#include "../../include/protocol.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/icmp6.h>
#include <linux/if_ether.h>
#include <time.h>

static uint32_t udp_icmp_rand32(void) {
    return ((uint32_t)rand() << 16) | (uint32_t)rand();
}

static uint16_t checksum16(const uint8_t *buf, size_t len) {
    uint32_t sum = 0;
    for (size_t i = 0; i + 1 < len; i += 2) {
        sum += ((uint16_t)buf[i] << 8) | buf[i + 1];
        while (sum > 0xFFFF) sum = (sum & 0xFFFF) + (sum >> 16);
    }
    if (len & 1) sum += ((uint16_t)buf[len-1] << 8);
    return (uint16_t)(~sum);
}

static void udp_icmp_build_target(struct in6_addr *dst, int index) {
    if (exact_addr_flags[index]) {
        *dst = exact_addr_table[index];
        return;
    }

    PrefixInfo *pcs = &prefix_table[index];
    unsigned char dst_addr[16] = {0};

    uint64_t rand_val = udp_icmp_rand32();
    uint64_t dst_prefix = pcs->prefix_stub + (pcs->mask_suffix & rand_val);
    dst_prefix = htonll(dst_prefix);
    memcpy(dst_addr, &dst_prefix, 8);

    uint32_t rand_suffix = udp_icmp_rand32();
    memcpy(dst_addr + 8, &rand_suffix, 4);

    uint32_t checksum = murmur3(dst_addr, 12, 0x11112222);
    checksum = htonl(checksum);
    memcpy(dst_addr + 12, &checksum, 4);

    memcpy(dst, dst_addr, 16);
}

int udp_icmp_build_probe(struct ethhdr *eth,
                         struct ip6_hdr *ip6,
                         void *l4,
                         int index) {
    struct udphdr *udp = (struct udphdr *)l4;
    if (!eth || !ip6 || !udp) return -1;

    PrefixInfo *pcs = &prefix_table[index];
    pcs->sent_packets++;

    memset(eth, 0, sizeof(struct ethhdr));
    memset(ip6, 0, sizeof(struct ip6_hdr));
    memset(l4, 0, sizeof(struct udphdr));

    sscanf(gateway_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &eth->h_dest[0], &eth->h_dest[1], &eth->h_dest[2],
           &eth->h_dest[3], &eth->h_dest[4], &eth->h_dest[5]);
    sscanf(source_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &eth->h_source[0], &eth->h_source[1], &eth->h_source[2],
           &eth->h_source[3], &eth->h_source[4], &eth->h_source[5]);
    eth->h_proto = htons(ETH_P_IPV6);

    ip6->ip6_flow = htonl(0x60000000);
    ip6->ip6_plen = htons(sizeof(struct udphdr));
    ip6->ip6_nxt  = IPPROTO_UDP;
    ip6->ip6_hlim = 64;
    inet_pton(AF_INET6, source_ip, &ip6->ip6_src);
    udp_icmp_build_target(&ip6->ip6_dst, index);

    udp->source = htons(40000 + (index % 20000));
    udp->dest   = htons(33434 + (rand() % 10000));
    udp->len    = htons(sizeof(struct udphdr));
    udp->check  = 0;

    struct {
        struct in6_addr src;
        struct in6_addr dst;
        uint32_t len;
        uint8_t zero[3];
        uint8_t next_header;
    } pseudo_hdr = {0};

    pseudo_hdr.src = ip6->ip6_src;
    pseudo_hdr.dst = ip6->ip6_dst;
    pseudo_hdr.len = htonl(sizeof(struct udphdr));
    pseudo_hdr.next_header = IPPROTO_UDP;

    uint8_t buf[sizeof(pseudo_hdr)+sizeof(struct udphdr)];
    memcpy(buf, &pseudo_hdr, sizeof(pseudo_hdr));
    memcpy(buf + sizeof(pseudo_hdr), udp, sizeof(struct udphdr));
    udp->check = htons(checksum16(buf, sizeof(buf)));

    return 0;
}

int udp_icmp_parse_response(uint8_t *buffer,
                            ssize_t len,
                            struct in6_addr *target_ip,
                            uint64_t *prefix_index) {
    if (!buffer || !target_ip || !prefix_index) return 0;
    if (len < sizeof(struct ethhdr)+sizeof(struct ip6_hdr)+sizeof(struct icmp6_hdr)) return 0;

    struct ethhdr *eth = (struct ethhdr *)buffer;
    if (ntohs(eth->h_proto)!=ETH_P_IPV6) return 0;

    struct ip6_hdr *outer = (struct ip6_hdr *)(buffer+sizeof(struct ethhdr));
    if (outer->ip6_nxt != IPPROTO_ICMPV6) return 0;

    struct icmp6_hdr *icmp = (struct icmp6_hdr *)(buffer+sizeof(struct ethhdr)+sizeof(struct ip6_hdr));
    if (!(icmp->icmp6_type==ICMP6_DST_UNREACH &&
          icmp->icmp6_code==ICMP6_DST_UNREACH_NOPORT)) return 0;

    uint8_t *inner = buffer+sizeof(struct ethhdr)+sizeof(struct ip6_hdr)+sizeof(struct icmp6_hdr);
    struct ip6_hdr *inner_ip6 = (struct ip6_hdr *)inner;
    struct udphdr *inner_udp = (struct udphdr *)(inner+sizeof(struct ip6_hdr));

    *target_ip = inner_ip6->ip6_dst;

    uint16_t sport = ntohs(inner_udp->source);
    if (sport < 40000) return 0;
    *prefix_index = (sport - 40000) % prefix_table_size;

    return 1;
}

protocol_t udp_icmp_protocol = {
    .name = "udp_icmp",
    .build_probe = udp_icmp_build_probe,
    .parse_response = udp_icmp_parse_response
};

__attribute__((constructor))
static void register_udp_icmp(void) {
    register_protocol(&udp_icmp_protocol);
}