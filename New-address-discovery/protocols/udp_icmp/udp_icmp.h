#ifndef UDP_ICMP_H
#define UDP_ICMP_H

#include <stdint.h>
#include <sys/types.h>
#include <netinet/if_ether.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>

/**
 * 构建一个 UDP 探测包
 */
int udp_icmp_build_probe(struct ethhdr *eth,
                         struct ip6_hdr *ip6,
                         void *l4,
                         int index);

/**
 * 解析收到的 ICMPv6 响应，提取命中 IPv6 地址
 */
int udp_icmp_parse_response(uint8_t *buffer,
                            ssize_t received_bytes,
                            struct in6_addr *target_ip,
                            uint64_t *prefix_index);

#endif