#ifndef ICMP_ECHO_REQUEST_FOR_DEFAULT_GATEWAY_H
#define ICMP_ECHO_REQUEST_FOR_DEFAULT_GATEWAY_H

#include <stdint.h>
#include <netinet/ip6.h>
#include <netinet/if_ether.h>

/* 构建 ICMPv6 Echo Request 探测包 */
int icmp_echo_build_probe(struct ethhdr *eth,
                          struct ip6_hdr *ip6,
                          void *l4,
                          int index,
                          int seq);

/* 解析 ICMPv6 响应，并映射到原 probe */
int icmp_echo_parse_response(uint8_t *buffer,
                             ssize_t len,
                             struct in6_addr *target_ip,
                             uint64_t *prefix_index,
                             int *seq);

#endif