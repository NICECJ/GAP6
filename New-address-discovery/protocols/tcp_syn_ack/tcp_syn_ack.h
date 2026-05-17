#ifndef TCP_SYN_ACK_H
#define TCP_SYN_ACK_H

#include <stdint.h>
#include <sys/types.h>
#include <netinet/ip6.h>
#include <netinet/if_ether.h>

/**
 * 构建 TCP SYN 探测包
 * 参数:
 *   eth  - 以太网头（可选，根据框架）
 *   ip6  - IPv6 头
 *   l4   - TCP 头（void*，可转换为 struct tcphdr*）
 *   index - 前缀索引
 */
int tcp_syn_ack_build_probe(struct ethhdr *eth,
                            struct ip6_hdr *ip6,
                            void *l4,
                            int index);

/**
 * 解析 TCP SYN / RST / ICMPv6 响应
 * 返回 1 表示命中活跃地址
 */
int tcp_syn_ack_parse_response(uint8_t *buffer,
                               ssize_t received_bytes,
                               struct in6_addr *target_ip,
                               uint64_t *prefix_index);

#endif