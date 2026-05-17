#ifndef HTTP_PROBE_H
#define HTTP_PROBE_H

#include <stdint.h>
#include <sys/types.h>
#include <netinet/ip6.h>
#include <netinet/if_ether.h>

/**
 * 构建 HTTP 探测 probe
 * 参数:
 *   eth - 以太头
 *   ip6 - IPv6 头
 *   l4  - UDP/TCP 头（或空指针，可根据框架需求）
 *   index - 前缀或地址索引
 */
int http_probe_build_probe(struct ethhdr *eth,
                           struct ip6_hdr *ip6,
                           void *l4,
                           int index);

/**
 * 解析 HTTP 响应
 * 参数:
 *   buffer - 接收到的数据
 *   received_bytes - 数据长度
 *   target_ip - 输出命中 IPv6 地址
 *   prefix_index - 输出前缀索引
 * 返回值: 1 = 命中有效地址，0 = 无效
 */
int http_probe_parse_response(uint8_t *buffer,
                              ssize_t received_bytes,
                              struct in6_addr *target_ip,
                              uint64_t *prefix_index);

#endif