#ifndef DNS_PROBE_H
#define DNS_PROBE_H

#include <stdint.h>
#include <netinet/ip6.h>
#include <netinet/if_ether.h>

/**
 * 构建 DNS 探测包
 * 参数:
 *   eth  - 以太头，可选
 *   ip6  - IPv6 头
 *   l4   - UDP/TCP 头（void*，可以转换成 struct udphdr*）
 *   index - 前缀或地址索引
 */
int dns_probe_build_probe(struct ethhdr *eth,
                          struct ip6_hdr *ip6,
                          void *l4,
                          int index,
                          int seq);

/**
 * 解析 DNS 响应
 * 参数:
 *   buffer - 接收到的数据
 *   len    - 数据长度
 *   target_ip - 输出命中 IPv6 地址
 *   prefix_index - 输出前缀索引
 *   seq    - 输出 probe 序号
 * 返回值: 1=命中活跃地址, 0=无效
 */
int dns_probe_parse_response(uint8_t *buffer,
                             ssize_t len,
                             struct in6_addr *target_ip,
                             uint64_t *prefix_index,
                             int *seq);

#endif