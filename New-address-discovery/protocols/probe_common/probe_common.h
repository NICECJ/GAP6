#ifndef PROBE_COMMON_H
#define PROBE_COMMON_H

#include "../../include/config.h"

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <netinet/if_ether.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/icmp6.h>
#include <netinet/udp.h>
#include <netinet/in.h>

#define PROBE_L4_BYTES ((size_t)sizeof(struct tcphdr))
#define PROBE_TCP_FIN 0x01
#define PROBE_TCP_SYN 0x02
#define PROBE_TCP_RST 0x04
#define PROBE_TCP_PSH 0x08
#define PROBE_TCP_ACK 0x10
#define PROBE_TCP_URG 0x20

uint32_t probe_rand32(void);
uint32_t probe_index_token(uint64_t index);
int probe_decode_index_token(uint32_t token, uint64_t *prefix_index);

void probe_build_target_addr(struct in6_addr *dst, int index);
int probe_match_exact_addr(const struct in6_addr *addr, uint64_t *matched_index);
int probe_validate_generated_addr(const struct in6_addr *addr);
int probe_accept_indexed_target(const struct in6_addr *addr,
                                uint64_t decoded_index,
                                struct in6_addr *target_ip,
                                uint64_t *prefix_index);

int probe_init_eth_ipv6(struct ethhdr *eth,
                        struct ip6_hdr *ip6,
                        int next_header,
                        uint16_t payload_len,
                        uint8_t hop_limit,
                        int index);

uint16_t probe_ipv6_l4_checksum(const struct in6_addr *src,
                                const struct in6_addr *dst,
                                uint8_t next_header,
                                const void *payload,
                                size_t payload_len);

int probe_build_tcp_probe(struct ethhdr *eth,
                          struct ip6_hdr *ip6,
                          struct tcphdr *tcp,
                          int index,
                          uint16_t dst_port,
                          uint8_t flags,
                          uint8_t hop_limit,
                          int ack_uses_token);

int probe_extract_tcp_index(const struct tcphdr *tcp,
                            uint64_t *prefix_index);

int probe_build_icmp_echo_probe(struct ethhdr *eth,
                                struct ip6_hdr *ip6,
                                struct icmp6_hdr *icmp,
                                int index,
                                uint8_t hop_limit);

int probe_extract_l4_token(const void *l4,
                           size_t l4_len,
                           uint64_t *prefix_index);

void probe_store_l4_token(void *l4, uint32_t token);

int probe_build_udp_probe(struct ethhdr *eth,
                          struct ip6_hdr *ip6,
                          struct udphdr *udp,
                          int index,
                          uint16_t dst_port,
                          uint8_t hop_limit);

int probe_read_ipv6_packet(const uint8_t *buffer,
                           ssize_t len,
                           struct ip6_hdr *ip6,
                           const uint8_t **payload,
                           size_t *payload_len);

int probe_read_embedded_ipv6(const uint8_t *buffer,
                             size_t len,
                             struct ip6_hdr *ip6,
                             const uint8_t **payload,
                             size_t *payload_len);

#endif
