#ifndef RTSOLPR_PRRTADV_H
#define RTSOLPR_PRRTADV_H

#include <stdint.h>
#include <sys/types.h>
#include <netinet/if_ether.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>

int rtsolpr_prrtadv_build_probe(struct ethhdr *eth,
                               struct ip6_hdr *ip6,
                               struct icmp6_hdr *icmp6,
                               int index);

int rtsolpr_prrtadv_parse_response(const uint8_t *buffer,
                                  ssize_t received_bytes,
                                  struct in6_addr *target_ip,
                                  uint64_t *prefix_index);

#endif