#ifndef UNA_NEIGHBOR_DISCOVERY_H
#define UNA_NEIGHBOR_DISCOVERY_H

#include <stdint.h>
#include <sys/types.h>
#include <netinet/if_ether.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>

int una_neighbor_discovery_build_probe(struct ethhdr *eth,
                                      struct ip6_hdr *ip6,
                                      struct nd_neighbor_advert *na,
                                      int index);

int una_neighbor_discovery_parse_response(const uint8_t *buffer,
                                         ssize_t received_bytes,
                                         struct in6_addr *target_ip,
                                         uint64_t *prefix_index);

#endif