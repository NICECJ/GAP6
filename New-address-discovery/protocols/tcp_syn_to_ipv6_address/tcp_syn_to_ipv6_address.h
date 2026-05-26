#ifndef TCP_SYN_TO_IPV6_ADDRESS_H
#define TCP_SYN_TO_IPV6_ADDRESS_H

#include <stdint.h>
#include <sys/types.h>
#include <netinet/if_ether.h>
#include <netinet/ip6.h>
#include <netinet/in.h>

int tcp_syn_to_ipv6_address_build_probe(struct ethhdr *eth,
                       struct ip6_hdr *ip6,
                       void *l4,
                       int index);

int tcp_syn_to_ipv6_address_parse_response(uint8_t *buffer,
                          ssize_t received_bytes,
                          struct in6_addr *target_ip,
                          uint64_t *prefix_index);

#endif
