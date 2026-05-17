#ifndef ACK_RST_H
#define ACK_RST_H

#include <stdint.h>
#include <sys/types.h>
#include <netinet/if_ether.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/in.h>

int ack_rst_build_probe(struct ethhdr *eth,
                        struct ip6_hdr *ip6,
                        struct tcphdr *tcp,
                        int index);

int ack_rst_parse_response(const uint8_t *buffer,
                           ssize_t received_bytes,
                           struct in6_addr *target_ip,
                           uint64_t *prefix_index);

#endif