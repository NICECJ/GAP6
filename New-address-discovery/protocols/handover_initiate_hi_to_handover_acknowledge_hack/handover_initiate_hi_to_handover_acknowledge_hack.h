#ifndef HANDOVER_INITIATE_HI_TO_HANDOVER_ACKNOWLEDGE_HACK_H
#define HANDOVER_INITIATE_HI_TO_HANDOVER_ACKNOWLEDGE_HACK_H

#include <stdint.h>
#include <sys/types.h>
#include <netinet/if_ether.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>

int handover_initiate_hi_to_handover_acknowledge_hack_build_probe(struct ethhdr *eth,
                                                                 struct ip6_hdr *ip6,
                                                                 struct icmp6_hdr *icmp6,
                                                                 int index);

int handover_initiate_hi_to_handover_acknowledge_hack_parse_response(const uint8_t *buffer,
                                                                    ssize_t received_bytes,
                                                                    struct in6_addr *target_ip,
                                                                    uint64_t *prefix_index);

#endif