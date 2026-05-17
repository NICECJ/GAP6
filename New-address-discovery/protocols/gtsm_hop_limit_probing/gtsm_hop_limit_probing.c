#include "gtsm_hop_limit_probing.h"
#include "../../include/config.h"
#include "../../include/hash.h"
#include "../../include/construct.h"
#include "../../include/protocol.h"

#include <string.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <linux/if_ether.h>

int gtsm_hop_limit_probing_build_probe(struct ethhdr *eth,
                                      struct ip6_hdr *ip6,
                                      struct icmp6_hdr *icmp6,
                                      int index) {
    constructICMPv6Packet(eth, ip6, icmp6, index);
    return 0;
}

int gtsm_hop_limit_probing_parse_response(const uint8_t *buffer,
                                         ssize_t received_bytes,
                                         struct in6_addr *target_ip,
                                         uint64_t *prefix_index) {
    (void)received_bytes;

    struct ethhdr* eth_hdr = (struct ethhdr*)buffer;
    if (ntohs(eth_hdr->h_proto) != ETH_P_IPV6)
        return 0;

    struct ip6_hdr* ip6_hdr =
        (struct ip6_hdr*)(buffer + sizeof(struct ethhdr));

    if (ip6_hdr->ip6_nxt != IPPROTO_ICMPV6)
        return 0;

    if (ip6_hdr->ip6_hlim != 255)
        return 0;

    struct icmp6_hdr* icmp6_hdr =
        (struct icmp6_hdr*)(buffer + sizeof(struct ethhdr) + sizeof(struct ip6_hdr));

    if (icmp6_hdr->icmp6_type != ICMP6_ECHO_REPLY)
        return 0;

    *target_ip = ip6_hdr->ip6_src;

    uint32_t embedded_checksum;
    memcpy(&embedded_checksum, target_ip->s6_addr + 12, sizeof(uint32_t));
    embedded_checksum = ntohl(embedded_checksum);

    uint32_t computed_checksum =
        murmur3(target_ip->s6_addr, 12, 0x11112222);

    if (embedded_checksum != computed_checksum)
        return 0;

    uint32_t seq = ntohs(icmp6_hdr->icmp6_seq);
    *prefix_index = seq >> 8;

    uint32_t bloom_index_1 = murmur3(target_ip->s6_addr, 16, 0x12345678);
    uint32_t bloom_index_2 = murmur3(target_ip->s6_addr, 16, 0x87654321);

    if ((bloom_filter[bloom_index_1 / 8] & (1 << (bloom_index_1 % 8))) &&
        (bloom_filter[bloom_index_2 / 8] & (1 << (bloom_index_2 % 8))))
        return 0;

    bloom_filter[bloom_index_1 / 8] |= (1 << (bloom_index_1 % 8));
    bloom_filter[bloom_index_2 / 8] |= (1 << (bloom_index_2 % 8));

    return 1;
}

protocol_t gtsm_hop_limit_probing_protocol = {
    .name = "gtsm_hop_limit_probing",
    .build_probe = gtsm_hop_limit_probing_build_probe,
    .parse_response = gtsm_hop_limit_probing_parse_response
};

/* automatic registration */
__attribute__((constructor))
static void register_gtsm_hop_limit_probing()
{
    register_protocol(&gtsm_hop_limit_probing_protocol);
}