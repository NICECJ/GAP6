#include "tcp_syn_to_ipv6_address.h"
#include "../../include/config.h"
#include "../../include/hash.h"
#include "../../include/construct.h"
#include "../../include/protocol.h"

#include <string.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <linux/if_ether.h>

int tcp_syn_to_ipv6_address_build_probe(struct ethhdr *eth,
                                       struct ip6_hdr *ip6,
                                       struct tcphdr *tcp,
                                       int index) {
    constructTCPv6Packet(eth, ip6, tcp, index);
    tcp->syn = 1;
    return 0;
}

int tcp_syn_to_ipv6_address_parse_response(const uint8_t *buffer,
                                          ssize_t received_bytes,
                                          struct in6_addr *target_ip,
                                          uint64_t *prefix_index) {
    (void)received_bytes;

    struct ethhdr* eth_hdr = (struct ethhdr*)buffer;
    if (ntohs(eth_hdr->h_proto) != ETH_P_IPV6)
        return 0;

    struct ip6_hdr* ip6_hdr =
        (struct ip6_hdr*)(buffer + sizeof(struct ethhdr));

    if (ip6_hdr->ip6_nxt != IPPROTO_TCP)
        return 0;

    struct tcphdr* tcp_hdr =
        (struct tcphdr*)(buffer + sizeof(struct ethhdr) + sizeof(struct ip6_hdr));

    if (!(tcp_hdr->rst))
        return 0;

    *target_ip = ip6_hdr->ip6_src;

    uint32_t embedded_checksum;
    memcpy(&embedded_checksum, target_ip->s6_addr + 12, sizeof(uint32_t));
    embedded_checksum = ntohl(embedded_checksum);

    uint32_t computed_checksum =
        murmur3(target_ip->s6_addr, 12, 0x11112222);

    if (embedded_checksum != computed_checksum)
        return 0;

    uint32_t seq = ntohl(tcp_hdr->seq);
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

protocol_t tcp_syn_to_ipv6_address_protocol = {
    .name = "tcp_syn_to_ipv6_address",
    .build_probe = tcp_syn_to_ipv6_address_build_probe,
    .parse_response = tcp_syn_to_ipv6_address_parse_response
};

/* automatic registration */
__attribute__((constructor))
static void register_tcp_syn_to_ipv6_address()
{
    register_protocol(&tcp_syn_to_ipv6_address_protocol);
}