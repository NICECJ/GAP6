#include "syn_rst.h"
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

int syn_rst_build_probe(struct ethhdr *eth,
                        struct ip6_hdr *ip6,
                        struct tcphdr *tcp,
                        int index)
{
    constructTCPv6Packet(eth, ip6, tcp, index);

    /* SYN probe */
    tcp->syn = 1;
    tcp->ack = 0;

    return 0;
}


int syn_rst_parse_response(const uint8_t *buffer,
                           ssize_t received_bytes,
                           struct in6_addr *target_ip,
                           uint64_t *prefix_index)
{
    (void)received_bytes;

    /* ================= Ethernet ================= */

    struct ethhdr* eth_hdr = (struct ethhdr*)buffer;

    if (ntohs(eth_hdr->h_proto) != ETH_P_IPV6)
        return 0;


    /* ================= IPv6 ================= */

    struct ip6_hdr* ip6_hdr =
        (struct ip6_hdr*)(buffer + sizeof(struct ethhdr));

    if (ip6_hdr->ip6_nxt != IPPROTO_TCP)
        return 0;


    /* ================= TCP ================= */

    struct tcphdr* tcp_hdr =
        (struct tcphdr*)(buffer + sizeof(struct ethhdr) + sizeof(struct ip6_hdr));

    /* SYN -> expect RST */
    if (!(tcp_hdr->rst))
        return 0;


    /* ================= Extract target ================= */

    *target_ip = ip6_hdr->ip6_src;


    /* ================= Address checksum validation ================= */

    uint32_t embedded_checksum;
    memcpy(&embedded_checksum, target_ip->s6_addr + 12, sizeof(uint32_t));
    embedded_checksum = ntohl(embedded_checksum);

    uint32_t computed_checksum =
        murmur3(target_ip->s6_addr, 12, 0x11112222);

    if (embedded_checksum != computed_checksum)
        return 0;


    /* ================= Recover prefix index ================= */

    uint32_t seq = ntohl(tcp_hdr->seq);
    *prefix_index = seq >> 8;


    /* ================= Bloom filter dedup ================= */

    uint32_t bloom_index_1 =
        murmur3(target_ip->s6_addr, 16, 0x12345678);

    uint32_t bloom_index_2 =
        murmur3(target_ip->s6_addr, 16, 0x87654321);

    if ((bloom_filter[bloom_index_1 / 8] & (1 << (bloom_index_1 % 8))) &&
        (bloom_filter[bloom_index_2 / 8] & (1 << (bloom_index_2 % 8))))
        return 0;

    bloom_filter[bloom_index_1 / 8] |= (1 << (bloom_index_1 % 8));
    bloom_filter[bloom_index_2 / 8] |= (1 << (bloom_index_2 % 8));

    return 1;
}


/* ================= protocol registration ================= */

protocol_t syn_rst_protocol = {
    .name = "syn_rst",
    .build_probe = syn_rst_build_probe,
    .parse_response = syn_rst_parse_response
};


/* automatic registration */

__attribute__((constructor))
static void register_syn_rst()
{
    register_protocol(&syn_rst_protocol);
}