#include "udp_icmp.h"
#include "../probe_common/probe_common.h"
#include "../../include/protocol.h"

#include <arpa/inet.h>
#include <netinet/icmp6.h>
#include <netinet/udp.h>
#include <string.h>

int udp_icmp_build_probe(struct ethhdr *eth,
                         struct ip6_hdr *ip6,
                         void *l4,
                         int index) {
    uint16_t dst_port = (uint16_t)(33434 + (probe_rand32() % 10000));
    return probe_build_udp_probe(eth,
                                 ip6,
                                 (struct udphdr *)l4,
                                 index,
                                 dst_port,
                                 64);
}

int udp_icmp_parse_response(uint8_t *buffer,
                            ssize_t received_bytes,
                            struct in6_addr *target_ip,
                            uint64_t *prefix_index) {
    struct ip6_hdr outer_ip6;
    const uint8_t *outer_payload;
    size_t outer_payload_len;
    struct icmp6_hdr icmp;

    if (!probe_read_ipv6_packet(buffer, received_bytes, &outer_ip6,
                                &outer_payload, &outer_payload_len)) {
        return 0;
    }

    if (outer_ip6.ip6_nxt != IPPROTO_ICMPV6 ||
        outer_payload_len < sizeof(icmp)) {
        return 0;
    }

    memcpy(&icmp, outer_payload, sizeof(icmp));
    if (icmp.icmp6_type != ICMP6_DST_UNREACH ||
        icmp.icmp6_code != ICMP6_DST_UNREACH_NOPORT) {
        return 0;
    }

    struct ip6_hdr inner_ip6;
    const uint8_t *inner_payload;
    size_t inner_payload_len;
    const uint8_t *inner_packet = outer_payload + sizeof(icmp);
    size_t inner_packet_len = outer_payload_len - sizeof(icmp);

    if (!probe_read_embedded_ipv6(inner_packet,
                                  inner_packet_len,
                                  &inner_ip6,
                                  &inner_payload,
                                  &inner_payload_len)) {
        return 0;
    }

    if (inner_ip6.ip6_nxt != IPPROTO_UDP ||
        inner_payload_len < sizeof(struct udphdr)) {
        return 0;
    }

    uint64_t decoded_index = prefix_table_size;
    if (!probe_extract_l4_token(inner_payload, inner_payload_len, &decoded_index)) {
        struct udphdr udp;
        memcpy(&udp, inner_payload, sizeof(udp));
        uint16_t sport = ntohs(udp.source);
        if (sport >= 40000) {
            uint64_t fallback_index = (uint64_t)(sport - 40000);
            if (fallback_index < prefix_table_size) {
                decoded_index = fallback_index;
            }
        }
    }

    return probe_accept_indexed_target(&inner_ip6.ip6_dst,
                                       decoded_index,
                                       target_ip,
                                       prefix_index);
}

protocol_t udp_icmp_protocol = {
    .name = "udp_icmp",
    .build_probe = udp_icmp_build_probe,
    .parse_response = udp_icmp_parse_response
};

__attribute__((constructor))
static void register_udp_icmp(void) {
    register_protocol(&udp_icmp_protocol);
}
