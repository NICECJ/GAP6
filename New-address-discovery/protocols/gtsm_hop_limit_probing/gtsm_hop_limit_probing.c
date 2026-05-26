#include "gtsm_hop_limit_probing.h"
#include "../probe_common/probe_common.h"
#include "../../include/protocol.h"

#include <netinet/icmp6.h>
#include <string.h>

int gtsm_hop_limit_probing_build_probe(struct ethhdr *eth,
                       struct ip6_hdr *ip6,
                       void *l4,
                       int index) {
    return probe_build_icmp_echo_probe(eth,
                                       ip6,
                                       (struct icmp6_hdr *)l4,
                                       index,
                                       255);
}

int gtsm_hop_limit_probing_parse_response(uint8_t *buffer,
                          ssize_t received_bytes,
                          struct in6_addr *target_ip,
                          uint64_t *prefix_index) {
    struct ip6_hdr ip6;
    const uint8_t *payload;
    size_t payload_len;
    struct icmp6_hdr icmp;

    if (!probe_read_ipv6_packet(buffer, received_bytes, &ip6,
                                &payload, &payload_len)) {
        return 0;
    }

    if (ip6.ip6_nxt != IPPROTO_ICMPV6 || payload_len < sizeof(icmp)) {
        return 0;
    }

    memcpy(&icmp, payload, sizeof(icmp));
    if (icmp.icmp6_type != ICMP6_ECHO_REPLY || ip6.ip6_hlim != 255) {
        return 0;
    }

    uint64_t decoded_index = prefix_table_size;
    probe_extract_l4_token(payload, payload_len, &decoded_index);
    return probe_accept_indexed_target(&ip6.ip6_src,
                                       decoded_index,
                                       target_ip,
                                       prefix_index);
}

protocol_t gtsm_hop_limit_probing_protocol = {
    .name = "gtsm_hop_limit_probing",
    .build_probe = gtsm_hop_limit_probing_build_probe,
    .parse_response = gtsm_hop_limit_probing_parse_response
};

__attribute__((constructor))
static void register_gtsm_hop_limit_probing(void) {
    register_protocol(&gtsm_hop_limit_probing_protocol);
}
