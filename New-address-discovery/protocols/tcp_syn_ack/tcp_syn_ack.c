#include "tcp_syn_ack.h"
#include "../probe_common/probe_common.h"
#include "../../include/protocol.h"

#include <netinet/tcp.h>
#include <string.h>

int tcp_syn_ack_build_probe(struct ethhdr *eth,
                       struct ip6_hdr *ip6,
                       void *l4,
                       int index) {
    return probe_build_tcp_probe(eth,
                                 ip6,
                                 (struct tcphdr *)l4,
                                 index,
                                 80,
                                 PROBE_TCP_SYN,
                                 64,
                                 0);
}

int tcp_syn_ack_parse_response(uint8_t *buffer,
                          ssize_t received_bytes,
                          struct in6_addr *target_ip,
                          uint64_t *prefix_index) {
    struct ip6_hdr ip6;
    const uint8_t *payload;
    size_t payload_len;
    struct tcphdr tcp;

    if (!probe_read_ipv6_packet(buffer, received_bytes, &ip6,
                                &payload, &payload_len)) {
        return 0;
    }

    if (ip6.ip6_nxt != IPPROTO_TCP || payload_len < sizeof(tcp)) {
        return 0;
    }

    memcpy(&tcp, payload, sizeof(tcp));
    if (!tcp.syn || !tcp.ack) {
        return 0;
    }

    uint64_t decoded_index = prefix_table_size;
    probe_extract_tcp_index(&tcp, &decoded_index);
    return probe_accept_indexed_target(&ip6.ip6_src,
                                       decoded_index,
                                       target_ip,
                                       prefix_index);
}

protocol_t tcp_syn_ack_protocol = {
    .name = "tcp_syn_ack",
    .build_probe = tcp_syn_ack_build_probe,
    .parse_response = tcp_syn_ack_parse_response
};

__attribute__((constructor))
static void register_tcp_syn_ack(void) {
    register_protocol(&tcp_syn_ack_protocol);
}
