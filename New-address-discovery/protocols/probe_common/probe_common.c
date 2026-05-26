#include "probe_common.h"
#include "../../include/hash.h"

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PROBE_TOKEN_MAGIC 0x47415036U

uint32_t probe_rand32(void) {
    return ((uint32_t)rand() << 16) ^ (uint32_t)rand();
}

uint32_t probe_index_token(uint64_t index) {
    uint32_t nonce = probe_rand32() & 0xffU;
    if (nonce == 0) {
        nonce = 1;
    }
    return ((uint32_t)index << 8) | nonce;
}

int probe_decode_index_token(uint32_t token, uint64_t *prefix_index) {
    if (!prefix_index || token == 0) {
        return 0;
    }

    uint64_t decoded = token >> 8;
    if (decoded >= prefix_table_size) {
        return 0;
    }

    *prefix_index = decoded;
    return 1;
}

static int probe_parse_mac(const char *text, uint8_t mac[ETH_ALEN]) {
    if (!text || !mac) {
        return 0;
    }

    return sscanf(text, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                  &mac[0], &mac[1], &mac[2],
                  &mac[3], &mac[4], &mac[5]) == 6;
}

void probe_build_target_addr(struct in6_addr *dst, int index) {
    if (!dst || index < 0 || (uint64_t)index >= prefix_table_size) {
        return;
    }

    if (exact_addr_flags[index]) {
        *dst = exact_addr_table[index];
        return;
    }

    PrefixInfo *pcs = &prefix_table[index];
    uint8_t addr[16] = {0};

    uint64_t rand_val = probe_rand32();
    uint64_t dst_prefix = pcs->prefix_stub + (pcs->mask_suffix & rand_val);
    dst_prefix = htonll(dst_prefix);
    memcpy(addr, &dst_prefix, sizeof(dst_prefix));

    uint32_t rand_suffix = probe_rand32();
    memcpy(addr + 8, &rand_suffix, sizeof(rand_suffix));

    uint32_t checksum = murmur3(addr, 12, 0x11112222);
    checksum = htonl(checksum);
    memcpy(addr + 12, &checksum, sizeof(checksum));

    memcpy(dst, addr, sizeof(addr));
}

int probe_match_exact_addr(const struct in6_addr *addr, uint64_t *matched_index) {
    if (!addr || !matched_index) {
        return 0;
    }

    for (uint64_t i = 0; i < prefix_table_size; i++) {
        if (!exact_addr_flags[i]) {
            continue;
        }

        if (memcmp(addr, &exact_addr_table[i], sizeof(*addr)) == 0) {
            *matched_index = i;
            return 1;
        }
    }

    return 0;
}

int probe_validate_generated_addr(const struct in6_addr *addr) {
    if (!addr) {
        return 0;
    }

    uint32_t embedded_checksum;
    memcpy(&embedded_checksum, addr->s6_addr + 12, sizeof(embedded_checksum));
    embedded_checksum = ntohl(embedded_checksum);

    uint32_t computed_checksum = murmur3(addr->s6_addr, 12, 0x11112222);
    return embedded_checksum == computed_checksum;
}

int probe_accept_indexed_target(const struct in6_addr *addr,
                                uint64_t decoded_index,
                                struct in6_addr *target_ip,
                                uint64_t *prefix_index) {
    if (!addr || !target_ip || !prefix_index) {
        return 0;
    }

    uint64_t exact_index = 0;
    if (probe_match_exact_addr(addr, &exact_index)) {
        *target_ip = *addr;
        *prefix_index = exact_index;
        return 1;
    }

    if (decoded_index >= prefix_table_size) {
        return 0;
    }

    if (!probe_validate_generated_addr(addr)) {
        return 0;
    }

    *target_ip = *addr;
    *prefix_index = decoded_index;
    return 1;
}

int probe_init_eth_ipv6(struct ethhdr *eth,
                        struct ip6_hdr *ip6,
                        int next_header,
                        uint16_t payload_len,
                        uint8_t hop_limit,
                        int index) {
    if (!eth || !ip6 || index < 0 || (uint64_t)index >= prefix_table_size) {
        return -1;
    }

    memset(eth, 0, sizeof(*eth));
    memset(ip6, 0, sizeof(*ip6));

    if (!probe_parse_mac(gateway_mac, eth->h_dest) ||
        !probe_parse_mac(source_mac, eth->h_source)) {
        return -1;
    }

    eth->h_proto = htons(ETH_P_IPV6);

    ip6->ip6_flow = htonl(0x60000000);
    ip6->ip6_plen = htons(payload_len);
    ip6->ip6_nxt = (uint8_t)next_header;
    ip6->ip6_hlim = hop_limit;

    if (inet_pton(AF_INET6, source_ip, &ip6->ip6_src) != 1) {
        return -1;
    }

    probe_build_target_addr(&ip6->ip6_dst, index);
    return 0;
}

static uint16_t probe_checksum16(const uint8_t *buf, size_t len) {
    uint32_t sum = 0;

    for (size_t i = 0; i + 1 < len; i += 2) {
        sum += ((uint16_t)buf[i] << 8) | buf[i + 1];
        while (sum > 0xffffU) {
            sum = (sum & 0xffffU) + (sum >> 16);
        }
    }

    if (len & 1U) {
        sum += (uint16_t)buf[len - 1] << 8;
        while (sum > 0xffffU) {
            sum = (sum & 0xffffU) + (sum >> 16);
        }
    }

    return (uint16_t)(~sum & 0xffffU);
}

uint16_t probe_ipv6_l4_checksum(const struct in6_addr *src,
                                const struct in6_addr *dst,
                                uint8_t next_header,
                                const void *payload,
                                size_t payload_len) {
    struct {
        struct in6_addr src;
        struct in6_addr dst;
        uint32_t len;
        uint8_t zero[3];
        uint8_t next_header;
    } pseudo_hdr;

    if (!src || !dst || !payload || payload_len > PROBE_L4_BYTES) {
        return 0;
    }

    memset(&pseudo_hdr, 0, sizeof(pseudo_hdr));
    pseudo_hdr.src = *src;
    pseudo_hdr.dst = *dst;
    pseudo_hdr.len = htonl((uint32_t)payload_len);
    pseudo_hdr.next_header = next_header;

    uint8_t checksum_buffer[sizeof(pseudo_hdr) + PROBE_L4_BYTES];
    memcpy(checksum_buffer, &pseudo_hdr, sizeof(pseudo_hdr));
    memcpy(checksum_buffer + sizeof(pseudo_hdr), payload, payload_len);

    uint16_t checksum = probe_checksum16(checksum_buffer,
                                         sizeof(pseudo_hdr) + payload_len);
    if (checksum == 0 && next_header == IPPROTO_UDP) {
        checksum = 0xffffU;
    }

    return htons(checksum);
}

int probe_build_tcp_probe(struct ethhdr *eth,
                          struct ip6_hdr *ip6,
                          struct tcphdr *tcp,
                          int index,
                          uint16_t dst_port,
                          uint8_t flags,
                          uint8_t hop_limit,
                          int ack_uses_token) {
    if (!tcp) {
        return -1;
    }

    if (probe_init_eth_ipv6(eth, ip6, IPPROTO_TCP,
                            (uint16_t)PROBE_L4_BYTES,
                            hop_limit, index) != 0) {
        return -1;
    }

    memset(tcp, 0, sizeof(*tcp));

    uint32_t token = probe_index_token((uint64_t)index);
    tcp->source = htons((uint16_t)(40000 + (index % 20000)));
    tcp->dest = htons(dst_port);
    tcp->seq = htonl(token);
    tcp->ack_seq = htonl(ack_uses_token ? token : 0);
    tcp->doff = 5;
    tcp->fin = (flags & PROBE_TCP_FIN) != 0;
    tcp->syn = (flags & PROBE_TCP_SYN) != 0;
    tcp->rst = (flags & PROBE_TCP_RST) != 0;
    tcp->psh = (flags & PROBE_TCP_PSH) != 0;
    tcp->ack = (flags & PROBE_TCP_ACK) != 0;
    tcp->urg = (flags & PROBE_TCP_URG) != 0;
    tcp->window = htons(65535);
    tcp->check = 0;
    tcp->check = probe_ipv6_l4_checksum(&ip6->ip6_src,
                                        &ip6->ip6_dst,
                                        IPPROTO_TCP,
                                        tcp,
                                        PROBE_L4_BYTES);
    return 0;
}

int probe_extract_tcp_index(const struct tcphdr *tcp,
                            uint64_t *prefix_index) {
    if (!tcp || !prefix_index) {
        return 0;
    }

    uint32_t ack = ntohl(tcp->ack_seq);
    uint32_t seq = ntohl(tcp->seq);

    if (tcp->ack && ack > 0 && probe_decode_index_token(ack - 1, prefix_index)) {
        return 1;
    }

    if (tcp->ack && ack > 0 && probe_decode_index_token(ack, prefix_index)) {
        return 1;
    }

    if (seq > 0 && probe_decode_index_token(seq, prefix_index)) {
        return 1;
    }

    if (seq > 0 && probe_decode_index_token(seq - 1, prefix_index)) {
        return 1;
    }

    return 0;
}

void probe_store_l4_token(void *l4, uint32_t token) {
    if (!l4) {
        return;
    }

    uint8_t *bytes = (uint8_t *)l4;
    uint32_t token_n = htonl(token);
    uint32_t magic_n = htonl(PROBE_TOKEN_MAGIC);
    uint32_t guard_n = htonl(token ^ PROBE_TOKEN_MAGIC);

    memcpy(bytes + 8, &token_n, sizeof(token_n));
    memcpy(bytes + 12, &magic_n, sizeof(magic_n));
    memcpy(bytes + 16, &guard_n, sizeof(guard_n));
}

int probe_extract_l4_token(const void *l4,
                           size_t l4_len,
                           uint64_t *prefix_index) {
    if (!l4 || !prefix_index || l4_len < PROBE_L4_BYTES) {
        return 0;
    }

    const uint8_t *bytes = (const uint8_t *)l4;
    uint32_t token_n;
    uint32_t magic_n;
    uint32_t guard_n;

    memcpy(&token_n, bytes + 8, sizeof(token_n));
    memcpy(&magic_n, bytes + 12, sizeof(magic_n));
    memcpy(&guard_n, bytes + 16, sizeof(guard_n));

    uint32_t token = ntohl(token_n);
    uint32_t magic = ntohl(magic_n);
    uint32_t guard = ntohl(guard_n);

    if (magic != PROBE_TOKEN_MAGIC || guard != (token ^ PROBE_TOKEN_MAGIC)) {
        return 0;
    }

    return probe_decode_index_token(token, prefix_index);
}

int probe_build_icmp_echo_probe(struct ethhdr *eth,
                                struct ip6_hdr *ip6,
                                struct icmp6_hdr *icmp,
                                int index,
                                uint8_t hop_limit) {
    if (!icmp) {
        return -1;
    }

    if (probe_init_eth_ipv6(eth, ip6, IPPROTO_ICMPV6,
                            (uint16_t)PROBE_L4_BYTES,
                            hop_limit, index) != 0) {
        return -1;
    }

    memset(icmp, 0, PROBE_L4_BYTES);

    uint32_t token = probe_index_token((uint64_t)index);
    icmp->icmp6_type = ICMP6_ECHO_REQUEST;
    icmp->icmp6_code = 0;
    icmp->icmp6_id = htons((uint16_t)(0x6000U | (index & 0x1fffU)));
    icmp->icmp6_seq = htons((uint16_t)(token & 0xffffU));
    probe_store_l4_token(icmp, token);
    icmp->icmp6_cksum = 0;
    icmp->icmp6_cksum = probe_ipv6_l4_checksum(&ip6->ip6_src,
                                               &ip6->ip6_dst,
                                               IPPROTO_ICMPV6,
                                               icmp,
                                               PROBE_L4_BYTES);
    return 0;
}

int probe_build_udp_probe(struct ethhdr *eth,
                          struct ip6_hdr *ip6,
                          struct udphdr *udp,
                          int index,
                          uint16_t dst_port,
                          uint8_t hop_limit) {
    if (!udp) {
        return -1;
    }

    if (probe_init_eth_ipv6(eth, ip6, IPPROTO_UDP,
                            (uint16_t)PROBE_L4_BYTES,
                            hop_limit, index) != 0) {
        return -1;
    }

    memset(udp, 0, PROBE_L4_BYTES);

    udp->source = htons((uint16_t)(40000 + (index % 20000)));
    udp->dest = htons(dst_port);
    udp->len = htons((uint16_t)PROBE_L4_BYTES);
    probe_store_l4_token(udp, probe_index_token((uint64_t)index));
    udp->check = 0;
    udp->check = probe_ipv6_l4_checksum(&ip6->ip6_src,
                                        &ip6->ip6_dst,
                                        IPPROTO_UDP,
                                        udp,
                                        PROBE_L4_BYTES);
    return 0;
}

int probe_read_ipv6_packet(const uint8_t *buffer,
                           ssize_t len,
                           struct ip6_hdr *ip6,
                           const uint8_t **payload,
                           size_t *payload_len) {
    if (!buffer || !ip6 || !payload || !payload_len) {
        return 0;
    }

    if (len < (ssize_t)(sizeof(struct ethhdr) + sizeof(struct ip6_hdr))) {
        return 0;
    }

    struct ethhdr eth;
    memcpy(&eth, buffer, sizeof(eth));
    if (ntohs(eth.h_proto) != ETH_P_IPV6) {
        return 0;
    }

    const uint8_t *ip6_start = buffer + sizeof(struct ethhdr);
    memcpy(ip6, ip6_start, sizeof(*ip6));

    size_t available_payload = (size_t)len - sizeof(struct ethhdr) - sizeof(struct ip6_hdr);
    size_t declared_payload = ntohs(ip6->ip6_plen);
    if (declared_payload > 0 && declared_payload < available_payload) {
        available_payload = declared_payload;
    }

    *payload = ip6_start + sizeof(struct ip6_hdr);
    *payload_len = available_payload;
    return 1;
}

int probe_read_embedded_ipv6(const uint8_t *buffer,
                             size_t len,
                             struct ip6_hdr *ip6,
                             const uint8_t **payload,
                             size_t *payload_len) {
    if (!buffer || !ip6 || !payload || !payload_len) {
        return 0;
    }

    if (len < sizeof(struct ip6_hdr)) {
        return 0;
    }

    memcpy(ip6, buffer, sizeof(*ip6));

    size_t available_payload = len - sizeof(struct ip6_hdr);
    size_t declared_payload = ntohs(ip6->ip6_plen);
    if (declared_payload > 0 && declared_payload < available_payload) {
        available_payload = declared_payload;
    }

    *payload = buffer + sizeof(struct ip6_hdr);
    *payload_len = available_payload;
    return 1;
}
