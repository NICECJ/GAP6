#include "tcp_syn_multiport.h"

#include "../../include/config.h"
#include "../../include/hash.h"
#include "../../include/protocol.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <linux/if_ether.h>
#include <unistd.h>

static const uint16_t common_ports[] = {
    80, 443, 22, 53, 25, 110, 143, 587, 993, 995, 8080, 8443
};

static const size_t common_ports_count =
    sizeof(common_ports) / sizeof(common_ports[0]);

static uint32_t tcp_syn_multiport_rand32(void) {
    return ((uint32_t)rand() << 16) | (uint32_t)rand();
}

static uint16_t checksum16(const uint8_t *buf, size_t len) {
    uint32_t sum = 0;

    for (size_t i = 0; i + 1 < len; i += 2) {
        sum += ((uint16_t)buf[i] << 8) | buf[i + 1];
        while (sum > 0xFFFF) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
    }

    if (len & 1) {
        sum += ((uint16_t)buf[len - 1] << 8);
        while (sum > 0xFFFF) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
    }

    return (uint16_t)(~sum);
}

static int parse_mac(const char *text, uint8_t mac[6]) {
    if (!text || !mac) {
        return -1;
    }

    int n = sscanf(text, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                   &mac[0], &mac[1], &mac[2],
                   &mac[3], &mac[4], &mac[5]);

    return (n == 6) ? 0 : -1;
}

static void tcp_syn_multiport_build_target(struct in6_addr *dst, int index) {
    if (exact_addr_flags[index]) {
        *dst = exact_addr_table[index];
        return;
    }

    PrefixInfo *pcs = &prefix_table[index];
    unsigned char dst_addr[16] = {0};

    uint64_t random_val = tcp_syn_multiport_rand32();
    uint64_t dst_prefix =
        pcs->prefix_stub + ((pcs->mask_suffix) & random_val);

    dst_prefix = htonll(dst_prefix);
    memcpy(dst_addr, &dst_prefix, 8);

    uint32_t random_suffix = tcp_syn_multiport_rand32();
    memcpy(dst_addr + 8, &random_suffix, 4);

    uint32_t embedded_checksum =
        murmur3(dst_addr, 12, 0x11112222);
    embedded_checksum = htonl(embedded_checksum);
    memcpy(dst_addr + 12, &embedded_checksum, 4);

    memcpy(dst, dst_addr, 16);
}

static uint16_t tcp_syn_multiport_pick_port(int index) {
    /*
     * 多端口轮换。
     * 如果同一个 index 被多次调度，sent_packets 会变化，
     * 这样同一个目标/前缀不会永远只探测 80。
     */
    uint64_t sent = prefix_table[index].sent_packets;
    size_t port_idx = (index + sent) % common_ports_count;
    return common_ports[port_idx];
}

static void tcp_syn_multiport_set_checksum(struct ip6_hdr *ip6,
                                           struct tcphdr *tcp) {
    struct {
        struct in6_addr src;
        struct in6_addr dst;
        uint32_t len;
        uint8_t zero[3];
        uint8_t next_header;
    } pseudo_hdr;

    memset(&pseudo_hdr, 0, sizeof(pseudo_hdr));
    pseudo_hdr.src = ip6->ip6_src;
    pseudo_hdr.dst = ip6->ip6_dst;
    pseudo_hdr.len = htonl(sizeof(struct tcphdr));
    pseudo_hdr.next_header = IPPROTO_TCP;

    uint8_t checksum_buffer[sizeof(pseudo_hdr) + sizeof(struct tcphdr)];
    memcpy(checksum_buffer, &pseudo_hdr, sizeof(pseudo_hdr));
    memcpy(checksum_buffer + sizeof(pseudo_hdr), tcp, sizeof(struct tcphdr));

    tcp->check = htons(checksum16(checksum_buffer, sizeof(checksum_buffer)));
}

int tcp_syn_multiport_build_probe(struct ethhdr *eth,
                                  struct ip6_hdr *ip6,
                                  void *l4,
                                  int index) {
    struct tcphdr *tcp = (struct tcphdr *)l4;

    if (!eth || !ip6 || !tcp) {
        return -1;
    }

    if (index < 0 || (uint64_t)index >= prefix_table_size) {
        return -1;
    }

    memset(eth, 0, sizeof(struct ethhdr));
    memset(ip6, 0, sizeof(struct ip6_hdr));
    memset(tcp, 0, sizeof(struct tcphdr));

    if (parse_mac(gateway_mac, eth->h_dest) != 0) {
        fprintf(stderr, "[tcp_syn_multiport] invalid gateway_mac: %s\n", gateway_mac);
        return -1;
    }

    if (parse_mac(source_mac, eth->h_source) != 0) {
        fprintf(stderr, "[tcp_syn_multiport] invalid source_mac: %s\n", source_mac);
        return -1;
    }

    eth->h_proto = htons(ETH_P_IPV6);

    ip6->ip6_flow = htonl(0x60000000);
    ip6->ip6_plen = htons(sizeof(struct tcphdr));
    ip6->ip6_nxt  = IPPROTO_TCP;
    ip6->ip6_hlim = 64;

    if (inet_pton(AF_INET6, source_ip, &ip6->ip6_src) != 1) {
        fprintf(stderr, "[tcp_syn_multiport] invalid source_ip: %s\n", source_ip);
        return -1;
    }

    tcp_syn_multiport_build_target(&ip6->ip6_dst, index);

    uint16_t sport = 40000 + (index % 20000);
    uint16_t dport = tcp_syn_multiport_pick_port(index);

    tcp->source = htons(sport);
    tcp->dest   = htons(dport);
    tcp->seq    = htonl(0xA0000000u | (uint32_t)(index & 0x0FFFFFFFu));
    tcp->ack_seq = 0;

    tcp->doff = 5;
    tcp->syn = 1;
    tcp->ack = 0;
    tcp->rst = 0;
    tcp->fin = 0;
    tcp->psh = 0;
    tcp->urg = 0;

    tcp->window = htons(64240);
    tcp->check = 0;
    tcp->urg_ptr = 0;

    tcp_syn_multiport_set_checksum(ip6, tcp);

    prefix_table[index].sent_packets++;

    return 0;
}

int tcp_syn_multiport_parse_response(uint8_t *buffer,
                                     ssize_t received_bytes,
                                     struct in6_addr *target_ip,
                                     uint64_t *prefix_index) {
    if (!buffer || !target_ip || !prefix_index) {
        return 0;
    }

    if ((size_t)received_bytes <
        sizeof(struct ethhdr) + sizeof(struct ip6_hdr) + sizeof(struct tcphdr)) {
        return 0;
    }

    struct ethhdr *eth = (struct ethhdr *)buffer;
    if (ntohs(eth->h_proto) != ETH_P_IPV6) {
        return 0;
    }

    struct ip6_hdr *ip6 =
        (struct ip6_hdr *)(buffer + sizeof(struct ethhdr));

    if (ip6->ip6_nxt != IPPROTO_TCP) {
        return 0;
    }

    struct tcphdr *tcp =
        (struct tcphdr *)(buffer + sizeof(struct ethhdr) + sizeof(struct ip6_hdr));

    uint16_t dst_port = ntohs(tcp->dest);

    /*
     * 我们发出去的源端口范围是 40000~59999。
     * 返回包的 destination port 应该等于当时的 source port。
     */
    if (dst_port < 40000 || dst_port >= 60000) {
        return 0;
    }

    /*
     * 强命中：
     * 1. SYN-ACK：端口开放
     * 2. RST：端口关闭但 TCP 栈有响应，说明地址大概率活跃
     */
    int is_syn_ack = (tcp->syn && tcp->ack);
    int is_rst = tcp->rst;

    if (!is_syn_ack && !is_rst) {
        return 0;
    }

    uint64_t idx = (uint64_t)(dst_port - 40000);

    if (prefix_table_size == 0) {
        return 0;
    }

    /*
     * 如果 prefix_table_size > 20000，这个映射只能近似恢复。
     * 但 target_ip 本身来自 ip6_src，结果文件记录的是目标地址，
     * 主要影响的是每个 prefix 的 received_packets 统计。
     */
    idx = idx % prefix_table_size;

    *target_ip = ip6->ip6_src;
    *prefix_index = idx;

    /*
     * 去重：避免同一地址因为多个端口、多次响应被反复写入。
     * 如果你的主程序已经统一去重，这段也不会有坏处。
     */
    uint32_t bloom_index_1 =
        murmur3(target_ip->s6_addr, 16, 0x12345678);
    uint32_t bloom_index_2 =
        murmur3(target_ip->s6_addr, 16, 0x87654321);

    if ((bloom_filter[bloom_index_1 / 8] & (1 << (bloom_index_1 % 8))) &&
        (bloom_filter[bloom_index_2 / 8] & (1 << (bloom_index_2 % 8)))) {
        return 0;
    }

    bloom_filter[bloom_index_1 / 8] |= (1 << (bloom_index_1 % 8));
    bloom_filter[bloom_index_2 / 8] |= (1 << (bloom_index_2 % 8));

    return 1;
}

protocol_t tcp_syn_multiport_protocol = {
    .name = "tcp_syn_multiport",
    .build_probe = tcp_syn_multiport_build_probe,
    .parse_response = tcp_syn_multiport_parse_response
};

__attribute__((constructor))
static void register_tcp_syn_multiport(void) {
    register_protocol(&tcp_syn_multiport_protocol);
}