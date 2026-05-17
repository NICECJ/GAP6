#include "construct.h"
#include "sample.h"
#include "config.h"

uint32_t generate_32bit_random() {
    uint32_t random_number = ((uint32_t)rand() << 16) | (uint32_t)rand();
    return random_number;
}

void constructICMPv6Packet(struct ethhdr *eth_hdr, struct ip6_hdr *ip6_hdr, struct icmp6_hdr *icmp6_hdr, int index) {
    PrefixInfo* tPCS = &prefix_table[index];
    tPCS->sent_packets++;

    // Ethernet header
    if (sscanf(gateway_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", 
        &eth_hdr->h_dest[0], &eth_hdr->h_dest[1], 
        &eth_hdr->h_dest[2], &eth_hdr->h_dest[3], 
        &eth_hdr->h_dest[4], &eth_hdr->h_dest[5]) != 6) {
        perror("Invalid gateway MAC address format");
        exit(1);
    }

    if (sscanf(source_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", 
        &eth_hdr->h_source[0], &eth_hdr->h_source[1], 
        &eth_hdr->h_source[2], &eth_hdr->h_source[3], 
        &eth_hdr->h_source[4], &eth_hdr->h_source[5]) != 6) {
        perror("Invalid source MAC address format");
        exit(1);
    }

    eth_hdr->h_proto = htons(ETH_P_IPV6);

    // IPv6 header
    ip6_hdr->ip6_flow = htonl(0x60000000); // Version, traffic class, flow label
    ip6_hdr->ip6_plen = htons(sizeof(struct icmp6_hdr)); // Payload length
    ip6_hdr->ip6_nxt = IPPROTO_ICMPV6; // Next header (ICMPv6)

    // ip6_hdr->ip6_hlim = rand() % 256;
    ip6_hdr->ip6_hlim = 64;
    // if (is_first_round || (tPCS->received_packets) <= 1) ip6_hdr->ip6_hlim = rand() % 256;
    // else ip6_hdr->ip6_hlim = select_next_hoplimit(index);

    if (inet_pton(AF_INET6, source_ip, &ip6_hdr->ip6_src) != 1) {
        perror("inet_pton failed to convert source IP");
        exit(1);
    }

    if (exact_addr_flags[index]) {
    ip6_hdr->ip6_dst = exact_addr_table[index];
    } else {
        unsigned char dst_addr[16] = {0};

        uint64_t random_val = generate_32bit_random();
        uint64_t dst_prefix = tPCS->prefix_stub +
                            ((tPCS->mask_suffix) & random_val);
        dst_prefix = htonll(dst_prefix);
        memcpy(dst_addr, &dst_prefix, sizeof(dst_prefix));

        uint32_t random_suffix = generate_32bit_random();
        memcpy(dst_addr + 8, &random_suffix, sizeof(random_suffix));

        uint32_t checksum = murmur3(dst_addr, 12, 0x11112222);
        checksum = htonl(checksum);
        memcpy(dst_addr + 12, &checksum, sizeof(checksum));

        memcpy(&ip6_hdr->ip6_dst, dst_addr, sizeof(dst_addr));
    }


    // ICMPv6 header
    icmp6_hdr->icmp6_type = ICMP6_ECHO_REQUEST; // Echo request
    icmp6_hdr->icmp6_code = 0;
    icmp6_hdr->icmp6_cksum = 0; // Checksum will be calculated later
    
    
    icmp6_hdr->icmp6_id = htons((uint16_t)(index >> 8)); // Identifier
    icmp6_hdr->icmp6_seq = htons((uint16_t)(index << 8) + (uint16_t)(ip6_hdr->ip6_hlim)); // Sequence number
    

    // Calculate ICMPv6 checksum
    struct {
        struct in6_addr src;
        struct in6_addr dst;
        uint32_t len;
        uint8_t zero[3];
        uint8_t next_header;
    } pseudo_hdr;

    memset(&pseudo_hdr, 0, sizeof(pseudo_hdr));
    pseudo_hdr.src = ip6_hdr->ip6_src;
    pseudo_hdr.dst = ip6_hdr->ip6_dst;
    pseudo_hdr.len = htonl(sizeof(struct icmp6_hdr));
    pseudo_hdr.next_header = IPPROTO_ICMPV6;

    uint8_t checksum_buffer[sizeof(pseudo_hdr) + sizeof(struct icmp6_hdr)];
    memcpy(checksum_buffer, &pseudo_hdr, sizeof(pseudo_hdr));
    memcpy(checksum_buffer + sizeof(pseudo_hdr), icmp6_hdr, sizeof(struct icmp6_hdr));

    uint32_t sum = 0;
    for (size_t i = 0; i < sizeof(checksum_buffer); i += 2) {
        sum += (checksum_buffer[i] << 8) | checksum_buffer[i + 1];
        if (sum > 0xFFFF) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
    }
    icmp6_hdr->icmp6_cksum = htons(~sum);
}


void constructTCPv6Packet(
    struct ethhdr *eth_hdr,
    struct ip6_hdr *ip6_hdr,
    struct tcphdr *tcp_hdr,
    int index
) {
    PrefixInfo* tPCS = &prefix_table[index];
    tPCS->sent_packets++;

    /* ========== Ethernet header ========== */
    if (sscanf(gateway_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
        &eth_hdr->h_dest[0], &eth_hdr->h_dest[1],
        &eth_hdr->h_dest[2], &eth_hdr->h_dest[3],
        &eth_hdr->h_dest[4], &eth_hdr->h_dest[5]) != 6) {
        perror("Invalid gateway MAC address format");
        exit(1);
    }

    if (sscanf(source_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
        &eth_hdr->h_source[0], &eth_hdr->h_source[1],
        &eth_hdr->h_source[2], &eth_hdr->h_source[3],
        &eth_hdr->h_source[4], &eth_hdr->h_source[5]) != 6) {
        perror("Invalid source MAC address format");
        exit(1);
    }

    eth_hdr->h_proto = htons(ETH_P_IPV6);

    /* ========== IPv6 header ========== */
    ip6_hdr->ip6_flow = htonl(0x60000000);     // Version 6
    ip6_hdr->ip6_plen = htons(sizeof(struct tcphdr));
    ip6_hdr->ip6_nxt  = IPPROTO_TCP;


    ip6_hdr->ip6_hlim = rand() % 256;
    // if (is_first_round || (tPCS->received_packets) <= 1)
    //     ip6_hdr->ip6_hlim = rand() % 256;
    // else
    //     ip6_hdr->ip6_hlim = select_next_hoplimit(index);

    if (inet_pton(AF_INET6, source_ip, &ip6_hdr->ip6_src) != 1) {
        perror("inet_pton failed (source_ip)");
        exit(1);
    }

    /* ========== IPv6 destination address generation ========== */
    if (exact_addr_flags[index]) {
    ip6_hdr->ip6_dst = exact_addr_table[index];
    } else {
        unsigned char dst_addr[16] = {0};

        uint64_t random_val = generate_32bit_random();
        uint64_t dst_prefix = tPCS->prefix_stub + ((tPCS->mask_suffix) & random_val);
        dst_prefix = htonll(dst_prefix);
        memcpy(dst_addr, &dst_prefix, sizeof(dst_prefix));

        uint32_t random_suffix = generate_32bit_random();
        memcpy(dst_addr + 8, &random_suffix, sizeof(random_suffix));

        uint32_t checksum = murmur3(dst_addr, 12, 0x11112222);
        checksum = htonl(checksum);
        memcpy(dst_addr + 12, &checksum, sizeof(checksum));

        memcpy(&ip6_hdr->ip6_dst, dst_addr, sizeof(dst_addr));
    }

    /* ========== TCP header (SYN, no ACK) ========== */
    memset(tcp_hdr, 0, sizeof(struct tcphdr));

    tcp_hdr->source  = htons(40000 + (rand() % 20000)); // ephemeral src port
    tcp_hdr->dest    = htons(12345);                    // unused dst port
    tcp_hdr->seq = htonl(
        ((uint32_t)index << 8) | (rand() & 0xFF)
    );
    tcp_hdr->ack_seq = 0;

    // Data offset = 5 (20 bytes), flags = SYN only
    tcp_hdr->doff = 5;   // 5 * 4 = 20 bytes TCP header
    tcp_hdr->syn  = 0;
    tcp_hdr->ack  = 1;
    tcp_hdr->rst  = 0;
    tcp_hdr->fin  = 0;
    tcp_hdr->psh  = 0;
    tcp_hdr->urg  = 0;

    tcp_hdr->window  = htons(65535);
    tcp_hdr->urg_ptr = 0;
    tcp_hdr->check   = 0;

    /* ========== TCP checksum (IPv6 pseudo-header) ========== */
    struct {
        struct in6_addr src;
        struct in6_addr dst;
        uint32_t len;
        uint8_t zero[3];
        uint8_t next_header;
    } pseudo_hdr;

    memset(&pseudo_hdr, 0, sizeof(pseudo_hdr));
    pseudo_hdr.src = ip6_hdr->ip6_src;
    pseudo_hdr.dst = ip6_hdr->ip6_dst;
    pseudo_hdr.len = htonl(sizeof(struct tcphdr));
    pseudo_hdr.next_header = IPPROTO_TCP;

    uint8_t checksum_buffer[sizeof(pseudo_hdr) + sizeof(struct tcphdr)];
    memcpy(checksum_buffer, &pseudo_hdr, sizeof(pseudo_hdr));
    memcpy(checksum_buffer + sizeof(pseudo_hdr),
           tcp_hdr, sizeof(struct tcphdr));

    uint32_t sum = 0;
    for (size_t i = 0; i < sizeof(checksum_buffer); i += 2) {
        sum += (checksum_buffer[i] << 8) | checksum_buffer[i + 1];
        if (sum > 0xFFFF)
            sum = (sum & 0xFFFF) + (sum >> 16);
    }

    tcp_hdr->check = htons(~sum);
}