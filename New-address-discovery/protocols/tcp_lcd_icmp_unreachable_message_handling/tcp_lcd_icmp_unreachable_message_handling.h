#ifndef TCP_LCD_ICMP_UNREACHABLE_MESSAGE_HANDLING_H
#define TCP_LCD_ICMP_UNREACHABLE_MESSAGE_HANDLING_H

#include <stdint.h>
#include <sys/types.h>
#include <netinet/if_ether.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>

int tcp_lcd_icmp_unreachable_message_handling_build_probe(struct ethhdr *eth,
                        struct ip6_hdr *ip6,
                        struct tcphdr *tcp,
                        int index);

int tcp_lcd_icmp_unreachable_message_handling_parse_response(const uint8_t *buffer,
                           ssize_t received_bytes,
                           struct in6_addr *target_ip,
                           uint64_t *prefix_index);

#endif