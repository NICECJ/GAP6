#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>
#include <sys/types.h>
#include <netinet/if_ether.h>
#include <netinet/ip6.h>
#include <netinet/in.h>

typedef struct protocol {

    const char *name;

    int (*build_probe)(
        struct ethhdr *eth,
        struct ip6_hdr *ip6,
        void *l4,
        int prefix_index
    );

    int (*parse_response)(
        uint8_t *buffer,
        ssize_t len,
        struct in6_addr *target_ip,
        uint64_t *prefix_index
    );

} protocol_t;


/* global current protocol */
extern protocol_t *current_protocol;


/* registry functions */
void register_protocol(protocol_t *p);
protocol_t *find_protocol(const char *name);
void load_protocol(const char *name);

#endif
