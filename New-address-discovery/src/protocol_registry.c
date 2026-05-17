#include <stdio.h>
#include <string.h>
#include "protocol.h"

#define MAX_PROTOCOLS 64

static protocol_t *protocol_list[MAX_PROTOCOLS];
static int protocol_count = 0;


/* register protocol automatically */
void register_protocol(protocol_t *p)
{
    if (protocol_count >= MAX_PROTOCOLS) {
        printf("Protocol registry full\n");
        return;
    }

    protocol_list[protocol_count++] = p;
}


/* find protocol by name */
protocol_t *find_protocol(const char *name)
{
    for (int i = 0; i < protocol_count; i++) {

        if (strcmp(protocol_list[i]->name, name) == 0)
            return protocol_list[i];
    }

    return NULL;
}