#include <stdio.h>
#include <stdlib.h>
#include "protocol.h"

protocol_t *current_protocol = NULL;

void load_protocol(const char *name)
{
    current_protocol = find_protocol(name);

    if (!current_protocol) {
        printf("Unknown protocol: %s\n", name);
        exit(1);
    }

    printf("Loaded protocol: %s\n", current_protocol->name);
}