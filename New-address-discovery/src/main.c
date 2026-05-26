#include "config.h"
#include "construct.h"
#include "sample.h"
#include "parser.h"
#include "protocol.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <math.h>
#include <time.h>
#include <linux/filter.h>
#include <linux/if_packet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <net/if.h>
#include <errno.h>
#include <inttypes.h>

/*
 * 用于控制接收线程退出。
 * 原来的 Recv() 是 while(1)，主线程 close(fd) 后接收线程还会 recvfrom(fd)，
 * 容易出现 recvfrom: Bad file descriptor 无限刷屏。
 */
static volatile int receiver_running = 1;


typedef struct {
    struct in6_addr addr;
    uint8_t used;
} UniqueAddrEntry;

static UniqueAddrEntry *unique_addr_table = NULL;
static size_t unique_addr_capacity = 0;
static size_t unique_addr_count = 0;

static uint64_t hash_in6_addr(const struct in6_addr *addr) {
    const uint8_t *bytes = addr->s6_addr;
    uint64_t hash = 1469598103934665603ULL;

    for (size_t i = 0; i < 16; i++) {
        hash ^= bytes[i];
        hash *= 1099511628211ULL;
    }

    return hash;
}

static int unique_addr_insert_no_resize(UniqueAddrEntry *table,
                                        size_t capacity,
                                        const struct in6_addr *addr) {
    size_t mask = capacity - 1;
    size_t pos = hash_in6_addr(addr) & mask;

    while (table[pos].used) {
        if (memcmp(&table[pos].addr, addr, sizeof(struct in6_addr)) == 0) {
            return 0;
        }
        pos = (pos + 1) & mask;
    }

    table[pos].addr = *addr;
    table[pos].used = 1;
    return 1;
}

static int unique_addr_resize(size_t new_capacity) {
    UniqueAddrEntry *new_table = calloc(new_capacity, sizeof(UniqueAddrEntry));
    if (!new_table) {
        return -1;
    }

    for (size_t i = 0; i < unique_addr_capacity; i++) {
        if (unique_addr_table[i].used) {
            unique_addr_insert_no_resize(new_table, new_capacity,
                                         &unique_addr_table[i].addr);
        }
    }

    free(unique_addr_table);
    unique_addr_table = new_table;
    unique_addr_capacity = new_capacity;
    return 0;
}

static int unique_addr_mark_seen(const struct in6_addr *addr) {
    if (unique_addr_capacity == 0) {
        if (unique_addr_resize(1024) != 0) {
            return -1;
        }
    }

    if ((unique_addr_count + 1) * 2 >= unique_addr_capacity) {
        if (unique_addr_resize(unique_addr_capacity * 2) != 0) {
            return -1;
        }
    }

    int inserted = unique_addr_insert_no_resize(unique_addr_table,
                                                unique_addr_capacity,
                                                addr);
    if (inserted > 0) {
        unique_addr_count++;
    }

    return inserted;
}

/*
 * 判断当前输入是否全是 exact address。
 *
 * 前提：
 * parser.c 在解析地址输入时设置 exact_addr_flags[index] = 1；
 * 解析前缀输入时设置 exact_addr_flags[index] = 0。
 *
 * 如果输入全是 6Genos 生成的地址列表，则进入 exact-address mode：
 * 每个地址只发一次。
 *
 * 如果输入包含前缀，则进入 prefix mode：
 * 保留原来的预算式多轮探测逻辑。
 */
static int detect_exact_address_mode(void) {
    if (prefix_table_size == 0) {
        return 0;
    }

    for (uint64_t i = 0; i < prefix_table_size; i++) {
        if (!exact_addr_flags[i]) {
            return 0;
        }
    }

    return 1;
}

/*
 * 发送 step 个探测包。
 *
 * 这里保留你原来的协议抽象：
 * current_protocol->build_probe(&eth, &ip6, &tcp, index)
 *
 * 注意：
 * 当前 main.c 仍然按 struct tcphdr 大小拷贝 L4。
 * 因此如果某些插件是 ICMP/UDP，但你的 main.c 没改 packet length，
 * 插件需要兼容这个框架，或者后续再把 build_probe 改成返回 packet_len。
 */
void Scan(uint64_t step) {
    uint8_t buffer[1500];

    struct ethhdr eth;
    struct ip6_hdr ip6;
    struct tcphdr tcp;

    int index = prefix_table_size - 1;

    for (uint64_t i = 0; i < step; ++i) {

        /* ===== prefix/address selection logic ===== */
        if (nonzero_budget_count) {
            uint64_t nonzero_index = rand() % nonzero_budget_count;
            index = nonzero_budget_indices[nonzero_index];

            if (prefix_allocated_budget[index] > 0) {
                prefix_allocated_budget[index]--;
            }

            if (prefix_allocated_budget[index] == 0) {
                nonzero_budget_indices[nonzero_index] =
                    nonzero_budget_indices[--nonzero_budget_count];
            }
        } else {
            index = rand() % prefix_table_size;
        }

        /* ===== protocol-specific probe construction ===== */
        if (current_protocol->build_probe(&eth, &ip6, &tcp, index) != 0) {
            continue;
        }

        /* ===== assemble packet buffer ===== */
        size_t offset = 0;

        memcpy(buffer + offset, &eth, sizeof(struct ethhdr));
        offset += sizeof(struct ethhdr);

        memcpy(buffer + offset, &ip6, sizeof(struct ip6_hdr));
        offset += sizeof(struct ip6_hdr);

        memcpy(buffer + offset, &tcp, sizeof(struct tcphdr));
        offset += sizeof(struct tcphdr);

        /* ===== send packet ===== */
        ssize_t sent = send(fd, buffer, offset, 0);
        if (sent < 0) {
            perror("send");
            continue;
        }

        /* ===== update statistics ===== */
        prefix_table[index].sent_packets++;
        prefix_table[index].sent_packets_this_round++;
    }
}

void* Recv(void* arg) {
    (void)arg;

    uint8_t buffer[1500];
    ssize_t received_bytes;
    struct sockaddr_storage src_addr;
    socklen_t addr_len = sizeof(src_addr);

    FILE* output_file = fopen(output_filename, "w");
    if (output_file == NULL) {
        perror("Failed to create file");
        exit(1);
    }

    while (receiver_running) {
        struct in6_addr target_ip;
        uint64_t prefix_index = 0;
        char target_ip_str[INET6_ADDRSTRLEN];

        received_bytes = recvfrom(fd, buffer, sizeof(buffer), 0,
                                  (struct sockaddr*)&src_addr, &addr_len);

        if (received_bytes < 0) {
            /*
             * socket 设置了 SO_RCVTIMEO，所以超时会返回 EAGAIN/EWOULDBLOCK。
             * 这是正常现象，用于检查 receiver_running 是否已经变为 0。
             */
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                continue;
            }

            /*
             * 如果 fd 已关闭，直接退出线程，避免 Bad file descriptor 无限刷屏。
             */
            if (errno == EBADF) {
                break;
            }

            perror("recvfrom");
            continue;
        }

        /* ===== protocol-specific response parsing ===== */
        if (!current_protocol->parse_response(buffer, received_bytes, &target_ip, &prefix_index)) {
            continue;
        }

        if (prefix_index >= prefix_table_size) {
            continue;
        }

        int unique_status = unique_addr_mark_seen(&target_ip);
        if (unique_status < 0) {
            fprintf(stderr, "Failed to allocate unique IPv6 address table\n");
            receiver_running = 0;
            break;
        }
        if (unique_status == 0) {
            continue;
        }

        inet_ntop(AF_INET6, &target_ip, target_ip_str, sizeof(target_ip_str));

        /* ===== update statistics ===== */
        __sync_add_and_fetch(&prefix_table[prefix_index].received_packets, 1);
        __sync_add_and_fetch(&prefix_table[prefix_index].received_packets_this_round, 1);
        __sync_add_and_fetch(&total_hits, 1);

        /* ===== output ===== */
        fprintf(output_file, "%s\n", target_ip_str);
        fflush(output_file);
    }

    fclose(output_file);
    return NULL;
}

int main(int argc, char *argv[]) {

    /* program name + 7 args = argc 8 */
    if (argc != 8) {
        printf("Usage: %s <protocol> <interface_name> <source_mac> <source_ip> <gateway_mac> <input_filename> <output_filename>\n", argv[0]);
        return 1;
    }

    printf("Protocol      : %s\n", argv[1]);

    /* ===== Load protocol module ===== */
    load_protocol(argv[1]);

    struct timespec start_time, end_time;
    double elapsed_sec;
    int hours, minutes;
    double seconds;

    clock_gettime(CLOCK_MONOTONIC, &start_time);

    /* Assign values from command line arguments */
    interface_name = argv[2];
    source_mac = argv[3];
    source_ip = argv[4];
    gateway_mac = argv[5];
    input_filename = argv[6];
    output_filename = argv[7];

    struct ifreq ifr;
    struct sockaddr_ll sll;

    /* ===== Create raw socket ===== */
    fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IPV6));
    if (fd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    /*
     * 设置接收超时，避免接收线程永久阻塞。
     * 这样主线程设置 receiver_running = 0 后，接收线程最多 1 秒内退出。
     */
    struct timeval recv_timeout;
    recv_timeout.tv_sec = 1;
    recv_timeout.tv_usec = 0;

    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO,
                   &recv_timeout, sizeof(recv_timeout)) < 0) {
        perror("setsockopt(SO_RCVTIMEO)");
        close(fd);
        exit(EXIT_FAILURE);
    }

    /* ===== Configure interface ===== */
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface_name, IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl(SIOCGIFINDEX)");
        close(fd);
        exit(EXIT_FAILURE);
    }

    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_IPV6);
    sll.sll_ifindex = ifr.ifr_ifindex;

    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("bind");
        close(fd);
        exit(EXIT_FAILURE);
    }

    /* ===== Allocate bloom filter ===== */
    bloom_filter = calloc(1, bloom_filter_SIZE);
    if (!bloom_filter) {
        perror("calloc");
        close(fd);
        exit(EXIT_FAILURE);
    }

    /* ===== Parse input file ===== */
    processAndParseCIDR();

    printf("prefix_table_size: %ld\n", prefix_table_size);

    if (prefix_table_size == 0) {
        fprintf(stderr, "No valid IPv6 targets loaded from input file: %s\n", input_filename);
        free(bloom_filter);
        close(fd);
        exit(EXIT_FAILURE);
    }

    /*
     * 输入模式判断：
     * - exact_address_mode = 1：输入是具体 IPv6 地址列表，例如 6Genos/res0.txt
     * - exact_address_mode = 0：输入是 BGP 前缀列表，例如 2001:1201:10::/48
     */
    int exact_address_mode = detect_exact_address_mode();

    if (exact_address_mode) {
        printf("[mode] exact-address input detected: each address will be probed once.\n");
    } else {
        printf("[mode] prefix input detected: use original budget-based probing.\n");
    }

    /* ===== Start receiving thread ===== */
    pthread_t recv_thread;
    receiver_running = 1;

    if (pthread_create(&recv_thread, NULL, Recv, NULL) != 0) {
        perror("pthread_create");
        free(bloom_filter);
        close(fd);
        exit(EXIT_FAILURE);
    }

    /*
     * 原前缀模式：
     *   budget_limit = 1e8
     *   first round step_size = 1e7
     *   later round step_size = 1e6
     *
     * 地址模式：
     *   budget_limit = prefix_table_size
     *   每个地址只分配 1 个 probe
     *   扫完一轮 break
     */
    uint64_t step_size = exact_address_mode ? prefix_table_size : (uint64_t)1e7;
    uint64_t total_sent = 0;
    uint64_t budget_limit = exact_address_mode ? prefix_table_size : (uint64_t)1e8;
    uint64_t next_threshold = exact_address_mode ? prefix_table_size : (uint64_t)1e7;

    while (total_sent < budget_limit) {

        if (!exact_address_mode && total_sent >= next_threshold) {

            clock_gettime(CLOCK_MONOTONIC, &end_time);

            elapsed_sec = (end_time.tv_sec - start_time.tv_sec) +
                          (end_time.tv_nsec - start_time.tv_nsec) / 1.0e9;

            hours = (int)(elapsed_sec / 3600);
            minutes = (int)((elapsed_sec - hours * 3600) / 60);
            seconds = elapsed_sec - hours * 3600 - minutes * 60;

            printf("Send %" PRIu64 "; Time: %dh %dm %.2fs\n",
                   next_threshold, hours, minutes, seconds);

            next_threshold += (uint64_t)1e7;
        }

        if (exact_address_mode) {
            step_size = prefix_table_size;
        } else {
            step_size = is_first_round ? (uint64_t)1e7 : (uint64_t)1e6;
        }

        uint64_t allocated_packets = 0;
        double total_weight = 0.0;
        nonzero_budget_count = 0;

        /*
         * Compute weights.
         *
         * 地址模式下其实不需要计算权重；
         * 但为了尽量少改逻辑，这里只在 prefix mode 下计算。
         */
        if (!exact_address_mode) {
            for (int index = 0; index < prefix_table_size; index++) {

                double current_ratio =
                    prefix_table[index].received_packets_this_round /
                    log(prefix_table[index].sent_packets_this_round + 10);

                double alpha0 = 0.1, eta = 1.0, alpha_min = 0.01, alpha_max = 1.0;
                double diff = fabs(current_ratio - prefix_table[index].ema_success_ratio);
                alpha = alpha0 + eta * diff;

                if (alpha < alpha_min) alpha = alpha_min;
                if (alpha > alpha_max) alpha = alpha_max;

                if (is_first_round)
                    prefix_table[index].ema_success_ratio = current_ratio;
                else
                    prefix_table[index].ema_success_ratio =
                        alpha * current_ratio +
                        (1 - alpha) * prefix_table[index].ema_success_ratio;

                double exploitation = prefix_table[index].ema_success_ratio;
                double exploration = 0.0;

                prefix_table[index].weight = exploitation + exploration;
                total_weight += prefix_table[index].weight;

                prefix_table[index].sent_packets_this_round = 0;
                prefix_table[index].received_packets_this_round = 0;
            }
        }

        /*
         * Allocate probing budget.
         *
         * exact-address mode:
         *   prefix_allocated_budget[index] = 1
         *
         * prefix mode:
         *   保留原来的预算分配逻辑。
         */
        for (int index = 0; index < prefix_table_size; index++) {

            if (exact_address_mode) {
                prefix_allocated_budget[index] = 1;
            } else {
                if (!is_first_round) {
                    if (total_weight > 0.0) {
                        prefix_allocated_budget[index] =
                            (uint64_t)((double)(step_size * prefix_table[index].weight) / total_weight);
                    } else {
                        /*
                         * 防止 total_weight = 0 导致除零。
                         * 如果所有节点都没有命中，就退化为均匀分配。
                         */
                        prefix_allocated_budget[index] =
                            (uint64_t)(step_size * 1.0 / prefix_table_size);
                    }
                } else {
                    prefix_allocated_budget[index] =
                        (uint64_t)(step_size * 1.0 / prefix_table_size);
                }
            }

            if (prefix_allocated_budget[index]) {
                nonzero_budget_indices[nonzero_budget_count++] = index;
            }

            allocated_packets += prefix_allocated_budget[index];
        }

        uint64_t remaining = budget_limit - total_sent;
        uint64_t to_scan = allocated_packets;

        if (to_scan > remaining) {
            to_scan = remaining;
        }

        if (to_scan == 0) {
            printf("[WARN] no packets allocated in this round, stop probing.\n");
            break;
        }

        Scan(to_scan);
        total_sent += to_scan;

        printf("%" PRIu64 " packets sent, %" PRIu64 " responses received, success rate: %lf\n",
               total_sent,
               total_hits,
               total_sent > 0 ? 1.0 * total_hits / total_sent : 0.0);

        if (exact_address_mode) {
            printf("[mode] exact-address probing finished after one pass.\n");
            break;
        }

        is_first_round = 0;
    }

    /*
     * 给响应包一点返回时间。
     * 地址模式下可以短一点，前缀模式保留原来的 10 秒。
     */
    if (exact_address_mode) {
        sleep(3);
    } else {
        sleep(10);
    }

    /* ===== Stop receiving thread cleanly ===== */
    receiver_running = 0;
    pthread_join(recv_thread, NULL);

    printf("[probe_result] output_file: %s\n", output_filename);
    printf("[probe_result] unique_addresses: %" PRIu64 "\n", total_hits);

    close(fd);
    free(bloom_filter);
    free(unique_addr_table);
    unique_addr_table = NULL;
    unique_addr_capacity = 0;
    unique_addr_count = 0;

    clock_gettime(CLOCK_MONOTONIC, &end_time);

    elapsed_sec = (end_time.tv_sec - start_time.tv_sec) +
                  (end_time.tv_nsec - start_time.tv_nsec) / 1.0e9;

    hours = (int)(elapsed_sec / 3600);
    minutes = (int)((elapsed_sec - hours * 3600) / 60);
    seconds = elapsed_sec - hours * 3600 - minutes * 60;

    printf("Loop execution time: %dh %dm %.2fs\n", hours, minutes, seconds);

    return 0;
}