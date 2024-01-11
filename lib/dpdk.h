#include <rte_ring_core.h>
#include <getopt.h>
#include <inttypes.h>
#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_debug.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_interrupts.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_memcpy.h>
#include <rte_memory.h>
#include <rte_mempool.h>
#include <rte_per_lcore.h>
#include <rte_prefetch.h>
#include <rte_random.h>
#include <rte_ring_core.h>
#include <rte_string_fns.h>
#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/types.h>
#include "config.h"
#include <rte_branch_prediction.h>
#include <rte_ethdev.h>

#ifndef DPDK_H
#define DPDK_H

#define MAX_PKT_BURST 32
extern bool force_quit;
int init_dpdk(int argc, char **argv);
int dpdk_close();
int dpdk_run();
int zs_l2_recv(struct rte_mbuf **pkts_buf);
int zs_l2_send(struct rte_mbuf **pkts_buf,int pkt_num);

int zs_malloc_mbufs(struct rte_mbuf** bufs,int num);
void print_stats(void) ;

#endif // DPDK_H