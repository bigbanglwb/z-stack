#include <rte_build_config.h>
#include "stdint.h"
#ifndef CONFIG_H
#define CONFIG_H


#define MAX_RX_QUEUE_PER_LCORE 16
#define NUM_PAIR_PORTS 2
#define TIMER_PERIOD 1 /* default period is 1 seconds */


#define DEBUG_LEVEL 0
#define ENABLE_SEND		1
#define ENABLE_ARP		1
#define ENABLE_ICMP		0
#define ENABLE_ARP_REPLY	0
#define ENABLE_DEBUG		1



#define ENABLE_RINGBUFFER	1
#define ENABLE_MULTHREAD	1

#define ENABLE_UDP_APP		0

#define ENABLE_TCP_APP		1
#define ENABLE_TIMER		0

#define LL_ADD(item, list) do {   \
    item->prev=NULL;            \
    item->next=list;            \
    if(list!=NULL){             \
        list->prev=item;        \
    }                           \
    list=item;                   \
}while(0)


#define LL_REMOVE(item, list)do{        \
    if(item->prev!=NULL){               \
        item->prev->next=item->next;    \
    }                                   \
    if(item->next!=NULL){               \
        item->next->prev=item->prev;    \
    }                                   \
    if(list==item){                     \
        list=item->next;                \
    }                                   \
    item->prev=item->next=NULL;         \
}while(0)

struct zs_config {
    struct {
        int      promiscuous_on;
        unsigned      rx_queue_per_lcore;
        // unsigned     port_list[RTE_MAX_ETHPORTS];
        unsigned     port_id;
        unsigned     nb_ports;
        unsigned nb_lcores;
        struct rte_ether_addr * src_mac_addr;
        struct rte_ether_addr * dst_mac_addr;
    } dpdk;

    uint64_t timer_period ; /* default period is 10 seconds */
};





extern volatile  struct zs_config zs_global_cfg;
extern const uint8_t __default_dst_mac[32];
struct rte_ether_addr* zs_get_dst_macaddr(uint32_t ip);
struct rte_ether_addr* zs_get_src_macaddr();
#endif // CONFIG_H