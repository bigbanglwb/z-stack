#include<rte_eal.h>
#include<rte_ethdev.h>
#include<rte_mbuf.h>
#include<stdio.h>
#include<arpa/inet.h>
#include <rte_arp.h>

#include "dpdk.h"

#ifndef ARP_H
#define ARP_H

struct arp_entry{
    uint32_t ip_addr;
    uint8_t mac_addr[RTE_ETHER_ADDR_LEN];
    struct arp_entry *prev;
    struct arp_entry *next;
};

extern struct arp_entry* arp_table;


struct rte_mbuf *ng_send_arp(struct rte_mempool *mbuf_pool, uint16_t opcode, uint8_t *dst_mac, uint32_t sip, uint32_t dip);

#endif	// ARP_H