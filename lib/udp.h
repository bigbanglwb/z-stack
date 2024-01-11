#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <rte_arp.h>
#include <rte_malloc.h>
#include "dpdk.h"
#ifndef UDP_H
#define UDP_H
//用于存放UDP数据包
struct offload{
	uint32_t sip;
	uint32_t dip;
	uint16_t sport;
	uint16_t dport;
	int protocol;
	unsigned char *data;
	uint16_t length;
};

int udp_process(struct rte_mbuf *udpmbuf);
int udp_out(struct rte_mempool *mbuf_pool);

#endif	// UDP_H