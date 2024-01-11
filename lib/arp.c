#include "arp.h"
#include "config.h"
#define NUM_MBUFS (4096-1)
#define BURST_SIZE	32
#define ENABLE_SEND		1
#define ENABLE_ARP		1

struct localhost *lhost = NULL;


#define MAKE_IPV4_ADDR(a, b, c, d) (a + (b<<8) + (c<<16) + (d<<24))
static uint32_t gLocalIp = MAKE_IPV4_ADDR(192, 168, 101, 83);
static uint32_t gSrcIp;
static uint32_t gDstIp;
static uint16_t gSrcPort;
static uint16_t gDstPort;
static uint8_t gSrcMac[RTE_ETHER_ADDR_LEN];
static uint8_t gDstMac[RTE_ETHER_ADDR_LEN];



static const struct rte_eth_conf port_conf_default = {
	.rxmode = {.mtu = RTE_ETHER_MAX_LEN} //RTE_ETHER_MAX_LEN 以太网数据中长度，一般为1518
};

struct arp_entry *arp_table;


#if ENABLE_ARP
/*
这段代码是一个函数 ng_encode_arp_pkt，用于构造 ARP 数据包的头部和数据部分。

msg: 指向数据包缓冲区的指针，用于存储构造的 ARP 数据包。
dst_mac: 目标主机的 MAC 地址，用于填充 ARP 数据包的目标 MAC 地址字段。
sip: 源 IP 地址，用于填充 ARP 数据包的源 IP 地址字段。
dip: 目标 IP 地址，用于填充 ARP 数据包的目标 IP 地址字段。

*/
static int ng_encode_arp_pkt(uint8_t *msg, uint16_t opcode, uint8_t *dst_mac, uint32_t sip, uint32_t dip) {
	//构造以太网头部（Ethernet Header），并将源MAC地址、目的MAC地址以及以太网类型（Ethernet Type）进行填充
	struct rte_ether_hdr * eth = (struct rte_ether_hdr *)msg;
	rte_memcpy(eth->src_addr.addr_bytes,zs_global_cfg.dpdk.src_mac_addr,RTE_ETHER_ADDR_LEN);
	if (!strncmp((const char *)dst_mac, (const char *)__default_dst_mac, RTE_ETHER_ADDR_LEN)){
		//链表中没有mac记录
		uint8_t mac[RTE_ETHER_ADDR_LEN] = {0x0};
		rte_memcpy(eth->dst_addr.addr_bytes, mac, RTE_ETHER_ADDR_LEN);
	} else {
		rte_memcpy(eth->dst_addr.addr_bytes,dst_mac,RTE_ETHER_ADDR_LEN);
	}
	eth->ether_type = htons(RTE_ETHER_TYPE_ARP);

	//构造 ARP（Address Resolution Protocol）数据包的头部
	struct rte_arp_hdr *arp = (struct rte_arp_hdr *)(eth+1);
	arp->arp_hardware = htons(1);//1:以太网
	arp->arp_protocol = htons(RTE_ETHER_TYPE_IPV4);
	arp->arp_hlen = RTE_ETHER_ADDR_LEN;//设置 ARP 数据包的硬件地址长度字段。在以太网中，MAC 地址长度为 6 字节
	arp->arp_plen = sizeof(uint32_t);//设置 ARP 数据包的协议地址长度字段。在 IPv4 中，IP 地址长度为 4 字节
	arp->arp_opcode = htons(opcode); //设置 ARP 数据包的操作码字段。这里的值 2 表示 ARP Reply（响应）

#if DEBUG_LEVEL
	// 以下代码用于调试，模拟设置源MAC地址
	const char* mac_address = "00:11:22:33:44:55";
	sscanf(mac_address, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",
			   &gSrcMac[0], &gSrcMac[1], &gSrcMac[2], &gSrcMac[3], &gSrcMac[4], &gSrcMac[5]);
	rte_memcpy(arp->arp_data.arp_sha.addr_bytes,gSrcMac,RTE_ETHER_ADDR_LEN);
#else
	rte_memcpy(arp->arp_data.arp_sha.addr_bytes,gSrcMac,RTE_ETHER_ADDR_LEN);
#endif
	rte_memcpy(arp->arp_data.arp_tha.addr_bytes,dst_mac,RTE_ETHER_ADDR_LEN);

	arp->arp_data.arp_sip = sip;
	arp->arp_data.arp_tip = dip;
	return 0;
}

struct rte_mbuf *ng_send_arp(struct rte_mempool *mbuf_pool, uint16_t opcode, uint8_t *dst_mac, uint32_t sip, uint32_t dip){
	const unsigned total_length = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);
	struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
	if(!mbuf){
		rte_exit(EXIT_FAILURE, "ng_send_arp rte_pktmbuf_alloc\n");
	}
	mbuf->pkt_len = total_length;
	mbuf->data_len = total_length;

	uint8_t *pkt_data = rte_pktmbuf_mtod(mbuf,uint8_t*);
	ng_encode_arp_pkt(pkt_data, opcode, dst_mac, sip, dip);

	return mbuf;
}

#if ENABLE_TIMER

static void
arp_request_timer_cb(__attribute__((unused)) struct rte_timer *tim,void *arg) 
{

	struct rte_mempool *mbuf_pool = (struct rte_mempool *)arg;
	

	int i = 0;
	for (i = 1;i <= 254;i ++) {

		uint32_t dstip = (gLocalIp & 0x00FFFFFF) | (0xFF000000 & (i << 24));
#if DEBUG_LEVEL
		struct in_addr addr;
		addr.s_addr = dstip;
		printf("arp ---> src: %s \n", inet_ntoa(addr));
#endif
		struct rte_mbuf *arpbuf = NULL;
		uint8_t *dstmac = ng_get_dst_macaddr(dstip);
		//在链表中查找有无目的IP的mac记录，以此来封装数据包中mac字段
		if (dstmac == NULL){
			arpbuf = ng_send_arp(mbuf_pool, RTE_ARP_OP_REQUEST, gDefaultArpMac, gLocalIp, dstip);
		}else {
			arpbuf = ng_send_arp(mbuf_pool, RTE_ARP_OP_REQUEST, dstmac, gLocalIp, dstip);
		}
		zs_l2_send(&arpbuf, 1);
	}
	
}
#endif

#endif