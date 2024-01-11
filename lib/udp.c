#include "udp.h"
#include "arp.h"





static int ng_encode_udp_pkt(uint8_t *msg,uint8_t *data,uint16_t total_len){
	//构造以太网头部（Ethernet Header），并将源MAC地址、目的MAC地址以及以太网类型（Ethernet Type）进行填充
	struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
	rte_memcpy(eth->src_addr.addr_bytes,zs_get_src_macaddr()->addr_bytes,RTE_ETHER_ADDR_LEN);
	rte_memcpy(eth->dst_addr.addr_bytes, gDstMac, RTE_ETHER_ADDR_LEN);
	eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);

	//构造IPv4头部（IPv4 Header）
	struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(msg +sizeof(struct rte_ether_hdr));
	ip->version_ihl = 0x45;
	ip->type_of_service = 0;
	ip->total_length = htons(total_len- sizeof(struct rte_ether_hdr));
	ip->packet_id = 0;
	ip->fragment_offset = 0;//fragment_offset 被设置为0，表示数据包不进行分片。
	ip->time_to_live = 64; //ttl = 64
	ip->next_proto_id = IPPROTO_UDP;
	ip->src_addr = gSrcIp;
	ip->dst_addr = gDstIp;
	ip->hdr_checksum = 0;
	ip->hdr_checksum = rte_ipv4_cksum(ip);

	//构造UDP头部（UDP Header）
	struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(msg +sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
	udp->src_port = gSrcPort;
	udp->dst_port = gDstPort;
	uint16_t udplen = total_len - sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv4_hdr);
	udp->dgram_len = htons(udplen);

    const char *source_str = "send day 2 by zxk";
    strcpy((char *)data, source_str);
	rte_memcpy((uint8_t *)(udp+1),data,udplen);
	udp->dgram_cksum = 0;
	udp->dgram_cksum = rte_ipv4_udptcp_cksum(ip,udp);

	struct in_addr addr;
	addr.s_addr = gSrcIp;
	printf(" zxk_send--> src: %s:%d, ", inet_ntoa(addr), ntohs(gSrcPort));
	addr.s_addr = gDstIp;
	printf("zxk_send dst: %s:%d\n", inet_ntoa(addr), ntohs(gDstPort));
	
	return 0;
}


static struct rte_mbuf *ng_send_udp(struct rte_mempool *mbuf_pool,uint8_t *data,uint16_t length){
	// 42是以太网头部（14字节）+ IPv4头部（20字节）+ UDP头部（8字节）
	const unsigned total_len = length + 42;

	// 使用rte_pktmbuf_alloc函数从指定的内存池中分配一个rte_mbuf结构
	struct rte_mbuf  *mbuf = rte_pktmbuf_alloc(mbuf_pool);
	if(!mbuf){
		rte_exit(EXIT_FAILURE,"rte_pktmbuf_alloc fail\n");
	}
	// 设置rte_mbuf的数据包长度和实际数据长度
	mbuf->pkt_len = total_len;
	mbuf->data_len = total_len;

	// 获取rte_mbuf的数据指针
	uint8_t * pktdata = rte_pktmbuf_mtod(mbuf,uint8_t *);
	
	// 使用ng_encode_udp_pkt函数对rte_mbuf进行填充
	ng_encode_udp_pkt(pktdata,data,total_len);

	return mbuf;
}


/*
用于处理接收到的UDP数据包。函数的主要功能是解析UDP数据包的头部信息，并将相关信息存储在一个名为offload的结构体中，
然后将结构体放入接收缓冲区进行后续处理。
*/
static int udp_process(struct rte_mbuf *udpmbuf){
	struct rte_ipv4_hdr *iphdr = rte_pktmbuf_mtod_offset(udpmbuf, struct rte_ipv4_hdr *, 
				sizeof(struct rte_ether_hdr));
	//(iphdr + 1) +1指的是偏移rte_ipv4_hdr（iphdr类型）大小
	struct rte_udp_hdr *udphdr = (struct rte_udp_hdr *)(iphdr + 1);
	struct in_addr addr;
	addr.s_addr = iphdr->src_addr;
	printf("udp_process ---> src: %s:%d \n", inet_ntoa(addr), ntohs(udphdr->src_port));
	printf("zxk udp data: %s\n",(unsigned char *)(udphdr+1));

	struct localhost *host = get_hostinfo_fromip_port(iphdr->dst_addr, udphdr->dst_port, iphdr->next_proto_id);
	if (host == NULL) {
		rte_pktmbuf_free(udpmbuf);
		return -3;
	} 
	struct offload *ol = rte_malloc("offload", sizeof(struct offload), 0);
	if (ol == NULL) {
		rte_pktmbuf_free(udpmbuf);
		return -1;
	}
	ol->dip = iphdr->dst_addr;
	ol->sip = iphdr->src_addr;
	ol->sport = udphdr->src_port;
	ol->dport = udphdr->dst_port;
	ol->protocol = IPPROTO_UDP;
	ol->length = ntohs(udphdr->dgram_len);

	ol->data = rte_malloc("unsigned char*", ol->length - sizeof(struct rte_udp_hdr), 0);
	if (ol->data == NULL) {

		rte_pktmbuf_free(udpmbuf);
		rte_free(ol);

		return -2;

	}
	//这里返回的数据只是简单拷贝收到的数据内容，后续可以根据需求完善
	rte_memcpy(ol->data, (unsigned char *)(udphdr+1), ol->length - sizeof(struct rte_udp_hdr));
	rte_ring_mp_enqueue(host->rcvbuf, ol); // recv buffer

	//通过互斥锁和条件变量通知相关线程有新数据可处理
	pthread_mutex_lock(&host->mutex);
	pthread_cond_signal(&host->cond);
	pthread_mutex_unlock(&host->mutex);

	rte_pktmbuf_free(udpmbuf);

	return 0;
}

static int ng_encode_udp_apppkt(uint8_t *msg, uint32_t sip, uint32_t dip,
	uint16_t sport, uint16_t dport, uint8_t *srcmac, uint8_t *dstmac,
	unsigned char *data, uint16_t total_len) {

	// encode 

	// 1 ethhdr
	struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
	rte_memcpy(eth->src_addr.addr_bytes, srcmac, RTE_ETHER_ADDR_LEN);
	rte_memcpy(eth->dst_addr.addr_bytes, dstmac, RTE_ETHER_ADDR_LEN);
	eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);
	

	// 2 iphdr 
	struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(msg + sizeof(struct rte_ether_hdr));
	ip->version_ihl = 0x45;
	ip->type_of_service = 0;
	ip->total_length = htons(total_len - sizeof(struct rte_ether_hdr));
	ip->packet_id = 0;
	ip->fragment_offset = 0;
	ip->time_to_live = 64; // ttl = 64
	ip->next_proto_id = IPPROTO_UDP;
	ip->src_addr = sip;
	ip->dst_addr = dip;
	
	ip->hdr_checksum = 0;
	ip->hdr_checksum = rte_ipv4_cksum(ip);

	// 3 udphdr 

	struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(msg + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
	udp->src_port = sport;
	udp->dst_port = dport;
	uint16_t udplen = total_len - sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv4_hdr);
	udp->dgram_len = htons(udplen);

	rte_memcpy((uint8_t*)(udp+1), data, udplen);

	udp->dgram_cksum = 0;
	udp->dgram_cksum = rte_ipv4_udptcp_cksum(ip, udp);

	return 0;
}

static struct rte_mbuf * ng_udp_pkt(struct rte_mempool *mbuf_pool, uint32_t sip, uint32_t dip,
	uint16_t sport, uint16_t dport, uint8_t *srcmac, uint8_t *dstmac,
	uint8_t *data, uint16_t length) {

	// mempool --> mbuf

	const unsigned total_len = length + 42;

	struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
	if (!mbuf) {
		rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc\n");
	}
	mbuf->pkt_len = total_len;
	mbuf->data_len = total_len;

	uint8_t *pktdata = rte_pktmbuf_mtod(mbuf, uint8_t*);

	ng_encode_udp_apppkt(pktdata, sip, dip, sport, dport, srcmac, dstmac,
		data, total_len);

	return mbuf;

}

int udp_out(struct rte_mempool *mbuf_pool) {
	struct localhost *host;
	for (host = lhost; host != NULL; host = host->next) {
		struct offload *ol;
		int nb_snd = rte_ring_mc_dequeue(host->sndbuf, (void **)&ol);
		if (nb_snd < 0) continue;

		struct in_addr addr;
		addr.s_addr = ol->dip;
		printf("udp_out ---> src: %s:%d \n", inet_ntoa(addr), ntohs(ol->dport));
		uint8_t *dstmac = zs_get_dst_macaddr(ol->dip)->addr_bytes;
		//不知道对方mac地址的情况，先发送arp
		if (dstmac == NULL) {
			struct rte_mbuf *arpbuf = ng_send_arp(mbuf_pool, RTE_ARP_OP_REQUEST, (uint8_t *)__default_dst_mac, 
				ol->sip, ol->dip);

			
			zs_l2_send(&arpbuf, 1);
			rte_ring_mp_enqueue(host->sndbuf, ol);
			
		} else {

			struct rte_mbuf *udpbuf = ng_udp_pkt(mbuf_pool, ol->sip, ol->dip, ol->sport, ol->dport,
				host->localmac, dstmac, ol->data, ol->length);

			zs_l2_send(&udpbuf, 1);
		}
	}
	return 0;
}