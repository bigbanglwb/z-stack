#include "dpdk.h"
// #include "udp.h"
#include "tcp.h"
#include "arp.h"
#include "config.h"
static void 
print_ethaddr(const char *name, const struct rte_ether_addr *eth_addr)
{
	char buf[RTE_ETHER_ADDR_FMT_SIZE];
	rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, eth_addr);
	printf("%s%s", name, buf);
}


//用户态协议栈处理数据包的线程
int pkt_process(void *arg){
	struct rte_mempool *mbuf_pool = (struct rte_mempool *)arg;
	
	while(1){
		struct rte_mbuf *mbufs[MAX_PKT_BURST];
		//从ring-in 环形队列中取出数据到mbufs

		unsigned num_recvd = zs_l2_recv(mbufs);

		unsigned i = 0;
		for (i = 0;i < num_recvd;i ++){
			//rte_ether_hdr是DPDK 中用于表示以太网数据包头部的结构体
			//rte_pktmbuf_mtod用于将数据包缓冲区中的数据指针转换为特定类型的指针，以方便对数据包头部进行解析
			struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(mbufs[i],struct rte_ether_hdr *);
#if ENABLE_ARP
			if(ehdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)){
				//将数据包偏移以太网数据包头部大小后，就是arp头部信息，再转换为struct rte_arp_hdr *
				struct rte_arp_hdr *ahdr = rte_pktmbuf_mtod_offset(mbufs[i],
					struct rte_arp_hdr *,sizeof(struct rte_ether_hdr));
#if DEBUG_LEVEL
				struct in_addr addr;
				addr.s_addr = ahdr->arp_data.arp_tip;
				printf("zxk arp ---> src: %s ", inet_ntoa(addr));

				addr.s_addr = gLocalIp;
				printf("zxk local: %s \n", inet_ntoa(addr));
#endif
				//只处理ip地址是本机的arp数据包
				if(ahdr->arp_data.arp_tip == gLocalIp){
					//处理ARP request包
					if (ahdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REQUEST)) {
#if DEBUG_LEVEL
						printf("arp --> request\n");
#endif
						//封装arp reply包
						struct rte_mbuf *arpbuf = ng_send_arp(mbuf_pool, RTE_ARP_OP_REPLY, ahdr->arp_data.arp_sha.addr_bytes, 
						ahdr->arp_data.arp_tip,ahdr->arp_data.arp_sip);

						
						zs_l2_send(&arpbuf, 1);
					}
					//处理ARP reply包
					else if (ahdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REPLY)) {
#if DEBUG_LEVEL
						printf("arp --> reply\n");
#endif
						/*
						尝试从 ARP 表中查找给定目标 IP 地址 ahdr->arp_data.arp_sip 对应的 MAC 地址。
						如果能找到，则将该 MAC 地址保存在 hwaddr 变量中，否则 hwaddr 为 NULL。
						*/
						uint8_t *hwaddr = zs_get_dst_macaddr(ahdr->arp_data.arp_sip)->addr_bytes;
						if (hwaddr == NULL) {
							// 从 ARP 表中没有找到对应的 MAC 地址，需要添加新的条目到 ARP 表中
							struct arp_entry *entry = rte_malloc("arp_entry",sizeof(struct arp_entry), 0);
							if (entry) {
								memset(entry, 0, sizeof(struct arp_entry));
								entry->ip_addr = ahdr->arp_data.arp_sip;
								rte_memcpy(entry->mac_addr, ahdr->arp_data.arp_sha.addr_bytes, RTE_ETHER_ADDR_LEN);
								

								// 将新条目添加到 ARP 表中
								LL_ADD(entry, arp_table);
								
							}
						}
#if DEBUG_LEVEL
						//遍历 ARP 表中的所有条目，并打印每个条目的 IP 地址和 MAC 地址信息。
						struct arp_entry *iter;
						for (iter = table->entries; iter != NULL; iter = iter->next) {
							struct in_addr addr;
							addr.s_addr = iter->ip;
							print_ethaddr("arp table --> mac: ", (struct rte_ether_addr *)iter->hwaddr);
							printf(" ip: %s \n", inet_ntoa(addr));
					
						}
#endif
					
					rte_pktmbuf_free(mbufs[i]);
					}
					continue;
				}
			}
#endif

			//rte_cpu_to_be_16用于将 16 位的数据从主机字节序（CPU 字节序）转换为网络字节序（大端字节序）
			if(ehdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)){
							//rte_pktmbuf_mtod_offset来获取数据包缓冲区中 IPv4 头部的指针
			//将数据包偏移以太网数据包头部大小后，就是IPV4头部信息，再转换为struct rte_ipv4_hdr *
			struct rte_ipv4_hdr * iphdr = rte_pktmbuf_mtod_offset(mbufs[i],struct rte_ipv4_hdr *,
			sizeof(struct rte_ether_hdr));
		
			if(iphdr->next_proto_id == IPPROTO_UDP){
				//TODO: udp_process
				// udp_process(mbufs[i]);
			}
#if ENABLE_TCP_APP
			if(iphdr->next_proto_id == IPPROTO_TCP){
				printf("ng_tcp_process\n");
				ng_tcp_process(mbufs[i]);
			}

#endif
#if ENABLE_ICMP
			if (iphdr->next_proto_id == IPPROTO_ICMP) {
				struct rte_icmp_hdr *icmphdr = (struct rte_icmp_hdr *)(iphdr + 1);
				struct in_addr addr;
				addr.s_addr = iphdr->src_addr;
				printf("zxk_icmp ---> src: %s ", inet_ntoa(addr));

				if (icmphdr->icmp_type == RTE_IP_ICMP_ECHO_REQUEST) {
					addr.s_addr = iphdr->dst_addr;
					printf("zxk local: %s , type : %d\n", inet_ntoa(addr), icmphdr->icmp_type);
					struct rte_mbuf *txbuf = ng_send_icmp(mbuf_pool, ehdr->s_addr.addr_bytes,
						iphdr->dst_addr, iphdr->src_addr, icmphdr->icmp_ident, icmphdr->icmp_seq_nb);

					//rte_eth_tx_burst(gDpdkPortId, 0, &txbuf, 1);
					//rte_pktmbuf_free(txbuf);
					rte_ring_mp_enqueue_burst(ring->out,(void **)&txbuf,1,NULL);

					rte_pktmbuf_free(mbufs[i]);
				}
			}
#endif
			}

		}
#if ENABLE_UDP_APP
// 		udp_out(mbuf_pool);
#endif
#if ENABLE_TCP_APP
		ng_tcp_out(mbuf_pool);
#endif
	}
	return 0;
}
