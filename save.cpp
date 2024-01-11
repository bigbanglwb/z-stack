#include "dpdk.h"
#include <getopt.h>
#include <rte_ether.h>
#include <rte_lcore.h>
#include <rte_mbuf_core.h>
#include <unistd.h>

static void signal_handler(int signum) {
    unsigned lcore_id;
    lcore_id  = rte_lcore_id();
    if (signum == SIGINT) {
        force_quit = true;
        printf("\n\nSignal %d received, lcore %u preparing to exit ...\n", signum,lcore_id);
        
  }
}
void zs_dump_packet(struct rte_mbuf *pkt)
{
    struct rte_ether_hdr  *eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
    
    if (rte_be_to_cpu_16(eth_hdr->ether_type) == RTE_ETHER_TYPE_IPV4) {
        // 解析IPv4头
        struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
        // 检查IP协议类型，例如TCP
        if (ip_hdr->next_proto_id == IPPROTO_TCP) {
            // 解析TCP头
            struct in_addr addr;
            struct rte_tcp_hdr *tcp_hdr = (struct rte_tcp_hdr *)(ip_hdr + 1);
            addr.s_addr = ip_hdr->src_addr;
            printf("tcp src: %s:%d, ", inet_ntoa(addr), ntohs(tcp_hdr->src_port));

            addr.s_addr = ip_hdr->dst_addr;
            printf("dst: %s:%d\n", inet_ntoa(addr), ntohs(tcp_hdr->dst_port));

        }
    }
}
int zs_encode_tcp_syn(struct rte_tcp_hdr *tcp_hdr){
    struct rte_mbuf *bufs[MAX_PKT_BURST];
    int ret = zs_malloc_mbufs(bufs,1);
    if(ret != 0)
    {
        printf("zs_malloc_mbufs failed\n");
        return -1;
    }
    const unsigned total_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr)+ sizeof(struct rte_tcp_hdr);

    struct rte_mbuf *mbuf = bufs[0];
    mbuf->data_len = total_len;
    mbuf->pkt_len = total_len;

    struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
    //TODO hard_code
    rte_memcpy(eth_hdr->dst_addr.addr_bytes, zs_global_cfg.dpdk.dst_mac_addr, RTE_ETHER_ADDR_LEN);
    rte_memcpy(eth_hdr->src_addr.addr_bytes, zs_global_cfg.dpdk.src_mac_addr, RTE_ETHER_ADDR_LEN);
    eth_hdr->ether_type = htons(RTE_ETHER_TYPE_IPV4);

    struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
    ip_hdr->version_ihl = 0x45;
	ip_hdr->type_of_service = 0;
	ip_hdr->total_length = htons(total_len - sizeof(struct rte_ether_hdr));
	ip_hdr->packet_id = 0;
	ip_hdr->fragment_offset = 0;
	ip_hdr->time_to_live = 64; // ttl = 64
	ip_hdr->next_proto_id = IPPROTO_UDP;
	ip_hdr->src_addr = gSrcIp;
	ip_hdr->dst_addr = gDstIp;

    struct rte_tcp_hdr *tcp_hdr = (struct rte_tcp_hdr *)(ip_hdr + 1);
}
void zs_tcp_handle(struct rte_ipv4_hdr *ip_hdr)
{
    // 解析TCP头
    struct in_addr addr;
    struct rte_tcp_hdr *tcp_hdr = (struct rte_tcp_hdr *)(ip_hdr + 1);
    addr.s_addr = ip_hdr->src_addr;
    printf("tcp src: %s:%d, ", inet_ntoa(addr), ntohs(tcp_hdr->src_port));

    addr.s_addr = ip_hdr->dst_addr;
    printf("dst: %s:%d\n", inet_ntoa(addr), ntohs(tcp_hdr->dst_port));

    if (tcp_hdr->tcp_flags & RTE_TCP_SYN_FLAG)
    {
        //client first handshake,server second handshake
        unsigned seq_num = ntohl(tcp_hdr->sent_seq)+1;
        zs_encode_tcp_syn(tcp_hdr);

    }else if(tcp_hdr->tcp_flags & RTE_TCP_ACK_FLAG)
    {
        // 处理第三次
    }
}

void zs_ipv4_handle(struct rte_ether_hdr *eth_hdr)
{
    struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
    if (ip_hdr->next_proto_id == IPPROTO_TCP) {
        // Handle tcp protocol     
        zs_tcp_handle(ip_hdr);
    }
}
void zs_eth_handle(struct rte_mbuf *pkt)
{
    struct rte_ether_hdr  *eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
    if (rte_be_to_cpu_16(eth_hdr->ether_type) == RTE_ETHER_TYPE_IPV4) {
        // Handle ipv4 protocol
        zs_ipv4_handle(eth_hdr);
    }
}




int main(int argc, char **argv) {
    struct rte_mbuf *buf[MAX_PKT_BURST];
    uint64_t prev_tsc, diff_tsc, cur_tsc, timer_tsc;
    unsigned lcore_id;
    

    force_quit = false;
    
    prev_tsc = 0;
	timer_tsc = 0;
    
    signal(SIGINT, signal_handler);
    init_dpdk(argc, argv);    
    dpdk_run();

    while(!force_quit)
    {
        cur_tsc = rte_rdtsc();
        diff_tsc = cur_tsc - prev_tsc;
        timer_tsc += diff_tsc;
        if (unlikely(timer_tsc >= zs_global_cfg.timer_period)) {
            print_stats(); 
            /* reset the timer */
            timer_tsc = 0;
            
        }        
        prev_tsc = cur_tsc;
        int nb_rx = zs_l2_recv(buf);
        for(int i=0;i<nb_rx;i++)
        {
            rte_prefetch0(rte_pktmbuf_mtod(buf[i], void *));
            zs_dump_packet(buf[i]);
        }

        zs_l2_send(buf,nb_rx);

    }
    
    
    dpdk_close();
    
    return 0;
}