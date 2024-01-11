#include<rte_eal.h>
#include<rte_ethdev.h>
#include<rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_timer.h>
#include<stdio.h>
#include<arpa/inet.h>

#define DEBUG_LEVEL 0
#include "arp.h"


#define ENABLE_SEND		1
#define ENABLE_ARP		1
#define ENABLE_ICMP		1
#define ENABLE_ARP_REPLY	1
#define ENABLE_DEBUG		1

#define ENABLE_TIMER		1

#define ENABLE_RINGBUFFER	1
#define ENABLE_MULTHREAD	1

#define ENABLE_UDP_APP		1

#define ENABLE_TCP_APP		1


#define NUM_MBUFS (4096-1)
#define BURST_SIZE	32
#define RING_SIZE	1024
#define TIMER_RESOLUTION_CYCLES 120000000000ULL // 10ms * 1000 = 10s * 6 
#if ENABLE_SEND
#define MAKE_IPV4_ADDR(a, b, c, d) (a + (b<<8) + (c<<16) + (d<<24))
static uint32_t gLocalIp = MAKE_IPV4_ADDR(192, 168, 101, 83);


static uint8_t gSrcMac[RTE_ETHER_ADDR_LEN];

#endif
#if ENABLE_ARP_REPLY

static uint8_t gDefaultArpMac[RTE_ETHER_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

#endif

#if ENABLE_RINGBUFFER
struct inout_ring{
	struct rte_ring *in;
	struct rte_ring *out;
};
	
static struct inout_ring *rInst = NULL;

static struct inout_ring *ringInstance(void){
	if(rInst == NULL){
		rInst = rte_malloc("in/out ring",sizeof(struct inout_ring),0);
		memset(rInst,0,sizeof(struct inout_ring));
	}
	return rInst;
}
#endif

#if ENABLE_UDP_APP
	static int udp_process(struct rte_mbuf *udpmbuf);
	static int udp_out(struct rte_mempool *mbuf_pool);

#endif

#if ENABLE_TCP_APP

static int ng_tcp_process(struct rte_mbuf *tcpmbuf);
static int ng_tcp_out(struct rte_mempool *mbuf_pool);

#define TCP_OPTION_LENGTH 	10  //这里是以4字节为单位，即option最大长度为10*4字节
#define TCP_MAX_SEQ 4294967295 
#define TCP_INITIAL_WINDOW	14600
typedef enum _NG_TCP_STATUS{
	NG_TCP_STATUS_CLOSED = 0,
	NG_TCP_STATUS_LISTEN,
	NG_TCP_STATUS_SYN_RCVD,
	NG_TCP_STATUS_SYN_SENT,
	NG_TCP_STATUS_ESTABLISHED,
	
	NG_TCP_STATUS_FIN_WAIT_1,
	NG_TCP_STATUS_FIN_WAIT_2,
	NG_TCP_STATUS_CLOSING,
	NG_TCP_STATUS_TIME_WAIT,
	
	NG_TCP_STATUS_CLOSE_WAIT,
	NG_TCP_STATUS_LAST_ACK
}NG_TCP_STATUS;


struct ng_tcp_stream{
	int fd;
	uint32_t dip;
	uint8_t localmac[RTE_ETHER_ADDR_LEN];
	uint16_t dport;
	uint8_t protocol;
	uint16_t sport;
	uint32_t sip;
	uint32_t snd_nxt;//seqnum
	uint32_t rcv_nxt;//acknum
	NG_TCP_STATUS status;//tcp 连接处于什么状态
	struct rte_ring *sndbuf; //发送下一个序列号，表示下一个要发送的数据包的序列号
	struct rte_ring *rcvbuf; //接收下一个序列号，表示下一个期望接收的数据包的序列号
	struct ng_tcp_stream *prev;
	struct ng_tcp_stream *next;

	pthread_cond_t cond; //条件变量
	pthread_mutex_t mutex; //锁
};

struct ng_tcp_table{
	int count;
	struct ng_tcp_stream *tcb_set;
};

/*
 0					 1					 2					 3	 
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|	   Source Port (16 bits)	 |	  Destination Port (16 bits)|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|					   Sequence Number (32 bits)				|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|					 Acknowledgment Number (32 bits)			|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Data |   |C|E|U|A|P|R|S|F|							   |W|
|Offset|Res|W|C|R|C|S|S|Y|I|			Window Size (16 bits) |
| (4)  |	|R|E|R|K|G|Y|N|N|								|
|	   |	| |W|G|K|S|H|H| |								|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|			 Checksum (16 bits) 		  | Urgent Pointer (16)|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|					 Options and Padding (Variable) 			|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
struct ng_tcp_fragment{
	uint16_t sport;
	uint16_t dport;
	uint32_t seqnum;
	uint32_t acknum;
	uint8_t hdrlen_off; //表示TCP头部的长度，以4字节为单位。用于确定数据部分的起始位置
	uint8_t tcp_flags;
	uint16_t windows; //表示接收方的窗口大小，用于流量控制。
	uint16_t cksum;
	uint16_t tcp_urp; //仅在 URG 标志位设置时有效，用于指示紧急数据的位置
	int optlen;  //Options 长度可变，最大占40字节
	uint32_t option[TCP_OPTION_LENGTH];
	unsigned char *data;
	uint32_t length;
};

struct ng_tcp_table *tInst = NULL;


static struct ng_tcp_table *tcpInstance(void){
	if(tInst == NULL){
		tInst = rte_malloc("ng_tcp_table",sizeof(struct ng_tcp_table),0);
		memset(tInst,0,sizeof(struct ng_tcp_table));
	}
	return tInst;
}
	
#endif
int gDpdkPortId = 0;//eth0
static const struct rte_eth_conf port_conf_default = {
.rxmode = {.max_rx_pkt_len = RTE_ETHER_MAX_LEN} //RTE_ETHER_MAX_LEN 以太网数据中长度，一般为1518
};

static void ng_init_port(struct rte_mempool *mbuf_pool){
	//查询系统中可用的以太网设备数量,比如eth0,eth1等
	uint16_t nb_sys_ports = rte_eth_dev_count_avail();
	if(nb_sys_ports == 0){
		rte_exit(EXIT_FAILURE, "No Supported eth found\n");
	}
	struct rte_eth_dev_info dev_info;
	//查询以太网接口属性，此处的id = 0,代表查询eth0
	rte_eth_dev_info_get(gDpdkPortId,&dev_info);

	const int num_rx_queues = 1;//设置接受队列大小，通常每个队列与一个独立CPU关联
	const int num_tx_queues = 1;
	struct rte_eth_conf port_conf = port_conf_default;
	//配置eth0相关属性，用于后面接收发送数据包
	rte_eth_dev_configure(gDpdkPortId,num_rx_queues,num_tx_queues,&port_conf);

	//用于配置以太网设备的接收队列
	if(rte_eth_rx_queue_setup(gDpdkPortId,0,1024,
	rte_eth_dev_socket_id(gDpdkPortId),NULL,mbuf_pool) < 0){
		rte_exit(EXIT_FAILURE, "Could not setup RX queue\n");
	}

#if ENABLE_SEND
	struct rte_eth_txconf txq_conf = dev_info.default_txconf;
	txq_conf.offloads = port_conf.rxmode.offloads;
	//用于配置以太网设备的发送队列
	if(rte_eth_tx_queue_setup(gDpdkPortId,0,1024,
	rte_eth_dev_socket_id(gDpdkPortId),&txq_conf) < 0){
		rte_exit(EXIT_FAILURE, "Could not setup TX queue\n");
	}
#endif
	//启动指定的网卡，使其能够接收和发送数据包
	//初始化指定的以太网设备，配置接收队列和设备属性，并启动该网卡，以便进行数据包的收发和处理操作
	if(rte_eth_dev_start(gDpdkPortId) < 0){
		rte_exit(EXIT_FAILURE, "Could not start\n");
	}
}

/*
static int ng_encode_udp_pkt(uint8_t *msg,uint8_t *data,uint16_t total_len){
	//构造以太网头部（Ethernet Header），并将源MAC地址、目的MAC地址以及以太网类型（Ethernet Type）进行填充
	struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
	rte_memcpy(eth->s_addr.addr_bytes,gSrcMac,RTE_ETHER_ADDR_LEN);
	rte_memcpy(eth->d_addr.addr_bytes, gDstMac, RTE_ETHER_ADDR_LEN);
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
*/
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
	rte_memcpy(eth->s_addr.addr_bytes,gSrcMac,RTE_ETHER_ADDR_LEN);
	if (!strncmp((const char *)dst_mac, (const char *)gDefaultArpMac, RTE_ETHER_ADDR_LEN)){
		//链表中没有mac记录
		uint8_t mac[RTE_ETHER_ADDR_LEN] = {0x0};
		rte_memcpy(eth->d_addr.addr_bytes, mac, RTE_ETHER_ADDR_LEN);
	} else {
		rte_memcpy(eth->d_addr.addr_bytes,dst_mac,RTE_ETHER_ADDR_LEN);
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

static struct rte_mbuf *ng_send_arp(struct rte_mempool *mbuf_pool, uint16_t opcode, uint8_t *dst_mac, uint32_t sip, uint32_t dip){
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

#endif

#if ENABLE_ICMP
static uint16_t ng_checksum(uint16_t *addr, int count) {
	register long sum = 0;

	while(count > 1){
		sum += *(unsigned short *)addr++;
		count -= 2;
	}
	if(count > 0){
		sum += *(unsigned char *)addr;
	}
	while(sum >> 16){
		sum = (sum & 0xffff) + (sum >> 16);
	}
	return ~sum;
}

static int ng_encode_icmp_pkt(uint8_t *msg,uint8_t *dst_mac,
uint32_t sip,uint32_t dip,uint16_t id,uint16_t seqnb){
	//1 ether header
	struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
	rte_memcpy(eth->s_addr.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
	rte_memcpy(eth->d_addr.addr_bytes,dst_mac,RTE_ETHER_ADDR_LEN);
	eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);

	//2 IP header
	struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(msg +sizeof(struct rte_ether_hdr));
	ip->version_ihl = 0x45;
	ip->type_of_service = 0;
	ip->total_length = htons(sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_icmp_hdr));
	ip->packet_id = 0;
	ip->fragment_offset = 0;
	ip->time_to_live = 64;
	ip->next_proto_id = IPPROTO_ICMP;
	ip->src_addr = sip;
	ip->dst_addr = dip;

	ip->hdr_checksum = 0;
	ip->hdr_checksum = rte_ipv4_cksum(ip);

	//ICMP header
	struct rte_icmp_hdr * icmp = (struct rte_icmp_hdr* )(msg + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
	icmp->icmp_type = RTE_IP_ICMP_ECHO_REPLY;
	icmp->icmp_code = 0;
	icmp->icmp_ident = id;
	icmp->icmp_seq_nb = seqnb;

	icmp->icmp_cksum = 0;
	icmp->icmp_cksum = ng_checksum((uint16_t *)icmp, sizeof(struct rte_icmp_hdr));

	return 0;
}

static struct rte_mbuf *ng_send_icmp(struct rte_mempool *mbuf_pool,uint8_t *dst_mac,
		uint32_t sip, uint32_t dip, uint16_t id, uint16_t seqnb) {
	const unsigned total_length = sizeof(struct rte_ether_hdr) +sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_icmp_hdr);
	struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
	
	if (!mbuf) {
		rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc fail\n");
	}
	mbuf->pkt_len = total_length;
	mbuf->data_len = total_length;

	uint8_t * pkt_data = rte_pktmbuf_mtod(mbuf, uint8_t *);
	ng_encode_icmp_pkt(pkt_data,dst_mac,sip,dip,id,seqnb);

	return mbuf;
}
#endif

static void 
print_ethaddr(const char *name, const struct rte_ether_addr *eth_addr)
{
	char buf[RTE_ETHER_ADDR_FMT_SIZE];
	rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, eth_addr);
	printf("%s%s", name, buf);
}

#if ENABLE_TIMER
//__attribute__((unused))：编译器属性(attribute)，告诉编译器该参数未被使用。避免编译警告
static void
arp_request_timer_cb(__attribute__((unused)) struct rte_timer *tim,void *arg) 
{

	struct rte_mempool *mbuf_pool = (struct rte_mempool *)arg;
	struct inout_ring *ring = ringInstance();

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

		//rte_eth_tx_burst(gDpdkPortId, 0, &arpbuf, 1);
		//rte_pktmbuf_free(arpbuf);
		rte_ring_mp_enqueue_burst(ring->out,(void **)&arpbuf,1,NULL);
		
	}
	
}
#endif

#if ENABLE_MULTHREAD
//用户态协议栈处理数据包的线程
static int pkt_process(void *arg){
	struct rte_mempool *mbuf_pool = (struct rte_mempool *)arg;
	struct inout_ring *ring = ringInstance();

	while(1){
		struct rte_mbuf *mbufs[BURST_SIZE];
		//从ring-in 环形队列中取出数据到mbufs
		unsigned num_recvd = rte_ring_mc_dequeue_burst(ring->in, (void**)mbufs,BURST_SIZE,NULL);

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

						//e_eth_tx_burst(gDpdkPortId,0,&arpbuf,1);
						//e_pktmbuf_free(arpbuf);

						rte_ring_mp_enqueue_burst(ring->out, (void**)&arpbuf, 1, NULL);
					}
					//处理ARP reply包
					else if (ahdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REPLY)) {
#if DEBUG_LEVEL
						printf("arp --> reply\n");
#endif
						//获取指向 ARP 表结构的指针，如果 ARP 表还未被创建，则会创建并初始化一个新的 ARP 表
						struct arp_table *table = arp_table_instance();

						/*
						尝试从 ARP 表中查找给定目标 IP 地址 ahdr->arp_data.arp_sip 对应的 MAC 地址。
						如果能找到，则将该 MAC 地址保存在 hwaddr 变量中，否则 hwaddr 为 NULL。
						*/
						uint8_t *hwaddr = ng_get_dst_macaddr(ahdr->arp_data.arp_sip);
						if (hwaddr == NULL) {
							// 从 ARP 表中没有找到对应的 MAC 地址，需要添加新的条目到 ARP 表中
							struct arp_entry *entry = rte_malloc("arp_entry",sizeof(struct arp_entry), 0);
							if (entry) {
								memset(entry, 0, sizeof(struct arp_entry));
								entry->ip = ahdr->arp_data.arp_sip;
								rte_memcpy(entry->hwaddr, ahdr->arp_data.arp_sha.addr_bytes, RTE_ETHER_ADDR_LEN);
								entry->type = 0;

								// 将新条目添加到 ARP 表中
								LL_ADD(entry, table->entries);
								table->count ++;
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
			if(ehdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)){
				continue;
			}
			//rte_pktmbuf_mtod_offset来获取数据包缓冲区中 IPv4 头部的指针
			//将数据包偏移以太网数据包头部大小后，就是IPV4头部信息，再转换为struct rte_ipv4_hdr *
			struct rte_ipv4_hdr * iphdr = rte_pktmbuf_mtod_offset(mbufs[i],struct rte_ipv4_hdr *,
			sizeof(struct rte_ether_hdr));
		
			if(iphdr->next_proto_id == IPPROTO_UDP){
		
				udp_process(mbufs[i]);
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
#if ENABLE_UDP_APP
		udp_out(mbuf_pool);
#endif
#if ENABLE_TCP_APP
		ng_tcp_out(mbuf_pool);
#endif
	}
	return 0;
}
#endif

#if ENABLE_UDP_APP
struct localhost{
	int fd;
	uint32_t localip;
	uint8_t localmac[RTE_ETHER_ADDR_LEN];
	uint16_t localport;
	uint8_t protocol;
	struct rte_ring *sndbuf;
	struct rte_ring *rcvbuf;
	struct localhost *prev;
	struct localhost *next;
	pthread_cond_t cond;
	pthread_mutex_t mutex;
};
static struct localhost *lhost = NULL;
#define DEFAULT_FD_NUM 3

#define MAX_FD_COUNT 1024
static unsigned char fd_table[MAX_FD_COUNT] = {0};
static int get_fd_frombitmap(void){
	int fd = DEFAULT_FD_NUM;
	for(;fd < MAX_FD_COUNT;fd++){
		//通过 (fd_table[fd/8]) 获取对应字节的位图，然后通过 (0x1 << (fd % 8)) 计算出一个只有对应位为1的掩码，
		//与字节进行按位与运算。如果结果为0，表示该文件描述符可用
		if((fd_table[fd/8] & (0x1 <<(fd % 8))) == 0){
			//如果找到一个可用的文件描述符，将设置对应的位图为1，表示该文件描述符已被使用
			fd_table[fd/8] |= (0x1 << (fd % 8));
			return fd;
		}
	}
	return -1;
}

static int set_fd_frombitmap(int fd){
	if(fd >= MAX_FD_COUNT) return -1;
	fd_table[fd/8] &= ~(0x1 << (fd % 8));//将特定位置0
	return 0;
}

static struct ng_tcp_stream *get_accept_tcb(uint16_t dport){

	struct ng_tcp_stream *apt;
	struct ng_tcp_table *table = tcpInstance();
	for(apt = table->tcb_set;apt != NULL;apt = apt->next){
		if(dport == apt->dport && apt->fd ==-1){
			return apt;
		}
	}
	return NULL;
}

static void* get_hostinfo_fromfd(int sockfd) {
	struct localhost *host;
	for(host = lhost; host!=NULL;host = host->next){
		if(sockfd == host->fd){
			return host;
		}
	}
#if ENABLE_TCP_APP
	struct ng_tcp_stream *stream = NULL;
	struct ng_tcp_table *table = tcpInstance();
	for(stream = table->tcb_set;stream != NULL;stream = stream->next){
		if(sockfd == stream->fd){
			return stream;
		}
	}
#endif
	return NULL;
}

static struct localhost *get_hostinfo_fromip_port(uint32_t dip, uint16_t port, uint8_t proto){
	struct localhost *host;
	for (host = lhost; host != NULL;host = host->next) {

		if (dip == host->localip && port == host->localport && proto == host->protocol) {
			return host;
		}

	}
	return NULL;
}

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
	rte_memcpy(eth->s_addr.addr_bytes, srcmac, RTE_ETHER_ADDR_LEN);
	rte_memcpy(eth->d_addr.addr_bytes, dstmac, RTE_ETHER_ADDR_LEN);
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

static int udp_out(struct rte_mempool *mbuf_pool) {
	struct localhost *host;
	for (host = lhost; host != NULL; host = host->next) {
		struct offload *ol;
		int nb_snd = rte_ring_mc_dequeue(host->sndbuf, (void **)&ol);
		if (nb_snd < 0) continue;

		struct in_addr addr;
		addr.s_addr = ol->dip;
		printf("udp_out ---> src: %s:%d \n", inet_ntoa(addr), ntohs(ol->dport));
			
		uint8_t *dstmac = ng_get_dst_macaddr(ol->dip);
		//不知道对方mac地址的情况，先发送arp
		if (dstmac == NULL) {
			struct rte_mbuf *arpbuf = ng_send_arp(mbuf_pool, RTE_ARP_OP_REQUEST, gDefaultArpMac, 
				ol->sip, ol->dip);

			struct inout_ring *ring = ringInstance();
			rte_ring_mp_enqueue_burst(ring->out, (void **)&arpbuf, 1, NULL);

			rte_ring_mp_enqueue(host->sndbuf, ol);
			
		} else {

			struct rte_mbuf *udpbuf = ng_udp_pkt(mbuf_pool, ol->sip, ol->dip, ol->sport, ol->dport,
				host->localmac, dstmac, ol->data, ol->length);

			struct inout_ring *ring = ringInstance();
			rte_ring_mp_enqueue_burst(ring->out, (void **)&udpbuf, 1, NULL);

		}
	}
	return 0;
}

static int nsocket(__attribute__((unused)) int domain, int type, __attribute__((unused))  int protocol) {

	int fd = get_fd_frombitmap(); 

	if (type == SOCK_DGRAM) {

		struct localhost *host = rte_malloc("localhost", sizeof(struct localhost), 0);
		if (host == NULL) {
			return -1;
		}
		memset(host, 0, sizeof(struct localhost));

		host->fd = fd;
		
		host->protocol = IPPROTO_UDP;
	
		//使用 rte_ring_create 创建一个接收缓冲区环形队列，并将指针赋给 host 结构体的 rcvbuf 成员
		host->rcvbuf = rte_ring_create("recv buffer", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
		if (host->rcvbuf == NULL) {
			rte_free(host);
			return -1;
		}

		使用 rte_ring_create 创建一个接收缓冲区环形队列，并将指针赋给 host 结构体的 sndbuf 成员
		host->sndbuf = rte_ring_create("send buffer", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
		if (host->sndbuf == NULL) {
			rte_ring_free(host->rcvbuf);
			rte_free(host);
			return -1;
		}

		//初始化互斥锁和条件变量，将空白的互斥锁和条件变量拷贝到 host 结构体的对应成员中
		pthread_cond_t blank_cond = PTHREAD_COND_INITIALIZER;
		rte_memcpy(&host->cond, &blank_cond, sizeof(pthread_cond_t));

		pthread_mutex_t blank_mutex = PTHREAD_MUTEX_INITIALIZER;
		rte_memcpy(&host->mutex, &blank_mutex, sizeof(pthread_mutex_t));

		LL_ADD(host, lhost);
		
	} else if (type == SOCK_STREAM) {


		struct ng_tcp_stream *stream = rte_malloc("ng_tcp_stream", sizeof(struct ng_tcp_stream), 0);
		if (stream == NULL) {
			return -1;
		}
		memset(stream, 0, sizeof(struct ng_tcp_stream));

		stream->fd = fd;
		stream->protocol = IPPROTO_TCP;
		stream->next = stream->prev = NULL;

		stream->rcvbuf = rte_ring_create("tcp recv buffer", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
		if (stream->rcvbuf == NULL) {

			rte_free(stream);
			return -1;
		}

	
		stream->sndbuf = rte_ring_create("tcp send buffer", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
		if (stream->sndbuf == NULL) {

			rte_ring_free(stream->rcvbuf);

			rte_free(stream);
			return -1;
		}

		pthread_cond_t blank_cond = PTHREAD_COND_INITIALIZER;
		rte_memcpy(&stream->cond, &blank_cond, sizeof(pthread_cond_t));

		pthread_mutex_t blank_mutex = PTHREAD_MUTEX_INITIALIZER;
		rte_memcpy(&stream->mutex, &blank_mutex, sizeof(pthread_mutex_t));

		struct ng_tcp_table *table = tcpInstance();
		LL_ADD(stream, table->tcb_set);
		// get_stream_from_fd();
	}

	return fd;
}
/*
将fd与网卡绑定
*/
static int nbind(int sockfd, const struct sockaddr *addr,
                __attribute__((unused))  socklen_t addrlen) {

	void *hostinfo =  get_hostinfo_fromfd(sockfd);
	if (hostinfo == NULL) return -1;

	struct localhost *host = (struct localhost *)hostinfo;
	if (host->protocol == IPPROTO_UDP) {
		
		const struct sockaddr_in *laddr = (const struct sockaddr_in *)addr;
		host->localport = laddr->sin_port;
		rte_memcpy(&host->localip, &laddr->sin_addr.s_addr, sizeof(uint32_t));
		rte_memcpy(host->localmac, gSrcMac, RTE_ETHER_ADDR_LEN);

	} else if (host->protocol == IPPROTO_TCP) {

		struct ng_tcp_stream *stream = (struct ng_tcp_stream *)hostinfo;
		
		const struct sockaddr_in *laddr = (const struct sockaddr_in *)addr;
		stream->dport = laddr->sin_port;
		rte_memcpy(&stream->dip, &laddr->sin_addr.s_addr, sizeof(uint32_t));
		rte_memcpy(stream->localmac, gSrcMac, RTE_ETHER_ADDR_LEN);

		stream->status = NG_TCP_STATUS_CLOSED;
		
	}

	return 0;

}

//将一个套接字标识的 TCP 流设置为监听状态NG_TCP_STATUS_LISTEN
static int nlisten(int sockfd,__attribute__((unused)) int backlog){
	//从文件描述符获取与套接字相关的主机信息
	void * hostinfo = get_hostinfo_fromfd(sockfd);
	if(hostinfo == NULL) return -1;

	struct ng_tcp_stream *stream = (struct ng_tcp_stream *)hostinfo;
	if(stream->protocol == IPPROTO_TCP){
		stream->status = NG_TCP_STATUS_LISTEN;
	}
	return 0;
}

//接受传入的 TCP 连接请求，并返回一个新的套接字文件描述符，可以使用该描述符在新连接上进行通信
static int naccept(int sockfd, struct sockaddr *addr, __attribute__((unused)) socklen_t *addrlen){

	void * hostinfo = get_hostinfo_fromfd(sockfd);
	if(hostinfo == NULL) return -1;

	struct ng_tcp_stream *stream = (struct ng_tcp_stream *)hostinfo;
	if(stream->protocol == IPPROTO_TCP){
		struct ng_tcp_stream *apt = NULL;

		pthread_mutex_lock(&stream->mutex);
		while((apt = get_accept_tcb(stream->dport)) == NULL) {
			//在条件变量上等待，直到有连接可以接受
			pthread_cond_wait(&stream->cond, &stream->mutex);
		} 
		pthread_mutex_unlock(&stream->mutex);
		
		//为新的连接分配一个文件描述符
		apt->fd = get_fd_frombitmap();

		struct sockaddr_in *saddr = (struct sockaddr_in *)addr;
		saddr->sin_port = apt->sport;
		rte_memcpy(&saddr->sin_addr.s_addr,&apt->sip,sizeof(uint32_t));

		return apt->fd;
	}
	return -1;
}

//将数据发送到一个基于 TCP 的连接的发送缓冲区stream->sndbuf中
static ssize_t nsend(int sockfd, const void *buf, size_t len,__attribute__((unused)) int flags) {

	ssize_t length = 0;

	void *hostinfo =  get_hostinfo_fromfd(sockfd);
	if (hostinfo == NULL) return -1;

	struct ng_tcp_stream *stream = (struct ng_tcp_stream *)hostinfo;
	if (stream->protocol == IPPROTO_TCP) {

		struct ng_tcp_fragment *fragment = rte_malloc("ng_tcp_fragment", sizeof(struct ng_tcp_fragment), 0);
		if (fragment == NULL) {
			return -2;
		}

		memset(fragment, 0, sizeof(struct ng_tcp_fragment));

		fragment->dport = stream->sport;
		fragment->sport = stream->dport;

		fragment->acknum = stream->rcv_nxt;
		fragment->seqnum = stream->snd_nxt;

		fragment->tcp_flags = RTE_TCP_ACK_FLAG | RTE_TCP_PSH_FLAG;
		fragment->windows = TCP_INITIAL_WINDOW;
		fragment->hdrlen_off = 0x50;


		fragment->data = rte_malloc("unsigned char *", len+1, 0);
		if (fragment->data == NULL) {
			rte_free(fragment);
			return -1;
		}
		memset(fragment->data, 0, len+1);

		rte_memcpy(fragment->data, buf, len);
		fragment->length = len;
		length = fragment->length;

		// int nb_snd = 0;
		rte_ring_mp_enqueue(stream->sndbuf, fragment);

	}

	
	return length;
}

//从接收缓冲区stream->rcvbuf中接收数据，将数据复制到指定的缓冲区buf
static ssize_t nrecv(int sockfd, void *buf, size_t len, __attribute__((unused)) int flags) {
	
	ssize_t length = 0;

	void *hostinfo =  get_hostinfo_fromfd(sockfd);
	if (hostinfo == NULL) return -1;

	struct ng_tcp_stream *stream = (struct ng_tcp_stream *)hostinfo;
	if (stream->protocol == IPPROTO_TCP) {

		struct ng_tcp_fragment *fragment = NULL;
		int nb_rcv = 0;

		printf("rte_ring_mc_dequeue before\n");
		pthread_mutex_lock(&stream->mutex);
		while ((nb_rcv = rte_ring_mc_dequeue(stream->rcvbuf, (void **)&fragment)) < 0) {
			pthread_cond_wait(&stream->cond, &stream->mutex);
		}
		pthread_mutex_unlock(&stream->mutex);
		printf("rte_ring_mc_dequeue after\n");

		if (fragment->length > len) {

			rte_memcpy(buf, fragment->data, len);

			uint32_t i = 0;
			for(i = 0;i < fragment->length-len;i ++) {
				fragment->data[i] = fragment->data[len+i];
			}
			fragment->length = fragment->length-len;
			length = fragment->length;

			rte_ring_mp_enqueue(stream->rcvbuf, fragment);

		} else if (fragment->length == 0) {

			rte_free(fragment);
			return 0;
		
		} else {

			rte_memcpy(buf, fragment->data, fragment->length);
			length = fragment->length;

			rte_free(fragment->data);
			fragment->data = NULL;

			rte_free(fragment);
			
		}

	}

	return length;
}


/*
我们自己实现的协议栈将数据放入rcvbuf中，udp server中通过nrecvfrom函数取出数据到buf中
*/
static ssize_t nrecvfrom(int sockfd, void *buf, size_t len, __attribute__((unused))  int flags,
                        struct sockaddr *src_addr, __attribute__((unused))  socklen_t *addrlen) {

	struct localhost *host =  get_hostinfo_fromfd(sockfd);
	if (host == NULL) return -1;

	struct offload *ol = NULL;
	unsigned char *ptr = NULL;
	
	struct sockaddr_in *saddr = (struct sockaddr_in *)src_addr;
	
	int nb = -1;
	pthread_mutex_lock(&host->mutex);
	while ((nb = rte_ring_mc_dequeue(host->rcvbuf, (void **)&ol)) < 0) {
		//这里会阻塞，直到收到包后pthread_cond_signal唤醒
		pthread_cond_wait(&host->cond, &host->mutex);
	}
	pthread_mutex_unlock(&host->mutex);
	

	saddr->sin_port = ol->sport;
	rte_memcpy(&saddr->sin_addr.s_addr, &ol->sip, sizeof(uint32_t));

	if (len < ol->length) {

		rte_memcpy(buf, ol->data, len);

		//将未拷贝的数据复制到新分配的内存中
		ptr = rte_malloc("unsigned char *", ol->length-len, 0);
		rte_memcpy(ptr, ol->data+len, ol->length-len);

		ol->length -= len;
		rte_free(ol->data);
		ol->data = ptr;
		
		rte_ring_mp_enqueue(host->rcvbuf, ol);

		return len;
		
	} else {
		rte_memcpy(buf, ol->data, ol->length);
		rte_free(ol->data);
		rte_free(ol);
		
		return ol->length;
	}
}
/*
将数据放入发送缓冲区环形队列中，以便后续从队列中发送数据
*/
static ssize_t nsendto(int sockfd, const void *buf, size_t len, __attribute__((unused))  int flags,
                      const struct sockaddr *dest_addr, __attribute__((unused))  socklen_t addrlen){
	struct localhost *host =  get_hostinfo_fromfd(sockfd);
	if (host == NULL) return -1;

	const struct sockaddr_in *daddr = (const struct sockaddr_in *)dest_addr;

	struct offload *ol = rte_malloc("offload", sizeof(struct offload), 0);
	if (ol == NULL) return -1;

	ol->dip = daddr->sin_addr.s_addr;
	ol->dport = daddr->sin_port;
	ol->sip = host->localip;
	ol->sport = host->localport;
	ol->length = len;

	struct in_addr addr;
	addr.s_addr = ol->dip;
	printf("nsendto ---> src: %s:%d \n", inet_ntoa(addr), ntohs(ol->dport));
	

	ol->data = rte_malloc("unsigned char *", len, 0);
	if (ol->data == NULL) {
		rte_free(ol);
		return -1;
	}

	rte_memcpy(ol->data, buf, len);
	//将 需要发送的ol 数据包放入发送缓冲区环形队列 host->sndbuf 中
	rte_ring_mp_enqueue(host->sndbuf, ol);

	return len;
}

static int nclose(int fd) {

	
	void *hostinfo =  get_hostinfo_fromfd(fd);
	if (hostinfo == NULL) return -1;

	struct localhost *host = (struct localhost*)hostinfo;
	if (host->protocol == IPPROTO_UDP) {

	LL_REMOVE(host, lhost);

	if (host->rcvbuf) {
		rte_ring_free(host->rcvbuf);
	}
	if (host->sndbuf){
		rte_ring_free(host->sndbuf);
	}

	rte_free(host);

		set_fd_frombitmap(fd);
		
	} else if (host->protocol == IPPROTO_TCP) { 

		struct ng_tcp_stream *stream = (struct ng_tcp_stream*)hostinfo;

		if (stream->status != NG_TCP_STATUS_LISTEN) {
			
			struct ng_tcp_fragment *fragment = rte_malloc("ng_tcp_fragment", sizeof(struct ng_tcp_fragment), 0);
			if (fragment == NULL) return -1;

			printf("nclose --> enter last ack\n");
			fragment->data = NULL;
			fragment->length = 0;
			fragment->sport = stream->dport;
			fragment->dport = stream->sport;

			fragment->seqnum = stream->snd_nxt;
			fragment->acknum = stream->rcv_nxt;

			fragment->tcp_flags = RTE_TCP_FIN_FLAG | RTE_TCP_ACK_FLAG;
			fragment->windows = TCP_INITIAL_WINDOW;
			fragment->hdrlen_off = 0x50;

			//给客户端发送FIN，表明断开
			rte_ring_mp_enqueue(stream->sndbuf, fragment);
			stream->status = NG_TCP_STATUS_LAST_ACK;

			
			set_fd_frombitmap(fd);

		} else { // nsocket

			struct ng_tcp_table *table = tcpInstance();
			LL_REMOVE(stream, table->tcb_set);	

			rte_free(stream);

		}
	}

	return 0;
}

#define UDP_APP_RECV_BUFFER_SIZE	128
/*
典型的udp server，此处绑定网卡为eth0，然后
*/
static int udp_server_entry(__attribute__((unused))  void *arg) {

	int connfd = nsocket(AF_INET, SOCK_DGRAM, 0);
	if (connfd == -1) {
		printf("sockfd failed\n");
		return -1;
	} 

	struct sockaddr_in localaddr, clientaddr; // struct sockaddr 
	memset(&localaddr, 0, sizeof(struct sockaddr_in));

	localaddr.sin_port = htons(8889);
	localaddr.sin_family = AF_INET;
	localaddr.sin_addr.s_addr = inet_addr("192.168.101.83"); // 0.0.0.0
	

	nbind(connfd, (struct sockaddr*)&localaddr, sizeof(localaddr));

	char buffer[UDP_APP_RECV_BUFFER_SIZE] = {0};
	socklen_t addrlen = sizeof(clientaddr);
	while (1){

		if (nrecvfrom(connfd, buffer, UDP_APP_RECV_BUFFER_SIZE, 0, 
			(struct sockaddr*)&clientaddr, &addrlen) < 0) {

			continue;

		}else{

			printf("recv from %s:%d, data:%s\n", inet_ntoa(clientaddr.sin_addr), 
				ntohs(clientaddr.sin_port), buffer);
			nsendto(connfd, buffer, strlen(buffer), 0, 
				(struct sockaddr*)&clientaddr, sizeof(clientaddr));
		}

	}
	nclose(connfd);
}

#endif

#if ENABLE_TCP_APP
static struct ng_tcp_stream * ng_tcp_stream_search(uint32_t sip,uint32_t dip,uint16_t sport,uint16_t dport){
	struct ng_tcp_table *table = tcpInstance();
	struct ng_tcp_stream *iter;
	//遍历TCP链表，找到tcp 连接记录
	for(iter = table->tcb_set;iter != NULL;iter = iter->next){// established
		if(iter->sip == sip && iter->dip == dip &&
		iter->sport == sport && iter->dport == dport){
			return iter;		
		}
	}
	for(iter = table->tcb_set;iter != NULL;iter = iter->next){// listen状态下sip.dip.soprt还没赋值
		if(iter->dport == dport && iter->status == NG_TCP_STATUS_LISTEN){
			return iter;
		}
	}
	return NULL;
}

static struct ng_tcp_stream *ng_tcp_stream_create(uint32_t sip,uint32_t dip,uint16_t sport,uint16_t dport){

	//申请stream空间，记录tcp连接回话过程的数据
	struct ng_tcp_stream *stream = rte_malloc("ng_tcp_stream",sizeof(struct ng_tcp_stream),0);
	if(stream == NULL) return NULL;

	stream->sip = sip;
	stream->dip = dip;
	stream->sport = sport;
	stream->dport = dport;
	stream->protocol = IPPROTO_TCP;
	stream->fd = -1;//暂时没用到，后面建立连接时赋值

	stream->status = NG_TCP_STATUS_LISTEN; //TCP server 初始状态
	printf("ng_tcp_stream_create\n");

	stream->sndbuf = rte_ring_create("sndbuf",RING_SIZE,rte_socket_id(),0);
	stream->rcvbuf = rte_ring_create("rcvbuf",RING_SIZE,rte_socket_id(),0);//rte_socket_id保证申请的空间和当前线程在同一内存池

	//seq num TCP会用这个序号来拼接数据
	uint32_t next_seed = time(NULL);
	stream->snd_nxt = rand_r(&next_seed) % TCP_MAX_SEQ;
	rte_memcpy(stream->localmac, gSrcMac, RTE_ETHER_ADDR_LEN);

	//初始化条件变量
	pthread_cond_t blank_cond = PTHREAD_COND_INITIALIZER;
	rte_memcpy(&stream->cond, &blank_cond, sizeof(pthread_cond_t));

	//初始化锁
	pthread_mutex_t blank_mutex = PTHREAD_MUTEX_INITIALIZER;
	rte_memcpy(&stream->mutex, &blank_mutex, sizeof(pthread_mutex_t));

	return stream;
}

static int ng_tcp_handle_listen(struct ng_tcp_stream *stream,struct rte_tcp_hdr*tcphdr,struct rte_ipv4_hdr *iphdr){
	if(tcphdr ->tcp_flags & RTE_TCP_SYN_FLAG){ //RTE_TCP_SYN_FLAG表示发起连接请求
		//TCP中的第一次握手，回发SYN+ACK(第二次握手)
		if(stream->status == NG_TCP_STATUS_LISTEN){ //只有在LISTEN状态才处理，然后切换状态，这样同一个连接只会处理一次请求

			struct ng_tcp_table *table = tcpInstance();
			struct ng_tcp_stream *syn = ng_tcp_stream_create(iphdr->src_addr,iphdr->dst_addr,tcphdr->src_port,tcphdr->dst_port);
			LL_ADD(syn,table->tcb_set);

			struct ng_tcp_fragment *fragment = rte_malloc("ng_tcp_fragment",sizeof(struct ng_tcp_fragment),0);
			if(fragment == NULL) return -1;
			memset(fragment,0,sizeof(struct ng_tcp_fragment));

			//收到tcp 客户端发送的连接请求后，组装回复的包
			fragment->sport = tcphdr->dst_port;
			fragment->dport = tcphdr->src_port;

			struct in_addr addr;
			addr.s_addr = syn->sip;
			printf("tcp --->src_addr:%s src_port:%d\n",inet_ntoa(addr),ntohs(tcphdr->src_port));

			addr.s_addr = syn->dip;
			printf("tcp --->dst_addr:%s dst_port:%d\n",inet_ntoa(addr),ntohs(tcphdr->dst_port));

			fragment->seqnum = syn->snd_nxt;
			fragment->acknum = ntohl(tcphdr->sent_seq) + 1;
			syn->rcv_nxt = fragment->acknum;

			fragment->tcp_flags = (RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG);
			fragment->windows = TCP_INITIAL_WINDOW;
			fragment->hdrlen_off = 0x50;

			fragment->data = NULL;
			fragment->length = 0;

			//将要发送的数据fragment放入环形队列syn->sndbuf中，tcp_out会去sndbuf取数据
			rte_ring_mp_enqueue(syn->sndbuf,fragment);
			syn->status = NG_TCP_STATUS_SYN_RCVD;
		}
	}
	return 0;
}

static int ng_tcp_handle_syn_rcvd(struct ng_tcp_stream * stream,struct rte_tcp_hdr *tcphdr){
	if(tcphdr->tcp_flags & RTE_TCP_ACK_FLAG){
		//TCP中的第三次握手，收到ACK
		if(stream->status == NG_TCP_STATUS_SYN_RCVD){
			uint32_t acknum = ntohl(tcphdr->recv_ack);
			if(acknum == stream->snd_nxt +1){ //表示对端收到了序列号为stream->snd_nxt的数据包
				
			}
			//tcp 连接完成。状态切换为ESTABLISHED
			stream->status = NG_TCP_STATUS_ESTABLISHED;
			//accept
			struct ng_tcp_stream * listener = ng_tcp_stream_search(0,0,0,stream->dport);
			if(listener == NULL){
				rte_exit(EXIT_FAILURE,"ng_tcp_stream_search failed\n");
			}
			//
			pthread_mutex_lock(&listener->mutex);
			pthread_cond_signal(&listener->cond);
			pthread_mutex_unlock(&listener->mutex);
			

		}

	}
	return 0;
}

static int ng_tcp_enqueue_recvbuffer(struct ng_tcp_stream * stream,struct rte_tcp_hdr *tcphdr,int tcplen){
	//recv buffer
	struct ng_tcp_fragment * rfragment = rte_malloc("ng_tcp_fragment",sizeof(struct ng_tcp_fragment),0);
	if(rfragment == NULL) return -1;
	memset(rfragment,0,sizeof(struct ng_tcp_fragment));

	//从数据包中取出数据封装到rfragment中，在将rfragment入队到tcp的环形队列stream->rcvbuf中
	rfragment->dport = ntohs(tcphdr->dst_port);
	rfragment->sport = ntohs(tcphdr->src_port);

	uint8_t hdrlen = tcphdr->data_off >> 4; //tcphdr->data_off=0x54,这里hdrlen=5
	int payloadlen = tcplen-hdrlen *4;	//tcplen-tcp头部长度 = 数据长度

	if(payloadlen > 0){
		uint8_t *payload = (uint8_t *)tcphdr + hdrlen*4;
		rfragment->data = rte_malloc("unsigned char *",payloadlen+1,0);
		if(rfragment->data == NULL){
			rte_free(rfragment);
			return -1;
		}
		memset(rfragment->data, 0, payloadlen+1);
		rte_memcpy(rfragment->data,payload,payloadlen);
		rfragment->length = payloadlen;
	}else if(payloadlen == 0){
		rfragment->length = 0;
		rfragment->data = NULL;
	}
	rte_ring_mp_enqueue(stream->rcvbuf,rfragment);

	pthread_mutex_lock(&stream->mutex);
	pthread_cond_signal(&stream->cond);
	pthread_mutex_unlock(&stream->mutex);

	return 0;
}

static int ng_tcp_send_ackpkt(struct ng_tcp_stream *stream,struct rte_tcp_hdr *tcphdr){
	struct ng_tcp_fragment * ackfrag = rte_malloc("ng_tcp_fragment",sizeof(struct ng_tcp_fragment),0);
	if(ackfrag == NULL) return -1;
	memset(ackfrag,0,sizeof(struct ng_tcp_fragment));
	ackfrag->dport = tcphdr->src_port;
	ackfrag->sport = tcphdr->dst_port;
	//remote
	printf("ng_tcp_send_ackpkt :%d,%d\n",stream->rcv_nxt,ntohs(tcphdr->sent_seq));

	ackfrag->acknum = stream->rcv_nxt;
	ackfrag->seqnum = stream->snd_nxt;

	ackfrag->tcp_flags = RTE_TCP_ACK_FLAG;
	ackfrag->windows = TCP_INITIAL_WINDOW;
	ackfrag->hdrlen_off = 0x50;
	ackfrag->data = NULL;
	ackfrag->length = 0;

	rte_ring_mp_enqueue(stream->sndbuf,ackfrag);
	
	return 0;
}

static int ng_tcp_handle_established(struct ng_tcp_stream *stream,struct rte_tcp_hdr *tcphdr,int tcplen){
	if(tcphdr->tcp_flags & RTE_TCP_SYN_FLAG){
		//todo
	}
	if(tcphdr->tcp_flags & RTE_TCP_PSH_FLAG){
		//已经建立连接，且客户端要求此数据交给上层应用处理
		ng_tcp_enqueue_recvbuffer(stream,tcphdr,tcplen);
		//回ACK包
		uint8_t hdrlen = tcphdr->data_off >> 4;
		int payloadlen = tcplen-hdrlen * 4;
		stream->rcv_nxt = stream->rcv_nxt + payloadlen;
		stream->snd_nxt = ntohl(tcphdr->recv_ack);
		ng_tcp_send_ackpkt(stream,tcphdr);
	}
	if (tcphdr->tcp_flags & RTE_TCP_ACK_FLAG) {

	}
	if(tcphdr->tcp_flags & RTE_TCP_FIN_FLAG){ //表示结束连接
		stream->status = NG_TCP_STATUS_CLOSE_WAIT;
		ng_tcp_enqueue_recvbuffer(stream, tcphdr, tcphdr->data_off >> 4);
		//send ack pkt
		stream->rcv_nxt = stream->rcv_nxt + 1;
		stream->snd_nxt = ntohl(tcphdr->recv_ack);

		ng_tcp_send_ackpkt(stream,tcphdr);
	}
	return 0;
}

static int ng_tcp_handle_close_wait(struct ng_tcp_stream * stream,struct rte_tcp_hdr *tcphdr){
	if(tcphdr->tcp_flags & RTE_TCP_FIN_FLAG){
		if(stream->status == NG_TCP_STATUS_CLOSE_WAIT){

		}
	}

	return 0;
}

static int ng_tcp_handle_last_ack(struct ng_tcp_stream *stream, struct rte_tcp_hdr *tcphdr) {
	if(tcphdr->tcp_flags & RTE_TCP_ACK_FLAG){
		if(stream->status == NG_TCP_STATUS_LAST_ACK){
			stream->status = NG_TCP_STATUS_CLOSED;

			printf("ng_tcp_handle_last_ack\n");
			struct ng_tcp_table *table = tcpInstance();
			LL_REMOVE(stream,table->tcb_set);

			rte_ring_free(stream->sndbuf);
			rte_ring_free(stream->rcvbuf);

			rte_free(stream);
		}
	}

	return 0;
}

static int ng_tcp_process(struct rte_mbuf *tcpmbuf){
	//先偏移rte_ether_hdr，再强转为rte_ipv4_hdr
	struct rte_ipv4_hdr *iphdr = rte_pktmbuf_mtod_offset(tcpmbuf,struct rte_ipv4_hdr*,
		sizeof(struct rte_ether_hdr));
	//先偏移rte_ipv4_hdr，再强转为rte_tcp_hdr
	struct rte_tcp_hdr *tcphdr = (struct rte_tcp_hdr *)(iphdr+1);

	//计算校验和，如果不同说明数据包被损坏了
	uint16_t tcpcksum = tcphdr->cksum;
	tcphdr->cksum = 0;
	uint16_t cksum = rte_ipv4_udptcp_cksum(iphdr,tcphdr);
	if(cksum != tcpcksum){
		printf("cksum: %x,tcp cksum: %x\n",cksum,tcpcksum);
		return -1;
	}

	struct ng_tcp_stream *stream = ng_tcp_stream_search(iphdr->src_addr,iphdr->dst_addr,
	tcphdr->src_port,tcphdr->dst_port);
	if(stream == NULL){
		return -2;
	}
	switch (stream->status){

		case NG_TCP_STATUS_CLOSED: // client
			break;

		case NG_TCP_STATUS_LISTEN: //server 处理第一次握手，发送第二次握手
			ng_tcp_handle_listen(stream,tcphdr,iphdr);
			break;

		case NG_TCP_STATUS_SYN_RCVD: //server  处理第三次握手
			ng_tcp_handle_syn_rcvd(stream,tcphdr);
			break;

		case NG_TCP_STATUS_SYN_SENT: //client
			break;

		case NG_TCP_STATUS_ESTABLISHED: {//server client
			int tcplen = ntohs(iphdr->total_length) - sizeof(struct rte_ipv4_hdr);
			ng_tcp_handle_established(stream,tcphdr,tcplen);
			break;
		}

		case NG_TCP_STATUS_FIN_WAIT_1: // ~client
			break;

		case NG_TCP_STATUS_FIN_WAIT_2: //~client
			break;
			
		case NG_TCP_STATUS_CLOSING: // ~client
			break;
			
		case NG_TCP_STATUS_TIME_WAIT: // ~client
			break;

		case NG_TCP_STATUS_CLOSE_WAIT: //~server
			ng_tcp_handle_close_wait(stream,tcphdr);
			break;

		case NG_TCP_STATUS_LAST_ACK: //~server
			ng_tcp_handle_last_ack(stream,tcphdr);
			break;
		
	}
	return 0;
}

static int ng_encode_tcp_apppkt(uint8_t *msg, uint32_t sip, uint32_t dip,
	uint8_t *srcmac, uint8_t *dstmac, struct ng_tcp_fragment *fragment) {
	// encode 
	const unsigned total_len = fragment->length + sizeof(struct rte_ether_hdr) +
							sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_tcp_hdr) + 
							fragment->optlen * sizeof(uint32_t);
	// 1 ethhdr
	struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
	rte_memcpy(eth->s_addr.addr_bytes, srcmac, RTE_ETHER_ADDR_LEN);
	rte_memcpy(eth->d_addr.addr_bytes, dstmac, RTE_ETHER_ADDR_LEN);
	eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);
	
	// 2 iphdr 
	struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(msg + sizeof(struct rte_ether_hdr));
	ip->version_ihl = 0x45;
	ip->type_of_service = 0;
	ip->total_length = htons(total_len - sizeof(struct rte_ether_hdr));
	ip->packet_id = 0;
	ip->fragment_offset = 0;
	ip->time_to_live = 64; // ttl = 64
	ip->next_proto_id = IPPROTO_TCP;
	ip->src_addr = sip;
	ip->dst_addr = dip;
	
	ip->hdr_checksum = 0;
	ip->hdr_checksum = rte_ipv4_cksum(ip);

	// 3 tcphdr 
	struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)(msg + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
	tcp->src_port = fragment->sport;
	tcp->dst_port = fragment->dport;
	tcp->sent_seq = htonl(fragment->seqnum);
	tcp->recv_ack = htonl(fragment->acknum);

	tcp->data_off = fragment->hdrlen_off;
	tcp->rx_win = fragment->windows;
	tcp->tcp_urp = fragment->tcp_urp;
	tcp->tcp_flags = fragment->tcp_flags;

	if (fragment->data != NULL) {
		uint8_t *payload = (uint8_t*)(tcp+1) + fragment->optlen * sizeof(uint32_t);
		rte_memcpy(payload, fragment->data, fragment->length);
	}

	tcp->cksum = 0;
	tcp->cksum = rte_ipv4_udptcp_cksum(ip, tcp);

	return 0;
}


static struct rte_mbuf *ng_tcp_pkt(struct rte_mempool *mbuf_pool,uint32_t sip,uint32_t dip,
	uint8_t *srcmac,uint8_t *dstmac,struct ng_tcp_fragment *fragment){

	//TCP data + eth_hdr + ip_hdr + tcp_hdr +tcp option(可选字段)
	const unsigned total_len = fragment->length + sizeof(struct rte_ether_hdr) +
		sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_tcp_hdr) + 
							fragment->optlen * sizeof(uint32_t);
	struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
	if (!mbuf) {
		rte_exit(EXIT_FAILURE, "ng_tcp_pkt rte_pktmbuf_alloc\n");
	}
	mbuf->pkt_len = total_len;
	mbuf->data_len = total_len;

	uint8_t *pktdata = rte_pktmbuf_mtod(mbuf, uint8_t*);

	ng_encode_tcp_apppkt(pktdata, sip, dip, srcmac, dstmac, fragment);

	return mbuf;
}

//从stream->sndbuf 中取出数据包放入ring->out buf中
static int ng_tcp_out(struct rte_mempool *mbuf_pool) {
	struct ng_tcp_table *table = tcpInstance();
	struct ng_tcp_stream *stream;

	for(stream = table->tcb_set;stream !=NULL;stream = stream->next){
		if(stream->sndbuf == NULL) continue;

		struct ng_tcp_fragment *fragment = NULL;
		int nb_snd = rte_ring_mc_dequeue(stream->sndbuf,(void **)&fragment);
		if(nb_snd < 0) continue;

		uint8_t *dstmac = ng_get_dst_macaddr(stream->sip);
		if(dstmac == NULL){
			struct rte_mbuf *arpbuf = ng_send_arp(mbuf_pool,RTE_ARP_OP_REQUEST,gDefaultArpMac,
				stream->dip,stream->sip);

				struct inout_ring *ring = ringInstance();
				rte_ring_mp_enqueue_burst(ring->out, (void **)&arpbuf,1,NULL);
				rte_ring_mp_enqueue(stream->sndbuf,fragment);
		}else{
			struct rte_mbuf *tcpbuf = ng_tcp_pkt(mbuf_pool,stream->dip,stream->sip,stream->localmac,dstmac,fragment);
			struct inout_ring *ring = ringInstance();
			rte_ring_mp_enqueue_burst(ring->out,(void **)&tcpbuf,1,NULL);

			if(fragment->data != NULL)
				rte_free(fragment->data);
			rte_free(fragment);
		}
	}
	
	return 0;
}

#define BUFFER_SIZE	1024
static int tcp_server_entry(__attribute__((unused))  void *arg){

	int listenfd = nsocket(AF_INET, SOCK_STREAM, 0);
	if (listenfd == -1) {
		return -1;
	}

	struct sockaddr_in servaddr;
	memset(&servaddr,0,sizeof(struct sockaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(9999);

	nbind(listenfd,(struct sockaddr *)&servaddr,sizeof(servaddr));

	nlisten(listenfd,10);

	while(1){

		struct sockaddr_in client;
		socklen_t len = sizeof(client);
		int connfd = naccept(listenfd,(struct sockaddr *)&client,&len);

		char buff[BUFFER_SIZE] = {0};
		while(1){
			int n = nrecv(connfd,buff,BUFFER_SIZE,0);
			if(n > 0){
				printf("recv: %s\n",buff);
				nsend(connfd,buff,n,0);
			}else if(n == 0){
				nclose(connfd);
				break;
			}else{
				
			}
		}
	}
	nclose(listenfd);
}

#endif

int main(int argc,char *argv[]){
	//初始化EAL环境
	if(rte_eal_init(argc,argv) < 0 ){
		rte_exit(EXIT_FAILURE,"Error with EAL init\n");
	}
	//创建内存池
	struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("mbuf pool",NUM_MBUFS,
	0,0,RTE_MBUF_DEFAULT_BUF_SIZE,rte_socket_id());
	if(mbuf_pool == NULL){
		rte_exit(EXIT_FAILURE,"Could not create mbuf pool\n");
	}

	//mbuf_pool 是一个预先创建好的内存池，它将被用于接收队列来存储数据包的缓冲区
	ng_init_port(mbuf_pool);

	rte_eth_macaddr_get(gDpdkPortId, (struct rte_ether_addr *)gSrcMac);
#if ENABLE_TIMER
	rte_timer_subsystem_init();

	struct rte_timer arp_timer;
	rte_timer_init(&arp_timer);

	uint64_t hz = rte_get_timer_hz();//函数用于获取 DPDK 计时器的频率（每秒的计时器滴答数)
	unsigned lcore_id = rte_lcore_id();//取当前线程的 ID
	//当rte_timer_manage 函数触发定时器时，这里调用回调函数arp_request_timer_cb，mbuf_pool是回调函数的参数
	rte_timer_reset(&arp_timer, hz, PERIODICAL, lcore_id, arp_request_timer_cb, mbuf_pool);

#endif

#if ENABLE_RINGBUFFER
	struct inout_ring *ring = ringInstance();
	if(ring == NULL){
		rte_exit(EXIT_FAILURE,"ring buffer init failed\n");
	}
	if(ring->in == NULL){
		//rte_ring_create 创建环形队列 in ring是队列名字
		ring->in = rte_ring_create("in ring",RING_SIZE,rte_socket_id(),RING_F_SP_ENQ | RING_F_SC_DEQ);
	}
	if (ring->out == NULL) {
		ring->out = rte_ring_create("out ring",RING_SIZE,rte_socket_id(),RING_F_SP_ENQ | RING_F_SC_DEQ);
	}
#endif

#if ENABLE_MULTHREAD
	lcore_id不一样。可以分配不同cpu给线程，实现负载均衡
	lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
	//启动用户态协议栈中处理数据包的线程
	rte_eal_remote_launch(pkt_process,mbuf_pool,lcore_id);
#endif

#if ENABLE_UDP_APP
	lcore_id = rte_get_next_lcore(lcore_id,1,0);
	//启动udp server 线程
	rte_eal_remote_launch(udp_server_entry,mbuf_pool,lcore_id);
#endif

#if ENABLE_TCP_APP
	lcore_id = rte_get_next_lcore(lcore_id,1,0);
	//启动 tcp server线程
	rte_eal_remote_launch(tcp_server_entry,mbuf_pool,lcore_id);
#endif

	while(1){
		//对rx数据包的处理
		//mbufs用于存储数据包的缓冲区结构体
		//BURST_SIZE表示每次从网卡接收数据包的最大数量
		struct rte_mbuf *rx[BURST_SIZE];
		unsigned num_recvd = rte_eth_rx_burst(gDpdkPortId,0,rx,BURST_SIZE);
		if(num_recvd > BURST_SIZE){
			rte_exit(EXIT_FAILURE,"Error receving from eth\n");
		}else if(num_recvd > 0){
			//将收到的数据包送入ring_in buffer中
			rte_ring_sp_enqueue_burst(ring->in, (void **)rx,num_recvd,NULL);
		}

		//对tx数据包的处理,从ring out 中取出数据保存到tx中，然后再发送出去
		struct rte_mbuf *tx[BURST_SIZE];
		unsigned nb_tx = rte_ring_sc_dequeue_burst(ring->out,(void **)tx,BURST_SIZE,NULL);
		if(nb_tx > 0){
			rte_eth_tx_burst(gDpdkPortId,0,tx,nb_tx);
			unsigned i = 0;
			for(i = 0;i < nb_tx;i++){
				rte_pktmbuf_free(tx[i]);
			}
		}

#if ENABLE_TIMER
		static uint64_t prev_tsc = 0, cur_tsc;
		uint64_t diff_tsc;

		cur_tsc = rte_rdtsc();
		diff_tsc = cur_tsc - prev_tsc;
		if (diff_tsc > TIMER_RESOLUTION_CYCLES)  //定时60s
		{
			//检查所有已经注册的计时器，并对已经到期的计时器触发相应的回调函数,这里触发 arp_request_timer_cb
			rte_timer_manage();
			prev_tsc = cur_tsc;
		}
#endif
	}
	return 0;
}



