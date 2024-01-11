#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_timer.h>
#include <stdint.h>
#include <arpa/inet.h>
#include "arp.h"
#include "dpdk.h"
#include <rte_ether.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#ifndef  _TCP_H_
#define _TCP_H_


#define NUM_MBUFS (4096-1)
#define BURST_SIZE	32
#define RING_SIZE	1024
#define TIMER_RESOLUTION_CYCLES 120000000000ULL // 10ms * 1000 = 10s * 6 
#define FLOW_TABLE_SIZE 1024
#if ENABLE_SEND
#define MAKE_IPV4_ADDR(a, b, c, d) (a + (b<<8) + (c<<16) + (d<<24))
static uint32_t gLocalIp = MAKE_IPV4_ADDR(192, 168, 101, 83);


static uint8_t gSrcMac[RTE_ETHER_ADDR_LEN];

#endif


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
struct ng_tcp_flow_key{
	uint32_t sip;
	uint32_t dip;
	uint16_t sport;
	uint16_t dport;
};
struct ng_tcp_flow{
	int fd;
	int protocol;
	struct ng_tcp_flow_key *key;
	uint8_t localmac[RTE_ETHER_ADDR_LEN];
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

struct ng_flow_table{
	struct ng_tcp_flow **half_connect_flows;
	struct rte_hash * total_connect_flows;	
	unsigned int num_flows;
	unsigned int max_flows;
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



extern struct ng_flow_table *tcb_table;
extern const uint32_t __default_ip;
extern const uint16_t __default_port;
int ng_tcp_process(struct rte_mbuf *tcpmbuf);
int ng_tcp_out(struct rte_mempool *mbuf_pool);
bool flow_table_half_add(struct ng_flow_table * flow_table, struct ng_tcp_flow * flow);
bool flow_table_hash_add(struct ng_flow_table * flow_table, struct ng_tcp_flow * flow);
struct ng_tcp_flow * flow_create(uint32_t src_ip, uint16_t src_port, uint32_t dst_ip, uint16_t dst_port);
bool flow_table_remove(struct ng_flow_table * flow_table, struct ng_tcp_flow * flow);
struct ng_tcp_flow * flow_table_lookup(struct ng_flow_table  * flow_table, uint32_t src_ip, uint32_t dst_ip,uint16_t sport,uint16_t dport);
#endif // _TCP_H_