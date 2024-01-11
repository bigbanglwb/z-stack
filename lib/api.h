#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_timer.h>
#include <stdio.h>
#include <arpa/inet.h>
#include "arp.h"
#include "dpdk.h"
#include "tcp.h"
#include "udp.h"

#ifndef _API_H_
#define _API_H_


#define DEFAULT_FD_NUM 3
#define MAX_FD_COUNT 1024
struct localhost{
	int fd;
	uint8_t protocol;
	uint32_t localip;
	uint8_t localmac[RTE_ETHER_ADDR_LEN];
	uint16_t localport;
	struct rte_ring *sndbuf;
	struct rte_ring *rcvbuf;
	struct localhost *prev;
	struct localhost *next;
	pthread_cond_t cond;
	pthread_mutex_t mutex;
};

extern unsigned char fd_table[MAX_FD_COUNT];
// extern struct localhost *lhost;

int get_fd_from_bitmap(void);

int set_fd_frombitmap(int fd);

struct ng_tcp_flow *get_accept_tcb(uint16_t dport);

void* get_hostinfo_fromfd(int sockfd);


int nsocket(__attribute__((unused)) int domain, int type, __attribute__((unused))  int protocol) ;

int nbind(int sockfd, const struct sockaddr *addr,
                __attribute__((unused))  socklen_t addrlen) ;

int nlisten(int sockfd,__attribute__((unused)) int backlog);

int naccept(int sockfd, struct sockaddr *addr, __attribute__((unused)) socklen_t *addrlen);

ssize_t nsend(int sockfd, const void *buf, size_t len,__attribute__((unused)) int flags) ;


ssize_t nrecv(int sockfd, void *buf, size_t len, __attribute__((unused)) int flags) ;

ssize_t nrecvfrom(int sockfd, void *buf, size_t len, __attribute__((unused))  int flags,
                        struct sockaddr *src_addr, __attribute__((unused))  socklen_t *addrlen) ;

ssize_t nsendto(int sockfd, const void *buf, size_t len, __attribute__((unused))  int flags,
                      const struct sockaddr *dest_addr, __attribute__((unused))  socklen_t addrlen);
int nclose(int fd) ;

#endif  // _API_H_