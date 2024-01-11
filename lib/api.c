#include <arpa/inet.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_timer.h>
#include <stdio.h>

#include "api.h"
#include "arp.h"
#include "dpdk.h"

static struct localhost *lhost = NULL;
unsigned char fd_table[MAX_FD_COUNT] = {0};

static struct localhost *get_hostinfo_fromip_port(uint32_t dip, uint16_t port,
                                                  uint8_t proto) {
  struct localhost *host;
  for (host = lhost; host != NULL; host = host->next) {
    if (dip == host->localip && port == host->localport &&
        proto == host->protocol) {
      return host;
    }
  }
  return NULL;
}

int get_fd_from_bitmap(void) {
  int fd = DEFAULT_FD_NUM;
  for (; fd < MAX_FD_COUNT; fd++) {
    //通过 (fd_table[fd/8]) 获取对应字节的位图，然后通过 (0x1 << (fd % 8))
    //计算出一个只有对应位为1的掩码，
    //与字节进行按位与运算。如果结果为0，表示该文件描述符可用
    if ((fd_table[fd / 8] & (0x1 << (fd % 8))) == 0) {
      //如果找到一个可用的文件描述符，将设置对应的位图为1，表示该文件描述符已被使用
      fd_table[fd / 8] |= (0x1 << (fd % 8));
      return fd;
    }
  }
  return -1;
}

int set_fd_frombitmap(int fd) {
  if (fd >= MAX_FD_COUNT) return -1;
  fd_table[fd / 8] &= ~(0x1 << (fd % 8));  //将特定位置0
  return 0;
}

struct ng_tcp_flow *get_accept_tcb(uint16_t dport) {
  for (int i = 0; i < tcb_table->num_flows; i++) {
    if (tcb_table->flows[i]->dport == dport) {
      return tcb_table->flows[i];
    }
  }
  return NULL;
}

void *get_hostinfo_from_fd(int sockfd) {
  // struct localhost *host;
  // for(host = lhost; host!=NULL;host = host->next){
  // 	if(sockfd == host->fd){
  // 		return host;
  // 	}
  // }
#if ENABLE_TCP_APP
  for (int i = 0; i < tcb_table->num_flows; i++) {
    if (tcb_table->flows[i]->fd == sockfd) {
      return tcb_table->flows[i];
      break;
    }
  }
#endif
  return NULL;
}
int nsocket_ring_init(struct localhost *host) {
  host->rcvbuf = rte_ring_create("recv buffer", RING_SIZE, rte_socket_id(),
                                 RING_F_SP_ENQ | RING_F_SC_DEQ);
  if (host->rcvbuf == NULL) {
    return -1;
  }
  host->sndbuf = rte_ring_create("send buffer", RING_SIZE, rte_socket_id(),
                                 RING_F_SP_ENQ | RING_F_SC_DEQ);
  if (host->sndbuf == NULL) {
    rte_ring_free(host->rcvbuf);
    return -1;
  }
  return 0;
}

int nsocket(__attribute__((unused)) int domain, int type,
            __attribute__((unused)) int protocol) {
  int fd = get_fd_from_bitmap();
  // UDP process
  if (type == SOCK_DGRAM) {
    struct localhost *host =
        rte_malloc("localhost", sizeof(struct localhost), 0);
    if (host == NULL) {
      return -1;
    }
    memset(host, 0, sizeof(struct localhost));

    host->fd = fd;

    host->protocol = IPPROTO_UDP;

    if (nsocket_ring_init(host) < 0) {
      rte_free(host);
      return -1;
    }

    //初始化互斥锁和条件变量，将空白的互斥锁和条件变量拷贝到 host
    //结构体的对应成员中
    pthread_cond_t blank_cond = PTHREAD_COND_INITIALIZER;
    rte_memcpy(&host->cond, &blank_cond, sizeof(pthread_cond_t));

    pthread_mutex_t blank_mutex = PTHREAD_MUTEX_INITIALIZER;
    rte_memcpy(&host->mutex, &blank_mutex, sizeof(pthread_mutex_t));

    LL_ADD(host, lhost);

  }
  // TCP process
  else if (type == SOCK_STREAM) {
    struct ng_tcp_flow *flow =
        flow_create(__default_ip, __default_port, __default_ip, __default_port);
    if (flow == NULL) {
      return -1;
    }

    flow->fd = fd;
    flow_table_half_add(tcb_table, flow);
  }

  return fd;
}
/*
将fd与网卡绑定
*/
int nbind(int sockfd, const struct sockaddr *addr,
          __attribute__((unused)) socklen_t addrlen) {
  void *hostinfo = get_hostinfo_from_fd(sockfd);
  if (hostinfo == NULL) return -1;

  struct localhost *host = (struct localhost *)hostinfo;
  if (host->protocol == IPPROTO_UDP) {
    const struct sockaddr_in *laddr = (const struct sockaddr_in *)addr;
    host->localport = laddr->sin_port;
    rte_memcpy(&host->localip, &laddr->sin_addr.s_addr, sizeof(uint32_t));
    rte_memcpy(host->localmac, gSrcMac, RTE_ETHER_ADDR_LEN);

  } else if (host->protocol == IPPROTO_TCP) {
    struct ng_tcp_flow *flow = (struct ng_tcp_flow *)hostinfo;

    const struct sockaddr_in *laddr = (const struct sockaddr_in *)addr;
    flow->dport = laddr->sin_port;
    rte_memcpy(&flow->dip, &laddr->sin_addr.s_addr, sizeof(uint32_t));
    rte_memcpy(flow->localmac, gSrcMac, RTE_ETHER_ADDR_LEN);

    flow->status = NG_TCP_STATUS_CLOSED;
    flow_table_hash_add(tcb_table, flow);
  }

  return 0;
}

//将一个套接字标识的 TCP 流设置为监听状态NG_TCP_STATUS_LISTEN
int nlisten(int sockfd, __attribute__((unused)) int backlog) {
  //从文件描述符获取与套接字相关的主机信息
  void *hostinfo = get_hostinfo_from_fd(sockfd);
  if (hostinfo == NULL) return -1;

  struct ng_tcp_flow *flow = (struct ng_tcp_flow *)hostinfo;
  if (flow->protocol == IPPROTO_TCP) {
    flow->status = NG_TCP_STATUS_LISTEN;
  }
  return 0;
}

//接受传入的 TCP
//连接请求，并返回一个新的套接字文件描述符，可以使用该描述符在新连接上进行通信
int naccept(int sockfd, struct sockaddr *addr,
            __attribute__((unused)) socklen_t *addrlen) {
  void *hostinfo = get_hostinfo_fromfd(sockfd);
  if (hostinfo == NULL) return -1;

  struct ng_tcp_flow *flow = (struct ng_tcp_flow *)hostinfo;
  if (flow->protocol == IPPROTO_TCP) {
    struct ng_tcp_flow *apt = NULL;

    pthread_mutex_lock(&flow->mutex);
    while ((apt = get_accept_tcb(flow->dport)) == NULL) {
      //在条件变量上等待，直到有连接可以接受
      pthread_cond_wait(&flow->cond, &flow->mutex);
    }
    pthread_mutex_unlock(&flow->mutex);

    //为新的连接分配一个文件描述符
    apt->fd = get_fd_from_bitmap();

    struct sockaddr_in *saddr = (struct sockaddr_in *)addr;
    saddr->sin_port = apt->sport;
    rte_memcpy(&saddr->sin_addr.s_addr, &apt->sip, sizeof(uint32_t));

    return apt->fd;
  }
  return -1;
}

//将数据发送到一个基于 TCP 的连接的发送缓冲区stream->sndbuf中
ssize_t nsend(int sockfd, const void *buf, size_t len,
              __attribute__((unused)) int flags) {
  ssize_t length = 0;

  void *hostinfo = get_hostinfo_fromfd(sockfd);
  if (hostinfo == NULL) return -1;

  struct ng_tcp_flow *flow = (struct ng_tcp_flow *)hostinfo;
  if (flow->protocol == IPPROTO_TCP) {
    struct ng_tcp_fragment *fragment =
        rte_malloc("ng_tcp_fragment", sizeof(struct ng_tcp_fragment), 0);
    if (fragment == NULL) {
      return -2;
    }

    memset(fragment, 0, sizeof(struct ng_tcp_fragment));

    fragment->dport = flow->sport;
    fragment->sport = flow->dport;

    fragment->acknum = flow->rcv_nxt;
    fragment->seqnum = flow->snd_nxt;

    fragment->tcp_flags = RTE_TCP_ACK_FLAG | RTE_TCP_PSH_FLAG;
    fragment->windows = TCP_INITIAL_WINDOW;
    fragment->hdrlen_off = 0x50;

    fragment->data = rte_malloc("unsigned char *", len + 1, 0);
    if (fragment->data == NULL) {
      rte_free(fragment);
      return -1;
    }
    memset(fragment->data, 0, len + 1);

    rte_memcpy(fragment->data, buf, len);
    fragment->length = len;
    length = fragment->length;

    // int nb_snd = 0;
    rte_ring_mp_enqueue(flow->sndbuf, fragment);
  }

  return length;
}

//从接收缓冲区stream->rcvbuf中接收数据，将数据复制到指定的缓冲区buf
ssize_t nrecv(int sockfd, void *buf, size_t len,
              __attribute__((unused)) int flags) {
  ssize_t length = 0;

  void *hostinfo = get_hostinfo_fromfd(sockfd);
  if (hostinfo == NULL) return -1;

  struct ng_tcp_flow *flow = (struct ng_tcp_flow *)hostinfo;
  if (flow->protocol == IPPROTO_TCP) {
    struct ng_tcp_fragment *fragment = NULL;
    int nb_rcv = 0;

    printf("rte_ring_mc_dequeue before\n");
    pthread_mutex_lock(&flow->mutex);
    while ((nb_rcv = rte_ring_mc_dequeue(flow->rcvbuf, (void **)&fragment)) <
           0) {
      pthread_cond_wait(&flow->cond, &flow->mutex);
    }
    pthread_mutex_unlock(&flow->mutex);
    printf("rte_ring_mc_dequeue after\n");

    if (fragment->length > len) {
      rte_memcpy(buf, fragment->data, len);

      uint32_t i = 0;
      for (i = 0; i < fragment->length - len; i++) {
        fragment->data[i] = fragment->data[len + i];
      }
      fragment->length = fragment->length - len;
      length = fragment->length;

      rte_ring_mp_enqueue(flow->rcvbuf, fragment);

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
我们自己实现的协议栈将数据放入rcvbuf中，udp
server中通过nrecvfrom函数取出数据到buf中
*/
ssize_t nrecvfrom(int sockfd, void *buf, size_t len,
                  __attribute__((unused)) int flags, struct sockaddr *src_addr,
                  __attribute__((unused)) socklen_t *addrlen) {
  struct localhost *host = get_hostinfo_fromfd(sockfd);
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
    ptr = rte_malloc("unsigned char *", ol->length - len, 0);
    rte_memcpy(ptr, ol->data + len, ol->length - len);

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
ssize_t nsendto(int sockfd, const void *buf, size_t len,
                __attribute__((unused)) int flags,
                const struct sockaddr *dest_addr,
                __attribute__((unused)) socklen_t addrlen) {
  struct localhost *host = get_hostinfo_fromfd(sockfd);
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

int nclose(int fd) {
  void *hostinfo = get_hostinfo_fromfd(fd);
  if (hostinfo == NULL) return -1;

  struct localhost *host = (struct localhost *)hostinfo;
  if (host->protocol == IPPROTO_UDP) {
    LL_REMOVE(host, lhost);

    if (host->rcvbuf) {
      rte_ring_free(host->rcvbuf);
    }
    if (host->sndbuf) {
      rte_ring_free(host->sndbuf);
    }

    rte_free(host);

    set_fd_frombitmap(fd);

  } else if (host->protocol == IPPROTO_TCP) {
    struct ng_tcp_flow *flow = (struct ng_tcp_flow *)hostinfo;

    if (flow->status != NG_TCP_STATUS_LISTEN) {
      struct ng_tcp_fragment *fragment =
          rte_malloc("ng_tcp_fragment", sizeof(struct ng_tcp_fragment), 0);
      if (fragment == NULL) return -1;

      printf("nclose --> enter last ack\n");
      fragment->data = NULL;
      fragment->length = 0;
      fragment->sport = flow->dport;
      fragment->dport = flow->sport;

      fragment->seqnum = flow->snd_nxt;
      fragment->acknum = flow->rcv_nxt;

      fragment->tcp_flags = RTE_TCP_FIN_FLAG | RTE_TCP_ACK_FLAG;
      fragment->windows = TCP_INITIAL_WINDOW;
      fragment->hdrlen_off = 0x50;

      //给客户端发送FIN，表明断开
      rte_ring_mp_enqueue(flow->sndbuf, fragment);
      flow->status = NG_TCP_STATUS_LAST_ACK;

      set_fd_frombitmap(fd);

    } else {  // nsocket

      flow_table_remove(tcb_table, flow);
    }
  }

  return 0;
}
