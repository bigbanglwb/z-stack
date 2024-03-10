#include <rte_malloc.h>
#include <stdint.h>

#include "tcp.h"

const uint32_t __default_ip = MAKE_IPV4_ADDR(0, 0, 0, 0);
const uint16_t __default_port = 0;

struct ng_flow_table *tcb_table = NULL;

static const struct rte_eth_conf port_conf_default = {
    .rxmode = {.mtu = RTE_ETHER_MAX_LEN}  // RTE_ETHER_MAX_LEN
                                          // 以太网数据中长度，一般为1518
};

int ng_flow_table_init() {
  struct rte_hash_parameters hash_params = {
      .name = "flow_table",
      .entries = FLOW_TABLE_SIZE,
      .key_len = sizeof(struct ng_tcp_flow_key),
      .hash_func = rte_jhash,
      .hash_func_init_val = 0,
  };

  struct rte_hash *hash = rte_hash_create(&hash_params);
  if (!hash) {
    printf("Error creating flow table hash.\n");
    return NULL;
  }

  struct ng_tcp_flow **flows = rte_malloc(
      "ng_tcp_flow", sizeof(struct ng_tcp_flow *) * FLOW_TABLE_SIZE, 0);
  if (!flows) {
    printf("Error allocating memory for flow cache.\n");
    rte_hash_free(hash);
    return NULL;
  }

  tcb_table = rte_malloc("ng_flow_table", sizeof(struct ng_flow_table), 0);
  if (!tcb_table) {
    printf("Error allocating memory for flow table.\n");
    rte_hash_free(hash);
    rte_free(flows);
    return NULL;
  }

  tcb_table->total_connect_flows = hash;
  tcb_table->half_connect_flows = flows;
  tcb_table->max_flows = FLOW_TABLE_SIZE;
}
struct ng_tcp_flow *flow_create(uint32_t src_ip, uint16_t src_port,
                                uint32_t dst_ip, uint16_t dst_port) {
  struct ng_tcp_flow *flow =
      rte_malloc("tcp_flow", sizeof(struct ng_tcp_flow), 0);
  if (!flow) {
    printf("Error allocating memory for new flow.\n");
    return NULL;
  }
  struct ng_tcp_flow_key *flow_key =
      rte_malloc("tcp_flow_key", sizeof(struct ng_tcp_flow), 0);

  flow_key->sip = src_ip;
  flow_key->sport = src_port;
  flow_key->dip = dst_ip;
  flow_key->dport = dst_port;

  flow->key = flow_key;
  flow->protocol = IPPROTO_TCP;

  flow->status = NG_TCP_STATUS_LISTEN;  // TCP server 初始状态
  printf("ng_tcp_flow_create\n");

  flow->sndbuf = rte_ring_create("sndbuf", RING_SIZE, rte_socket_id(), 0);
  flow->rcvbuf =
      rte_ring_create("rcvbuf", RING_SIZE, rte_socket_id(),
                      0);  // rte_socket_id保证申请的空间和当前线程在同一内存池

  // seq num TCP会用这个序号来拼接数据
  uint32_t next_seed = time(NULL);
  flow->snd_nxt = rand_r(&next_seed) % TCP_MAX_SEQ;
  rte_memcpy(flow->localmac, gSrcMac, RTE_ETHER_ADDR_LEN);

  //初始化条件变量
  pthread_cond_t blank_cond = PTHREAD_COND_INITIALIZER;
  rte_memcpy(&flow->cond, &blank_cond, sizeof(pthread_cond_t));

  //初始化锁
  pthread_mutex_t blank_mutex = PTHREAD_MUTEX_INITIALIZER;
  rte_memcpy(&flow->mutex, &blank_mutex, sizeof(pthread_mutex_t));

  return flow;
}

bool flow_table_remove(struct ng_flow_table *flow_table,
                       struct ng_tcp_flow *flow) {
  // 从哈希表中删除流对象
  int ret = rte_hash_del_key(flow_table->total_connect_flows, &flow->key);
  if (ret < 0) {
    printf("Error removing flow from hash table: %s\n", rte_strerror(abs(ret)));
    return false;
  }
  // 从半连接队列中删除流对象
  int i;
  for (i = 0; i < flow_table->num_flows; i++) {
    struct ng_tcp_flow_key *key = flow_table->half_connect_flows[i]->key;
    if (key->sip == flow->key->sip && key->sip == flow->key->dip) {
      free(flow_table->half_connect_flows[i]);
      break;
    }
  }
  if (i == flow_table->num_flows) {
    printf("Flow not found in cache.\n");
    return false;
  }
  flow_table->half_connect_flows[i] =
      flow_table->half_connect_flows[--flow_table->num_flows];
  rte_free(flow);
  rte_free(flow->key);
  return true;
}

// 将流对象添加到全连接队列中
bool flow_table_hash_add(struct ng_flow_table *flow_table,
                         struct ng_tcp_flow *flow) {
  // 检查是否已达到最大允许的流数
  if (flow_table->num_flows == flow_table->max_flows) {
    printf("Maximum number of flows reached.\n");
    return false;
  }
  // 将流对象加入哈希表
  int ret =
      rte_hash_add_key_data(flow_table->total_connect_flows, &flow->key, flow);
  if (ret < 0) {
    printf("Error adding flow to hash table: %s\n", rte_strerror(abs(ret)));
    free(flow);
    return false;
  }
  return true;
}

// 将流对象添加到半连接队列中
bool flow_table_half_add(struct ng_flow_table *flow_table,
                         struct ng_tcp_flow *flow) {
  // 检查是否已达到最大允许的流数
  if (flow_table->num_flows == flow_table->max_flows) {
    printf("Maximum number of flows reached.\n");
    return false;
  }
  // 将流对象加入缓存数组
  flow_table->half_connect_flows[flow_table->num_flows++] = flow;
  return true;
}

struct ng_tcp_flow *flow_table_hash_lookup(struct ng_flow_table *flow_table,
                                           uint32_t src_ip, uint32_t dst_ip,
                                           uint16_t sport, uint16_t dport) {}

static struct ng_tcp_flow *ng_tcp_flow_search(uint32_t sip, uint32_t dip,
                                              uint16_t sport, uint16_t dport) {
  struct ng_tcp_flow_key key = {
      .sip = sip, .dip = dip, .dport = dport, .sport = sport};

  struct ng_tcp_flow *flow;
  int ret = rte_hash_lookup_data(tcb_table->total_connect_flows, &key,
                                 (void **)&flow);
  if (ret != 0) {
    return flow;
  }
  // listen状态下sip.dip.doprt还没赋值
  key.sip = key.dip = __default_ip;
  key.dport = __default_port;
  ret = rte_hash_lookup_data(tcb_table->total_connect_flows, &key,
                             (void **)&flow);
  if (ret != 0) {
    return flow;
  }
  return NULL;

  // TODO

  // for(iter = table->tcb_set;iter != NULL;iter = iter->next){//
  // listen状态下sip.dip.soprt还没赋值 	if(iter->dport == dport && iter->status
  // == NG_TCP_STATUS_LISTEN){ 		return iter;
  // 	}
  // }
}

static int ng_tcp_handle_listen(struct ng_tcp_flow *flow,
                                struct rte_tcp_hdr *tcphdr,
                                struct rte_ipv4_hdr *iphdr) {
  if (tcphdr->tcp_flags &
      RTE_TCP_SYN_FLAG) {  // RTE_TCP_SYN_FLAG表示发起连接请求
    // TCP中的第一次握手，回发SYN+ACK(第二次握手)
    if (flow->status ==
        NG_TCP_STATUS_LISTEN) {  //只有在LISTEN状态才处理，然后切换状态，这样同一个连接只会处理一次请求

      struct ng_tcp_flow *syn = flow_create(iphdr->src_addr, iphdr->dst_addr,
                                            tcphdr->src_port, tcphdr->dst_port);
      flow_table_hash_add(tcb_table, syn);

      struct ng_tcp_fragment *fragment =
          rte_malloc("ng_tcp_fragment", sizeof(struct ng_tcp_fragment), 0);
      if (fragment == NULL) return -1;
      memset(fragment, 0, sizeof(struct ng_tcp_fragment));

      //收到tcp 客户端发送的连接请求后，组装回复的包
      fragment->sport = tcphdr->dst_port;
      fragment->dport = tcphdr->src_port;

      struct in_addr addr;
      addr.s_addr = syn->key->sip;
      printf("tcp --->src_addr:%s src_port:%d\n", inet_ntoa(addr),
             ntohs(tcphdr->src_port));

      addr.s_addr = syn->key->dip;
      printf("tcp --->dst_addr:%s dst_port:%d\n", inet_ntoa(addr),
             ntohs(tcphdr->dst_port));

      fragment->seqnum = syn->snd_nxt;
      fragment->acknum = ntohl(tcphdr->sent_seq) + 1;
      syn->rcv_nxt = fragment->acknum;

      fragment->tcp_flags = (RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG);
      fragment->windows = TCP_INITIAL_WINDOW;
      fragment->hdrlen_off = 0x50;

      fragment->data = NULL;
      fragment->length = 0;

      //将要发送的数据fragment放入环形队列syn->sndbuf中，tcp_out会去sndbuf取数据
      rte_ring_mp_enqueue(syn->sndbuf, fragment);
      syn->status = NG_TCP_STATUS_SYN_RCVD;
    }
  }
  return 0;
}

static int ng_tcp_handle_syn_rcvd(struct ng_tcp_flow *flow,
                                  struct rte_tcp_hdr *tcphdr) {
  if (tcphdr->tcp_flags & RTE_TCP_ACK_FLAG) {
    // TCP中的第三次握手，收到ACK
    if (flow->status == NG_TCP_STATUS_SYN_RCVD) {
      uint32_t acknum = ntohl(tcphdr->recv_ack);
      if (acknum ==
          flow->snd_nxt + 1) {  //表示对端收到了序列号为flow->snd_nxt的数据包
      }
      // tcp 连接完成。状态切换为ESTABLISHED
      flow->status = NG_TCP_STATUS_ESTABLISHED;
      // accept
      struct ng_tcp_flow *listener =
          ng_tcp_flow_search(0, 0, 0, flow->key->dport);
      if (listener == NULL) {
        rte_exit(EXIT_FAILURE, "ng_tcp_flow_search failed\n");
      }
      //
      pthread_mutex_lock(&listener->mutex);
      pthread_cond_signal(&listener->cond);
      pthread_mutex_unlock(&listener->mutex);
    }
  }
  return 0;
}

static int ng_tcp_enqueue_recvbuffer(struct ng_tcp_flow *flow,
                                     struct rte_tcp_hdr *tcphdr, int tcplen) {
  // recv buffer
  struct ng_tcp_fragment *rfragment =
      rte_malloc("ng_tcp_fragment", sizeof(struct ng_tcp_fragment), 0);
  if (rfragment == NULL) return -1;
  memset(rfragment, 0, sizeof(struct ng_tcp_fragment));

  //从数据包中取出数据封装到rfragment中，在将rfragment入队到tcp的环形队列flow->rcvbuf中
  rfragment->dport = ntohs(tcphdr->dst_port);
  rfragment->sport = ntohs(tcphdr->src_port);

  uint8_t hdrlen = tcphdr->data_off >> 4;  // tcphdr->data_off=0x54,这里hdrlen=5
  int payloadlen = tcplen - hdrlen * 4;  // tcplen-tcp头部长度 = 数据长度

  if (payloadlen > 0) {
    uint8_t *payload = (uint8_t *)tcphdr + hdrlen * 4;
    rfragment->data = rte_malloc("unsigned char *", payloadlen + 1, 0);
    if (rfragment->data == NULL) {
      rte_free(rfragment);
      return -1;
    }
    memset(rfragment->data, 0, payloadlen + 1);
    rte_memcpy(rfragment->data, payload, payloadlen);
    rfragment->length = payloadlen;
  } else if (payloadlen == 0) {
    rfragment->length = 0;
    rfragment->data = NULL;
  }
  rte_ring_mp_enqueue(flow->rcvbuf, rfragment);

  pthread_mutex_lock(&flow->mutex);
  pthread_cond_signal(&flow->cond);
  pthread_mutex_unlock(&flow->mutex);

  return 0;
}

static int ng_tcp_send_ackpkt(struct ng_tcp_flow *flow,
                              struct rte_tcp_hdr *tcphdr) {
  struct ng_tcp_fragment *ackfrag =
      rte_malloc("ng_tcp_fragment", sizeof(struct ng_tcp_fragment), 0);
  if (ackfrag == NULL) return -1;
  memset(ackfrag, 0, sizeof(struct ng_tcp_fragment));
  ackfrag->dport = tcphdr->src_port;
  ackfrag->sport = tcphdr->dst_port;
  // remote
  printf("ng_tcp_send_ackpkt :%d,%d\n", flow->rcv_nxt, ntohs(tcphdr->sent_seq));

  ackfrag->acknum = flow->rcv_nxt;
  ackfrag->seqnum = flow->snd_nxt;

  ackfrag->tcp_flags = RTE_TCP_ACK_FLAG;
  ackfrag->windows = TCP_INITIAL_WINDOW;
  ackfrag->hdrlen_off = 0x50;
  ackfrag->data = NULL;
  ackfrag->length = 0;

  rte_ring_mp_enqueue(flow->sndbuf, ackfrag);

  return 0;
}

static int ng_tcp_handle_established(struct ng_tcp_flow *flow,
                                     struct rte_tcp_hdr *tcphdr, int tcplen) {
  if (tcphdr->tcp_flags & RTE_TCP_SYN_FLAG) {
    // todo
  }
  if (tcphdr->tcp_flags & RTE_TCP_PSH_FLAG) {
    //已经建立连接，且客户端要求此数据交给上层应用处理
    ng_tcp_enqueue_recvbuffer(flow, tcphdr, tcplen);
    //回ACK包
    uint8_t hdrlen = tcphdr->data_off >> 4;
    int payloadlen = tcplen - hdrlen * 4;
    flow->rcv_nxt = flow->rcv_nxt + payloadlen;
    flow->snd_nxt = ntohl(tcphdr->recv_ack);
    ng_tcp_send_ackpkt(flow, tcphdr);
  }
  if (tcphdr->tcp_flags & RTE_TCP_ACK_FLAG) {
  }
  if (tcphdr->tcp_flags & RTE_TCP_FIN_FLAG) {  //表示结束连接
    flow->status = NG_TCP_STATUS_CLOSE_WAIT;
    ng_tcp_enqueue_recvbuffer(flow, tcphdr, tcphdr->data_off >> 4);
    // send ack pkt
    flow->rcv_nxt = flow->rcv_nxt + 1;
    flow->snd_nxt = ntohl(tcphdr->recv_ack);

    ng_tcp_send_ackpkt(flow, tcphdr);
  }
  return 0;
}

static int ng_tcp_handle_close_wait(struct ng_tcp_flow *flow,
                                    struct rte_tcp_hdr *tcphdr) {
  if (tcphdr->tcp_flags & RTE_TCP_FIN_FLAG) {
    if (flow->status == NG_TCP_STATUS_CLOSE_WAIT) {
    }
  }

  return 0;
}

static int ng_tcp_handle_last_ack(struct ng_tcp_flow *flow,
                                  struct rte_tcp_hdr *tcphdr) {
  if (tcphdr->tcp_flags & RTE_TCP_ACK_FLAG) {
    if (flow->status == NG_TCP_STATUS_LAST_ACK) {
      flow->status = NG_TCP_STATUS_CLOSED;

      printf("ng_tcp_handle_last_ack\n");

      flow_table_remove(tcb_table, flow);

      rte_ring_free(flow->sndbuf);
      rte_ring_free(flow->rcvbuf);

      rte_free(flow);
    }
  }

  return 0;
}

int ng_tcp_process(struct rte_mbuf *tcpmbuf) {
  //先偏移rte_ether_hdr，再强转为rte_ipv4_hdr
  struct rte_ipv4_hdr *iphdr = rte_pktmbuf_mtod_offset(
      tcpmbuf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
  //先偏移rte_ipv4_hdr，再强转为rte_tcp_hdr
  struct rte_tcp_hdr *tcphdr = (struct rte_tcp_hdr *)(iphdr + 1);

  //计算校验和，如果不同说明数据包被损坏了
  uint16_t tcpcksum = tcphdr->cksum;
  tcphdr->cksum = 0;
  uint16_t cksum = rte_ipv4_udptcp_cksum(iphdr, tcphdr);
  if (cksum != tcpcksum) {
    printf("cksum: %x,tcp cksum: %x\n", cksum, tcpcksum);
    return -1;
  }
  // handle received packet, src -> dst/ dst -> src
  struct ng_tcp_flow *flow = ng_tcp_flow_search(
      iphdr->dst_addr, iphdr->src_addr, tcphdr->dst_port, tcphdr->src_port);
  if (flow == NULL) {
    return -2;
  }
  switch (flow->status) {
    case NG_TCP_STATUS_CLOSED:  // client
      break;

    case NG_TCP_STATUS_LISTEN:  // server 处理第一次握手，发送第二次握手
      ng_tcp_handle_listen(flow, tcphdr, iphdr);
      break;

    case NG_TCP_STATUS_SYN_RCVD:  // server  处理第三次握手
      ng_tcp_handle_syn_rcvd(flow, tcphdr);
      break;

    case NG_TCP_STATUS_SYN_SENT:  // client
      break;

    case NG_TCP_STATUS_ESTABLISHED: {  // server client
      int tcplen = ntohs(iphdr->total_length) - sizeof(struct rte_ipv4_hdr);
      ng_tcp_handle_established(flow, tcphdr, tcplen);
      break;
    }

    case NG_TCP_STATUS_FIN_WAIT_1:  // ~client
      break;

    case NG_TCP_STATUS_FIN_WAIT_2:  //~client
      break;

    case NG_TCP_STATUS_CLOSING:  // ~client
      break;

    case NG_TCP_STATUS_TIME_WAIT:  // ~client
      break;

    case NG_TCP_STATUS_CLOSE_WAIT:  //~server
      ng_tcp_handle_close_wait(flow, tcphdr);
      break;

    case NG_TCP_STATUS_LAST_ACK:  //~server
      ng_tcp_handle_last_ack(flow, tcphdr);
      break;
  }
  return 0;
}

static int ng_encode_tcp_apppkt(uint8_t *msg, uint32_t sip, uint32_t dip,
                                uint8_t *srcmac, uint8_t *dstmac,
                                struct ng_tcp_fragment *fragment) {
  // encode
  const unsigned total_len = fragment->length + sizeof(struct rte_ether_hdr) +
                             sizeof(struct rte_ipv4_hdr) +
                             sizeof(struct rte_tcp_hdr) +
                             fragment->optlen * sizeof(uint32_t);
  // 1 ethhdr
  struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
  rte_memcpy(eth->src_addr.addr_bytes, srcmac, RTE_ETHER_ADDR_LEN);
  rte_memcpy(eth->dst_addr.addr_bytes, dstmac, RTE_ETHER_ADDR_LEN);
  eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);

  // 2 iphdr
  struct rte_ipv4_hdr *ip =
      (struct rte_ipv4_hdr *)(msg + sizeof(struct rte_ether_hdr));
  ip->version_ihl = 0x45;
  ip->type_of_service = 0;
  ip->total_length = htons(total_len - sizeof(struct rte_ether_hdr));
  ip->packet_id = 0;
  ip->fragment_offset = 0;
  ip->time_to_live = 64;  // ttl = 64
  ip->next_proto_id = IPPROTO_TCP;
  ip->src_addr = sip;
  ip->dst_addr = dip;

  ip->hdr_checksum = 0;
  ip->hdr_checksum = rte_ipv4_cksum(ip);

  // 3 tcphdr
  struct rte_tcp_hdr *tcp =
      (struct rte_tcp_hdr *)(msg + sizeof(struct rte_ether_hdr) +
                             sizeof(struct rte_ipv4_hdr));
  tcp->src_port = fragment->sport;
  tcp->dst_port = fragment->dport;
  tcp->sent_seq = htonl(fragment->seqnum);
  tcp->recv_ack = htonl(fragment->acknum);

  tcp->data_off = fragment->hdrlen_off;
  tcp->rx_win = fragment->windows;
  tcp->tcp_urp = fragment->tcp_urp;
  tcp->tcp_flags = fragment->tcp_flags;

  if (fragment->data != NULL) {
    uint8_t *payload =
        (uint8_t *)(tcp + 1) + fragment->optlen * sizeof(uint32_t);
    rte_memcpy(payload, fragment->data, fragment->length);
  }

  tcp->cksum = 0;
  tcp->cksum = rte_ipv4_udptcp_cksum(ip, tcp);

  return 0;
}

static struct rte_mbuf *ng_tcp_pkt(struct rte_mempool *mbuf_pool, uint32_t sip,
                                   uint32_t dip, uint8_t *srcmac,
                                   uint8_t *dstmac,
                                   struct ng_tcp_fragment *fragment) {
  // TCP data + eth_hdr + ip_hdr + tcp_hdr +tcp option(可选字段)
  const unsigned total_len = fragment->length + sizeof(struct rte_ether_hdr) +
                             sizeof(struct rte_ipv4_hdr) +
                             sizeof(struct rte_tcp_hdr) +
                             fragment->optlen * sizeof(uint32_t);
  struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
  if (!mbuf) {
    rte_exit(EXIT_FAILURE, "ng_tcp_pkt rte_pktmbuf_alloc\n");
  }
  mbuf->pkt_len = total_len;
  mbuf->data_len = total_len;

  uint8_t *pktdata = rte_pktmbuf_mtod(mbuf, uint8_t *);

  ng_encode_tcp_apppkt(pktdata, sip, dip, srcmac, dstmac, fragment);

  return mbuf;
}

//从flow->sndbuf 中取出数据包放入ring->out buf中
int ng_tcp_out(struct rte_mempool *mbuf_pool) {
  struct ng_tcp_flow *flow;

  for (flow = table->tcb_set; flow != NULL; flow = flow->next) {
    if (flow->sndbuf == NULL) continue;

    struct ng_tcp_fragment *fragment = NULL;
    int nb_snd = rte_ring_mc_dequeue(flow->sndbuf, (void **)&fragment);
    if (nb_snd < 0) continue;

    uint8_t *dstmac = zs_get_dst_macaddr(flow->sip)->addr_bytes;
    if (dstmac == NULL) {
      struct rte_mbuf *arpbuf =
          ng_send_arp(mbuf_pool, RTE_ARP_OP_REQUEST,
                      (uint8_t *)__default_dst_mac, flow->dip, flow->sip);
      zs_l2_send(&arpbuf, 1);
      rte_ring_mp_enqueue(flow->sndbuf, fragment);
    } else {
      struct rte_mbuf *tcpbuf = ng_tcp_pkt(mbuf_pool, flow->dip, flow->sip,
                                           flow->localmac, dstmac, fragment);

      zs_l2_send(&tcpbuf, 1);
      if (fragment->data != NULL) rte_free(fragment->data);
      rte_free(fragment);
    }
  }

  return 0;
}
