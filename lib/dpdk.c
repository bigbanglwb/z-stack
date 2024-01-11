/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2016 Intel Corporation
 */


#include "dpdk.h"








bool force_quit ;

/* Ports set in promiscuous mode off by default. */
static int promiscuous_on;
static const char *_MSG_POOL = "MSG_POOL";
static const char *_RECV_RING = "RECV_RING";
static const char *_SEND_RING = "SEND_RING";
static const int _MAX_MSG_BUF_SIZE = 10240;

#define RTE_LOGTYPE_ZSTACK RTE_LOGTYPE_USER1

#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */
#define MEMPOOL_CACHE_SIZE 256
#define MSG_NUM 10
#define RX_DESC_DEFAULT 1024
#define TX_DESC_DEFAULT 1024
#define NB_SOCKETS 8
#define MAX_RX_QUEUE_PER_LCORE 16
#define MAX_TX_QUEUE_PER_PORT 16

static uint16_t nb_rxd = RX_DESC_DEFAULT;
static uint16_t nb_txd = TX_DESC_DEFAULT;

struct rte_ring *send_ring, *recv_ring;
static struct rte_mempool *message_pool;
struct rte_mempool *pktmbuf_pool;

static unsigned int rx_queue_per_lcore = 1;

struct lcore_conf {
  uint16_t proc_id;
  uint16_t socket_id;
  uint16_t port_id;
  uint16_t tx_queue_id;
  uint16_t rx_queue_id;
  struct rte_eth_dev_tx_buffer *tx_buffer[RTE_MAX_ETHPORTS];
} __rte_cache_aligned;

struct lcore_conf lcore_conf[RTE_MAX_LCORE];

static struct rte_eth_dev_tx_buffer *tx_buffer[RTE_MAX_ETHPORTS];

static struct rte_eth_conf port_conf = {
    .txmode =
        {
            .mq_mode = RTE_ETH_MQ_TX_NONE,
        },
};

/* Per-port statistics struct */
struct zstack_port_statistics {
  uint64_t tx;
  uint64_t rx;
  uint64_t dropped;
  uint64_t recv_ring_enq;
  uint64_t recv_ring_deq;
  uint64_t send_ring_enq;
  uint64_t send_ring_deq;
} __rte_cache_aligned;
struct zstack_port_statistics port_statistics[RTE_MAX_ETHPORTS];

#define MAX_TIMER_PERIOD 86400 /* 1 day max */
/* A tsc-based timer responsible for triggering statistics printout */


/* Print out statistics on packets dropped */
void print_stats(void) {
  uint64_t total_packets_dropped, total_packets_tx, total_packets_rx;
  unsigned port_id;

  total_packets_dropped = 0;
  total_packets_tx = 0;
  total_packets_rx = 0;

  const char clr[] = {27, '[', '2', 'J', '\0'};
  const char topLeft[] = {27, '[', '1', ';', '1', 'H', '\0'};

  // /* Clear screen and move to top left */
  // printf("%s%s", clr, topLeft);

  printf("\nPort statistics ====================================");

  for (port_id = 0; port_id < RTE_MAX_ETHPORTS; port_id++) {
    /* skip disabled ports */
    /* hard code */
    if (port_id != 0)
			continue;
    printf(
        "\nStatistics for port %u ------------------------------"
        "\nPackets sent: %24" PRIu64 
        "\nPackets received: %20" PRIu64
        "\nPackets dropped: %21" PRIu64
        "\nRecv ring enq: %23" PRIu64 
        "\nRecv ring deq: %23" PRIu64
        "\nSend ring enq: %23" PRIu64 
        "\nSend ring deq: %23" PRIu64,
        port_id, port_statistics[port_id].tx, 
        port_statistics[port_id].rx,
        port_statistics[port_id].dropped, 
        port_statistics[port_id].recv_ring_enq,
        port_statistics[port_id].recv_ring_deq,
        port_statistics[port_id].send_ring_enq,
        port_statistics[port_id].send_ring_deq);

    total_packets_dropped += port_statistics[port_id].dropped;
    total_packets_tx += port_statistics[port_id].tx;
    total_packets_rx += port_statistics[port_id].rx;
  }
  printf(
      "\nAggregate statistics ==============================="
      "\nTotal packets sent: %18" PRIu64 "\nTotal packets received: %14" PRIu64
      "\nTotal packets dropped: %15" PRIu64,
      total_packets_tx, total_packets_rx, total_packets_dropped);
  printf("\n====================================================\n");

  fflush(stdout);
}

struct rte_mbuf * zs_malloc_mbuf(){
  struct rte_mbuf *mbuf;
  mbuf = rte_pktmbuf_alloc(pktmbuf_pool);
  if (mbuf == NULL) {
      rte_exit(EXIT_FAILURE, "Cannot allocate mbuf\n");
    }
  return mbuf;
}

int zs_malloc_mbufs(struct rte_mbuf ** mbufs,int num){
  mbufs = rte_malloc(NULL, sizeof(struct rte_mbuf *) * num, 0);
  if (mbufs == NULL) {
    rte_exit(EXIT_FAILURE, "Cannot allocate mbufs\n");
  }
  for (int i = 0; i < num; i++) {
    mbufs[i] = rte_pktmbuf_alloc(pktmbuf_pool);
    if (mbufs[i] == NULL) {
      rte_exit(EXIT_FAILURE, "Cannot allocate mbuf\n");
    }
  }
  return 0;
}

int zs_l2_recv(struct rte_mbuf **pkts_buf){
  int nb_ring_deq;
  nb_ring_deq = rte_ring_dequeue_bulk(recv_ring, (void **)pkts_buf, MAX_PKT_BURST, NULL);
  port_statistics[zs_global_cfg.dpdk.port_id].recv_ring_deq += nb_ring_deq;
  return nb_ring_deq;
}

int zs_l2_send(struct rte_mbuf **pkts_buf,int pkt_num) {
  int ret = 0;
  
  while (pkt_num != ret) {
    ret +=  rte_ring_enqueue_bulk(send_ring, (void **)pkts_buf + ret, pkt_num - ret, NULL);
  }
  port_statistics[zs_global_cfg.dpdk.port_id].send_ring_enq += ret;
  return ret;
}


/* main processing loop */
static void main_loop(void) {
  
  struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
  struct rte_mbuf *tx_burst[MAX_PKT_BURST];
  struct rte_eth_dev_tx_buffer *buffer;
  unsigned lcore_id;
  unsigned nb_rx,nb_tx;
  unsigned port_id;
  unsigned rx_queue_id,tx_queue_id;
  const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S *
			BURST_TX_DRAIN_US;
  uint64_t prev_tsc, diff_tsc, cur_tsc, timer_tsc;
  unsigned sent;

  timer_tsc = 0;
  diff_tsc = 0;
  prev_tsc = 0;
  cur_tsc = 0;

  lcore_id = rte_lcore_id();
  port_id = lcore_conf[lcore_id].port_id;
  rx_queue_id = lcore_conf[lcore_id].rx_queue_id;
  tx_queue_id = lcore_conf[lcore_id].tx_queue_id;

  printf("lcore_id=%u,port_id=%u,rx_queue_id=%u,tx_queue_id=%u,drain_tsc=%lu, enter main loop\n",lcore_id,port_id,rx_queue_id,tx_queue_id,drain_tsc);

  while (!force_quit) {

    
    sent = 0;

    cur_tsc = rte_rdtsc();

    diff_tsc = cur_tsc - prev_tsc;

    timer_tsc += diff_tsc;

    prev_tsc =  cur_tsc; 

    
    if (unlikely(timer_tsc >= zs_global_cfg.timer_period))
    {
      // printf("lcore:%d,timer_tsc:%lu,zs_global_cfg.timer_period:%lu\n",rte_lcore_id(),timer_tsc,zs_global_cfg.timer_period);
      
    }
    
    // send packet in txbuf

    if (unlikely(diff_tsc >= 500)) {
      buffer = lcore_conf[lcore_id].tx_buffer[port_id];
      nb_tx = rte_ring_dequeue_burst(send_ring, (void **)tx_burst, MAX_PKT_BURST, NULL);
      port_statistics[zs_global_cfg.dpdk.port_id].send_ring_deq += nb_tx;

      for (int i = 0;i < nb_tx; i++)
      { 
        sent += rte_eth_tx_buffer(port_id, tx_queue_id, buffer, tx_burst[i]);
      }
        
      
      sent += rte_eth_tx_buffer_flush(port_id, tx_queue_id, buffer);
			if (sent)
        port_statistics[port_id].tx += sent;
    }


    
    // recv from queue
    nb_rx = rte_eth_rx_burst(port_id, rx_queue_id, pkts_burst, MAX_PKT_BURST);
    
    // struct rte_eth_stats *stats;
    // rte_eth_stats_get(port_id, stats);
    
    if (unlikely(timer_tsc >= zs_global_cfg.timer_period))
    {
      // printf("lcore %u: recv packet=%u\n",lcore_id,nb_rx);
      timer_tsc = 0;
    }

    if (unlikely(nb_rx == 0)) 
      continue;
    

    
    port_statistics[port_id].rx += nb_rx;
    unsigned nb_ring_enq = 0;
    while (nb_rx > 0 && !force_quit) {
      nb_ring_enq = rte_ring_enqueue_bulk(recv_ring, (void **)pkts_burst, nb_rx, NULL);
      nb_rx -= nb_ring_enq;
      port_statistics[port_id].recv_ring_enq += nb_ring_enq;
    }
    
    
    
    
    


  }
}
static int zstack_launch_one_lcore(__rte_unused void *dummy) {
  main_loop();
  return 0;
}




int dpdk_close() {
  int port_id = 0, ret;
  unsigned lcore_id;
  RTE_LCORE_FOREACH_WORKER(lcore_id) {
  if (rte_eal_wait_lcore(lcore_id) < 0) {
      ret = -1;
      break;
    }
  }


  for (int i = 0; i < RTE_MAX_ETHPORTS; i++) {
    if (tx_buffer[i] != NULL) {
      rte_free(tx_buffer[i]);
      tx_buffer[i] = NULL;
    }
  }
  RTE_ETH_FOREACH_DEV(port_id) {
    printf("Closing port %d...", port_id);

    ret = rte_eth_dev_stop(port_id);
    if (ret != 0) printf("rte_eth_dev_stop: err=%d, port=%d\n", ret, port_id);
    rte_eth_dev_close(port_id);
    printf(" Done\n");
  }

  /* clean up the EAL */
  rte_eal_cleanup();
  printf("Bye...\n");

  return ret;
}
int init_msg_ring(void) {
  const unsigned flags = 0;
  const unsigned ring_size = 64;
  const unsigned pool_size = 1024;
  const unsigned pool_cache = 32;
  const unsigned priv_data_sz = 0;

  /* Start of ring structure. 8< */
  if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
    send_ring = rte_ring_create(_SEND_RING, ring_size, rte_socket_id(), flags);
    recv_ring = rte_ring_create(_RECV_RING, ring_size, rte_socket_id(), flags);
    message_pool = rte_mempool_create(_MSG_POOL, pool_size*10, _MAX_MSG_BUF_SIZE,
                                      pool_cache, priv_data_sz, NULL, NULL,
                                      NULL, NULL, rte_socket_id(), flags);
  } else {
    recv_ring = rte_ring_lookup(_RECV_RING);
    send_ring = rte_ring_lookup(_SEND_RING);
    message_pool = rte_mempool_lookup(_MSG_POOL);
  }

  if (send_ring == NULL)
    rte_exit(EXIT_FAILURE, "Problem getting sending ring\n");
  if (recv_ring == NULL)
    rte_exit(EXIT_FAILURE, "Problem getting receiving ring\n");
  if (message_pool == NULL)
    rte_exit(EXIT_FAILURE, "Problem getting message pool\n");

  RTE_LOG(INFO, ZSTACK, "Finished Process Init.\n");

  return 0;
}

/* Main functional part of port initialization. 8< */
static inline int port_init(uint16_t port_id, struct rte_mempool *mbuf_pool) {
  
  struct rte_eth_dev_info dev_info;
  struct rte_eth_txconf txconf;
  struct rte_eth_rxconf rxconf;
  unsigned rx_rings = 1, tx_rings = 1;
  unsigned lcore_id;
  unsigned nb_lcores;
  int ret;

  nb_lcores = zs_global_cfg.dpdk.nb_lcores;

  struct rte_eth_conf port_conf = {
      .rxmode = {.mq_mode = RTE_ETH_MQ_RX_RSS},
      .rx_adv_conf = {.rss_conf = {
                         .rss_key = NULL,
                         .rss_hf = RTE_ETH_RSS_IPV4
         }
      }
    };

  if (!rte_eth_dev_is_valid_port(port_id)) return -1;
  
  ret = rte_eth_dev_info_get(port_id, &dev_info);
  if (ret < 0) {
    printf("Error during getting device (port %u) info: %s\n", port_id,
           strerror(-ret));
    return ret;
  }

  if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
    port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;
  
  
  
  rx_rings = tx_rings = nb_lcores;
  printf("rx_rings=%u,tx_rings=%u\n",rx_rings,tx_rings);
  /* Configure the Ethernet device. */
  ret = rte_eth_dev_configure(port_id, rx_rings, tx_rings, &port_conf);
  if (ret != 0)
    rte_exit(EXIT_FAILURE, "Cannot configure device: err=%s, port=%u\n",
             rte_strerror(ret), port_id);

  ret = rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &nb_rxd, &nb_txd);
  if (ret != 0)
    rte_exit(EXIT_FAILURE,
             "Cannot adjust number of descriptors: err=%d, port=%u\n", ret,
             port_id);

  /* Allocate and set up 1 RX queue per Ethernet port. */
  rxconf = dev_info.default_rxconf;
  rxconf.offloads = port_conf.rxmode.offloads;

  
  for (int q = 0; q < rx_rings; q++) {
    ret = rte_eth_rx_queue_setup(
        port_id, q, nb_rxd, rte_eth_dev_socket_id(port_id), &rxconf, mbuf_pool);
    if (ret != 0)
      rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup:err=%d, port=%u\n", ret,
               port_id);
  }

  txconf = dev_info.default_txconf;
  txconf.offloads = port_conf.txmode.offloads;
  /* Allocate and set up 1 TX queue per Ethernet port. */
  for (int q = 0; q < tx_rings; q++) {
    ret = rte_eth_tx_queue_setup(port_id, q, nb_txd,
                                 rte_eth_dev_socket_id(port_id), &txconf);
    if (ret != 0)
      rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup:err=%d, port=%u\n", ret,
               port_id);
  }

   

  /* Starting Ethernet port. 8< */
  ret = rte_eth_dev_start(port_id);
  if (ret < 0)
    rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err=%d, port=%u\n", ret, port_id);

  /* Display the port MAC address. */
  struct rte_ether_addr addr;
  ret = rte_eth_macaddr_get(port_id, &addr);
  if (ret < 0)
    rte_exit(EXIT_FAILURE, "Cannot get MAC address: err=%d, port=%u\n", ret,
             port_id);
  ;

  printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8
         " %02" PRIx8 " %02" PRIx8 "\n",
         port_id, RTE_ETHER_ADDR_BYTES(&addr));

  /* Enable RX in promiscuous mode for the Ethernet device. */
  ret = rte_eth_promiscuous_enable(port_id);
  /* End of setting RX port in promiscuous mode. */
  if (ret < 0)
    rte_exit(EXIT_FAILURE, "rte_eth_promiscuous_enable:err=%s, port=%u\n",
             rte_strerror(-ret), port_id);
  return 0;
}

int dpdk_run() {
  unsigned int lcore_id;
  int ret = 0;
  /* launch per-lcore init on every lcore */
  rte_eal_mp_remote_launch(zstack_launch_one_lcore, NULL, SKIP_MAIN);

  return ret;
}

void init_lcore_conf() {
  unsigned lcore_id;
  unsigned proc_id;
  unsigned port_id;


  proc_id = 0;
  port_id = zs_global_cfg.dpdk.port_id;
  RTE_LCORE_FOREACH(lcore_id) {
    /* skip master core, main core is used for tcp-stack, hard code */
    if (rte_lcore_is_enabled(lcore_id) == 0 | lcore_id == rte_get_main_lcore() ) 
      continue;
    if (zs_global_cfg.dpdk.nb_lcores >= RTE_MAX_LCORE)
      rte_exit(EXIT_FAILURE, "Not enough cores\n");
    lcore_conf[lcore_id].socket_id = rte_lcore_to_socket_id(lcore_id);
    lcore_conf[lcore_id].port_id = port_id;
    lcore_conf[lcore_id].proc_id = proc_id;
    lcore_conf[lcore_id].tx_queue_id = proc_id;
    lcore_conf[lcore_id].rx_queue_id = proc_id;

    /* Initialize TX buffers */
		lcore_conf[lcore_id].tx_buffer[port_id] = rte_zmalloc_socket("tx_buffer",
				RTE_ETH_TX_BUFFER_SIZE(MAX_PKT_BURST), 0,
				rte_eth_dev_socket_id(port_id));
		if (lcore_conf[lcore_id].tx_buffer[port_id] == NULL)
			rte_exit(EXIT_FAILURE, "Cannot allocate buffer for tx on port %u\n",
					port_id);


    rte_eth_tx_buffer_init(lcore_conf[lcore_id].tx_buffer[port_id] , MAX_PKT_BURST);
   
    
    proc_id++;
  }
}


void init_pkt_mempool(void) {
  unsigned nb_mbufs =
      RTE_MAX(zs_global_cfg.dpdk.nb_ports *
                  (nb_rxd + nb_txd + MAX_PKT_BURST +
                   zs_global_cfg.dpdk.nb_lcores * MEMPOOL_CACHE_SIZE),
                81920U);
  printf("nb_mbufs=%u\n",nb_mbufs);
  /* Create the mbuf pool. 8< */
  pktmbuf_pool =
      rte_pktmbuf_pool_create("pktmbuf_pool", nb_mbufs, MEMPOOL_CACHE_SIZE, 0,
                              RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

  if (pktmbuf_pool == NULL)
    rte_exit(EXIT_FAILURE, "Cannot init pkt mbuf pool\n");
}


int init_dpdk(int argc, char **argv) {
  // one lcore for send/recv
  // one main core for tcp stack 

  unsigned int lcore_id;
  int ret = 0;

  /* Initializion the Environment Abstraction Layer (EAL). 8< */
  ret = rte_eal_init(argc, argv);

  if (ret < 0) 
    rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
  argc -= ret;
  argv += ret;
  /* >8 End of initialization the Environment Abstraction Layer (EAL). */

  
  /* main core is used for tcp-stack , hard code */
  zs_global_cfg.dpdk.nb_lcores = rte_lcore_count() - 1 ;

  zs_global_cfg.dpdk.nb_ports = rte_eth_dev_count_avail();

  

  if (zs_global_cfg.dpdk.nb_ports <= 0)
    rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");

  zs_global_cfg.dpdk.port_id = 0;  // hard code , only one port
  rte_eth_macaddr_get(zs_global_cfg.dpdk.port_id, zs_global_cfg.dpdk.src_mac_addr);

  init_lcore_conf();

  init_pkt_mempool();

  /* Initializing ports. 8< */
  if (port_init(zs_global_cfg.dpdk.port_id, pktmbuf_pool) != 0)
    rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n",
             zs_global_cfg.dpdk.port_id);
  /* >8 End of initializing all ports. */

  init_msg_ring();

  
  zs_global_cfg.timer_period = TIMER_PERIOD * rte_get_timer_hz();
  
  return ret;
}

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
