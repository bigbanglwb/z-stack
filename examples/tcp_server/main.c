#include <unistd.h>
#include <getopt.h>

#include "server.c"
#include "dpdk.h"
#include "config.h"

#define MAX_PKT_BURST 32
static void signal_handler(int signum) {
    unsigned lcore_id;
    lcore_id  = rte_lcore_id();
    if (signum == SIGINT) {
        force_quit = true;
        printf("\n\nSignal %d received, lcore %u preparing to exit ...\n", signum,lcore_id);
        
  }
}

int main(int argc,char *argv[]){

	struct rte_mbuf *buf[MAX_PKT_BURST];
    uint64_t prev_tsc, diff_tsc, cur_tsc, timer_tsc;
    unsigned lcore_id;
    

    force_quit = false;
    
    prev_tsc = 0;
	timer_tsc = 0;
    
    signal(SIGINT, signal_handler);
    init_dpdk(argc, argv);    
    dpdk_run();

#if ENABLE_TIMER
	rte_timer_subsystem_init();

	struct rte_timer arp_timer;
	rte_timer_init(&arp_timer);

	uint64_t hz = rte_get_timer_hz();//函数用于获取 DPDK 计时器的频率（每秒的计时器滴答数)
	unsigned lcore_id = rte_lcore_id();//取当前线程的 ID
	//当rte_timer_manage 函数触发定时器时，这里调用回调函数arp_request_timer_cb，mbuf_pool是回调函数的参数
	rte_timer_reset(&arp_timer, hz, PERIODICAL, lcore_id, arp_request_timer_cb, mbuf_pool);

#endif

#if ENABLE_MULTHREAD
	// lcore_id不一样。可以分配不同cpu给线程，实现负载均衡
	lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
	//启动用户态协议栈中处理数据包的线程
	rte_eal_remote_launch(pkt_process,NULL,lcore_id);
#endif


#if ENABLE_TCP_APP
	lcore_id = rte_get_next_lcore(lcore_id,1,0);
	//启动 tcp server线程
	rte_eal_remote_launch(tcp_server_entry,NULL,lcore_id);
#endif

	while(!force_quit){

		cur_tsc = rte_rdtsc();
        diff_tsc = cur_tsc - prev_tsc;
        timer_tsc += diff_tsc;
        if (unlikely(timer_tsc >= zs_global_cfg.timer_period)) {
            print_stats(); 
            /* reset the timer */
            timer_tsc = 0;
            
        }        
        prev_tsc = cur_tsc;
        

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