
#include "config.h"


volatile  struct zs_config zs_global_cfg ={
    .timer_period = TIMER_PERIOD
};
const uint8_t __default_dst_mac[32] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

struct rte_ether_addr* zs_get_dst_macaddr(uint32_t ip){
    return zs_global_cfg.dpdk.dst_mac_addr;
}
struct rte_ether_addr* zs_get_src_macaddr(){
    return zs_global_cfg.dpdk.src_mac_addr;
}