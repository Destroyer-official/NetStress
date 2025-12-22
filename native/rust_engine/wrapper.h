// DPDK header wrapper for bindgen
// **Validates: Requirements 10.2** - DPDK PMD header bindings

#ifdef DPDK_AVAILABLE
#include <rte_branch_prediction.h>
#include <rte_config.h>
#include <rte_debug.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_per_lcore.h>
#include <rte_ring.h>
#include <rte_tcp.h>
#include <rte_udp.h>


// PMD-specific headers
#include <rte_pmd_e1000.h>
#include <rte_pmd_i40e.h>
#include <rte_pmd_ixgbe.h>

#endif