/* SPDX-License-Identifier: BSD-3-Clause
 * Packet generator + receiver using DPDK.
 * Sends a fixed dummy UDP packet at line rate and prints received packets.
 */

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_udp.h>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024
#define NUM_MBUFS    8191
#define MBUF_CACHE   250
#define BURST_SIZE   32

/* Dummy packet parameters */
#define DST_MAC   {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
#define SRC_MAC   {0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE}
#define SRC_IP    RTE_IPV4(10, 0, 0, 1)
#define DST_IP    RTE_IPV4(10, 0, 0, 2)
#define SRC_PORT  12345
#define DST_PORT  54321
#define PAYLOAD_LEN 64

static volatile int keep_running = 1;
static struct rte_mempool *mbuf_pool;

static void signal_handler(int sig)
{
	(void)sig;
	keep_running = 0;
}

/* Initialise a single ethernet port. */
static int port_init(uint16_t port)
{
	struct rte_eth_conf port_conf = {0};
	struct rte_eth_dev_info dev_info;
	uint16_t nb_rxd = RX_RING_SIZE;
	uint16_t nb_txd = TX_RING_SIZE;
	int ret;

	if (!rte_eth_dev_is_valid_port(port))
		return -1;

	ret = rte_eth_dev_info_get(port, &dev_info);
	if (ret != 0) {
		printf("Error getting device info for port %u: %s\n",
		       port, rte_strerror(-ret));
		return ret;
	}

	if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
		port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

	ret = rte_eth_dev_configure(port, 1, 1, &port_conf);
	if (ret != 0)
		return ret;

	ret = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	if (ret != 0)
		return ret;

	ret = rte_eth_rx_queue_setup(port, 0, nb_rxd,
			rte_eth_dev_socket_id(port), NULL, mbuf_pool);
	if (ret < 0)
		return ret;

	ret = rte_eth_tx_queue_setup(port, 0, nb_txd,
			rte_eth_dev_socket_id(port), NULL);
	if (ret < 0)
		return ret;

	ret = rte_eth_dev_start(port);
	if (ret < 0)
		return ret;

	ret = rte_eth_promiscuous_enable(port);
	if (ret != 0) {
		printf("Warning: promiscuous mode enable failed for port %u: %s\n",
		       port, rte_strerror(-ret));
	}

	return 0;
}

/* Build a dummy UDP/IP/Ethernet packet inside an mbuf. */
static struct rte_mbuf *build_dummy_packet(void)
{
	struct rte_mbuf *m = rte_pktmbuf_alloc(mbuf_pool);
	if (m == NULL)
		return NULL;

	/* Total sizes */
	uint16_t pkt_data_len = sizeof(struct rte_ether_hdr) +
				sizeof(struct rte_ipv4_hdr)  +
				sizeof(struct rte_udp_hdr)   +
				PAYLOAD_LEN;

	m->data_len = pkt_data_len;
	m->pkt_len  = pkt_data_len;

	char *pkt = rte_pktmbuf_mtod(m, char *);
	memset(pkt, 0, pkt_data_len);

	/* --- Ethernet header --- */
	struct rte_ether_hdr *eth = (struct rte_ether_hdr *)pkt;
	uint8_t dst_mac[] = DST_MAC;
	uint8_t src_mac[] = SRC_MAC;
	memcpy(&eth->dst_addr, dst_mac, RTE_ETHER_ADDR_LEN);
	memcpy(&eth->src_addr, src_mac, RTE_ETHER_ADDR_LEN);
	eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

	/* --- IPv4 header --- */
	struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(pkt + sizeof(*eth));
	ip->version_ihl     = (4 << 4) | 5;  /* IPv4, 20-byte header */
	ip->type_of_service  = 0;
	ip->total_length     = rte_cpu_to_be_16(sizeof(*ip) +
						 sizeof(struct rte_udp_hdr) +
						 PAYLOAD_LEN);
	ip->packet_id        = 0;
	ip->fragment_offset  = 0;
	ip->time_to_live     = 64;
	ip->next_proto_id    = IPPROTO_UDP;
	ip->src_addr         = rte_cpu_to_be_32(SRC_IP);
	ip->dst_addr         = rte_cpu_to_be_32(DST_IP);
	ip->hdr_checksum     = 0;
	ip->hdr_checksum     = rte_ipv4_cksum(ip);

	/* --- UDP header --- */
	struct rte_udp_hdr *udp = (struct rte_udp_hdr *)((char *)ip + sizeof(*ip));
	udp->src_port    = rte_cpu_to_be_16(SRC_PORT);
	udp->dst_port    = rte_cpu_to_be_16(DST_PORT);
	udp->dgram_len   = rte_cpu_to_be_16(sizeof(*udp) + PAYLOAD_LEN);
	udp->dgram_cksum = 0;

	/* --- Payload (fill with a pattern) --- */
	uint8_t *payload = (uint8_t *)udp + sizeof(*udp);
	for (int i = 0; i < PAYLOAD_LEN; i++)
		payload[i] = (uint8_t)(i & 0xff);

	return m;
}

/* RX loop: runs on a secondary lcore. */
static int rx_loop(__rte_unused void *arg)
{
	uint16_t port = 0;
	struct rte_mbuf *bufs[BURST_SIZE];
	uint64_t rx_total = 0;
	uint64_t last_print = rte_rdtsc();
	uint64_t hz = rte_get_tsc_hz();

	printf("[RX] Running on lcore %u\n", rte_lcore_id());

	while (keep_running) {
		uint16_t nb_rx = rte_eth_rx_burst(port, 0, bufs, BURST_SIZE);
		if (nb_rx == 0)
			continue;

		rx_total += nb_rx;

		/* Print a summary every second */
		uint64_t now = rte_rdtsc();
		if (now - last_print >= hz) {
			printf("[RX] Received %"PRIu64" total packets\n", rx_total);
			last_print = now;
		}

		/* Free received mbufs */
		for (uint16_t i = 0; i < nb_rx; i++)
			rte_pktmbuf_free(bufs[i]);
	}

	printf("[RX] Total packets received: %"PRIu64"\n", rx_total);
	return 0;
}

/* TX loop: runs on the main lcore. */
static void tx_loop(uint16_t port)
{
	struct rte_mbuf *bufs[BURST_SIZE];
	uint64_t tx_total = 0;
	uint64_t last_print = rte_rdtsc();
	uint64_t hz = rte_get_tsc_hz();

	printf("[TX] Running on lcore %u\n", rte_lcore_id());

	while (keep_running) {
		/* Build a burst of identical dummy packets */
		for (int i = 0; i < BURST_SIZE; i++) {
			bufs[i] = build_dummy_packet();
			if (bufs[i] == NULL) {
				/* Couldn't allocate; send what we have */
				if (i == 0)
					continue;
				uint16_t sent = rte_eth_tx_burst(port, 0, bufs, i);
				for (uint16_t j = sent; j < i; j++)
					rte_pktmbuf_free(bufs[j]);
				tx_total += sent;
				goto stats;
			}
		}

		uint16_t sent = rte_eth_tx_burst(port, 0, bufs, BURST_SIZE);
		for (uint16_t j = sent; j < BURST_SIZE; j++)
			rte_pktmbuf_free(bufs[j]);
		tx_total += sent;

stats:
		/* Print a summary every second */
		{
			uint64_t now = rte_rdtsc();
			if (now - last_print >= hz) {
				printf("[TX] Sent %"PRIu64" total packets\n", tx_total);
				last_print = now;
			}
		}
	}

	printf("[TX] Total packets sent: %"PRIu64"\n", tx_total);
}

int main(int argc, char *argv[])
{
	int ret;
	uint16_t port_id = 0;
	uint16_t nb_ports;
	unsigned int lcore_id;

	/* --- EAL init --- */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "EAL init failed\n");
	argc -= ret;
	argv += ret;

	signal(SIGINT,  signal_handler);
	signal(SIGTERM, signal_handler);

	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports == 0)
		rte_exit(EXIT_FAILURE, "No Ethernet ports available\n");

	printf("Using port %u (of %u available)\n", port_id, nb_ports);

	/* --- Create mbuf pool --- */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
					     MBUF_CACHE, 0,
					     RTE_MBUF_DEFAULT_BUF_SIZE,
					     rte_socket_id());
	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool: %s\n",
			 rte_strerror(rte_errno));

	/* --- Initialise port --- */
	ret = port_init(port_id);
	if (ret != 0)
		rte_exit(EXIT_FAILURE, "Cannot init port %u: %s\n",
			 port_id, rte_strerror(-ret));

	/* --- Launch RX on the first available secondary lcore --- */
	int rx_launched = 0;
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		if (!rx_launched) {
			rte_eal_remote_launch(rx_loop, NULL, lcore_id);
			rx_launched = 1;
			break;
		}
	}
	if (!rx_launched)
		printf("Warning: no secondary lcore available; RX disabled. "
		       "Run with at least -l 0-1\n");

	/* --- TX runs on the main lcore --- */
	tx_loop(port_id);

	/* --- Wait for RX lcore --- */
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		rte_eal_wait_lcore(lcore_id);
	}

	/* --- Cleanup --- */
	rte_eth_dev_stop(port_id);
	rte_eth_dev_close(port_id);
	rte_eal_cleanup();

	return 0;
}
