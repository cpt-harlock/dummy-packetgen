/* SPDX-License-Identifier: BSD-3-Clause
 * Packet generator + receiver using DPDK.
 * Sends a fixed dummy UDP packet at line rate and prints received packets.
 */

#include <getopt.h>
#include <limits.h>
#include <locale.h>
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
#define DEFAULT_PAYLOAD_LEN 64
#define MAX_PAYLOAD_LEN (UINT16_MAX - sizeof(struct rte_ipv4_hdr) - sizeof(struct rte_udp_hdr))

/* Histogram parameters */
#define HIST_NUM_BINS  10000
#define HIST_BIN_WIDTH 1       /* latency units per bin */

/* Maximum number of RX queues / worker lcores */
#define MAX_RX_QUEUES  16

/* Per-RX-queue context: packet counter and per-lcore histogram. */
struct rx_ctx {
	uint16_t  queue_id;
	uint64_t  rx_total;
	/* per-lcore histogram (only populated when latency_mode is set) */
	uint64_t  hist_bins[HIST_NUM_BINS];
	uint64_t  hist_overflow;
	uint64_t  hist_total;
	uint32_t  hist_min;
	uint32_t  hist_max;
};

static struct rx_ctx  rx_ctxs[MAX_RX_QUEUES];
static uint16_t       nb_rx_queues;

static volatile int keep_running = 1;
static struct rte_mempool *rx_mbuf_pool;
static struct rte_mempool *tx_mbuf_pool;

/* 0 = unlimited (line rate) */
static uint64_t target_pps;
static uint16_t payload_len = DEFAULT_PAYLOAD_LEN;
static int range_mode;

/* Packet size used when preloading TX mbuf data buffers. */
static uint16_t template_pkt_len;

/* Debug mode: dump raw bytes of each received packet */
static int debug_mode;

/* Latency / histogram mode: disabled by default */
static int latency_mode;

/* Test mode */
static int test_mode;
static volatile uint64_t tx_total_global = 0;
static volatile uint64_t rx_total_global = 0;

/* Global histogram – filled by the RX lcore, read after join. */
static uint64_t hist_bins[HIST_NUM_BINS];
static uint64_t hist_overflow;          /* counts above the last bin */
static uint64_t hist_total;
static uint32_t hist_global_min;
static uint32_t hist_global_max;

/*
 * Returns percentile as the lower edge of the histogram bin that contains
 * the rank. permille: 500 = p50, 990 = p99, 999 = p99.9.
 */
static uint32_t hist_percentile_bin_start(uint32_t permille, int *in_overflow)
{
	uint64_t cumulative = 0;
	uint64_t rank;

	*in_overflow = 0;
	if (hist_total == 0)
		return 0;

	/* ceil(hist_total * permille / 1000) without floating point */
	rank = (hist_total * permille + 999) / 1000;
	if (rank == 0)
		rank = 1;

	for (uint32_t i = 0; i < HIST_NUM_BINS; i++) {
		cumulative += hist_bins[i];
		if (cumulative >= rank)
			return i * HIST_BIN_WIDTH;
	}

	*in_overflow = 1;
	return HIST_NUM_BINS * HIST_BIN_WIDTH;
}

static void hist_dump(const char *filename)
{
	FILE *f = fopen(filename, "w");
	if (!f) {
		printf("Failed to open %s for writing\n", filename);
		return;
	}

	fprintf(f, "bin_start,bin_end,count\n");
	for (uint32_t i = 0; i < HIST_NUM_BINS; i++) {
		if (hist_bins[i] == 0)
			continue;
		fprintf(f, "%u,%u,%" PRIu64 "\n",
			i * HIST_BIN_WIDTH,
			(i + 1) * HIST_BIN_WIDTH,
			hist_bins[i]);
	}
	if (hist_overflow > 0)
		fprintf(f, "%u,inf,%" PRIu64 "\n",
			HIST_NUM_BINS * HIST_BIN_WIDTH, hist_overflow);
	fclose(f);

	printf("[HIST] %" PRIu64 " samples written to %s  "
	       "(min=%u max=%u overflow=%" PRIu64 ")\n",
	       hist_total, filename,
	       hist_global_min, hist_global_max, hist_overflow);

	if (hist_total > 0) {
		int p50_overflow;
		int p99_overflow;
		int p999_overflow;
		uint32_t p50 = hist_percentile_bin_start(500, &p50_overflow);
		uint32_t p99 = hist_percentile_bin_start(990, &p99_overflow);
		uint32_t p999 = hist_percentile_bin_start(999, &p999_overflow);

		printf("[HIST-PCT] p50=%u%s  p99=%u%s  p99.9=%u%s\n",
		       p50, p50_overflow ? "+" : "",
		       p99, p99_overflow ? "+" : "",
		       p999, p999_overflow ? "+" : "");
		printf("[HIST-PCT (us)] p50=%.2f%s  p99=%.2f%s  p99.9=%.2f%s\n",
		       4*p50/1000.0, p50_overflow ? "+" : "",
		       4*p99/1000.0, p99_overflow ? "+" : "",
		       4*p999/1000.0, p999_overflow ? "+" : "");	   
	}
}

static void signal_handler(int sig)
{
	(void)sig;
	keep_running = 0;
}

/* Initialise a single ethernet port with the requested number of RX queues.
 * *nb_queues may be reduced if the device supports fewer. */
static int port_init(uint16_t port, uint16_t *nb_queues)
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

	/* Cap to what the device supports */
	if (*nb_queues > dev_info.max_rx_queues)
		*nb_queues = dev_info.max_rx_queues;

	/* Enable RSS when using multiple RX queues */
	if (*nb_queues > 1) {
		port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;
		port_conf.rx_adv_conf.rss_conf.rss_hf =
			dev_info.flow_type_rss_offloads &
			(RTE_ETH_RSS_IP | RTE_ETH_RSS_UDP);
	}

	ret = rte_eth_dev_configure(port, *nb_queues, 1, &port_conf);
	if (ret != 0)
		return ret;

	ret = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	if (ret != 0)
		return ret;

	for (uint16_t q = 0; q < *nb_queues; q++) {
		ret = rte_eth_rx_queue_setup(port, q, nb_rxd,
				rte_eth_dev_socket_id(port), NULL, rx_mbuf_pool);
		if (ret < 0)
			return ret;
	}

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

static uint32_t next_dst_ip(uint64_t packet_index)
{
	uint32_t base_prefix = DST_IP & 0xffff0000u;
	uint32_t base_host = DST_IP & 0x0000ffffu;
	uint32_t host_part;

	if (!range_mode)
		return DST_IP;

	host_part = (base_host + (uint32_t)packet_index) & 0x0000ffffu;
	return base_prefix | host_part;
}

static void init_packet_bytes(char *pkt)
{
	memset(pkt, 0, template_pkt_len);

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
						 payload_len);
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
	udp->dgram_len   = rte_cpu_to_be_16(sizeof(*udp) + payload_len);
	udp->dgram_cksum = 0;

	/* --- Payload (fill with a pattern) --- */
	uint8_t *payload = (uint8_t *)udp + sizeof(*udp);
	for (uint16_t i = 0; i < payload_len; i++)
		payload[i] = (uint8_t)(i & 0xff);

	return;
}

/* Preload every TX mbuf data buffer once so the hot path avoids memcpy. */
static int preload_tx_pool(void)
{
	unsigned int max_mbufs = rte_mempool_avail_count(tx_mbuf_pool);
	struct rte_mbuf **bufs;
	unsigned int count = 0;

	template_pkt_len = sizeof(struct rte_ether_hdr) +
			   sizeof(struct rte_ipv4_hdr)  +
			   sizeof(struct rte_udp_hdr)   +
			   payload_len;

	bufs = calloc(max_mbufs, sizeof(*bufs));
	if (bufs == NULL)
		return -1;

	for (;;) {
		struct rte_mbuf *m = rte_pktmbuf_alloc(tx_mbuf_pool);
		if (m == NULL)
			break;

		init_packet_bytes(rte_pktmbuf_mtod(m, char *));
		bufs[count++] = m;
	}

	for (unsigned int i = 0; i < count; i++)
		rte_pktmbuf_free(bufs[i]);

	free(bufs);
	return count > 0 ? 0 : -1;

	return 0;
}

/*
 * Copy the template into a pre-allocated mbuf and, in range mode,
 * patch the destination IP and recompute the IPv4 checksum.
 */
inline static void fill_packet(struct rte_mbuf *m, uint32_t dst_ip)
{
	m->data_len = template_pkt_len;
	m->pkt_len  = template_pkt_len;

	if (range_mode) {
		char *pkt = rte_pktmbuf_mtod(m, char *);
		struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)
					  (pkt + sizeof(struct rte_ether_hdr));
		ip->dst_addr     = rte_cpu_to_be_32(dst_ip);
		ip->hdr_checksum = rte_ipv4_cksum(ip);
	}
}

static int parse_payload_len(const char *arg, uint16_t *value)
{
	char *end = NULL;
	unsigned long parsed;

	parsed = strtoul(arg, &end, 10);
	if (arg[0] == '\0' || end == arg || *end != '\0')
		return -1;
	if (parsed > MAX_PAYLOAD_LEN)
		return -1;

	*value = (uint16_t)parsed;
	return 0;
}

/* RX loop: runs on a worker lcore. arg points to this lcore's rx_ctx. */
static int rx_loop(void *arg)
{
	struct rx_ctx *ctx = arg;
	uint16_t queue = ctx->queue_id;
	struct rte_mbuf *bufs[BURST_SIZE];
	uint64_t last_print = rte_rdtsc();
	uint64_t hz = rte_get_tsc_hz();

	/* Latency tracking (reset every print interval) */
	uint64_t lat_sum = 0;
	uint64_t lat_count = 0;
	uint32_t lat_min = UINT32_MAX;
	uint32_t lat_max = 0;

	if (latency_mode) {
		ctx->hist_min = UINT32_MAX;
		ctx->hist_max = 0;
	}

	printf("[RX] lcore %u polling queue %u\n", rte_lcore_id(), queue);
	if (!latency_mode)
		printf("[RX] Latency/histogram tracking disabled\n");

	while (keep_running) {
		uint16_t nb_rx = rte_eth_rx_burst(0, queue, bufs, BURST_SIZE);
		if (nb_rx == 0)
			continue;

		ctx->rx_total += nb_rx;

		for (uint16_t i = 0; i < nb_rx; i++) {
			struct rte_mbuf *m = bufs[i];

			/* Need at least 47 bytes to read both timestamps */
			if (latency_mode && rte_pktmbuf_data_len(m) >= 47) {
				uint8_t *pkt = rte_pktmbuf_mtod(m, uint8_t *);

				if (debug_mode) {
					printf("[RX-DBG] q%u pkt #%"PRIu64" (%u bytes) "
					       "first 47 bytes:\n",
					       queue, ctx->rx_total,
					       rte_pktmbuf_data_len(m));
					for (int b = 0; b < 47; b++) {
						printf("%02x ", pkt[b]);
						if ((b & 0xf) == 0xf)
							printf("\n");
					}
					printf("\n");
				}

				uint32_t rx_timestamp;
				uint32_t tx_timestamp;
				memcpy(&rx_timestamp, pkt + 39, sizeof(uint32_t));
				memcpy(&tx_timestamp, pkt + 43, sizeof(uint32_t));
				uint32_t latency = tx_timestamp - rx_timestamp;

				if (debug_mode) {
					printf("[RX-DBG]   rx_ts=%u (off 39)  "
					       "tx_ts=%u (off 43)  "
					       "latency=%u\n",
					       rx_timestamp, tx_timestamp, latency);
				}

				lat_sum += latency;
				lat_count++;
				if (latency < lat_min)
					lat_min = latency;
				if (latency > lat_max)
					lat_max = latency;

				/* Record in per-lcore histogram */
				uint32_t bin = latency / HIST_BIN_WIDTH;
				if (bin < HIST_NUM_BINS)
					ctx->hist_bins[bin]++;
				else
					ctx->hist_overflow++;
				ctx->hist_total++;
				if (latency < ctx->hist_min)
					ctx->hist_min = latency;
				if (latency > ctx->hist_max)
					ctx->hist_max = latency;
			}

			rte_pktmbuf_free(m);
		}

		/* Print a summary every second */
		uint64_t now = rte_rdtsc();
		if (now - last_print >= hz) {
			if (latency_mode && lat_count > 0) {
				printf("[RX] q%u total=%'lu  interval_pkts=%"PRIu64
				       "  latency min=%u avg=%"PRIu64" max=%u\n",
				       queue, ctx->rx_total, lat_count,
				       lat_min, lat_sum / lat_count, lat_max);
			} else {
				printf("[RX] q%u total=%'lu\n", queue, ctx->rx_total);
			}
			last_print = now;
			lat_sum = 0;
			lat_count = 0;
			lat_min = UINT32_MAX;
			lat_max = 0;
		}
	}

	printf("[RX] q%u total packets received: %'lu\n", queue, ctx->rx_total);
	return 0;
}

/* Merge per-lcore RX stats into global counters. Must be called after all
 * worker lcores have been joined. */
static void merge_rx_ctxs(void)
{
	hist_global_min = UINT32_MAX;
	hist_global_max = 0;

	for (uint16_t q = 0; q < nb_rx_queues; q++) {
		struct rx_ctx *ctx = &rx_ctxs[q];

		rx_total_global += ctx->rx_total;

		if (!latency_mode)
			continue;

		for (uint32_t i = 0; i < HIST_NUM_BINS; i++)
			hist_bins[i] += ctx->hist_bins[i];
		hist_overflow += ctx->hist_overflow;
		hist_total    += ctx->hist_total;
		if (ctx->hist_min < hist_global_min)
			hist_global_min = ctx->hist_min;
		if (ctx->hist_max > hist_global_max)
			hist_global_max = ctx->hist_max;
	}
}

/* TX loop: runs on the main lcore. */
static void tx_loop(uint16_t port)
{
	struct rte_mbuf *bufs[BURST_SIZE];
	uint64_t tx_total = 0;
	uint64_t packet_index = 0;
	uint64_t start_tsc = rte_rdtsc();
	uint64_t last_print = rte_rdtsc();
	uint64_t hz = rte_get_tsc_hz();

	/*
	 * Rate-limiting: if target_pps > 0, compute the TSC ticks
	 * to wait between each burst so that the average rate matches.
	 */
	uint64_t ticks_per_burst = 0;
	if (target_pps > 0) {
		ticks_per_burst = hz * BURST_SIZE / target_pps;
		printf("[TX] Rate-limiting to %" PRIu64 " pps "
		       "(burst interval ~%" PRIu64 " ticks)\n",
		       target_pps, ticks_per_burst);
	} else {
		printf("[TX] Sending at line rate (no pps limit)\n");
	}

	printf("[TX] Running on lcore %u\n", rte_lcore_id());

	uint64_t next_send = rte_rdtsc();

	while (keep_running) {
		if (test_mode && (rte_rdtsc() - start_tsc) >= (10 * hz)) {
			printf("[TEST] 10 second run completed, stopping traffic\n");
			keep_running = 0;
			break;
		}

		/* Pace: wait until it's time to send the next burst */
		if (ticks_per_burst > 0) {
			while (rte_rdtsc() < next_send && keep_running)
				;
			next_send += ticks_per_burst;
		}

		/* Pre-allocate the entire burst in one pool dequeue */
		if (rte_pktmbuf_alloc_bulk(tx_mbuf_pool, bufs, BURST_SIZE) < 0)
			goto stats;

		/* Fill each mbuf from the template, patching per-packet fields */
		for (int i = 0; i < BURST_SIZE; i++) {
			fill_packet(bufs[i], next_dst_ip(packet_index));
			packet_index++;
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
				printf("[TX] Sent %'lu total packets\n", tx_total);
				last_print = now;
			}
		}
	}

	printf("[TX] Total packets sent: %'lu\n", tx_total);
	tx_total_global = tx_total;
}

static void usage(const char *prog)
{
	printf("Usage: %s [EAL options] -- [--pps <packets/sec>] [--payload-len <bytes>] [--range] [--debug] [--test] [--latency]\n"
	       "  --pps N   Target TX rate in packets per second (0 = line rate, default)\n"
	       "  --payload-len N   UDP payload size in bytes (default: %u, max: %u)\n"
	       "  --range   Vary the destination IPv4 low 16 bits for each packet\n"
	       "  --debug   Hex-dump received packets up to the timestamp fields\n"
	       "  --test    Run traffic for 10 seconds, wait 1 second, then exit\n"
	       "  --latency Enable latency tracking and histogram (default: disabled)\n",
	       prog, DEFAULT_PAYLOAD_LEN, (unsigned int)MAX_PAYLOAD_LEN);
}

int main(int argc, char *argv[])
{
	int ret;
	int exit_status = 0;
	uint16_t port_id = 0;
	uint16_t nb_ports;
	unsigned int lcore_id;
    
	setlocale(LC_NUMERIC, ""); // Usa locale di sistema per i separatori

	/* --- EAL init --- */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "EAL init failed\n");
	argc -= ret;
	argv += ret;

	/* --- Parse app-specific options (after "--") --- */
	static struct option long_options[] = {
		{"pps",         required_argument, NULL, 'p'},
		{"payload-len", required_argument, NULL, 's'},
		{"range",       no_argument,       NULL, 'r'},
		{"debug",       no_argument,       NULL, 'd'},
		{"test",        no_argument,       NULL, 't'},
		{"latency",     no_argument,       NULL, 'l'},
		{"help",        no_argument,       NULL, 'h'},
		{NULL,           0,                 NULL,  0 }
	};

	int opt;
	while ((opt = getopt_long(argc, argv, "p:s:rdtlh", long_options, NULL)) != -1) {
		switch (opt) {
		case 'p':
			target_pps = strtoull(optarg, NULL, 10);
			break;
		case 's':
			if (parse_payload_len(optarg, &payload_len) != 0)
				rte_exit(EXIT_FAILURE,
					 "Invalid payload length '%s' (expected 0-%u)\n",
					 optarg, (unsigned int)MAX_PAYLOAD_LEN);
			break;
		case 'r':
			range_mode = 1;
			break;
		case 'd':
			debug_mode = 1;
			break;
		case 't':
			test_mode = 1;
			break;
		case 'l':
			latency_mode = 1;
			break;
		case 'h':
		default:
			usage(argv[0]);
			return 0;
		}
	}

	signal(SIGINT,  signal_handler);
	signal(SIGTERM, signal_handler);

	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports == 0)
		rte_exit(EXIT_FAILURE, "No Ethernet ports available\n");

	printf("Using port %u (of %u available)\n", port_id, nb_ports);
	printf("Configured UDP payload length: %u bytes\n", payload_len);
	printf("Destination IP range mode: %s\n",
	       range_mode ? "enabled (varying low 16 bits)" : "disabled");
	printf("Latency / histogram tracking: %s\n",
	       latency_mode ? "enabled" : "disabled");

	/* Determine how many RX queues/lcores to use */
	nb_rx_queues = 0;
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		nb_rx_queues++;
		if (nb_rx_queues == MAX_RX_QUEUES)
			break;
	}
	if (nb_rx_queues == 0)
		nb_rx_queues = 1;

	/* --- Create RX/TX mbuf pools --- */
	rx_mbuf_pool = rte_pktmbuf_pool_create("RX_MBUF_POOL", NUM_MBUFS * nb_ports,
						MBUF_CACHE, 0,
						RTE_MBUF_DEFAULT_BUF_SIZE,
						rte_socket_id());
	if (rx_mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create RX mbuf pool: %s\n",
			 rte_strerror(rte_errno));

	tx_mbuf_pool = rte_pktmbuf_pool_create("TX_MBUF_POOL", NUM_MBUFS * nb_ports,
						MBUF_CACHE, 0,
						RTE_MBUF_DEFAULT_BUF_SIZE,
						rte_socket_id());
	if (tx_mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create TX mbuf pool: %s\n",
			 rte_strerror(rte_errno));

	/* --- Preload TX mbufs with the packet contents --- */
	if (preload_tx_pool() != 0)
		rte_exit(EXIT_FAILURE, "Cannot preload TX mbuf pool\n");

	/* --- Initialise port --- */
	ret = port_init(port_id, &nb_rx_queues);
	if (ret != 0)
		rte_exit(EXIT_FAILURE, "Cannot init port %u: %s\n",
			 port_id, rte_strerror(-ret));

	/* Initialise per-queue RX contexts */
	memset(rx_ctxs, 0, sizeof(rx_ctxs));
	for (uint16_t q = 0; q < nb_rx_queues; q++)
		rx_ctxs[q].queue_id = q;
	printf("Using %u RX queue(s)\n", nb_rx_queues);

	/* --- Launch one RX lcore per queue --- */
	{
		uint16_t q = 0;
		RTE_LCORE_FOREACH_WORKER(lcore_id) {
			if (q >= nb_rx_queues)
				break;
			rte_eal_remote_launch(rx_loop, &rx_ctxs[q], lcore_id);
			q++;
		}
		if (q == 0)
			printf("Warning: no secondary lcore available; RX disabled. "
			       "Run with at least -l 0-1\n");
		else
			printf("Launched %u RX lcore(s)\n", q);
	}

	/* --- TX runs on the main lcore --- */
	tx_loop(port_id);

	if (test_mode) {
		printf("[TEST] Waiting 1 second before exit\n");
		rte_delay_ms(1000);
	}

	/* --- Wait for RX lcore --- */
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		rte_eal_wait_lcore(lcore_id);
	}

	/* --- Merge per-lcore RX stats into globals --- */
	merge_rx_ctxs();

	printf("[STATS] Packet diff (sent - received): %" PRId64
	       "  (sent=%" PRIu64 " received=%" PRIu64 ")\n",
	       (int64_t)tx_total_global - (int64_t)rx_total_global,
	       tx_total_global, rx_total_global);

	{
		uint64_t sent = tx_total_global;
		uint64_t received = rx_total_global;
		uint64_t abs_diff = (sent >= received) ? (sent - received)
		                                     : (received - sent);
		int success;

		/* diff < 0.1% of sent packets, i.e. abs_diff * 1000 < sent */
		if (sent == 0)
			success = (abs_diff == 0);
		else
			success = (abs_diff * 1000ULL < sent);

		if (success) {
			printf("\x1b[32mSUCCESS\x1b[0m: final diff=%" PRIu64
			       " (< 0.1%% of sent=%" PRIu64 ")\n",
			       abs_diff, sent);
			exit_status = 0;
		} else {
			printf("\x1b[35mFAIL\x1b[0m: final diff=%" PRIu64
			       " (>= 0.1%% of sent=%" PRIu64 ")\n",
			       abs_diff, sent);
			exit_status = -1;
		}
	}

	/* --- Dump latency histogram --- */
	if (latency_mode)
		hist_dump("latency_histogram.csv");

	/* --- Cleanup --- */
	rte_eth_dev_stop(port_id);
	rte_eth_dev_close(port_id);
	rte_eal_cleanup();

	return exit_status;
}
