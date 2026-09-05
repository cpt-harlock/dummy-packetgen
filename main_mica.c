/* SPDX-License-Identifier: BSD-3-Clause
 * Packet generator + receiver using DPDK.
 * Sends MICA UDP request packets (GET/SET, tiny/small key-value sizes,
 * Zipfian key popularity) at line rate and prints received packets.
 *
 * This is a fork of packetgenlatency (main.c) that replaces the dummy
 * fixed payload with a MICA UDP request payload:
 *
 *   byte 0                         : opcode (see MICA_UDP_OP_* below)
 *   bytes 1..key_size              : key   (tiny: 8B, small: 16B)
 *   bytes key_size+1..+value_size  : value (SET only; tiny: 8B, small: 32B)
 *
 * The latency-mode timestamp fields (read by the RX side at fixed frame
 * offsets 43/47, i.e. UDP payload bytes 1..8) are intentionally left
 * un-shifted: the MICA opcode/key/value layout is not adjusted to make
 * room for them. Every MICA payload variant (9, 17 or 49 bytes) is long
 * enough to satisfy the RX side's ">= 51 bytes total frame" check, so
 * --latency keeps working as-is; whatever writes those timestamp bytes
 * on the wire will simply overwrite the first bytes of the key (and, for
 * SET, possibly part of the value) as a side effect.
 */

#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <locale.h>
#include <math.h>
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
#include <rte_ring.h>
#include <rte_udp.h>

#define RX_RING_SIZE    1024
#define TX_RING_SIZE    1024
#define NUM_MBUFS       8191
#define MBUF_CACHE      250
#define BURST_SIZE      64     /* larger bursts amortise per-burst overhead */
#define PREFETCH_OFFSET  3     /* prefetch this many packets ahead */
#define WORK_RING_SIZE  4096   /* per-queue SPSC ring depth; must be power of 2 */
#define TEST_WARMUP_PACKETS 5000

/* Periodic-burst mode parameters */
#define PERIODIC_BURST_COUNT       256    /* packets per burst */
#define PERIODIC_BURST_INTERVAL_US 1000   /* burst period in microseconds */

/* Poisson-rate mode parameters */
#define POISSON_RATE_MEAN_PPS    10000000ULL  /* mean rate: 10 Mpps */
#define POISSON_RATE_INTERVAL_US    5000      /* re-sample every 5 ms */

/* --- MICA UDP protocol --- */
#define MICA_UDP_OP_GET_TINY  0
#define MICA_UDP_OP_SET_TINY  1
#define MICA_UDP_OP_GET_SMALL 2
#define MICA_UDP_OP_SET_SMALL 3

#define TINY_KEY_SIZE     8
#define TINY_VALUE_SIZE   8
#define SMALL_KEY_SIZE    16
#define SMALL_VALUE_SIZE  32

/* Dummy packet parameters */
#define DST_MAC   {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
#define SRC_MAC   {0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE}
#define SRC_IP    RTE_IPV4(10, 0, 0, 1)
#define DST_IP    RTE_IPV4(10, 0, 0, 2)
#define SRC_PORT  12345
#define DST_PORT  54321

/* Default MICA workload parameters */
#define DEFAULT_MICA_GET_PCT     50      /* 50% GET, 50% SET */
#define DEFAULT_MICA_DB_SIZE     1000000 /* number of distinct keys */
#define DEFAULT_MICA_ZIPF_THETA  0.99    /* YCSB-like skew */

/* Histogram parameters */
#define HIST_NUM_BINS  10000
#define HIST_BIN_WIDTH 1       /* latency units per bin */

/* Maximum number of RX queues / worker lcores */
#define MAX_RX_QUEUES  16
#define MAX_WORKER_LCORES (MAX_RX_QUEUES * 2)

/*
 * Pipeline mode: one IO lcore drains the NIC into a per-queue SPSC ring;
 * a paired worker lcore dequeues, processes, and frees packets.  Enabled
 * automatically when at least two worker lcores are available per queue.
 */
static struct rte_ring *work_rings[MAX_RX_QUEUES];
static int pipeline_mode;

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
static uint16_t tx_cores = 1;
static int range_mode;

/* Packet size used when preloading TX mbuf data buffers (worst case: SET). */
static uint16_t template_pkt_len;

/* Debug mode: dump raw bytes of each received packet */
static int debug_mode;

/* Latency / histogram mode: disabled by default */
static int latency_mode;

/* Test mode */
static int test_mode;

/* Periodic-burst mode: send PERIODIC_BURST_COUNT packets at start of each 1 ms,
 * then stay idle for the remainder of the interval. */
static int periodic_burst_mode;

/* Poisson-rate mode: re-sample TX rate every POISSON_RATE_INTERVAL_US from a
 * Poisson distribution with mean POISSON_RATE_MEAN_PPS, then pace that many
 * packets evenly across the interval. */
static int poisson_rate_mode;

/* --- MICA workload configuration (fixed for the whole run) --- */
static int      mica_use_small;             /* 0 = tiny, 1 = small */
static uint16_t mica_key_size;
static uint16_t mica_value_size;
static uint8_t  mica_op_get;                /* MICA_UDP_OP_GET_{TINY,SMALL} */
static uint8_t  mica_op_set;                /* MICA_UDP_OP_SET_{TINY,SMALL} */
static uint16_t mica_get_payload_len;       /* 1 + key_size */
static uint16_t mica_set_payload_len;       /* 1 + key_size + value_size */
static uint16_t mica_get_frame_len;         /* eth+ip+udp+get_payload_len */
static uint16_t mica_set_frame_len;         /* eth+ip+udp+set_payload_len */
static uint16_t mica_ip_total_len_get_be;
static uint16_t mica_ip_total_len_set_be;
static uint16_t mica_udp_dgram_len_get_be;
static uint16_t mica_udp_dgram_len_set_be;

static uint32_t mica_get_pct = DEFAULT_MICA_GET_PCT;   /* 0-100 */
static uint64_t mica_db_size = DEFAULT_MICA_DB_SIZE;   /* Zipfian universe size */
static double   mica_zipf_theta = DEFAULT_MICA_ZIPF_THETA;

/* --- PRNG + Poisson sampler used by poisson-rate mode --- */

static uint64_t xorshift64(uint64_t *state)
{
	uint64_t x = *state;
	x ^= x << 13;
	x ^= x >> 7;
	x ^= x << 17;
	*state = x;
	return x;
}

/*
 * Sample from Poisson(lambda) via the normal approximation N(lambda, lambda),
 * valid for large lambda (here ~50 000 per interval).
 * Uses Box-Muller to generate the N(0,1) variate.
 */
static uint64_t poisson_sample(double lambda, uint64_t *rng_state)
{
	/* Two uniform samples in (0, 1] */
	double u1 = (double)((xorshift64(rng_state) >> 11) | 1ULL) /
		    (double)(1ULL << 53);
	double u2 = (double)((xorshift64(rng_state) >> 11) | 1ULL) /
		    (double)(1ULL << 53);

	/* Box-Muller: one N(0,1) sample */
	double z = sqrt(-2.0 * log(u1)) * cos(2.0 * M_PI * u2);

	double sample = lambda + sqrt(lambda) * z;
	return sample > 0.0 ? (uint64_t)(sample + 0.5) : 0;
}

/*
 * Zipfian key-popularity generator (rejection-inversion-free closed form,
 * as used by YCSB's ZipfianGenerator). zeta(n, theta) is computed once at
 * startup; each draw afterwards is O(1).
 */
struct zipf_gen {
	uint64_t n;
	double   theta;
	double   alpha;
	double   zetan;
	double   eta;
};

static double zipf_zeta(uint64_t n, double theta)
{
	double sum = 0.0;
	for (uint64_t i = 1; i <= n; i++)
		sum += 1.0 / pow((double)i, theta);
	return sum;
}

static void zipf_gen_init(struct zipf_gen *z, uint64_t n, double theta)
{
	double zeta2 = zipf_zeta(2, theta);

	z->n     = n;
	z->theta = theta;
	z->alpha = 1.0 / (1.0 - theta);
	z->zetan = zipf_zeta(n, theta);
	z->eta   = (1.0 - pow(2.0 / (double)n, 1.0 - theta)) /
		   (1.0 - zeta2 / z->zetan);
}

/* Returns a key index in [0, z->n) */
static uint64_t zipf_next(struct zipf_gen *z, uint64_t *rng_state)
{
	double u = (double)((xorshift64(rng_state) >> 11) | 1ULL) /
		   (double)(1ULL << 53);
	double uz = u * z->zetan;

	if (uz < 1.0)
		return 0;
	if (uz < 1.0 + pow(0.5, z->theta))
		return 1;

	double val = (double)z->n * pow(z->eta * u - z->eta + 1.0, z->alpha);
	uint64_t idx = (uint64_t)val;
	if (idx >= z->n)
		idx = z->n - 1;
	return idx;
}

/* Shared across all TX lcores: same (n, theta), so zeta is computed once. */
static struct zipf_gen mica_zipf;

static volatile uint64_t tx_total_global = 0;
static volatile uint64_t rx_total_global = 0;

struct tx_ctx {
	uint16_t  port_id;
	uint16_t  queue_id;
	uint16_t  stride;
	uint64_t  packet_index;
	uint64_t  tx_total;
	uint64_t  rng_state;   /* per-lcore PRNG: op choice, key, value */
};

static struct tx_ctx tx_ctxs[MAX_WORKER_LCORES + 1];
static uint16_t nb_tx_lcores;

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
 * *nb_rx_queues may be reduced if the device supports fewer. */
static int port_init(uint16_t port, uint16_t *nb_rx_queues, uint16_t *nb_tx_queues)
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
	if (*nb_rx_queues > dev_info.max_rx_queues)
		*nb_rx_queues = dev_info.max_rx_queues;
	if (*nb_tx_queues > dev_info.max_tx_queues)
		return -ENOTSUP;

	/* Enable RSS when using multiple RX queues */
	if (*nb_rx_queues > 1) {
		port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;
		port_conf.rx_adv_conf.rss_conf.rss_hf =
			dev_info.flow_type_rss_offloads &
			(RTE_ETH_RSS_IP | RTE_ETH_RSS_UDP);
	}

	ret = rte_eth_dev_configure(port, *nb_rx_queues, *nb_tx_queues, &port_conf);
	if (ret != 0)
		return ret;

	ret = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	if (ret != 0)
		return ret;

	for (uint16_t q = 0; q < *nb_rx_queues; q++) {
		ret = rte_eth_rx_queue_setup(port, q, nb_rxd,
				rte_eth_dev_socket_id(port), NULL, rx_mbuf_pool);
		if (ret < 0)
			return ret;
	}

	for (uint16_t q = 0; q < *nb_tx_queues; q++) {
		ret = rte_eth_tx_queue_setup(port, q, nb_txd,
				rte_eth_dev_socket_id(port), NULL);
		if (ret < 0)
			return ret;
	}

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

/*
 * Build the static portion of the packet template once (worst-case length:
 * a SET packet). fill_packet() below patches the opcode, key, value, IP/UDP
 * lengths and checksum on every send, since GET and SET payloads differ in
 * size.
 */
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
	ip->total_length     = mica_ip_total_len_set_be; /* patched again per-packet */
	ip->packet_id        = 0;
	ip->fragment_offset  = 0;
	ip->time_to_live     = 64;
	ip->next_proto_id    = IPPROTO_UDP;
	ip->src_addr         = rte_cpu_to_be_32(SRC_IP);
	ip->dst_addr         = rte_cpu_to_be_32(DST_IP);
	ip->hdr_checksum     = 0; /* recomputed per-packet in fill_packet() */

	/* --- UDP header --- */
	struct rte_udp_hdr *udp = (struct rte_udp_hdr *)((char *)ip + sizeof(*ip));
	udp->src_port    = rte_cpu_to_be_16(SRC_PORT);
	udp->dst_port    = rte_cpu_to_be_16(DST_PORT);
	udp->dgram_len   = mica_udp_dgram_len_set_be; /* patched again per-packet */
	udp->dgram_cksum = 0;

	/* --- Payload placeholder: opcode + zeroed key/value --- */
	uint8_t *payload = (uint8_t *)udp + sizeof(*udp);
	payload[0] = mica_op_set;
}

/* Preload every TX mbuf data buffer once so the hot path avoids memcpy. */
static int preload_tx_pool(void)
{
	unsigned int max_mbufs = rte_mempool_avail_count(tx_mbuf_pool);
	struct rte_mbuf **bufs;
	unsigned int count = 0;

	template_pkt_len = mica_set_frame_len;

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
}

/*
 * Copy the template into a pre-allocated mbuf, pick GET or SET (per
 * --mica-get-pct), draw a Zipfian key id in [0, mica_db_size), fill the
 * value with random bytes on SET, patch IP/UDP lengths + checksum and, in
 * range mode, the destination IP.
 */
inline static void fill_packet(struct tx_ctx *ctx, struct rte_mbuf *m, uint32_t dst_ip)
{
	char *pkt = rte_pktmbuf_mtod(m, char *);
	struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)
				  (pkt + sizeof(struct rte_ether_hdr));
	struct rte_udp_hdr *udp = (struct rte_udp_hdr *)((char *)ip + sizeof(*ip));
	uint8_t *payload = (uint8_t *)udp + sizeof(*udp);

	int is_get = (uint32_t)(xorshift64(&ctx->rng_state) % 100) < mica_get_pct;
	uint16_t frame_len = is_get ? mica_get_frame_len : mica_set_frame_len;

	m->data_len = frame_len;
	m->pkt_len  = frame_len;

	ip->total_length = is_get ? mica_ip_total_len_get_be : mica_ip_total_len_set_be;
	udp->dgram_len    = is_get ? mica_udp_dgram_len_get_be : mica_udp_dgram_len_set_be;

	if (range_mode)
		ip->dst_addr = rte_cpu_to_be_32(dst_ip);

	ip->hdr_checksum = 0;
	ip->hdr_checksum = rte_ipv4_cksum(ip);

	/* --- MICA payload: opcode + key (+ value on SET) --- */
	payload[0] = is_get ? mica_op_get : mica_op_set;

	uint64_t key_id = zipf_next(&mica_zipf, &ctx->rng_state);
	uint8_t *key = payload + 1;
	memset(key, 0, mica_key_size);
	memcpy(key, &key_id, RTE_MIN((size_t)mica_key_size, sizeof(key_id)));

	if (!is_get) {
		uint8_t *value = key + mica_key_size;
		for (uint16_t off = 0; off < mica_value_size; off += sizeof(uint64_t)) {
			uint64_t r = xorshift64(&ctx->rng_state);
			memcpy(value + off, &r,
			       RTE_MIN((size_t)(mica_value_size - off), sizeof(r)));
		}
	}
}

static int parse_mica_size(const char *arg)
{
	if (strcmp(arg, "tiny") == 0)
		return 0;
	if (strcmp(arg, "small") == 0)
		return 1;
	return -1;
}

static int parse_percent(const char *arg, uint32_t *value)
{
	char *end = NULL;
	unsigned long parsed;

	parsed = strtoul(arg, &end, 10);
	if (arg[0] == '\0' || end == arg || *end != '\0')
		return -1;
	if (parsed > 100)
		return -1;

	*value = (uint32_t)parsed;
	return 0;
}

static int parse_db_size(const char *arg, uint64_t *value)
{
	char *end = NULL;
	unsigned long long parsed;

	parsed = strtoull(arg, &end, 10);
	if (arg[0] == '\0' || end == arg || *end != '\0')
		return -1;
	if (parsed < 2)
		return -1;

	*value = (uint64_t)parsed;
	return 0;
}

static int parse_theta(const char *arg, double *value)
{
	char *end = NULL;
	double parsed;

	parsed = strtod(arg, &end);
	if (arg[0] == '\0' || end == arg || *end != '\0')
		return -1;
	if (!(parsed >= 0.0) || parsed >= 1.0)
		return -1;

	*value = parsed;
	return 0;
}

static int parse_tx_cores(const char *arg, uint16_t *value)
{
	char *end = NULL;
	unsigned long parsed;

	parsed = strtoul(arg, &end, 10);
	if (arg[0] == '\0' || end == arg || *end != '\0')
		return -1;
	if (parsed == 0 || parsed > MAX_WORKER_LCORES + 1)
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

		/* Prime the prefetch pipeline for the first packets in the burst. */
		for (uint16_t i = 0; i < RTE_MIN(nb_rx, (uint16_t)PREFETCH_OFFSET); i++)
			rte_prefetch0(rte_pktmbuf_mtod(bufs[i], void *));

		for (uint16_t i = 0; i < nb_rx; i++) {
			/* Prefetch packet data for a future iteration. */
			if (i + PREFETCH_OFFSET < nb_rx)
				rte_prefetch0(rte_pktmbuf_mtod(bufs[i + PREFETCH_OFFSET], void *));

			struct rte_mbuf *m = bufs[i];

			/* Need at least 51 bytes to read both timestamps */
			if (latency_mode && rte_pktmbuf_data_len(m) >= 51) {
				uint8_t *pkt = rte_pktmbuf_mtod(m, uint8_t *);

				if (debug_mode) {
					printf("[RX-DBG] q%u pkt #%"PRIu64" (%u bytes) "
					       "first 47 bytes:\n",
					       queue, ctx->rx_total,
					       rte_pktmbuf_data_len(m));
					for (int b = 0; b < 64; b++) {
						printf("%02x ", pkt[b]);
						if ((b & 0xf) == 0xf)
							printf("\n");
					}
					printf("\n");
				}

				uint32_t rx_timestamp;
				uint32_t tx_timestamp;
				memcpy(&rx_timestamp, pkt + 43, sizeof(uint32_t));
				memcpy(&tx_timestamp, pkt + 47, sizeof(uint32_t));
				uint32_t latency = tx_timestamp - rx_timestamp;

				if (debug_mode) {
					printf("[RX-DBG]   rx_ts=%u (off 43)  "
					       "tx_ts=%u (off 47)  "
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
		}

		for (uint16_t i = 0; i < nb_rx; i++)
			rte_pktmbuf_free(bufs[i]);

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

/* -----------------------------------------------------------------------
 * Pipeline mode: IO lcore + worker lcore per queue
 * -----------------------------------------------------------------------
 * The IO lcore's only job is to drain the NIC as fast as possible and
 * push mbufs into the per-queue SPSC ring.  Keeping this lcore free of
 * any packet inspection means it can sustain line-rate bursts without
 * jitter from processing work.
 *
 * The worker lcore dequeues from the ring, processes timestamps/histogram,
 * and bulk-frees the burst — completely off the NIC polling critical path.
 */

static int io_lcore(void *arg)
{
	struct rx_ctx *ctx = arg;
	uint16_t queue = ctx->queue_id;
	struct rte_ring *ring = work_rings[queue];
	struct rte_mbuf *bufs[BURST_SIZE];

	printf("[IO] lcore %u draining queue %u → ring\n", rte_lcore_id(), queue);

	while (keep_running) {
		uint16_t nb_rx = rte_eth_rx_burst(0, queue, bufs, BURST_SIZE);
		if (nb_rx == 0)
			continue;

		uint16_t nb_enq = rte_ring_enqueue_burst(ring, (void **)bufs,
							  nb_rx, NULL);
		/* Drop any packets that couldn't fit — ring is full (back-pressure). */
		for (uint16_t i = nb_enq; i < nb_rx; i++)
			rte_pktmbuf_free(bufs[i]);
	}
	return 0;
}

static int worker_lcore(void *arg)
{
	struct rx_ctx *ctx = arg;
	uint16_t queue = ctx->queue_id;
	struct rte_ring *ring = work_rings[queue];
	struct rte_mbuf *bufs[BURST_SIZE];
	uint64_t last_print = rte_rdtsc();
	uint64_t hz = rte_get_tsc_hz();

	uint64_t lat_sum = 0;
	uint64_t lat_count = 0;
	uint32_t lat_min = UINT32_MAX;
	uint32_t lat_max = 0;

	if (latency_mode) {
		ctx->hist_min = UINT32_MAX;
		ctx->hist_max = 0;
	}

	printf("[WORKER] lcore %u processing queue %u\n", rte_lcore_id(), queue);

	/* Drain the ring even after keep_running clears so we don't leak mbufs. */
	while (keep_running || rte_ring_count(ring) > 0) {
		uint16_t nb = rte_ring_dequeue_burst(ring, (void **)bufs,
						     BURST_SIZE, NULL);
		if (nb == 0)
			continue;

		ctx->rx_total += nb;

		/* Prime the prefetch pipeline. */
		for (uint16_t i = 0; i < RTE_MIN(nb, (uint16_t)PREFETCH_OFFSET); i++)
			rte_prefetch0(rte_pktmbuf_mtod(bufs[i], void *));

		for (uint16_t i = 0; i < nb; i++) {
			if (i + PREFETCH_OFFSET < nb)
				rte_prefetch0(rte_pktmbuf_mtod(bufs[i + PREFETCH_OFFSET],
							       void *));

			struct rte_mbuf *m = bufs[i];

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
				memcpy(&rx_timestamp, pkt + 43, sizeof(uint32_t));
				memcpy(&tx_timestamp, pkt + 47, sizeof(uint32_t));
				uint32_t latency = tx_timestamp - rx_timestamp;

				if (debug_mode) {
					printf("[RX-DBG]   rx_ts=%u (off 39)  "
					       "tx_ts=%u (off 43)  "
					       "latency=%u\n",
					       rx_timestamp, tx_timestamp, latency);
				}

				lat_sum += latency;
				lat_count++;
				if (latency < lat_min) lat_min = latency;
				if (latency > lat_max) lat_max = latency;

				uint32_t bin = latency / HIST_BIN_WIDTH;
				if (bin < HIST_NUM_BINS)
					ctx->hist_bins[bin]++;
				else
					ctx->hist_overflow++;
				ctx->hist_total++;
				if (latency < ctx->hist_min) ctx->hist_min = latency;
				if (latency > ctx->hist_max) ctx->hist_max = latency;
			}
		}

		for (uint16_t i = 0; i < nb; i++)
			rte_pktmbuf_free(bufs[i]);

		uint64_t now = rte_rdtsc();
		if (now - last_print >= hz) {
			if (latency_mode && lat_count > 0) {
				printf("[WORKER] q%u total=%'lu  interval_pkts=%"PRIu64
				       "  latency min=%u avg=%"PRIu64" max=%u\n",
				       queue, ctx->rx_total, lat_count,
				       lat_min, lat_sum / lat_count, lat_max);
			}
			last_print = now;
			lat_sum = 0;
			lat_count = 0;
			lat_min = UINT32_MAX;
			lat_max = 0;
		}
	}

	printf("[WORKER] q%u total packets processed: %'lu\n", queue, ctx->rx_total);
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

/* TX loop: runs on one lcore per TX queue. */
static int tx_loop(void *arg)
{
	struct tx_ctx *ctx = arg;
	struct rte_mbuf *bufs[BURST_SIZE];
	uint64_t tx_total = 0;
	uint64_t packet_index = ctx->packet_index;
	uint64_t start_tsc;
	uint64_t last_print = rte_rdtsc();
	uint64_t hz = rte_get_tsc_hz();

	/* Per-lcore PRNG seed (op choice, Zipfian key draw, value bytes). */
	ctx->rng_state = rte_rdtsc() ^ ((uint64_t)ctx->queue_id * 0x9e3779b97f4a7c15ULL) ^ 0xa5a5a5a5a5a5a5a5ULL;
	if (ctx->rng_state == 0)
		ctx->rng_state = 0x1234567890abcdefULL;

	/*
	 * Rate-limiting: if target_pps > 0, compute the TSC ticks
	 * to wait between each burst so that the average rate matches.
	 */
	uint64_t ticks_per_burst = 0;
	if (target_pps > 0) {
		uint64_t per_core_pps = target_pps /
			RTE_MAX((uint64_t)1, (uint64_t)nb_tx_lcores);
		if (per_core_pps == 0)
			per_core_pps = 1;
		ticks_per_burst = hz * BURST_SIZE / per_core_pps;
		printf("[TX] q%u rate-limiting to ~%" PRIu64 " pps "
		       "(burst interval ~%" PRIu64 " ticks)\n",
		       ctx->queue_id,
		       per_core_pps,
		       ticks_per_burst);
	} else {
		printf("[TX] q%u sending at line rate (no pps limit)\n", ctx->queue_id);
	}

	printf("[TX] q%u running on lcore %u\n", ctx->queue_id, rte_lcore_id());

	if (test_mode) {
		uint64_t warmup_target = TEST_WARMUP_PACKETS / nb_tx_lcores;
		if (ctx->queue_id < (TEST_WARMUP_PACKETS % nb_tx_lcores))
			warmup_target++;

		uint64_t warmup_sent = 0;
		while (keep_running && warmup_sent < warmup_target) {
			uint16_t burst = (uint16_t)RTE_MIN((uint64_t)BURST_SIZE,
						   warmup_target - warmup_sent);

			if (rte_pktmbuf_alloc_bulk(tx_mbuf_pool, bufs, burst) < 0)
				continue;

			for (uint16_t i = 0; i < burst; i++) {
				fill_packet(ctx, bufs[i], next_dst_ip(packet_index));
				packet_index += ctx->stride;
			}

			uint16_t sent = rte_eth_tx_burst(ctx->port_id, ctx->queue_id,
							 bufs, burst);
			for (uint16_t i = sent; i < burst; i++)
				rte_pktmbuf_free(bufs[i]);

			warmup_sent += sent;
			tx_total += sent;
		}

		printf("[TEST] q%u warmup sent %" PRIu64 " packets\n",
		       ctx->queue_id, warmup_sent);
	}

	start_tsc = rte_rdtsc();

	uint64_t next_send = rte_rdtsc();

	/* Periodic-burst state */
	uint64_t pb_next_burst = rte_rdtsc();
	uint64_t pb_burst_count = PERIODIC_BURST_COUNT / RTE_MAX((uint64_t)1, (uint64_t)nb_tx_lcores);
	if (pb_burst_count == 0)
		pb_burst_count = 1;
	uint64_t pb_remaining  = pb_burst_count;
	uint64_t pb_ticks_per_interval = hz * PERIODIC_BURST_INTERVAL_US / 1000000ULL;
	if (periodic_burst_mode)
		printf("[TX] q%u periodic-burst mode: %" PRIu64 " pkts every %u us\n",
		       ctx->queue_id,
		       pb_burst_count,
		       (unsigned int)PERIODIC_BURST_INTERVAL_US);

	/* Poisson-rate state */
	uint64_t pr_ticks_per_interval = hz * POISSON_RATE_INTERVAL_US / 1000000ULL;
	double   pr_lambda = (double)POISSON_RATE_MEAN_PPS *
			     POISSON_RATE_INTERVAL_US / 1000000.0;
	uint64_t pr_rng_state   = rte_rdtsc() ^ 0xdeadbeefcafe0000ULL;
	uint64_t pr_next_interval   = rte_rdtsc() + pr_ticks_per_interval;
	uint64_t pr_interval_pkts   = (uint64_t)(pr_lambda + 0.5); /* first interval: mean */
	uint64_t pr_sent_this_interval = 0;
	/* ticks between BURST_SIZE-packet sends to pace evenly across the interval */
	uint64_t pr_ticks_per_send  = (pr_interval_pkts > 0)
		? pr_ticks_per_interval /
		  ((pr_interval_pkts + BURST_SIZE - 1) / BURST_SIZE)
		: pr_ticks_per_interval;
	uint64_t pr_next_send       = rte_rdtsc();
	if (poisson_rate_mode)
		printf("[TX] q%u poisson-rate mode: mean %llu pps, "
		       "re-sample every %u us (lambda=%.0f pkts/interval)\n",
		       ctx->queue_id,
		       (unsigned long long)POISSON_RATE_MEAN_PPS,
		       (unsigned int)POISSON_RATE_INTERVAL_US,
		       pr_lambda);

	while (keep_running) {
		if (test_mode && (rte_rdtsc() - start_tsc) >= (10 * hz)) {
			printf("[TEST] 10 second run completed, stopping traffic\n");
			keep_running = 0;
			break;
		}

		if (periodic_burst_mode) {
			/* If the current burst is exhausted, idle until the next period. */
			if (pb_remaining == 0) {
				if (rte_rdtsc() < pb_next_burst)
					goto stats;
				pb_next_burst = rte_rdtsc() + pb_ticks_per_interval;
				pb_remaining   = PERIODIC_BURST_COUNT;
			}

			uint16_t burst = (uint16_t)RTE_MIN((uint64_t)BURST_SIZE, pb_remaining);
			if (rte_pktmbuf_alloc_bulk(tx_mbuf_pool, bufs, burst) < 0)
				goto stats;

			for (uint16_t i = 0; i < burst; i++) {
				fill_packet(ctx, bufs[i], next_dst_ip(packet_index));
				packet_index += ctx->stride;
			}

			uint16_t sent = rte_eth_tx_burst(ctx->port_id, ctx->queue_id,
							 bufs, burst);
			for (uint16_t j = sent; j < burst; j++)
				rte_pktmbuf_free(bufs[j]);
			tx_total   += sent;
			pb_remaining -= burst;
			goto stats;
		}

		if (poisson_rate_mode) {
			uint64_t now = rte_rdtsc();

			/* Start of a new interval: re-sample the rate. */
			if (now >= pr_next_interval) {
				pr_interval_pkts = poisson_sample(pr_lambda, &pr_rng_state);
				pr_sent_this_interval = 0;
				pr_next_interval += pr_ticks_per_interval;
				pr_ticks_per_send = (pr_interval_pkts > 0)
					? pr_ticks_per_interval /
					  ((pr_interval_pkts + BURST_SIZE - 1) / BURST_SIZE)
					: pr_ticks_per_interval;
				pr_next_send = now;
			}

			/* Idle for the rest of the interval once quota is filled. */
			if (pr_sent_this_interval >= pr_interval_pkts)
				goto stats;

			/* Pace sends evenly across the interval. */
			if (now < pr_next_send)
				goto stats;
			pr_next_send += pr_ticks_per_send;

			uint16_t burst = (uint16_t)RTE_MIN(
				(uint64_t)BURST_SIZE,
				pr_interval_pkts - pr_sent_this_interval);
			if (rte_pktmbuf_alloc_bulk(tx_mbuf_pool, bufs, burst) < 0)
				goto stats;

			for (uint16_t i = 0; i < burst; i++) {
				fill_packet(ctx, bufs[i], next_dst_ip(packet_index));
				packet_index += ctx->stride;
			}

			uint16_t sent = rte_eth_tx_burst(ctx->port_id, ctx->queue_id,
							 bufs, burst);
			for (uint16_t j = sent; j < burst; j++)
				rte_pktmbuf_free(bufs[j]);
			tx_total += sent;
			pr_sent_this_interval += sent;
			goto stats;
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
			fill_packet(ctx, bufs[i], next_dst_ip(packet_index));
			packet_index += ctx->stride;
		}

		uint16_t sent = rte_eth_tx_burst(ctx->port_id, ctx->queue_id, bufs, BURST_SIZE);
		for (uint16_t j = sent; j < BURST_SIZE; j++)
			rte_pktmbuf_free(bufs[j]);
		tx_total += sent;

stats:
		/* Print a summary every second */
		{
			uint64_t now = rte_rdtsc();
			if (now - last_print >= hz) {
				printf("[TX] q%u sent %" PRIu64 " total packets\n",
				       ctx->queue_id, tx_total);
				last_print = now;
			}
		}
	}

	printf("[TX] q%u total packets sent: %" PRIu64 "\n",
	       ctx->queue_id, tx_total);
	ctx->tx_total = tx_total;
	return 0;
}

static void usage(const char *prog)
{
	printf("Usage: %s [EAL options] -- [--pps <packets/sec>] [--tx-cores <count>] "
	       "[--mica-size tiny|small] [--mica-get-pct <0-100>] [--mica-db-size <N>] "
	       "[--mica-zipf-theta <0-1)>] [--range] [--debug] [--test] [--latency] "
	       "[--periodic-burst] [--poisson-rate]\n"
	       "  --pps N   Target TX rate in packets per second (0 = line rate, default)\n"
	       "  --tx-cores N   Number of lcores used for TX (includes main lcore, default: 1)\n"
	       "  --mica-size tiny|small   MICA key/value size class (default: tiny; "
	       "tiny=%u/%uB key/value, small=%u/%uB key/value)\n"
	       "  --mica-get-pct N   Percentage of GET requests, rest are SET (default: %u)\n"
	       "  --mica-db-size N   Number of distinct keys in the Zipfian key space (default: %u)\n"
	       "  --mica-zipf-theta X   Zipfian skew in [0,1) (default: %.2f)\n"
	       "  --range   Vary the destination IPv4 low 16 bits for each packet\n"
	       "  --debug   Hex-dump received packets up to the timestamp fields\n"
	       "  --test    Send 10000 warmup packets, then run traffic for 10 seconds, wait 2 second, then exit\n"
	       "  --latency Enable latency tracking and histogram (default: disabled)\n"
	       "  --periodic-burst  Send %u packets as a burst at the start of each %u us window;\n"
	       "                    no traffic for the rest of the window.\n"
	       "  --poisson-rate    Re-sample TX rate every %u us from Poisson(mean=%llu pps);\n"
	       "                    packets are paced evenly across each interval.\n",
	       prog,
	       (unsigned int)TINY_KEY_SIZE, (unsigned int)TINY_VALUE_SIZE,
	       (unsigned int)SMALL_KEY_SIZE, (unsigned int)SMALL_VALUE_SIZE,
	       (unsigned int)DEFAULT_MICA_GET_PCT,
	       (unsigned int)DEFAULT_MICA_DB_SIZE,
	       DEFAULT_MICA_ZIPF_THETA,
	       (unsigned int)PERIODIC_BURST_COUNT,
	       (unsigned int)PERIODIC_BURST_INTERVAL_US,
	       (unsigned int)POISSON_RATE_INTERVAL_US, (unsigned long long)POISSON_RATE_MEAN_PPS);
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
		{"pps",             required_argument, NULL, 'p'},
		{"tx-cores",        required_argument, NULL, 'c'},
		{"mica-size",       required_argument, NULL, 'z'},
		{"mica-get-pct",    required_argument, NULL, 'g'},
		{"mica-db-size",    required_argument, NULL, 'D'},
		{"mica-zipf-theta", required_argument, NULL, 'Z'},
		{"range",           no_argument,       NULL, 'r'},
		{"debug",           no_argument,       NULL, 'd'},
		{"test",            no_argument,       NULL, 't'},
		{"latency",         no_argument,       NULL, 'l'},
		{"periodic-burst",  no_argument,       NULL, 'b'},
		{"poisson-rate",    no_argument,       NULL, 'P'},
		{"help",            no_argument,       NULL, 'h'},
		{NULL,              0,                 NULL,  0 }
	};

	int opt;
	while ((opt = getopt_long(argc, argv, "p:c:z:g:D:Z:rdtlbPh", long_options, NULL)) != -1) {
		switch (opt) {
		case 'p':
			target_pps = strtoull(optarg, NULL, 10);
			break;
		case 'c':
			if (parse_tx_cores(optarg, &tx_cores) != 0)
				rte_exit(EXIT_FAILURE,
					 "Invalid TX core count '%s' (expected 1-%u)\n",
					 optarg, (unsigned int)(MAX_WORKER_LCORES + 1));
			break;
		case 'z': {
			int size_class = parse_mica_size(optarg);
			if (size_class < 0)
				rte_exit(EXIT_FAILURE,
					 "Invalid --mica-size '%s' (expected tiny|small)\n",
					 optarg);
			mica_use_small = size_class;
			break;
		}
		case 'g':
			if (parse_percent(optarg, &mica_get_pct) != 0)
				rte_exit(EXIT_FAILURE,
					 "Invalid --mica-get-pct '%s' (expected 0-100)\n",
					 optarg);
			break;
		case 'D':
			if (parse_db_size(optarg, &mica_db_size) != 0)
				rte_exit(EXIT_FAILURE,
					 "Invalid --mica-db-size '%s' (expected >= 2)\n",
					 optarg);
			break;
		case 'Z':
			if (parse_theta(optarg, &mica_zipf_theta) != 0)
				rte_exit(EXIT_FAILURE,
					 "Invalid --mica-zipf-theta '%s' (expected in [0,1))\n",
					 optarg);
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
		case 'b':
			periodic_burst_mode = 1;
			break;
		case 'P':
			poisson_rate_mode = 1;
			break;
		case 'h':
		default:
			usage(argv[0]);
			return 0;
		}
	}

	signal(SIGINT,  signal_handler);
	signal(SIGTERM, signal_handler);

	/* --- Resolve MICA size class into concrete key/value sizes --- */
	mica_key_size   = mica_use_small ? SMALL_KEY_SIZE   : TINY_KEY_SIZE;
	mica_value_size = mica_use_small ? SMALL_VALUE_SIZE  : TINY_VALUE_SIZE;
	mica_op_get     = mica_use_small ? MICA_UDP_OP_GET_SMALL : MICA_UDP_OP_GET_TINY;
	mica_op_set     = mica_use_small ? MICA_UDP_OP_SET_SMALL : MICA_UDP_OP_SET_TINY;

	mica_get_payload_len = 1 + mica_key_size;
	mica_set_payload_len = 1 + mica_key_size + mica_value_size;
	mica_get_frame_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) +
			     sizeof(struct rte_udp_hdr) + mica_get_payload_len;
	mica_set_frame_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) +
			     sizeof(struct rte_udp_hdr) + mica_set_payload_len;

	mica_ip_total_len_get_be = rte_cpu_to_be_16(sizeof(struct rte_ipv4_hdr) +
						     sizeof(struct rte_udp_hdr) +
						     mica_get_payload_len);
	mica_ip_total_len_set_be = rte_cpu_to_be_16(sizeof(struct rte_ipv4_hdr) +
						     sizeof(struct rte_udp_hdr) +
						     mica_set_payload_len);
	mica_udp_dgram_len_get_be = rte_cpu_to_be_16(sizeof(struct rte_udp_hdr) + mica_get_payload_len);
	mica_udp_dgram_len_set_be = rte_cpu_to_be_16(sizeof(struct rte_udp_hdr) + mica_set_payload_len);

	/* Zipfian generator: same (n, theta) for every TX lcore, computed once. */
	zipf_gen_init(&mica_zipf, mica_db_size, mica_zipf_theta);

	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports == 0)
		rte_exit(EXIT_FAILURE, "No Ethernet ports available\n");

	printf("Using port %u (of %u available)\n", port_id, nb_ports);
	printf("MICA size class: %s (key=%uB value=%uB, GET payload=%uB SET payload=%uB)\n",
	       mica_use_small ? "small" : "tiny",
	       mica_key_size, mica_value_size,
	       mica_get_payload_len, mica_set_payload_len);
	printf("MICA workload: get-pct=%u%%  db-size=%" PRIu64 "  zipf-theta=%.3f\n",
	       mica_get_pct, mica_db_size, mica_zipf_theta);
	printf("Destination IP range mode: %s\n",
	       range_mode ? "enabled (varying low 16 bits)" : "disabled");
	printf("Latency / histogram tracking: %s\n",
	       latency_mode ? "enabled" : "disabled");
	printf("TX lcores requested: %u\n", tx_cores);

	/* Collect all worker lcores and reserve N-1 workers for TX (main is TX core 0). */
	uint16_t nb_worker_lcores = 0;
	unsigned int worker_lcores[MAX_WORKER_LCORES];
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		if (nb_worker_lcores < MAX_WORKER_LCORES)
			worker_lcores[nb_worker_lcores++] = lcore_id;
	}

	if (tx_cores > nb_worker_lcores + 1)
		rte_exit(EXIT_FAILURE,
			 "Requested --tx-cores=%u but only %u total lcores are available for TX\n",
			 tx_cores, (unsigned int)(nb_worker_lcores + 1));

	uint16_t nb_extra_tx_workers = tx_cores - 1;
	uint16_t rx_worker_offset = nb_extra_tx_workers;
	uint16_t nb_rx_worker_lcores = nb_worker_lcores - nb_extra_tx_workers;
	nb_tx_lcores = tx_cores;

	if (nb_rx_worker_lcores >= 2) {
		/* Pipeline mode: one IO lcore + one worker lcore per queue. */
		pipeline_mode = 1;
		nb_rx_queues = nb_rx_worker_lcores / 2;
	} else {
		nb_rx_queues = nb_rx_worker_lcores > 0 ? nb_rx_worker_lcores : 1;
	}
	if (nb_rx_queues > MAX_RX_QUEUES)
		nb_rx_queues = MAX_RX_QUEUES;

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
	ret = port_init(port_id, &nb_rx_queues, &nb_tx_lcores);
	if (ret != 0)
		rte_exit(EXIT_FAILURE, "Cannot init port %u (rxq=%u txq=%u): %s\n",
			 port_id, nb_rx_queues, nb_tx_lcores,
			 rte_strerror(-ret));

	if (nb_tx_lcores != tx_cores)
		rte_exit(EXIT_FAILURE,
			 "TX queue count mismatch after init (requested %u, got %u)\n",
			 tx_cores, nb_tx_lcores);

	/* Initialise per-queue RX contexts */
	memset(rx_ctxs, 0, sizeof(rx_ctxs));
	for (uint16_t q = 0; q < nb_rx_queues; q++)
		rx_ctxs[q].queue_id = q;
	printf("Using %u RX queue(s)\n", nb_rx_queues);
	printf("Using %u TX queue(s)\n", nb_tx_lcores);

	/* Initialise TX contexts (queue 0 runs on main lcore). */
	memset(tx_ctxs, 0, sizeof(tx_ctxs));
	for (uint16_t i = 0; i < nb_tx_lcores; i++) {
		tx_ctxs[i].port_id = port_id;
		tx_ctxs[i].queue_id = i;
		tx_ctxs[i].stride = nb_tx_lcores;
		tx_ctxs[i].packet_index = i;
	}

	/* --- Launch RX lcores --- */
	if (pipeline_mode) {
		/*
		 * Pipeline: for each queue, launch an IO lcore (NIC drain only)
		 * and a worker lcore (packet processing).  Two lcores per queue.
		 */
		for (uint16_t q = 0; q < nb_rx_queues; q++) {
			char ring_name[32];
			snprintf(ring_name, sizeof(ring_name), "work_ring_%u", q);
			work_rings[q] = rte_ring_create(ring_name, WORK_RING_SIZE,
							rte_socket_id(),
							RING_F_SP_ENQ | RING_F_SC_DEQ);
			if (work_rings[q] == NULL)
				rte_exit(EXIT_FAILURE,
					 "Cannot create work ring %u: %s\n",
					 q, rte_strerror(rte_errno));

			rte_eal_remote_launch(io_lcore,     &rx_ctxs[q], worker_lcores[rx_worker_offset + q * 2]);
			rte_eal_remote_launch(worker_lcore, &rx_ctxs[q], worker_lcores[rx_worker_offset + q * 2 + 1]);
		}
		printf("Pipeline mode: launched %u queue(s) × (1 IO + 1 worker) lcore\n",
		       nb_rx_queues);
	} else {
		/* Single-lcore mode (optimised rx_loop with prefetch). */
		for (uint16_t q = 0; q < nb_rx_queues && q < nb_rx_worker_lcores; q++)
			rte_eal_remote_launch(rx_loop, &rx_ctxs[q], worker_lcores[rx_worker_offset + q]);

		if (nb_rx_worker_lcores == 0)
			printf("Warning: no secondary lcore available; RX disabled. "
			       "Run with more lcores or lower --tx-cores\n");
		else
			printf("Single-lcore mode: launched %u RX lcore(s)\n", nb_rx_queues);
	}

	rte_delay_ms(1000);

	/* Launch extra TX lcores (if any). */
	for (uint16_t i = 1; i < nb_tx_lcores; i++)
		rte_eal_remote_launch(tx_loop, &tx_ctxs[i], worker_lcores[i - 1]);

	/* --- TX queue 0 runs on the main lcore --- */
	tx_loop(&tx_ctxs[0]);

	if (test_mode) {
		printf("[TEST] Waiting 2 seconds before exit\n");
		rte_delay_ms(2000);
	}

	/* --- Wait for RX lcore --- */
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		rte_eal_wait_lcore(lcore_id);
	}

	/* --- Merge per-lcore RX stats into globals --- */
	merge_rx_ctxs();

	/* --- Merge per-lcore TX stats into globals --- */
	tx_total_global = 0;
	for (uint16_t i = 0; i < nb_tx_lcores; i++)
		tx_total_global += tx_ctxs[i].tx_total;

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

		/* diff < 0.5% of sent packets, i.e. abs_diff * 200 < sent */
		if (sent == 0)
			success = (abs_diff == 0);
		else
			success = (abs_diff * 200ULL < sent);
		float diff_pct = sent > 0 ? (100.0 * abs_diff / sent) : 0.0;
		if (success) {
			printf("\x1b[32mSUCCESS\x1b[0m: final diff=%" PRIu64
			       " (%.2f%% of sent=%" PRIu64 ")\n",
			       abs_diff, diff_pct, sent);
			exit_status = 0;
		} else {
			printf("\x1b[35mFAIL\x1b[0m: final diff=%" PRIu64
			       " (%.2f%% of sent=%" PRIu64 ")\n",
			       abs_diff, diff_pct, sent);
			exit_status = -1;
		}
	}

	/* --- Dump latency histogram --- */
	if (latency_mode)
		hist_dump("latency_histogram_mica.csv");

	/* --- Cleanup --- */
	rte_eth_dev_stop(port_id);
	rte_eth_dev_close(port_id);
	rte_eal_cleanup();

	return exit_status;
}
