/*
 * tsps.c for tsps
 * by lenormf
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>// required on certain implementations of socket(2)
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <limits.h>
#include <time.h>
#include <string.h>

// FIXME
#define DEBUG

// Preprocessor macros
#define MAX_PORTS_SCANNED 1024
#define MAX_FILTERED_RETRIES 3
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))
#define RAND_UINT16() ((uint16_t)rand() % (USHRT_MAX + 1))
#define RAND_UINT32() ((uint32_t)rand() % UINT_MAX)

// Debugging macros
#ifdef DEBUG
#define DEBUG_PRINTF(fmt, va...) fprintf(stderr, fmt, ##va)
#else
#define DEBUG_PRINTF(_, ...)
#endif

#define DEBUG_PRINT_IPV4(buff) do { \
	struct iphdr *p = (struct iphdr*)(buff); \
	DEBUG_PRINTF("IPv4 packet:\n" \
	       "version: %u\n" \
	       "IHL: %u\n" \
	       "TOS: %u\n" \
	       "tot_len: %u\n" \
	       "id: %u\n" \
	       "flags: %u\n" \
	       "frag_off: %u\n" \
	       "TTL: %u\n" \
	       "protocol: %u\n" \
	       "check: %x\n" \
	       "saddr: %u\n" \
	       "daddr: %u\n\n", \
	       (p)->version, (p)->ihl, (p)->tos, ntohs((p)->tot_len), ntohs((p)->id), (ntohs((p)->frag_off) & 0xC000) >> 12, ntohs((p)->frag_off) & 0x3FFF, (p)->ttl, (p)->protocol, ntohs((p)->check), ntohl((p)->saddr), ntohl((p)->daddr)); \
	(void)p; \
} while (0)

#define DEBUG_PRINT_TCPV4(buff) do { \
	struct tcphdr *p = (struct tcphdr*)(buff); \
	DEBUG_PRINTF("TCPv4 packet:\n" \
	       "source: %u\n" \
	       "dest: %u\n" \
	       "seq: %u\n" \
	       "ack_seq: %u\n" \
	       "doff: %u\n" \
	       "fin: %u\n" \
	       "syn: %u\n" \
	       "rst: %u\n" \
	       "psh: %u\n" \
	       "ack: %u\n" \
	       "urg: %u\n" \
	       "window: %u\n" \
	       "check: %x\n" \
	       "urg_prt: %u\n\n", \
	       ntohs((p)->source), ntohs((p)->dest), ntohl((p)->seq), ntohl((p)->ack_seq), (p)->doff, (p)->fin, (p)->syn, (p)->rst, (p)->psh, (p)->ack, (p)->urg, ntohs((p)->window), ntohs((p)->check), ntohs((p)->urg_ptr)); \
	(void)p; \
} while (0)

// Types
typedef enum {
	PACKET_TCP4,
} ePacketType;

typedef enum {
	FLAG_NULL = 0,
	FLAG_FIN = 1,
	FLAG_SYN = 2,
	FLAG_XSMAS = 4,
} eTCPFlags;

typedef enum {
	METHOD_UNKNOWN = -1,
	METHOD_SYN,
} eScanMethod;

typedef enum {
	SERVICE_UNKNOWN,
	SERVICE_SSH,
} eService;

typedef enum {
	STATUS_UNKNOWN = -1,
	STATUS_OPEN = 1,
	STATUS_CLOSED = 2,
	STATUS_FILTERED = 4,
} ePortStatus;

typedef enum {
	STATE_UNKNOWN = -1,
	STATE_READ,
	STATE_WRITE,
	STATE_TIMEOUT,
} eFdState;

typedef struct ports_list_s {
	uint16_t port;
	ePortStatus status;
	eService service;

	struct ports_list_s *next;
} ports_list_t;

typedef struct scan_config_s {
	int verbose;
	int fingerprint_services;
	eScanMethod method;
	char const *target_address;
	struct sockaddr *target_sockaddr;
} scan_config_t;

struct tcp_pseudo_header_s {
	uint32_t saddr;
	uint32_t taddr;
	uint8_t zero;
	uint8_t protocol;
	uint16_t length;
};

// Utils/private functions
static ports_list_t *push_port(ports_list_t **pl, uint16_t port, ePortStatus status, eService service) {
	ports_list_t *new;

	new = malloc(sizeof(ports_list_t));
	if (!new)
		return NULL;

	new->port = port;
	new->service = service;
	new->status = status;
	new->next = *pl;
	*pl = new;

	return new;
}

static char const *ps_to_str(ePortStatus st) {
	static struct {
		ePortStatus status;
		char const *s;
	} const st_ref[] = {
		{STATUS_UNKNOWN, "unknown"},
		{STATUS_OPEN, "open"},
		{STATUS_CLOSED, "closed"},
		{STATUS_FILTERED, "filtered"},
	};
	uint32_t i;
	for (i = 0; i < ARRAY_SIZE(st_ref); i++)
		if (st_ref[i].status == st)
			return st_ref[i].s;

	return NULL;
}

static struct {
	eService service;
	char const *s;
} const ss_ref[] = {
	{SERVICE_UNKNOWN, "unknown"},
	{SERVICE_SSH, "ssh"},
};

static char const *pss_to_str(eService ss) {
	uint32_t i;
	for (i = 0; i < ARRAY_SIZE(ss_ref); i++)
		if (ss_ref[i].service == ss)
			return ss_ref[i].s;

	return NULL;
}

static struct sockaddr *dn_to_sockaddr(char const *dn) {
	static struct sockaddr ret;

	struct addrinfo hints;
	struct addrinfo *results;

	bzero(&hints, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;
	hints.ai_socktype = 0;
	hints.ai_flags = 0;
	hints.ai_protocol = 0;

	if (getaddrinfo(dn, NULL, &hints, &results) < 0)
		return NULL;

	memcpy(&ret, results->ai_addr, sizeof(struct sockaddr));

	freeaddrinfo(results);

	return &ret;
}

static void array_shuffle(uint16_t *a, size_t n) {
	size_t i;
	for (i = 0; i < n - 1; i++) {
		size_t j = i + rand() / (RAND_MAX / (n - i) + 1);
		uint16_t tmp = a[j];
		a[j] = a[i];
		a[i] = tmp;
	}
}

static uint16_t tcp4_checksum(uint16_t *buffer, int size) {
	uint64_t cksum;

	cksum = 0;
	while (size > 1) {
		cksum += *buffer++;
		size -= sizeof(uint16_t);
	}
	if (size)
		cksum += *(uint16_t*)buffer;

	cksum = (cksum >> 16) + (cksum & 0xFFFF);
	cksum += (cksum >> 16);

	return (uint16_t)(~cksum);
}

static uint8_t await_fd_state(int fd, eFdState state, uint64_t usec) {
	int r;
	fd_set fds;
	struct timeval tv = {
		.tv_sec = 0,
		.tv_usec = usec,
	};

	FD_ZERO(&fds);
	FD_SET(fd, &fds);
	if (state == STATE_READ) {
		r = select(fd + 1, &fds, NULL, NULL, NULL);
	} else if (state == STATE_WRITE) {
		r = select(fd + 1, NULL, &fds, NULL, NULL);
	} else if (state == STATE_TIMEOUT) {
		r = select(0, NULL, NULL, NULL, &tv);
	} else {
		return 1;
	}

	if (r < 0)
		return 1;

	if (state == STATE_TIMEOUT
	    || FD_ISSET(fd, &fds))
		return 0;

	return 1;
}

// Packet crafters
void crafter_ip4(char *buffer, struct sockaddr *taddr, uint8_t target_protocol) {
	struct iphdr *head = (struct iphdr*)buffer;

	head->ihl = 5;
	head->version = 4;
	head->tos = 0;
	head->id = htons(RAND_UINT16());
	head->frag_off = htons(0x4000);
	head->ttl = 0x40;
	head->protocol = target_protocol;
	head->check = htons(0);
	// FIXME
	head->saddr = inet_addr("192.168.1.24");//htons(RAND_UINT32());
	head->daddr = ((struct sockaddr_in*)taddr)->sin_addr.s_addr;

	switch (target_protocol) {
		case IPPROTO_TCP:
			head->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
			// Set by the kernel
			head->check = 0;
			break;
	}
}

void crafter_tcp4(char *buffer, struct sockaddr *taddr, uint16_t port, uint16_t options) {
	struct iphdr *iphead;
	struct tcphdr *tcphead;
	struct tcp_pseudo_header_s pseudo;

	crafter_ip4(buffer, taddr, IPPROTO_TCP);

	iphead = (struct iphdr*)buffer;
	tcphead = (struct tcphdr*)(buffer + iphead->ihl * sizeof(uint32_t));

	tcphead->source = RAND_UINT16();
	tcphead->dest = htons(port);
	tcphead->seq = RAND_UINT32();
	tcphead->ack_seq = 0;
	tcphead->doff = sizeof(struct tcphdr) / sizeof(uint32_t);
	tcphead->res1 = 0;
	tcphead->res2 = 0;

	tcphead->urg = 0;
	tcphead->ack = 0;
	tcphead->psh = 0;
	tcphead->rst = 0;
	tcphead->syn = 0;
	tcphead->fin = 0;

	if ((options & FLAG_FIN) == FLAG_FIN)
		tcphead->fin = 1;
	else if ((options & FLAG_SYN) == FLAG_SYN)
		tcphead->syn = 1;
	else if ((options & FLAG_XSMAS) == FLAG_XSMAS) {
		tcphead->fin = 1;
		tcphead->psh = 1;
		tcphead->urg = 1;
	}

	tcphead->window = htons(29200);
	tcphead->check = 0;
	tcphead->urg_ptr = 0;

	char buff[sizeof(struct tcp_pseudo_header_s) + sizeof(struct tcphdr)];

	pseudo.saddr = iphead->saddr;
	pseudo.taddr = iphead->daddr;
	pseudo.zero = 0;
	pseudo.protocol = iphead->protocol;
	pseudo.length = htons(sizeof(struct tcphdr));

	memcpy(buff, tcphead, sizeof(struct tcphdr));
	memcpy(buff + sizeof(struct tcphdr), &pseudo, sizeof(struct tcp_pseudo_header_s));

	tcphead->check = tcp4_checksum((uint16_t*)buff, sizeof(struct tcp_pseudo_header_s) + ntohs(pseudo.length));
}

static struct {
	ePacketType type;
	void (*craft)(char*, struct sockaddr*, uint16_t, uint16_t);
} const packet_crafters_ref[] = {
	{PACKET_TCP4, &crafter_tcp4},
};

// Port scanners
static ePortStatus scanner_syn(int sock, struct sockaddr *taddr, uint16_t port) {
	struct sockaddr_in sin;
	char packet[128];

	packet_crafters_ref[PACKET_TCP4].craft(packet, taddr, port, FLAG_SYN);

	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	sin.sin_addr.s_addr = ((struct sockaddr_in*)taddr)->sin_addr.s_addr;

	DEBUG_PRINT_IPV4(packet);
	DEBUG_PRINT_TCPV4(packet + ((struct iphdr*)packet)->ihl * sizeof(uint32_t));

	if (await_fd_state(sock, STATE_WRITE, 0))
		return STATUS_UNKNOWN;

	if (sendto(sock, packet, ntohs(((struct iphdr*)packet)->tot_len), 0, (struct sockaddr*)&sin, sizeof(struct sockaddr_in)) < 0) {
		fprintf(stderr, "Unable to send packet (port %hd)\n", port);
		return STATUS_UNKNOWN;
	}

	char buffer[256];
	struct iphdr *iph;
	struct tcphdr *tcph;
	while (1) {
		uint32_t i;
		uint8_t read_state;
		ssize_t len;

		i = 0;
		do {

			i++;
			read_state = await_fd_state(sock, STATE_READ, 200 * 1000);
			if (read_state == 0)
				break;

			if (read_state == 1)
				return STATUS_UNKNOWN;
			else if (i >= MAX_FILTERED_RETRIES)
				return STATUS_FILTERED;
		} while (read_state == 2);

		len = recv(sock, buffer, ARRAY_SIZE(buffer), 0);
		if (len < 0) {
			return STATUS_UNKNOWN;
		}

		if ((size_t)len < sizeof(struct iphdr) + sizeof(struct tcphdr)) {
			// packet too short
			continue;
		}

		iph = (struct iphdr*)buffer;
		if (iph->protocol != IPPROTO_TCP) {
			// not TCP
			continue;
		}

		DEBUG_PRINT_IPV4(iph);
		DEBUG_PRINT_TCPV4(tcph);

		tcph = (struct tcphdr*)(buffer + iph->ihl * sizeof(uint32_t));
		if (ntohs(tcph->source) != port) {
			// wrong port
			continue;
		}

		if (tcph->rst == 1)
			return STATUS_CLOSED;

		break;
	}

	return STATUS_OPEN;
}

static struct {
	eScanMethod method;
	char const *str;
	ePortStatus (*scanner)(int, struct sockaddr*, uint16_t);
} const port_scanners_ref[] = {
	{METHOD_SYN, "SYN", &scanner_syn},
};

static ePortStatus scan_port(int sock, uint16_t port, scan_config_t const *conf) {
	return port_scanners_ref[conf->method].scanner(sock, conf->target_sockaddr, port);
}

static eService scan_service(uint16_t port) {
	return SERVICE_UNKNOWN;
}

static ports_list_t *scan_ports(int sock, scan_config_t const *conf) {
	ports_list_t *pl;
	uint16_t ports[MAX_PORTS_SCANNED];
	unsigned int i;

	pl = NULL;
	for (i = 0; i < ARRAY_SIZE(ports); i++)
		ports[i] = i;
	array_shuffle(ports, ARRAY_SIZE(ports));

	for (i = 0; i < ARRAY_SIZE(ports); i++) {
		ePortStatus s;
		eService ss;

		ss = SERVICE_UNKNOWN;
		s = scan_port(sock, ports[i], conf);
		if ((s & STATUS_OPEN) == STATUS_OPEN)
			ss = scan_service(ports[i]);

		if (!push_port(&pl, ports[i], s, ss)) {
			fprintf(stderr, "Memory exhausted\n");
			return NULL;
		}
	}

	return pl;
}

static void print_report(ports_list_t *report, int verbose) {
	char const * const head_fmt = "%7s   %10s   %s\n";
	char const * const entry_fmt = "%7d | %10s . %s\n";

	fprintf(stdout, head_fmt, "port", "status", "service");

	uint32_t i;
	for (i = 0; i < MAX_PORTS_SCANNED; i++) {
		ports_list_t *pl;

		pl = report;
		while (pl) {
			if (i == pl->port) {
				if ((pl->status != STATUS_UNKNOWN
				     && pl->status != STATUS_CLOSED)
				    || verbose)
					fprintf(stdout, entry_fmt, pl->port, ps_to_str(pl->status), pss_to_str(pl->service));
				break;
			}

			pl = pl->next;
		}
	}
}

static void usage(char const *av) {
	fprintf(stdout, "Usage: %s [-v] [-f] [-h | -m <method>] <target address>\n", av);
	fprintf(stdout, "\t-v: enable verbose mode (default: disabled)\n"
			"\t-m: scan method (default: SYN)\n"
			"\t-f: enable services fingerprinting (default: disabled)\n");
}

static int set_config(int ac, char **av, scan_config_t *conf) {
	int opt;

	bzero(conf, sizeof(scan_config_t));

	conf->method = METHOD_SYN;
	while ((opt = getopt(ac, av, "hvfm:")) != -1) {
		switch (opt) {
			case 'h':
				usage(*av);
				return 1;
			case 'v':
				conf->verbose = 1;
				break;
			case 'f':
				conf->fingerprint_services = 1;
				break;
			case 'm': {
				uint32_t i;
				for (i = 0; i < ARRAY_SIZE(port_scanners_ref); i++)
					if (!strcasecmp(port_scanners_ref[i].str, optarg)) {
						conf->method = port_scanners_ref[i].method;
						break;
					}
				if (conf->method == METHOD_UNKNOWN) {
					fprintf(stderr, "Unsupported scanning method \"%s\"\n", optarg);
					return 1;
				}
				break;
			}
			default:
				fprintf(stderr, "Unknown option '%c'\n", opt);
				return 1;
		}
	}

	if (optind >= ac) {
		fprintf(stderr, "Option parsing error\n");
		return 1;
	}

	conf->target_address = av[optind];

	conf->target_sockaddr = dn_to_sockaddr(conf->target_address);
	if (!conf->target_sockaddr) {
		fprintf(stderr, "Unable to resolve address\n");
		return 1;
	}

	return 0;
}

// Entry point
int main(int ac, char **av) {
	int sock;
	scan_config_t conf;
	ports_list_t *report;

	if (ac < 2) {
		usage(*av);
		return 1;
	}

	srand(getpid() * time(NULL));

	if (set_config(ac, av, &conf)) {
		return 2;
	}

	sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (sock < 0) {
		fprintf(stderr, "Unable to create socket\n");
		return 3;
	}

	int const one = 1;
	if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
		fprintf(stderr, "Unable to set options on the socket\n");
		return 4;
	}

	if (conf.verbose)
		fprintf(stdout, "Scan summary: host:%s ports:0-%d method:%u\n", conf.target_address, MAX_PORTS_SCANNED, conf.method);

	report = scan_ports(sock, &conf);
	print_report(report, conf.verbose);

	close(sock);
	for (; report != NULL; report = report->next)
		free(report);

	return 0;
}
