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
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <limits.h>
#include <time.h>
#include <string.h>

// Preprocessor macros
#define MAX_PORTS_SCANNED 1024
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))
#define RAND_UINT16() ((uint16_t)rand() % (USHRT_MAX + 1))
#define RAND_UINT32() ((uint32_t)rand() % UINT_MAX)

#define PRINT_IPV4(p) do { \
	printf("IPv4 packet:\n" \
	       "version: %u\n" \
	       "IHL: %u\n" \
	       "TOS: %u\n" \
	       "tot_len: %u\n" \
	       "id: %u\n" \
	       "frag_off: %u\n" \
	       "TTL: %u\n" \
	       "protocol: %u\n" \
	       "check: %x\n" \
	       "saddr: %u\n" \
	       "daddr: %u\n", \
	       (p)->version, (p)->ihl, (p)->tos, ntohs((p)->tot_len), (p)->id, (p)->frag_off, (p)->ttl, (p)->protocol, ntohs((p)->check), ntohl((p)->saddr), ntohl((p)->daddr)); \
} while (0)

#define PRINT_TCPV4(p) do { \
	printf("TCPv4 packet:\n" \
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
	       "urg_prt: %u\n", \
	       ntohs((p)->source), ntohs((p)->dest), ntohl((p)->seq), ntohl((p)->ack_seq), (p)->doff, (p)->fin, (p)->syn, (p)->rst, (p)->psh, (p)->ack, (p)->urg, ntohs((p)->window), ntohs((p)->check), ntohs((p)->urg_ptr)); \
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
	STATUS_UNKNOWN = -1,
	STATUS_OPEN = 1,
	STATUS_CLOSED = 2,
	STATUS_FILTERED = 4,
} ePortStatus;

typedef struct ports_list_s {
	uint16_t port;
	ePortStatus status;

	struct ports_list_s *next;
} ports_list_t;

typedef struct {
	int verbose;
	eScanMethod method;
	char const *target_address;
	struct sockaddr *target_sockaddr;
} scan_config_t;

// Utils/private functions
static ports_list_t *push_port(ports_list_t **pl, uint16_t port, ePortStatus status) {
	ports_list_t *new;

	new = malloc(sizeof(ports_list_t));
	if (!new)
		return NULL;

	new->port = port;
	new->status = status;
	new->next = *pl;
	*pl = new;

	return new;
}

static char const *ps_to_str(ePortStatus st) {
	static struct {
		ePortStatus status;
		char const *s;
	} st_ref[] = {
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
	unsigned long cksum;

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

// Packet crafters
void crafter_ip4(char *buffer, struct sockaddr *taddr, uint8_t target_protocol) {
	struct iphdr *head = (struct iphdr*)buffer;

	head->ihl = 5;
	head->version = 4;
	head->tos = 0;
	head->id = RAND_UINT16();
	head->frag_off = 0;
	head->ttl = 255;
	head->protocol = target_protocol;
	head->check = 0;
	head->saddr = RAND_UINT32();
	head->daddr = htons(((struct sockaddr_in*)taddr)->sin_addr.s_addr);

	switch (target_protocol) {
		case IPPROTO_TCP:
			head->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
			head->check = tcp4_checksum((uint16_t*)buffer, head->tot_len);
			break;
	}
}

struct tcpphdr {
	uint32_t saddr;
	uint32_t daddr;
	uint8_t zero;
	uint8_t protocol;
	uint16_t length;
};

void crafter_tcp4(char *buffer, struct sockaddr *taddr, uint16_t port, uint16_t options) {
	struct tcphdr *tcphead;
	struct tcpphdr tcpphead;

	crafter_ip4(buffer, taddr, IPPROTO_TCP);

	tcphead = (struct tcphdr*)(buffer + ((struct iphdr*)buffer)->ihl + sizeof(uint32_t));

	tcpphead.saddr = RAND_UINT32();
	tcpphead.daddr = htons(((struct sockaddr_in*)taddr)->sin_addr.s_addr);
	tcpphead.zero = 0;
	tcpphead.protocol = IPPROTO_TCP;
	tcpphead.length = htons(sizeof(struct tcphdr));

	tcphead->source = RAND_UINT16();
	tcphead->dest = htons(port);
	tcphead->seq = 0;
	tcphead->ack_seq = 0;
	tcphead->doff = 5;

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

	tcphead->window = htons(5840);
	tcphead->check = 0;
	tcphead->urg_ptr = 0;

	char pack[sizeof(struct tcpphdr) + sizeof(struct tcphdr)];

	memcpy(pack, &tcpphead, sizeof(struct tcpphdr));
	memcpy(pack + sizeof(struct tcpphdr), tcphead, sizeof(struct tcphdr));

	tcphead->check = tcp4_checksum((uint16_t*)pack, ARRAY_SIZE(pack));
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
	char packet[4096];

	packet_crafters_ref[PACKET_TCP4].craft(packet, taddr, port, FLAG_SYN);

	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	sin.sin_addr.s_addr = ((struct iphdr*)packet)->saddr;

	if (sendto(sock, packet, ((struct iphdr*)packet)->tot_len, 0, (struct sockaddr*)&sin, sizeof(struct sockaddr)) < 0) {
		fprintf(stderr, "Unable to send packet (port %hd)\n", port);
		return STATUS_UNKNOWN;
	}

	char buffer[4096];
	ssize_t len;
	struct iphdr *iph;
	struct tcphdr *tcph;
	len = recvfrom(sock, buffer, ARRAY_SIZE(buffer), 0, NULL, NULL);
	if (len < 0) {
		fprintf(stderr, "Unable to receive packet\n");
		return STATUS_UNKNOWN;
	}
	if ((size_t)len < sizeof(struct iphdr) + sizeof(struct tcphdr)) {
		return STATUS_FILTERED;
	} else {
		iph = (struct iphdr*)buffer;
		tcph = (struct tcphdr*)(buffer + iph->ihl * sizeof(uint32_t));

		if (tcph->rst == 1)
			return STATUS_CLOSED;
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

static ports_list_t *scan_ports(int sock, scan_config_t const *conf) {
	ports_list_t *pl;
	uint16_t ports[MAX_PORTS_SCANNED];
	unsigned int i;

	pl = NULL;
	for (i = 0; i < ARRAY_SIZE(ports); i++)
		ports[i] = i + 1;
	array_shuffle(ports, ARRAY_SIZE(ports));

	for (i = 0; i < ARRAY_SIZE(ports); i++) {
		ePortStatus s;

		s = scan_port(sock, ports[i], conf);
		if (!push_port(&pl, ports[i], s)) {
			fprintf(stderr, "Memory exhausted\n");
			return NULL;
		}
	}

	return pl;
}

static void print_report(ports_list_t *report, int verbose) {
	char const * const entry_fmt = "%7d | %s\n";
	char const * const head_fmt = "%8s  %s\n";

	fprintf(stdout, head_fmt, "port", "status");

	uint32_t i;
	for (i = 1; i < MAX_PORTS_SCANNED + 1; i++) {
		ports_list_t *pl;

		pl = report;
		while (pl) {
			if (i == pl->port) {
				if ((pl->status != STATUS_UNKNOWN
				     && pl->status != STATUS_CLOSED)
				    || verbose)
					fprintf(stdout, entry_fmt, pl->port, ps_to_str(pl->status));
				break;
			}

			pl = pl->next;
		}
	}
}

static void usage(char const *av) {
	fprintf(stdout, "Usage: %s [-v] [-h | -m <method>] <target address>\n", av);
	fprintf(stdout, "\t-v: enable verbose mode (default: disabled)\n"
			"\t-m: scan method (default: SYN)\n");
}

static int set_config(int ac, char **av, scan_config_t *conf) {
	int opt;

	conf->verbose = 0;
	conf->method = METHOD_UNKNOWN;
	conf->target_address = NULL;
	while ((opt = getopt(ac, av, "hvm:")) != -1) {
		switch (opt) {
			case 'h':
				usage(*av);
				return 1;
			case 'v':
				conf->verbose = 1;
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

	report = scan_ports(sock, &conf);
	print_report(report, conf.verbose);

	close(sock);
	for (; report != NULL; report = report->next)
		free(report);

	return 0;
}
