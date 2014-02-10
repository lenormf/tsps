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
#include <ifaddrs.h>
#include <net/if.h>

// Preprocessor macros
#define MAX_PORTS_SCANNED 1024
#define MAX_FILTERED_RETRIES 3
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))
#define RAND_UINT16() ((uint16_t)rand() % (USHRT_MAX + 1))
#define RAND_UINT32() ((uint32_t)rand() % UINT_MAX)
#define RAND_UINT32_RANGE(f, t) ((uint32_t)(rand() % ((t) - (f)) + (f)))

// Debugging macros
#ifdef DEBUG
#define DEBUG_PRINTF(fmt, va...) fprintf(stderr, fmt "\n", ##va)
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
	       "daddr: %u\n", \
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
	       "urg_ptr: %u\n", \
	       ntohs((p)->source), ntohs((p)->dest), ntohl((p)->seq), ntohl((p)->ack_seq), (p)->doff, (p)->fin, (p)->syn, (p)->rst, (p)->psh, (p)->ack, (p)->urg, ntohs((p)->window), ntohs((p)->check), ntohs((p)->urg_ptr)); \
	(void)p; \
} while (0)

// Types
typedef enum {
	PACKET_IP4,
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
	METHOD_SYN = 0,
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
	int no_delay;
	uint16_t ports_amount;

	eScanMethod method;
	char const *target_address;
	struct sockaddr *target_sockaddr;

	char const *iface_name;
	struct sockaddr *iface_sockaddr;
} scan_config_t;

struct tcp_pseudo_header_s {
	uint32_t saddr;
	uint32_t taddr;
	uint8_t zero;
	uint8_t protocol;
	uint16_t length;
};

// Lookup tables
static struct {
	eService service;
	char const *s;
} const ss_ref[] = {
	{SERVICE_UNKNOWN, "unknown"},
	{SERVICE_SSH, "ssh"},
};

static void crafter_tcp4(char*, struct sockaddr*, struct sockaddr*, uint16_t, uint16_t);
static void crafter_ip4(char*, struct sockaddr*, struct sockaddr*, uint16_t, uint16_t);
static struct {
	ePacketType type;
	void (*craft)(char*, struct sockaddr*, struct sockaddr*, uint16_t, uint16_t);
} const packet_crafters_ref[] = {
	{PACKET_IP4, &crafter_ip4},
	{PACKET_TCP4, &crafter_tcp4},
};

static ePortStatus scanner_syn(int sock, struct sockaddr *saddr, struct sockaddr *taddr, uint16_t port);
static struct {
	eScanMethod method;
	char const *str;
	ePortStatus (*scanner)(int, struct sockaddr*, struct sockaddr*, uint16_t);
} const port_scanners_ref[] = {
	{METHOD_SYN, "SYN", &scanner_syn},
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

static struct sockaddr *iface_to_sockaddr(char const *iface_name) {
	static struct sockaddr ret;
	struct sockaddr *r;
	struct ifaddrs *ifap;

	if (getifaddrs(&ifap) < 0)
		return NULL;

	r = NULL;
	struct ifaddrs *iface;
	for (iface = ifap; iface; iface = iface->ifa_next) {
		if (iface->ifa_addr->sa_family != AF_INET
		    || (iface->ifa_flags & IFF_LOOPBACK) == IFF_LOOPBACK
		    || (iface->ifa_flags & IFF_UP) != IFF_UP)
			continue;

		if (iface_name
		    && strcmp(iface_name, iface->ifa_name))
			continue;

		DEBUG_PRINTF("Interface detected: %s", iface->ifa_name);

		r = &ret;
		memcpy(&ret, iface->ifa_addr, sizeof(struct sockaddr));

		break;
	}

	freeifaddrs(ifap);

	return r;
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
	switch (state) {
		case STATE_READ:
			r = select(fd + 1, &fds, NULL, NULL, usec ? &tv : NULL);
			break;
		case STATE_WRITE:
			r = select(fd + 1, NULL, &fds, NULL, usec ? &tv : NULL);
			break;
		case STATE_TIMEOUT:
			r = select(0, NULL, NULL, NULL, &tv);
			break;
		default: return 1;
	}

	if (r < 0)
		return 1;

	if (state == STATE_TIMEOUT)
		return 2;
	else if (FD_ISSET(fd, &fds))
		return 0;

	return 1;
}

// Packet crafters
static void crafter_ip4(char *buffer, struct sockaddr *saddr, struct sockaddr *taddr, uint16_t target_protocol, uint16_t options) {
	struct iphdr *head = (struct iphdr*)buffer;

	(void)options;

	head->ihl = 5;
	head->version = 4;
	head->tos = 0;
	head->id = htons(RAND_UINT16());
	head->frag_off = htons(0x4000);
	head->ttl = 0x40;
	head->protocol = (uint8_t)target_protocol;
	head->check = htons(0);
	head->saddr = ((struct sockaddr_in*)saddr)->sin_addr.s_addr;
	head->daddr = ((struct sockaddr_in*)taddr)->sin_addr.s_addr;

	switch (target_protocol) {
		case IPPROTO_TCP:
			head->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
			// Set by the kernel
			head->check = 0;
			break;
	}
}

static void crafter_tcp4(char *buffer, struct sockaddr *saddr, struct sockaddr *taddr, uint16_t port, uint16_t options) {
	struct iphdr *iphead;
	struct tcphdr *tcphead;
	struct tcp_pseudo_header_s pseudo;

	packet_crafters_ref[PACKET_IP4].craft(buffer, saddr, taddr, IPPROTO_TCP, 0);

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

// Port scanners
static ePortStatus scanner_syn(int sock, struct sockaddr *saddr, struct sockaddr *taddr, uint16_t port) {
	struct sockaddr_in sin;
	char packet[128];

	packet_crafters_ref[PACKET_TCP4].craft(packet, saddr, taddr, port, FLAG_SYN);

	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	sin.sin_addr.s_addr = ((struct sockaddr_in*)taddr)->sin_addr.s_addr;

	DEBUG_PRINTF("Sent packet:");
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
		struct sockaddr_in addr;
		socklen_t addr_len;

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

		addr_len = sizeof(struct sockaddr_in);
		len = recvfrom(sock, buffer, ARRAY_SIZE(buffer), 0, (struct sockaddr*)&addr, &addr_len);
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

		tcph = (struct tcphdr*)(buffer + iph->ihl * sizeof(uint32_t));

		DEBUG_PRINTF("Received packet:");
		DEBUG_PRINT_IPV4(iph);
		DEBUG_PRINT_TCPV4(tcph);

		if (ntohs(tcph->source) != port
		    || addr.sin_addr.s_addr != ((struct sockaddr_in*)taddr)->sin_addr.s_addr) {
			// either wrong port, or the packet doesn't come from the target
			continue;
		}

		if (tcph->rst == 1)
			return STATUS_CLOSED;

		break;
	}

	return STATUS_OPEN;
}

static ePortStatus scan_port(int sock, uint16_t port, scan_config_t const *conf) {
	return port_scanners_ref[conf->method].scanner(sock, conf->iface_sockaddr, conf->target_sockaddr, port);
}

static eService scan_service(uint16_t port) {
	return SERVICE_UNKNOWN;
}

static ports_list_t *scan_ports(int sock, scan_config_t const *conf) {
	ports_list_t *pl;
	uint16_t *ports;
	unsigned int i;

	ports = malloc(conf->ports_amount * sizeof(uint16_t));
	if (!ports) {
		fprintf(stderr, "Memory exhausted\n");
		return NULL;
	}

	pl = NULL;
	for (i = 0; i < conf->ports_amount; i++)
		ports[i] = i;
	array_shuffle(ports, conf->ports_amount);

	for (i = 0; i < conf->ports_amount; i++) {
		ePortStatus s;
		eService ss;

		DEBUG_PRINTF("Scanning port #%u", ports[i]);

		ss = SERVICE_UNKNOWN;
		s = scan_port(sock, ports[i], conf);
		if ((s & STATUS_OPEN) == STATUS_OPEN)
			ss = scan_service(ports[i]);

		if (!push_port(&pl, ports[i], s, ss)) {
			fprintf(stderr, "Memory exhausted\n");
			return NULL;
		}

		if (!conf->no_delay) {
			uint32_t delay_usec;

			delay_usec = RAND_UINT32_RANGE(500, 3000);
			DEBUG_PRINTF("Delay: %uµs", delay_usec);
			await_fd_state(0, STATE_TIMEOUT, delay_usec * 1000);
		}
	}

	return pl;
}

static void print_report(ports_list_t *report, uint16_t list_size, int verbose) {
	char const * const head_fmt  = "%7s   %9s  %s\n";
	char const * const entry_fmt = "%7d | %9s  %s\n";
	uint32_t closed_ports;
	uint32_t unknown_ports;

	fprintf(stdout, head_fmt, "port", "status", "service");

	uint32_t i;
	for (i = 0, closed_ports = 0, unknown_ports = 0; i < list_size; i++) {
		ports_list_t *pl;

		pl = report;
		while (pl) {
			if (i == pl->port) {
				if (pl->status != STATUS_CLOSED) {
					switch (pl->status) {
						case STATUS_CLOSED:
							closed_ports++;
							break;
						case STATUS_UNKNOWN:
							unknown_ports++;
							break;
						default:
							fprintf(stdout, entry_fmt, pl->port, ps_to_str(pl->status), pss_to_str(pl->service));
							break;
					}
				}

				break;
			}

			pl = pl->next;
		}
	}

	if (verbose) {
		fprintf(stdout, "Amount of ports scanned: %hd\n", list_size);
		if (closed_ports)
			fprintf(stdout, "Amount of ports closed: %u\n", closed_ports);
		if (unknown_ports)
			fprintf(stdout, "Couldn't determine the state of %u port%c\n", unknown_ports, unknown_ports <= 1 ? 0 : 's');
	}
}

static void usage(char const *av) {
	fprintf(stdout, "Usage: %s [-h | OPTIONS ] <target address>\n", av);
	fprintf(stdout, "Available options:\n"
			"\t-v: enable verbose mode (default: disabled)\n"
			"\t-m <method>: scan method (default: SYN)\n"
			"\t-f: enable services fingerprinting (default: disabled)\n"
			"\t-d: disable random delay between ports (default: enabled)\n"
			"\t-n <number>: amount of ports to be scanned (default: 2014)\n"
			"\t-i <iface>: interface to use (default will be automatically detected)\n");
	fprintf(stdout, "Certain scanning methods require superuser privileges, in order to be able to create raw sockets\n");
}

static int set_config(int ac, char **av, scan_config_t *conf) {
	int opt;

	bzero(conf, sizeof(scan_config_t));

	conf->ports_amount = MAX_PORTS_SCANNED;
	conf->method = METHOD_SYN;
	while ((opt = getopt(ac, av, "hvfdm:n:i:")) != -1) {
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
			case 'd':
				conf->no_delay = 1;
				break;
			case 'm': {
				conf->method = METHOD_UNKNOWN;

				uint32_t i;
				for (i = 0; i < ARRAY_SIZE(port_scanners_ref); i++) {
					if (!strcasecmp(port_scanners_ref[i].str, optarg)) {
						conf->method = port_scanners_ref[i].method;
						break;
					}
				}

				if (conf->method == METHOD_UNKNOWN) {
					fprintf(stderr, "Unsupported scanning method \"%s\"\n", optarg);
					return 1;
				}
				break;
			}
			case 'n': {
				int n;

				n = atoi(optarg);
				if (n > INT16_MAX) {
					fprintf(stderr, "Invalid amount of ports: %d\n", n);
					return 1;
				} else if (n == -1) {
					n = UINT16_MAX;
				}

				conf->ports_amount = (uint16_t)n;

				break;
			}
			case 'i': {
				conf->iface_name = strdup(optarg);
				break;
			}
			default:
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

	conf->iface_sockaddr = iface_to_sockaddr(conf->iface_name);
	if (!conf->iface_sockaddr) {
		fprintf(stderr, "Unable to get the interface's address\n");
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
		fprintf(stdout, "Scan summary: host:%s(%s) ports:0-%d method:%s iface:%s\n", conf.target_address, inet_ntoa(((struct sockaddr_in*)conf.target_sockaddr)->sin_addr), conf.ports_amount - 1, port_scanners_ref[conf.method].str, conf.iface_name ? conf.iface_name : "default");

	report = scan_ports(sock, &conf);
	print_report(report, conf.ports_amount, conf.verbose);

	close(sock);
	for (; report != NULL; report = report->next)
		free(report);
	free((void*)conf.iface_name);

	return 0;
}
