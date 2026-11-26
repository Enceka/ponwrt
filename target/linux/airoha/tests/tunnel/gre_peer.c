#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <poll.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

enum { SOURCE_PORT = 41001, DEST_PORT = 42002, MARK_SIZE = 256 };

static void fail(const char *what)
{
	perror(what);
	exit(1);
}

static void enter_ns(const char *path)
{
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0 || setns(fd, CLONE_NEWNET) < 0)
		fail(path);
	close(fd);
}

static struct sockaddr_in endpoint(const char *ip, unsigned int port)
{
	struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(port) };
	if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
		fprintf(stderr, "invalid IPv4 address: %s\n", ip);
		exit(2);
	}
	return addr;
}

static int udp(const struct sockaddr_in *addr)
{
	int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0 || bind(fd, (const void *)addr, sizeof(*addr)) < 0)
		fail("bind UDP");
	return fd;
}

static unsigned int be16(const unsigned char *bytes)
{
	return ((unsigned int)bytes[0] << 8) | bytes[1];
}

static int ipv4(const unsigned char *ip, size_t len, unsigned int proto,
		const struct sockaddr_in *src, const struct sockaddr_in *dst)
{
	return ip[0] == 0x45 && be16(ip + 2) == len && !(be16(ip + 6) & 0xbfff) &&
	       ip[9] == proto && !memcmp(ip + 12, &src->sin_addr, 4) &&
	       !memcmp(ip + 16, &dst->sin_addr, 4);
}

static int64_t millis(void)
{
	struct timespec now;
	if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
		fail("clock_gettime");
	return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

int main(int argc, char **argv)
{
	if (argc != 8 || (strcmp(argv[1], "exchange") && strcmp(argv[1], "noroute"))) {
		fprintf(stderr, "usage: %s exchange|noroute tx-nspath rx-nspath inner-src inner-dst outer-src outer-dst\n", argv[0]);
		return 2;
	}
	int withdrawn = !strcmp(argv[1], "noroute");
	struct sockaddr_in src = endpoint(argv[4], SOURCE_PORT), dst = endpoint(argv[5], DEST_PORT);
	struct sockaddr_in outer_src = endpoint(argv[6], 0), outer_dst = endpoint(argv[7], 0);
	unsigned char mark[MARK_SIZE];
	if (getrandom(mark, sizeof(mark), 0) != sizeof(mark))
		fail("getrandom");
	struct pollfd fds[2] = {{ .fd = -1, .events = POLLIN }, { .fd = -1, .events = POLLIN }};
	if (!withdrawn) {
		enter_ns(argv[3]);
		fds[0].fd = udp(&dst);
		struct sockaddr_ll wire = { .sll_family = AF_PACKET, .sll_protocol = htons(ETH_P_IP),
			.sll_ifindex = if_nametoindex("wire") };
		fds[1].fd = socket(AF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC, htons(ETH_P_IP));
		if (!wire.sll_ifindex || fds[1].fd < 0 || bind(fds[1].fd, (void *)&wire, sizeof(wire)) < 0)
			fail("bind AF_PACKET wire");
	}
	enter_ns(argv[2]);
	int sender = udp(&src);
	ssize_t sent = sendto(sender, mark, sizeof(mark), 0, (void *)&dst, sizeof(dst));
	if (withdrawn && sent < 0 && errno == ENETUNREACH) {
		puts("withdrawn route: ENETUNREACH");
		return 0;
	}
	if (sent != sizeof(mark))
		fail("send UDP");
	if (withdrawn) {
		fputs("withdrawn route still sends\n", stderr);
		return 1;
	}
	int64_t deadline = millis() + 3000;
	while (fds[0].fd >= 0 || fds[1].fd >= 0) {
		int left = deadline - millis();
		if (left <= 0) {
			fprintf(stderr, "timeout %s -> %s: udp=%s wire=%s\n", argv[4], argv[5],
				fds[0].fd < 0 ? "ok" : "missing", fds[1].fd < 0 ? "ok" : "missing");
			return 1;
		}
		if (poll(fds, 2, left) < 0) {
			if (errno == EINTR) continue;
			fail("poll");
		}
		for (int index = 0; index < 2; index++) {
			union {struct sockaddr_in ip; struct sockaddr_ll ll;} from;
			socklen_t size = sizeof(from);
			unsigned char buf[52 + MARK_SIZE];
			if (!(fds[index].revents & POLLIN)) continue;
			ssize_t len = recvfrom(fds[index].fd, buf, sizeof(buf), MSG_TRUNC,
					       (void *)&from, &size);
			if (len < 0) fail("recvfrom");
			if (!index) {
				if (len != MARK_SIZE || from.ip.sin_port != src.sin_port ||
				    from.ip.sin_addr.s_addr != src.sin_addr.s_addr || memcmp(buf, mark, MARK_SIZE))
					continue;
			} else {
				if (len != sizeof(buf) || from.ll.sll_pkttype != PACKET_HOST ||
				    !ipv4(buf, len, IPPROTO_GRE, &outer_src, &outer_dst) || buf[8] != 63 ||
				    memcmp(buf + 20, "\0\0\x08\0", 4) ||
				    !ipv4(buf + 24, len - 24, IPPROTO_UDP, &src, &dst) ||
				    be16(buf + 44) != SOURCE_PORT || be16(buf + 46) != DEST_PORT ||
				    be16(buf + 48) != MARK_SIZE + 8 || memcmp(buf + 52, mark, MARK_SIZE))
					continue;
			}
			close(fds[index].fd);
			fds[index].fd = -1;
		}
	}
	printf("%s -> %s: UDP and GRE wire match\n", argv[4], argv[5]);
	return 0;
}
