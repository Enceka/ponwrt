#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

enum { SPORT2_MAP, RX2_BASE, RX2_SIZE, RX2_CPU, RX2_DMA,
	RX4_BASE, RX4_SIZE, RX4_CPU, RX4_DMA, WORD_COUNT };

static const uint32_t addresses[WORD_COUNT] = {
	[SPORT2_MAP] = 0x1fb520e0,
	[RX2_BASE] = 0x1fb56240, [RX2_SIZE] = 0x1fb56244,
	[RX2_CPU] = 0x1fb56248, [RX2_DMA] = 0x1fb5624c,
	[RX4_BASE] = 0x1fb56280, [RX4_SIZE] = 0x1fb56284,
	[RX4_CPU] = 0x1fb56288, [RX4_DMA] = 0x1fb5628c,
};

static int check_board(void)
{
	FILE *file = fopen("/proc/device-tree/compatible", "rb");
	char *item = NULL;
	size_t capacity = 0;
	bool found = false;
	ssize_t length;

	if (!file) {
		perror("/proc/device-tree/compatible");
		return -1;
	}
	while ((length = getdelim(&item, &capacity, '\0', file)) > 0) {
		if (item[length - 1] == '\0' &&
		    (!strcmp(item, "fiberhome,hg5585f-ct") ||
		     !strcmp(item, "fiberhome,hg5585f-cu"))) {
			found = true;
			break;
		}
	}
	free(item);
	fclose(file);
	if (!found)
		fputs("expected HG5585F CT/CU device tree; skipped MMIO\n", stderr);
	return found ? 0 : -1;
}

static int read_words(uint32_t words[WORD_COUNT])
{
	long page_size = sysconf(_SC_PAGESIZE);
	off_t mapped = -1;
	void *page = MAP_FAILED;
	int fd, status = -1;

	if (page_size <= 0 || page_size % sizeof(uint32_t)) {
		fputs("invalid MMIO page size\n", stderr);
		return -1;
	}
	fd = open("/dev/mem", O_RDONLY | O_SYNC);
	if (fd < 0) {
		perror("/dev/mem");
		return -1;
	}
	for (size_t index = 0; index < WORD_COUNT; index++) {
		size_t offset = addresses[index] % page_size;
		off_t base = addresses[index] - offset;

		if (base != mapped) {
			if (page != MAP_FAILED)
				munmap(page, page_size);
			page = mmap(NULL, page_size, PROT_READ, MAP_SHARED, fd, base);
			if (page == MAP_FAILED) {
				perror("mmap /dev/mem");
				goto out;
			}
			mapped = base;
		}
		words[index] = ((const volatile uint32_t *)page)[offset / sizeof(uint32_t)];
	}
	status = 0;
out:
	if (page != MAP_FAILED)
		munmap(page, page_size);
	close(fd);
	return status;
}

static unsigned int sport2_cport(uint32_t map)
{
	return (map >> 8) & 0xf;
}

static bool ring_ready(const uint32_t *words)
{
	return words[0] && !(words[0] & 3) && words[1] == 0x00100080 &&
	       (words[2] & 0xffff) < 128 && (words[3] & 0xffff) < 128;
}

static void print_ring(unsigned int ring, const uint32_t *words)
{
	printf("qdma1.rx%u base=0x%08" PRIx32 " size=0x%08" PRIx32
	       " ndesc=%u threshold=%u cpu_idx=%u dma_idx=%u ready=%d\n",
	       ring, words[0], words[1], words[1] & 0xffff, words[1] >> 16,
	       words[2] & 0xffff, words[3] & 0xffff, ring_ready(words));
}

static int self_test(void)
{
	uint32_t ring[] = { 0x84f99000, 0x00100080, 0xffff007f, 2 };

	if (sport2_cport(0xabcde5ff) != 5 || sport2_cport(0x55555055) != 0 ||
	    !ring_ready(ring))
		return 1;
	const uint32_t bad[] = { 0, 0x00100000, 128, 128 };
	for (size_t index = 0; index < 4; index++) {
		uint32_t saved = ring[index];
		ring[index] = bad[index];
		if (ring_ready(ring))
			return 1;
		ring[index] = saved;
	}
	puts("offline self-test: PASS");
	return 0;
}

int main(int argc, char **argv)
{
	uint32_t words[WORD_COUNT];
	struct stat info;
	bool pon0_present;

	if (argc == 2 && !strcmp(argv[1], "--self-test"))
		return self_test();
	if (argc != 1) {
		fprintf(stderr, "usage: %s [--self-test]\n", argv[0]);
		return 2;
	}
	if (check_board())
		return 1;
	if (stat("/sys/class/net", &info) < 0) {
		perror("/sys/class/net");
		return 1;
	}
	pon0_present = stat("/sys/class/net/pon0", &info) == 0;
	if (!pon0_present && errno != ENOENT) {
		perror("/sys/class/net/pon0");
		return 1;
	}
	printf("pon0_present=%d optical_ingress_hit=not_measured\n", pon0_present);
	if (read_words(words))
		return 1;
	print_ring(2, words + RX2_BASE);
	print_ring(4, words + RX4_BASE);
	unsigned int cport = sport2_cport(words[SPORT2_MAP]);
	printf("sport2_map=0x%08" PRIx32 " cport=%u forcecpu_route_ready=%d\n",
	       words[SPORT2_MAP], cport, cport == 5);
	return 0;
}
