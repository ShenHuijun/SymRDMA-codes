/* diag_sweep.c — L9 fault-sweep 失败定位: 哪些页换出未就位?
 * 复现 L9 序列: 触摸全部页 → madvise PAGEOUT 目标页 → 检查
 *   ① READ_IOVA 是否哨兵 (IOMMU 侧)
 *   ② smaps Swap (OS 侧)
 * 分类: OS已换出+IOMMU未哨兵 = notifier 漏; 两者皆非 = madvise 未生效
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdint.h>

struct symrdma_ioc_reg_mr { uint64_t va_start; uint64_t len; int mr_id; };
struct symrdma_ioc_read_iova { int mr_id; uint64_t iova; size_t offset; uint32_t value; };

#define SYMRDMA_IOC_MAGIC 'S'
#define SYMRDMA_IOC_REG_MR    _IOWR(SYMRDMA_IOC_MAGIC, 1, struct symrdma_ioc_reg_mr)
#define SYMRDMA_IOC_READ_IOVA _IOWR(SYMRDMA_IOC_MAGIC, 5, struct symrdma_ioc_read_iova)
#define SYMRDMA_IOC_DEREG_MR  _IOW(SYMRDMA_IOC_MAGIC, 2, int)

#define SENTINEL_MAGIC 0xdeadbeef
#define NPAGES 256
#define PSZ 4096

static int read_iova4(int fd, int id, uint64_t iova)
{
	struct symrdma_ioc_read_iova q;
	memset(&q, 0, sizeof(q));
	q.mr_id = id; q.iova = iova; q.offset = 0;
	if (ioctl(fd, SYMRDMA_IOC_READ_IOVA, &q) < 0) return 0xffffffffu;
	return q.value;
}

/* 从 /proc/self/smaps 查某 VA 页的 Swap kB */
static long swap_kb_of(unsigned long va)
{
	FILE *f = fopen("/proc/self/smaps", "r");
	char line[256], hdr[128];
	long val = -1;
	if (!f) return -1;
	snprintf(hdr, sizeof(hdr), "%lx", va);
	while (fgets(line, sizeof(line), f)) {
		unsigned long start, end;
		if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
			int inrange = (va >= start && va < end);
			if (inrange) {
				while (fgets(line, sizeof(line), f)) {
					if (sscanf(line, "Swap: %ld", &val) == 1)
						break;
					if (line[0] >= '0' && line[0] <= '9' &&
					    strchr(line, '-'))
						break;
				}
			}
		}
		if (val >= 0) break;
	}
	fclose(f);
	return val;
}

int main(void)
{
	int fd = open("/dev/symrdma", O_RDWR);
	if (fd < 0) { perror("open"); return 1; }
	char *buf = mmap(NULL, NPAGES * PSZ, PROT_READ|PROT_WRITE,
			 MAP_ANONYMOUS|MAP_PRIVATE|MAP_NORESERVE, -1, 0);
	if (buf == MAP_FAILED) { perror("mmap"); return 1; }
	memset(buf, 0xAB, NPAGES * PSZ);

	struct symrdma_ioc_reg_mr r = { .va_start = (uint64_t)buf, .len = NPAGES * PSZ };
	if (ioctl(fd, SYMRDMA_IOC_REG_MR, &r) < 0) { perror("REG_MR"); return 1; }
	printf("mr_id=%d va=%llx\n", r.mr_id, (unsigned long long)buf);

	/* L9 同款: 三轮递增换出, 每轮前触摸全部页 */
	int fracs[] = {10, 25, 50, 75, 100};
	for (int fi = 0; fi < 5; fi++) {
		int nswap = NPAGES * fracs[fi] / 100;
		memset(buf, 0xAB, NPAGES * PSZ);   /* 触摸全部页 (换入) */

		for (int i = 0; i < nswap; i++)
			madvise(buf + i * PSZ, PSZ, MADV_PAGEOUT);
		usleep(500000);

		int not_ready = 0, os_swapped_iommu_stale = 0, madvise_failed = 0;
		for (int i = 0; i < nswap; i++) {
			uint32_t v = read_iova4(fd, r.mr_id,
						(uint64_t)buf + i * PSZ);
			if (v == SENTINEL_MAGIC) continue;
			not_ready++;
			long sw = swap_kb_of((unsigned long)buf + i * PSZ);
			if (sw > 0) os_swapped_iommu_stale++;
			else madvise_failed++;
		}
		printf("fault=%3d%%: 目标 %d 页, 未就位 %d (OS已换出+IOMMU未哨兵: %d, madvise未换出: %d)\n",
		       fracs[fi], nswap, not_ready,
		       os_swapped_iommu_stale, madvise_failed);
		if (not_ready && not_ready <= 5) {
			for (int i = 0; i < nswap; i++) {
				uint32_t v = read_iova4(fd, r.mr_id,
						(uint64_t)buf + i * PSZ);
				if (v != SENTINEL_MAGIC)
					printf("  页 %d IOMMU=0x%08x smaps_Swap=%ld kB\n",
					       i, v,
					       swap_kb_of((unsigned long)buf + i * PSZ));
			}
		}
	}
	ioctl(fd, SYMRDMA_IOC_DEREG_MR, r.mr_id);
	munmap(buf, NPAGES * PSZ);
	close(fd);
	return 0;
}
