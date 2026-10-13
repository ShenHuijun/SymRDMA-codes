/* diag_notifier.c — 环境诊断: MMU notifier 触发矩阵 + 哨兵页污染检测
 *
 * 用途 (非 Level 测试, 环境异常时定位用):
 *   1. 各内存事件是否触发 mmu_notifier.invalidate_range_start:
 *      MADV_PAGEOUT (reclaim 路径, 5.5+) / MADV_DONTNEED (zap 路径) /
 *      MADV_COLD (仅清 accessed, 预期不触发) — 经 /proc/symrdma 统计差值。
 *   2. 哨兵页污染检测: REMAP/PAGEOUT 后 READ_IOVA 应为 0xdeadbeef;
 *      若为其他值 (如历史 RDMA 写入的数据) 则全局哨兵页已被污染 —
 *      典型根因: identity_mtt_write_offset 未配 32GB (写区域 MTT=VA,
 *      RDMA Write 落读 IOVA 的 RW 哨兵映射)。需重载模块恢复。
 *   3. 惰性换入语义: PAGEOUT 后 CPU 触碰换回, IOMMU 应仍指哨兵。
 *
 * 编译: make diag_notifier (无依赖, /dev/symrdma 即可运行)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdint.h>
#include <time.h>

/* MADV_PAGEOUT/COLD: 5.5+ 内核支持; 旧 glibc 头文件无定义时兑底 */
#ifndef MADV_PAGEOUT
#define MADV_PAGEOUT 21
#endif
#ifndef MADV_COLD
#define MADV_COLD 20
#endif

struct symrdma_ioc_reg_mr { uint64_t va_start; uint64_t len; int mr_id; };
struct symrdma_ioc_read_iova { int mr_id; uint64_t iova; size_t offset; uint32_t value; };
struct symrdma_ioc_repair { int mr_id; unsigned long page_idx; };

#define SYMRDMA_IOC_MAGIC 'S'
#define SYMRDMA_IOC_REG_MR    _IOWR(SYMRDMA_IOC_MAGIC, 1, struct symrdma_ioc_reg_mr)
#define SYMRDMA_IOC_DEREG_MR  _IOW(SYMRDMA_IOC_MAGIC, 2, int)
#define SYMRDMA_IOC_READ_IOVA _IOWR(SYMRDMA_IOC_MAGIC, 5, struct symrdma_ioc_read_iova)
#define SYMRDMA_IOC_REPAIR    _IOWR(SYMRDMA_IOC_MAGIC, 6, struct symrdma_ioc_repair)

#define SENTINEL_MAGIC 0xdeadbeef

static long long reg_mr(int fd, void *va, size_t len)
{
	struct symrdma_ioc_reg_mr r;
	memset(&r, 0, sizeof(r));
	r.va_start = (uint64_t)va; r.len = len;
	if (ioctl(fd, SYMRDMA_IOC_REG_MR, &r) < 0) { perror("REG_MR"); return -1; }
	return r.mr_id;
}

static uint32_t read_iova4(int fd, long long id, uint64_t iova)
{
	struct symrdma_ioc_read_iova q;
	memset(&q, 0, sizeof(q));
	q.mr_id = (int)id; q.iova = iova; q.offset = 0;
	if (ioctl(fd, SYMRDMA_IOC_READ_IOVA, &q) < 0) return 0xffffffffu;
	return q.value;
}

static unsigned get_notifier_calls(void)
{
	FILE *f = fopen("/proc/symrdma", "r");
	char line[256]; unsigned v = 0;
	if (!f) return 0;
	while (fgets(line, sizeof(line), f))
		if (strstr(line, "notifier 回调"))
			sscanf(strstr(line, "回调:"), "回调: %u", &v);
	fclose(f);
	return v;
}

static void show(int fd, const char *tag, long long id, uint64_t riov)
{
	uint32_t v = read_iova4(fd, id, riov);
	printf("  %-36s READ_IOVA=0x%08x %s\n", tag, v,
	       v == SENTINEL_MAGIC ? "<== 哨兵!" :
	       (v == 0xffffffffu ? "<== 无映射" : ""));
}

static void msleep(long ms) { struct timespec t = { ms / 1000, (ms % 1000) * 1000000 }; nanosleep(&t, NULL); }

int main(void)
{
	int fd = open("/dev/symrdma", O_RDWR);
	if (fd < 0) { perror("open /dev/symrdma"); return 1; }

	size_t SZ = 4 * 4096;
	char *a = mmap(NULL, SZ, PROT_READ|PROT_WRITE,
		       MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE, -1, 0);
	char *b = mmap(NULL, SZ, PROT_READ|PROT_WRITE,
		       MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE, -1, 0);
	if (a == MAP_FAILED || b == MAP_FAILED) { perror("mmap"); return 1; }
	memset(a, 0x41, SZ); memset(b, 0x42, SZ);
	long long ida = reg_mr(fd, a, SZ);
	long long idb = reg_mr(fd, b, SZ);
	if (ida < 0 || idb < 0) return 1;
	printf("MR a=%lld   MR b=%lld\n", ida, idb);

	/* read_iova = VA (恒等) */
	uint64_t riov = (uint64_t)a;
	uint64_t riovb = (uint64_t)b;

	printf("\n[基线] notifier_calls=%u\n", get_notifier_calls());
	show(fd, "a[0] 驻留", ida, riov);

	/* ---- 实验 1: MADV_PAGEOUT ---- */
	memset(a, 0x41, SZ);
	unsigned n0 = get_notifier_calls();
	int ret = madvise(a, 4096, MADV_PAGEOUT);
	msleep(300);
	unsigned n1 = get_notifier_calls();
	printf("\n[实验1] MADV_PAGEOUT a[0]: ret=%d notifier_calls %u→%u (%+d)\n",
	       ret, n0, n1, (int)(n1 - n0));
	show(fd, "a[0] 后", ida, riov);

	struct symrdma_ioc_repair rp; memset(&rp, 0, sizeof(rp));
	rp.mr_id = (int)ida; rp.page_idx = 0;
	if (ioctl(fd, SYMRDMA_IOC_REPAIR, &rp) == 0)
		show(fd, "a[0] REPAIR 后", ida, riov);
	else
		printf("  REPAIR 失败: %m\n");

	/* ---- 实验 2: MADV_DONTNEED ---- */
	memset(a, 0x41, SZ);
	msleep(100);
	n0 = get_notifier_calls();
	ret = madvise(a, 4096, MADV_DONTNEED);
	msleep(300);
	n1 = get_notifier_calls();
	printf("\n[实验2] MADV_DONTNEED a[0]: ret=%d notifier_calls %u→%u (%+d)\n",
	       ret, n0, n1, (int)(n1 - n0));
	show(fd, "a[0] 后", ida, riov);
	memset(&rp, 0, sizeof(rp)); rp.mr_id = (int)ida; rp.page_idx = 0;
	ioctl(fd, SYMRDMA_IOC_REPAIR, &rp);

	/* ---- 实验 3: MADV_COLD ---- */
	memset(a, 0x41, SZ);
	msleep(100);
	n0 = get_notifier_calls();
	ret = madvise(a, 4096, MADV_COLD);
	msleep(300);
	n1 = get_notifier_calls();
	printf("\n[实验3] MADV_COLD a[0]: ret=%d notifier_calls %u→%u (%+d)\n",
	       ret, n0, n1, (int)(n1 - n0));
	show(fd, "a[0] 后", ida, riov);

	/* ---- 实验 4: PAGEOUT→CPU 换回→惰性? ---- */
	memset(a, 0x41, SZ);
	madvise(a, 4096, MADV_PAGEOUT);
	msleep(300);
	printf("\n[实验4] PAGEOUT 后: (b[0] 对照)");
	show(fd, "b[0] (未动)", idb, riovb);
	show(fd, "a[0]", ida, riov);
	uint32_t before = *(uint32_t *)a;
	msleep(100);
	printf("  CPU 读回 = 0x%08x\n", before);
	show(fd, "a[0] CPU 换回后 (惰性→应仍哨兵)", ida, riov);
	memset(&rp, 0, sizeof(rp)); rp.mr_id = (int)ida; rp.page_idx = 0;
	ioctl(fd, SYMRDMA_IOC_REPAIR, &rp);
	show(fd, "a[0] REPAIR 后", ida, riov);

	/* 结论: 重新触发一次 PAGEOUT, 若 IOMMU 仍指哨兵则魔数应可读 */
	memset(a, 0x41, SZ);
	madvise(a, 4096, MADV_PAGEOUT);
	msleep(300);
	if (read_iova4(fd, ida, riov) == SENTINEL_MAGIC)
		printf("\n结论: 哨兵页正常 (0xdeadbeef)\n");
	else
		printf("\n结论: 哨兵页异常 — 读非魔数, 疑似污染 (重载模块恢复; 根因排查见文件头注释)\n");

	ioctl(fd, SYMRDMA_IOC_DEREG_MR, (int)ida);
	ioctl(fd, SYMRDMA_IOC_DEREG_MR, (int)idb);
	munmap(a, SZ); munmap(b, SZ);
	close(fd);
	return 0;
}
