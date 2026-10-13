/* npreg_bench.c — L17: 注册可扩展性基准 (A 轴基线 → Phase 2 组模型对照)
 * 注册规模基准 (Phase 0)。
 *
 * 测什么: SYMRDMA_IOC_REG_MR / DEREG_MR ioctl 耗时随 MR 尺寸 + 预触碰
 * 模式的扩展性 — 单机, 无 RDMA/QP, 纯控制面。预期当前形态 :
 *   - pages[] kcalloc (24B/页) + version kzalloc (4B/页) 为单块物理连续
 *     大分配 → 某个尺寸之上必失败 (ENOMEM, 失败点即 A 轴问题陈述);
 *   - 成功注册的耗时 ∝ 页数 (逐页 follow_page_nofault + 逐页 2×
 *     iommu_map, ~µs/页量级) → GB 级分钟化。
 * Phase 2 组模型后同一工具复测: GRP_ABSENT/GRP_RESIDENT 组 2MB 单次
 * 映射 + PMD 级遍历 → 64GB ≤1s 门禁 (iommu_huge=0 关闭可回归旧行为)。
 *
 * 触碰模式 (-t):
 *   none   MAP_NORESERVE 不触碰 — 全缺失页 (注册走哨兵/黑洞路径)
 *   first  只触碰第 0 页
 *   sparse 每 2MB 触碰 1 页 (模拟稀疏驻留)
 *   all    逐页触碰 (驻留路径; 大尺寸耗时/内存开销大, 限 ≤8GB)
 *
 * 输出 (stdout, CSV; # 开头为表头/注释行):
 *   REG,thp=<on|off>,touch=<mode>,size_mb=<n>,iter=<k>,reg_ms=<x>,dereg_ms=<y>,rc=<0|-errno>
 *   失败点行 rc=非 0, reg_ms 为失败耗时 (kcalloc 尝试), dereg_ms=-1。
 *
 * 用法: npreg_bench -S 4G -t sparse [-i 3] [-T off] [-v]
 *   -S 尺寸 (K/M/G 后缀); -i 迭代次数 (默认 3, 取中位报告于 stderr);
 *   -T on → mmap 后 madvise(MADV_HUGEPAGE) (THP 驻留组对照);
 *   -v → stderr 打印逐次详情。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <fcntl.h>

#define SYMRDMA_IOC_MAGIC 'S'

struct symrdma_ioc_reg_mr {
	uint64_t va_start;
	uint64_t len;
	int      mr_id;
};

#define SYMRDMA_IOC_REG_MR   _IOWR(SYMRDMA_IOC_MAGIC, 1, struct symrdma_ioc_reg_mr)
#define SYMRDMA_IOC_DEREG_MR _IOW(SYMRDMA_IOC_MAGIC,  2, int)

#define HPAGE (2UL * 1024 * 1024)

static double now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1e3 + ts.tv_nsec / 1e6;
}

static unsigned long parse_size(const char *s)
{
	unsigned long v;
	char *end;

	v = strtoul(s, &end, 0);
	if (end == s)
		return 0;
	if (*end == 'k' || *end == 'K')
		v <<= 10;
	else if (*end == 'm' || *end == 'M')
		v <<= 20;
	else if (*end == 'g' || *end == 'G')
		v <<= 30;
	return v;
}

/* 触碰页 (写一字节 — 确保分配+驻留) */
static void touch_page(char *base, unsigned long off)
{
	base[off] = 1;
}

int main(int argc, char **argv)
{
	unsigned long size = 0, off;
	int iters = 3, thp_on = 0, verbose = 0, opt, i, fd, failed_enomem = 0;
	const char *touch = "none";
	char *base, *raw;
	double reg_ms[16], dereg_ms[16];
	int reg_rc[16];
	int n_ok = 0;

	while ((opt = getopt(argc, argv, "S:t:i:T:v")) != -1) {
		switch (opt) {
		case 'S': size = parse_size(optarg); break;
		case 't': touch = optarg; break;
		case 'i': iters = atoi(optarg); break;
		case 'T': thp_on = !strcmp(optarg, "on"); break;
		case 'v': verbose = 1; break;
		default:
			fprintf(stderr,
				"用法: %s -S <size[K|M|G]> -t <none|first|sparse|all> "
				"[-i iters] [-T on|off] [-v]\n", argv[0]);
			return 1;
		}
	}
	if (size < HPAGE || (size % 4096)) {
		fprintf(stderr, "尺寸须 ≥2MB 且 4KB 对齐\n");
		return 1;
	}
	if (iters < 1 || iters > 16) {
		fprintf(stderr, "-i 范围 1..16\n");
		return 1;
	}

	/* 2MB 对齐映射 (组模型对齐前提; 基线形态不受影响) */
	base = mmap(NULL, size + HPAGE, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
	if (base == MAP_FAILED) {
		perror("mmap");
		return 1;
	}
	raw = base;
	base = (char *)(((uintptr_t)base + HPAGE - 1) & ~(HPAGE - 1));
	if (thp_on)
		madvise(base, size, MADV_HUGEPAGE);
	else
		madvise(base, size, MADV_NOHUGEPAGE);

	if (!strcmp(touch, "first")) {
		touch_page(base, 0);
	} else if (!strcmp(touch, "sparse")) {
		for (off = 0; off < size; off += HPAGE)
			touch_page(base, off);
	} else if (!strcmp(touch, "all")) {
		if (size > (8UL << 30)) {
			fprintf(stderr, "all 模式限 ≤8GB (内存/时间)\n");
			return 1;
		}
		for (off = 0; off < size; off += 4096)
			touch_page(base, off);
	} else if (strcmp(touch, "none")) {
		fprintf(stderr, "未知触碰模式: %s\n", touch);
		return 1;
	}

	fd = open("/dev/symrdma", O_RDWR);
	if (fd < 0) {
		perror("open /dev/symrdma");
		return 1;
	}

	printf("# npreg_bench: size=%luMB touch=%s thp=%s iters=%d\n",
	       size >> 20, touch, thp_on ? "on" : "off", iters);

	for (i = 0; i < iters; i++) {
		struct symrdma_ioc_reg_mr reg = {
			.va_start = (uintptr_t)base,
			.len = size,
			.mr_id = -1,
		};
		double t0, t1;
		int rc;

		t0 = now_ms();
		rc = ioctl(fd, SYMRDMA_IOC_REG_MR, &reg);
		t1 = now_ms();
		reg_ms[i] = t1 - t0;
		reg_rc[i] = rc ? -errno : 0;

		dereg_ms[i] = -1;
		if (rc == 0) {
			double t2 = now_ms();

			if (ioctl(fd, SYMRDMA_IOC_DEREG_MR, reg.mr_id))
				fprintf(stderr, "[iter %d] DEREG 失败: %s\n",
					i, strerror(errno));
			else {
				dereg_ms[i] = now_ms() - t2;
				n_ok++;
			}
		} else if (errno == ENOMEM) {
			failed_enomem = 1;
		}
		printf("REG,thp=%s,touch=%s,size_mb=%lu,iter=%d,reg_ms=%.2f,dereg_ms=%.2f,rc=%d\n",
		       thp_on ? "on" : "off", touch, size >> 20, i,
		       reg_ms[i], dereg_ms[i], reg_rc[i]);
		fflush(stdout);
		if (verbose)
			fprintf(stderr, "  iter %d: reg=%.2fms rc=%d dereg=%.2fms\n",
				i, reg_ms[i], reg_rc[i], dereg_ms[i]);
		usleep(100000);
	}

	/* stderr 摘要: 成功迭代的中位数 */
	if (n_ok > 0) {
		double a[16];
		int k = 0;

		for (i = 0; i < iters; i++)
			if (!reg_rc[i])
				a[k++] = reg_ms[i];
		/* 插入排序取中位 */
		for (i = 1; i < k; i++) {
			double v = a[i];
			int j = i - 1;
			while (j >= 0 && a[j] > v) { a[j + 1] = a[j]; j--; }
			a[j + 1] = v;
		}
		fprintf(stderr, "[npreg_bench] %luMB %s thp=%s: reg 中位 %.2f ms "
			"(%d/%d 成功)%s\n", size >> 20, touch,
			thp_on ? "on" : "off", a[k / 2], n_ok, iters,
			failed_enomem ? " [含 ENOMEM 失败迭代]" : "");
	} else {
		fprintf(stderr, "[npreg_bench] %luMB %s thp=%s: 全部失败 "
			"(rc=%d, %s) — A 轴失败点\n", size >> 20, touch,
			thp_on ? "on" : "off", reg_rc[0],
			strerror(-reg_rc[0]));
	}

	close(fd);
	munmap(raw, size + HPAGE);
	return 0;
}
