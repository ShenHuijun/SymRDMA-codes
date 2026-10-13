/*
 * npmapbench.c — IOMMU 组粒度映射微基准用户态驱动 (v0.38.0, L19 B 轴)
 *
 * 驱动内核 SYMRDMA_IOC_MAPBENCH (cmd 12) 对同一满组 (512 页, 2MB)
 * 实测三种映射形态的 unmap+map+sync 成本 (双域, 持 st->lock):
 *   mode 0 (PERPAGE) — v0.37 逐页形态基线 (16 页/块交错, 2 flush/块/域)
 *   mode 1 (SG)      — Phase 1 段批 (整组 unmap_fast + map_sg_atomic
 *                       run 合并 + 单次 sync/域)
 *   mode 2 (SUPER)   — Phase 2 2MB 超页单条 (恢复段不计时)
 *
 * 流程: mmap 8MB+2MB 余量 → 2MB 对齐裁切 (MADV_HUGEPAGE, THP 尽力; 组
 * 提升/超页映射均要求 read_iova=va 2MB 对齐) → REG_MR (THP 场景注册时
 * 整组提升 GRP_RESIDENT; 无 THP 时逐页 RESIDENT — MAPBENCH 内核侧先
 * 归一为逐页形态, 两者均可) → 三模式各 iters 次迭代 → 输出 ns/iter
 * 与相对 mode 0 加速比 → READ_IOVA 抽查 (首/中/尾页经 IOMMU 页表读回,
 * 等价 NIC 视角 — 映射未被基准破坏)。
 *
 * 对照开关: iommu_huge=0 时组机制关闭 → 退出码 3 (对照形态短路,
 * 门禁脚本据此区分); 正常路径退出码 0, 基准/抽查失败退出码 2。
 *
 * 编译: gcc -O2 -Wall -o npmapbench npmapbench.c
 * 运行: sudo ./npmapbench [iters]   (默认 1000; mode0 ~100µs/iter)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

static int iommu_huge_enabled(void)
{
	char c = '1';
	int fd = open("/sys/module/symrdma/parameters/iommu_huge", O_RDONLY);

	if (fd >= 0) {
		if (read(fd, &c, 1) == 1 && c == '0')
			c = '0';
		else
			c = '1';
		close(fd);
	}
	return c == '1';
}

/* ---- 与 symrdma.h 保持同步 (tests/programs 同款内联副本) ---- */
#define SYMRDMA_IOC_MAGIC       'S'

struct symrdma_ioc_reg_mr {
	unsigned long long va_start, len;
	int mr_id;
};
struct symrdma_ioc_get_iova {
	int mr_id;
	unsigned long page_idx;
	unsigned long long read_iova, write_iova;
};
struct symrdma_ioc_read_iova {
	int mr_id;
	unsigned long long iova;
	size_t offset;
	uint32_t value;
};
struct symrdma_ioc_mapbench {
	int             mr_id;
	unsigned long   page_idx;
	unsigned long   iters;
	int             mode;
	unsigned long long ns_total;
	unsigned long   map_ops;
};

#define SYMRDMA_IOC_REG_MR   _IOWR(SYMRDMA_IOC_MAGIC, 1, struct symrdma_ioc_reg_mr)
#define SYMRDMA_IOC_DEREG_MR _IOW(SYMRDMA_IOC_MAGIC,  2, int)
#define SYMRDMA_IOC_GET_IOVA _IOWR(SYMRDMA_IOC_MAGIC, 4, struct symrdma_ioc_get_iova)
#define SYMRDMA_IOC_READ_IOVA _IOWR(SYMRDMA_IOC_MAGIC, 5, struct symrdma_ioc_read_iova)
#define SYMRDMA_IOC_MAPBENCH _IOWR(SYMRDMA_IOC_MAGIC, 12, struct symrdma_ioc_mapbench)

enum symrdma_mapbench_mode {
	SYMRDMA_MB_PERPAGE = 0,
	SYMRDMA_MB_SG      = 1,
	SYMRDMA_MB_SUPER   = 2,
};

/* 组常量 (须与内核 SYMRDMA_GROUP_SHIFT/PAGES 一致) */
#define GROUP_PAGES    512
#define GROUP_SIZE     (GROUP_PAGES * 4096UL)
#define NPAGES         (4 * GROUP_PAGES)          /* 4 组 = 8MB */
#define PAGE_SIZE      4096

static int failed = 0;

static uint32_t page_word(size_t pg)
{
	return (uint32_t)0x01010101U * (uint8_t)(pg & 0xff);
}

/* 经 IOMMU 页表读页首 4 字节 (READ_IOVA = 单机 RDMA Read 替身:
 * 读的即 NIC 会读到的, 同一页表同一翻译路径) */
static int read_page_word(int fd, int mr_id, unsigned long long riova,
			   size_t pg, uint32_t *out)
{
	struct symrdma_ioc_read_iova rd;

	memset(&rd, 0, sizeof(rd));
	rd.mr_id = mr_id;
	rd.iova = riova + (unsigned long long)pg * PAGE_SIZE;
	rd.offset = 0;
	if (ioctl(fd, SYMRDMA_IOC_READ_IOVA, &rd) != 0)
		return -1;
	*out = rd.value;
	return 0;
}

static double run_mode(int fd, int mr_id, unsigned long gidx,
		       int mode, unsigned long iters)
{
	struct symrdma_ioc_mapbench mb;
	int ret;

	memset(&mb, 0, sizeof(mb));
	mb.mr_id = mr_id;
	mb.page_idx = gidx * GROUP_PAGES;
	mb.iters = iters;
	mb.mode = mode;

	ret = ioctl(fd, SYMRDMA_IOC_MAPBENCH, &mb);
	if (ret != 0) {
		if (mode == 2 && errno == EINVAL)
			printf("  mode 2: 超页前置不满足 (pa 未 2MB 对齐 — THP 未就位?)\n");
		else
			printf("  mode %d: MAPBENCH 失败 (%s)\n",
			       mode, strerror(errno));
		failed++;
		return 0;
	}
	if (mb.map_ops != iters) {
		printf("  mode %d: 完成迭代 %lu/%lu (部分失败)\n",
		       mode, mb.map_ops, iters);
		failed++;
	}
	return (double)mb.ns_total / mb.map_ops;
}

int main(int argc, char **argv)
{
	unsigned long iters = argc > 1 ? strtoul(argv[1], NULL, 0) : 1000;
	unsigned char *buf;
	struct symrdma_ioc_reg_mr reg = {0};
	int fd, mr_id, ret;
	double t_pp, t_sg, t_sp;
	size_t i;

	printf("=== npmapbench: IOMMU 组粒度映射微基准 (iters=%lu) ===\n",
	       iters);

	fd = open("/dev/symrdma", O_RDWR);
	if (fd < 0) {
		perror("open /dev/symrdma");
		return 1;
	}

	/* iommu_huge=0 对照路径: 组机制关闭 → MAPBENCH 无意义, 内核将
	 * 对 !mr->groups 返回 -EINVAL; 直接短路退出 (码 3 = 对照形态) */
	if (!iommu_huge_enabled()) {
		printf("iommu_huge=0 — 组机制关闭, MAPBENCH 对照形态不可用\n");
		close(fd);
		return 3;
	}

	/* 2MB 对齐 8MB (+2MB 余量裁切): 组提升与超页映射均要求
	 * read_iova = va_start 2MB 对齐 (恒等映射), 且 THP 需 2MB 对齐
	 * VA 边界才按超页分配 */
	size_t map_len = NPAGES * PAGE_SIZE + GROUP_SIZE;
	unsigned char *raw = mmap(NULL, map_len, PROT_READ | PROT_WRITE,
				  MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

	if (raw == MAP_FAILED) {
		perror("mmap");
		close(fd);
		return 1;
	}
	buf = (unsigned char *)(((unsigned long)raw + GROUP_SIZE - 1) &
				 ~(GROUP_SIZE - 1));
	madvise(buf, NPAGES * PAGE_SIZE, MADV_HUGEPAGE);
	for (i = 0; i < NPAGES; i++)
		memset(buf + i * PAGE_SIZE, (int)(i & 0xff), PAGE_SIZE);

	reg.va_start = (unsigned long long)buf;
	reg.len = NPAGES * PAGE_SIZE;
	ret = ioctl(fd, SYMRDMA_IOC_REG_MR, &reg);
	if (ret != 0) {
		perror("REG_MR");
		munmap(raw, map_len);
		close(fd);
		return 1;
	}
	mr_id = reg.mr_id;
	printf("REG_MR ok (mr_id=%d, %zu 页 / 4 组)\n", mr_id, (size_t)NPAGES);

	/* 组 1 (中间组, 避开边界的首组特殊路径) */
	t_pp = run_mode(fd, mr_id, 1, SYMRDMA_MB_PERPAGE, iters);
	t_sg = run_mode(fd, mr_id, 1, SYMRDMA_MB_SG, iters);
	t_sp = run_mode(fd, mr_id, 1, SYMRDMA_MB_SUPER, iters);

	printf("\n--- 结果 (双域 unmap+map+sync, 组=512 页) ---\n");
	printf("  mode 0 (v0.37 逐页): %10.2f µs/iter\n", t_pp / 1000.0);
	printf("  mode 1 (sg 段批):    %10.2f µs/iter\n", t_sg / 1000.0);
	printf("  mode 2 (2MB 超页):   %10.2f µs/iter\n", t_sp / 1000.0);
	if (t_pp > 0 && t_sg > 0 && t_sp > 0) {
		printf("  sg/逐页   加速比: %.2fx\n", t_pp / t_sg);
		printf("  超页/逐页 加速比: %.2fx\n", t_pp / t_sp);
	}

	/* 抽查: READ_IOVA 经 IOMMU 页表读回 (组 1 首/1/4/中/3/4/尾页,
	 * 三形态混合重映射后翻译仍正确 — 数据面完整性) */
	{
		struct symrdma_ioc_get_iova gi;
		unsigned long long riova;
		int err = 0;

		memset(&gi, 0, sizeof(gi));
		gi.mr_id = mr_id;
		gi.page_idx = 0;
		if (ioctl(fd, SYMRDMA_IOC_GET_IOVA, &gi) != 0) {
			perror("GET_IOVA");
			failed++;
		} else {
			riova = gi.read_iova;
			for (i = 0; i <= 4; i++) {
				size_t pg = GROUP_PAGES + i * (GROUP_PAGES / 4 - 1);
				uint32_t w;

				if (read_page_word(fd, mr_id, riova, pg, &w)) {
					printf("  数据抽查失败: 页 %zu READ_IOVA %s\n",
					       pg, strerror(errno));
					err++;
				} else if (w != page_word(pg)) {
					printf("  数据抽查失败: 页 %zu 读回 0x%08x != 0x%08x\n",
					       pg, w, page_word(pg));
					err++;
				}
			}
			if (!err)
				printf("  数据抽查: ok (READ_IOVA 组 1 首/1/4/中/3/4/尾页)\n");
			failed += err;
		}
	}

	ioctl(fd, SYMRDMA_IOC_DEREG_MR, mr_id);
	munmap(raw, map_len);
	close(fd);

	if (failed) {
		printf("\n结果: 失败 (%d)\n", failed);
		return 2;
	}
	printf("npmapbench: 完成\n");
	return 0;
}
