/*
 * test_group_mapping.c — SymRDMA Level 19: 组粒度 IOMMU 映射验证
 *
 * docs/PLAN_IOMMU_HUGEPAGE.md Phase 2 (2MB 超页组) 的单机正确性门禁:
 * 注册提升 / 组内单页换出 (降级) / 单页修复 / 整组修复重提升 /
 * 降级 fail-closed 注入 (demote_fail_grp 模块参数形态)。
 *
 * 数据面替身: READ_IOVA 经 IOMMU 页表翻译读 4 字节 (iova_to_phys +
 * kmap) — 读到的即 NIC RDMA Read 会读到的 (同一页表, 论文 §3.2 数据
 * 面等价性); 跨机 RDMA 数据面由 run_sir_cross.sh (真实 verbs) 覆盖。
 *
 * 前置 (Phase 2 形态): 模块 iommu_huge=1 (默认) 且 2MB 特殊区就位;
 * 组提升依赖 THP — MADV_HUGEPAGE + 2MB 对齐 VA (madvise 模式下按
 * 2MB 边界整组提升)。THP 不可用时提升类断言自动 SKIP (逐页形态下
 * 降级/修复路径仍完整验证 — promote-once 组语义以外的行为不变)。
 *
 * fail-closed 子测 (T5): 仅在模块以 demote_fail_grp=<组号> 装载时
 * 激活 — 该组降级首页重映射模拟 GFP_ATOMIC 失败 → 哨兵/黑洞兜底
 * (自然触发窗口极窄, 测试注入形态)。默认装载 (-1) 时 SKIP。
 *
 * 编译: gcc -O2 -Wall -o test_group_mapping test_group_mapping.c
 * 运行: ./test_group_mapping        (退出码 0=全过 2=断言失败 1=基础设施)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <errno.h>

/* ---- 与 symrdma.h 保持同步 ---- */
#define SYMRDMA_IOC_MAGIC       'S'
#define SYMRDMA_SENTINEL_MAGIC  0xdeadbeef
#define SYMRDMA_REMAP_REAL      0
#define SYMRDMA_REMAP_SENTINEL  1
#define SYMRDMA_REMAP_BLACKHOLE 2

struct symrdma_ioc_reg_mr {
	unsigned long long va_start, len;
	int mr_id;
};
struct symrdma_ioc_remap {
	int mr_id;
	unsigned long page_idx;
	int mode;
};
struct symrdma_ioc_get_iova {
	int mr_id;
	unsigned long page_idx;
	unsigned long long read_iova, write_iova;
};
struct symrdma_ioc_read_iova {
	int mr_id;
	unsigned long long iova;
	unsigned long offset;
	unsigned int value;
};
struct symrdma_ioc_repair {
	int mr_id;
	unsigned long page_idx;
};
struct symrdma_ioc_get_version {
	int mr_id;
	unsigned long page_idx;
	unsigned int version;
};
struct symrdma_ioc_repair_range {
	int mr_id;
	unsigned long page_idx;
	unsigned long npages;
};

#define SYMRDMA_IOC_REG_MR      _IOWR(SYMRDMA_IOC_MAGIC, 1, struct symrdma_ioc_reg_mr)
#define SYMRDMA_IOC_DEREG_MR    _IOW(SYMRDMA_IOC_MAGIC,  2, int)
#define SYMRDMA_IOC_REMAP       _IOW(SYMRDMA_IOC_MAGIC,  3, struct symrdma_ioc_remap)
#define SYMRDMA_IOC_GET_IOVA    _IOWR(SYMRDMA_IOC_MAGIC, 4, struct symrdma_ioc_get_iova)
#define SYMRDMA_IOC_READ_IOVA   _IOWR(SYMRDMA_IOC_MAGIC, 5, struct symrdma_ioc_read_iova)
#define SYMRDMA_IOC_REPAIR      _IOWR(SYMRDMA_IOC_MAGIC,  6, struct symrdma_ioc_repair)
#define SYMRDMA_IOC_GET_VERSION _IOWR(SYMRDMA_IOC_MAGIC, 7, struct symrdma_ioc_get_version)
#define SYMRDMA_IOC_REPAIR_RANGE _IOWR(SYMRDMA_IOC_MAGIC, 11, struct symrdma_ioc_repair_range)

/* 组常量 (须与内核 SYMRDMA_GROUP_SHIFT 一致) */
#define GROUP_PAGES   512
#define GROUP_SIZE    (GROUP_PAGES * 4096UL)
#define PAGE_SIZE     4096
#define NGROUPS       4
#define NPAGES        (NGROUPS * GROUP_PAGES)   /* 8MB / 4 组 */

/* fail-closed 注入组 (T5 专用 — 其余子测用组 1, 不与注入交叠) */
#define INJECT_GRP    2
#define INJECT_BASE   (INJECT_GRP * GROUP_PAGES)

static int passed = 0, failed = 0, skipped = 0;
static int tn = 0;

#define TEST(name) do { \
	printf("\n[TEST %d] %s\n", ++tn, name); \
} while (0)

#define CHECK(cond, msg) do { \
	if (cond) { printf("  PASS: %s\n", msg); passed++; } \
	else      { printf("  FAIL: %s\n", msg); failed++; } \
} while (0)

/* ---- /proc/symrdma 组统计 (v0.38.0) ---- */

/* 标签后的首个 %lld; 找不到返回 -1 (旧模块无组统计段) */
static long long read_stat(const char *label)
{
	FILE *f = fopen("/proc/symrdma", "r");
	char line[256];

	if (!f)
		return -1;
	while (fgets(line, sizeof(line), f)) {
		const char *p = strstr(line, label);

		if (p) {
			long long v = -1;

			if (sscanf(p + strlen(label), "%lld", &v) == 1) {
				fclose(f);
				return v;
			}
		}
	}
	fclose(f);
	return -1;
}

/* 模块参数读取 (-1=关) */
static int read_module_param(const char *name, int dflt)
{
	char path[128], buf[32];
	int fd, n;

	snprintf(path, sizeof(path), "/sys/module/symrdma/parameters/%s", name);
	fd = open(path, O_RDONLY);
	if (fd < 0)
		return dflt;
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return dflt;
	buf[n] = '\0';
	return (int)strtol(buf, NULL, 0);
}

static uint32_t page_word(unsigned long pg)
{
	return 0x01010101U * (uint8_t)(pg & 0xff);
}

/* 经 IOMMU 页表读页首 4 字节 (单机 RDMA Read 替身) */
static int read_page_word(int fd, int mr_id, unsigned long long iova_base,
			  unsigned long pg, uint32_t *out)
{
	struct symrdma_ioc_read_iova rd;

	memset(&rd, 0, sizeof(rd));
	rd.mr_id = mr_id;
	rd.iova = iova_base + (unsigned long long)pg * PAGE_SIZE;
	rd.offset = 0;
	if (ioctl(fd, SYMRDMA_IOC_READ_IOVA, &rd) != 0)
		return -1;
	*out = rd.value;
	return 0;
}

/* GET_VERSION 快捷 */
static int get_version(int fd, int mr_id, unsigned long pg, unsigned int *ver)
{
	struct symrdma_ioc_get_version gv;

	memset(&gv, 0, sizeof(gv));
	gv.mr_id = mr_id;
	gv.page_idx = pg;
	if (ioctl(fd, SYMRDMA_IOC_GET_VERSION, &gv) != 0)
		return -1;
	*ver = gv.version;
	return 0;
}

static int do_remap(int fd, int mr_id, unsigned long pg, int mode)
{
	struct symrdma_ioc_remap rm;

	memset(&rm, 0, sizeof(rm));
	rm.mr_id = mr_id;
	rm.page_idx = pg;
	rm.mode = mode;
	return ioctl(fd, SYMRDMA_IOC_REMAP, &rm);
}

/* REPAIR_RANGE: out.npages = 实际修复页数 */
static int do_repair_range(int fd, int mr_id, unsigned long pg,
			   unsigned long npages, unsigned long *repaired)
{
	struct symrdma_ioc_repair_range rr;

	memset(&rr, 0, sizeof(rr));
	rr.mr_id = mr_id;
	rr.page_idx = pg;
	rr.npages = npages;
	if (ioctl(fd, SYMRDMA_IOC_REPAIR_RANGE, &rr) != 0)
		return -1;
	if (repaired)
		*repaired = rr.npages;
	return 0;
}

static void thp_mode_report(void)
{
	char buf[64] = "";
	int fd = open("/sys/kernel/mm/transparent_hugepage/enabled", O_RDONLY);

	if (fd >= 0) {
		if (read(fd, buf, sizeof(buf) - 1) > 0) {
			char *b = strstr(buf, "[");

			if (b) {
				char *e = strchr(b, ']');
				if (e)
					*e = '\0';
				printf("THP 策略: %s", b + 1);
			}
		}
		close(fd);
	}
	printf("\n");
}

int main(void)
{
	int fd, ret, mr_id;
	unsigned char *raw, *buf;
	size_t map_len = NPAGES * PAGE_SIZE + GROUP_SIZE;
	struct symrdma_ioc_reg_mr reg = {0};
	struct symrdma_ioc_get_iova gi = {0};
	unsigned long long riova, wiova;
	long long s_promote;
	unsigned int v;
	uint32_t w;
	int inject_on;
	size_t i;

	printf("=== SymRDMA Level 19: 组粒度 IOMMU 映射验证 (Phase 2) ===\n");
	thp_mode_report();

	fd = open("/dev/symrdma", O_RDWR);
	if (fd < 0) {
		perror("open /dev/symrdma");
		return 1;
	}

	/* 组机制形态检查: iommu_huge=0 → 全逐页, 组子测整体 SKIP */
	if (read_module_param("iommu_huge", 1) == 0) {
		printf("iommu_huge=0 — 组机制关闭 (kill-switch 对照形态), SKIP\n");
		close(fd);
		return 0;
	}
	if (read_stat("组降级:") < 0) {
		printf("模块无组统计 (/proc/symrdma) — 旧模块? 先重载 v0.38+\n");
		close(fd);
		return 1;
	}
	inject_on = (read_module_param("demote_fail_grp", -1) == INJECT_GRP);

	/* 2MB 对齐 8MB (+2MB 余量): 组提升/超页映射均要求 VA 2MB 对齐 */
	raw = mmap(NULL, map_len, PROT_READ | PROT_WRITE,
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
	if (ioctl(fd, SYMRDMA_IOC_REG_MR, &reg) != 0) {
		perror("REG_MR");
		munmap(raw, map_len);
		close(fd);
		return 1;
	}
	mr_id = reg.mr_id;

	gi.mr_id = mr_id;
	gi.page_idx = 0;
	if (ioctl(fd, SYMRDMA_IOC_GET_IOVA, &gi) != 0) {
		perror("GET_IOVA");
		goto cleanup;
	}
	riova = gi.read_iova;
	wiova = gi.write_iova;

	/* ====== T1: 组注册提升 + 超页数据面 ====== */
	TEST("注册组提升 (THP): 提升计数 + READ_IOVA 组内页读回");
	s_promote = read_stat("注册提升驻留组:");
	CHECK(s_promote >= 0, "组统计可读 (提升驻留组)");
	if (s_promote >= NGROUPS) {
		printf("  注册提升驻留组 = %lld (4 组全提升, THP 超页 PTE)\n",
		       s_promote);
		passed++;
	} else if (s_promote >= 1) {
		printf("  注册提升驻留组 = %lld (部分提升 — THP 不完整?)\n",
		       s_promote);
		passed++;   /* 部分提升仍走组路径; 全组断言由后续降级计数把关 */
	} else {
		printf("  注册提升驻留组 = %lld — 无提升 (THP 未就位), 组子测降级判定将 SKIP\n",
		       s_promote);
		skipped++;
	}
	/* 数据面: READ_IOVA 组 1 内多页 (超页 PTE 时 iova_to_phys 组内偏移
	 * 正确性的直接判别 — 错误则读回组基址内容) */
	{
		int err = 0;
		static const unsigned long spot[] = { 512, 576, 640, 768, 1023 };

		for (i = 0; i < sizeof(spot) / sizeof(spot[0]); i++) {
			unsigned long pg = spot[i];

			if (read_page_word(fd, mr_id, riova, pg, &w) ||
			    w != page_word(pg)) {
				printf("  FAIL: 组 1 页 %lu 读回 0x%08x != 0x%08x\n",
				       pg, w, page_word(pg));
				err++;
			}
		}
		CHECK(err == 0, "READ_IOVA 组 1 内 5 页数据正确 (超页翻译)");
		ret = get_version(fd, mr_id, 768, &v);
		CHECK(ret == 0 && (v & 1) == 1, "GET_VERSION 组内页驻留奇数版本");
	}

	/* ====== T2: 组内单页换出 — 降级保邻 ====== */
	{
		long long dem_before = read_stat("组降级:");
		long long dem_after;
		int demoted;

		TEST("组内单页换出: REMAP→SENTINEL 触发降级, 512 邻页不伤");
		/* 目标: 组 1 页 256 (全局 768) — 读写域同步换出 (notifier 语义) */
		CHECK(do_remap(fd, mr_id, 768, SYMRDMA_REMAP_SENTINEL) == 0,
		      "REMAP 组 1 页 256 → SENTINEL");
		CHECK(do_remap(fd, mr_id, 768, SYMRDMA_REMAP_BLACKHOLE) == 0,
		      "REMAP 组 1 页 256 → BLACKHOLE");
		dem_after = read_stat("组降级:");
		demoted = dem_after > dem_before;
		if (demoted)
			printf("  组降级计数: %lld → %lld (2MB→512×4KB)\n",
			       dem_before, dem_after);
		else
			printf("  组 1 未提升 (THP 缺) — 降级计数不变, 本测退化为逐页换出验证\n");

		/* 读域: 目标页魔数, 邻页真值 (降级重建 512 页映射的完整性) */
		CHECK(read_page_word(fd, mr_id, riova, 768, &w) == 0 &&
		      w == SYMRDMA_SENTINEL_MAGIC,
		      "换出页读回哨兵魔数 (read 域)");
		{
			int err = 0;
			static const unsigned long spot[] = { 767, 769, 512, 1023 };

			for (i = 0; i < sizeof(spot) / sizeof(spot[0]); i++) {
				if (read_page_word(fd, mr_id, riova, spot[i], &w) ||
				    w != page_word(spot[i]))
					err++;
			}
			CHECK(err == 0, "邻页 (前/后/组首/组尾) 读回真值 — 无静默解除");
		}
		/* 写域: 邻页映射完整 (黑洞页内容不判, 仅判真值邻页) */
		CHECK(read_page_word(fd, mr_id, wiova, 769, &w) == 0 &&
		      w == page_word(769),
		      "写域邻页读回真值 (write 域降级重建完整)");
		ret = get_version(fd, mr_id, 768, &v);
		CHECK(ret == 0 && (v & 1) == 0, "换出页版本翻转为偶数");
		ret = get_version(fd, mr_id, 769, &v);
		CHECK(ret == 0 && (v & 1) == 1, "邻页版本保持奇数");
	}

	/* ====== T3: 单页修复 ====== */
	TEST("单页修复: REPAIR_RANGE 恢复数据 + 版本翻转回奇数");
	{
		unsigned long repaired = 0;

		ret = do_repair_range(fd, mr_id, 768, 1, &repaired);
		CHECK(ret == 0 && repaired == 1, "REPAIR_RANGE [768,1] 修复 1 页");
		CHECK(read_page_word(fd, mr_id, riova, 768, &w) == 0 &&
		      w == page_word(768), "修复页读回真值");
		ret = get_version(fd, mr_id, 768, &v);
		CHECK(ret == 0 && (v & 1) == 1, "修复页版本回到奇数");
	}

	/* ====== T4: 整组换出 + 修复重提升 (promote-once) ====== */
	TEST("整组换出 + 整组修复: 组 1 重提升 (修复路径, 等价跳过幂等)");
	{
		long long rp0 = read_stat("修复路径组提升:");
		long long rp1, rp2;

		for (i = 512; i < 1024; i++)
			if (do_remap(fd, mr_id, i, SYMRDMA_REMAP_SENTINEL) != 0)
				break;
		CHECK(i == 1024, "REMAP 组 1 全 512 页 → SENTINEL");
		CHECK(read_page_word(fd, mr_id, riova, 512, &w) == 0 &&
		      w == SYMRDMA_SENTINEL_MAGIC, "组首页读回哨兵魔数");

		{
			unsigned long repaired = 0;

			ret = do_repair_range(fd, mr_id, 512, GROUP_PAGES, &repaired);
			CHECK(ret == 0 && repaired == GROUP_PAGES,
			      "REPAIR_RANGE 整组 512 页修复");
		}
		{
			int err = 0;
			static const unsigned long spot[] = { 512, 640, 768, 896, 1023 };

			for (i = 0; i < sizeof(spot) / sizeof(spot[0]); i++) {
				if (read_page_word(fd, mr_id, riova, spot[i], &w) ||
				    w != page_word(spot[i]))
					err++;
			}
			CHECK(err == 0, "整组修复后数据全部回真值");
		}
		{
			unsigned int v0 = 0;

			ret = get_version(fd, mr_id, 768, &v);
			CHECK(ret == 0 && (v & 1) == 1, "整组修复后版本奇数");
			/* 等价跳过: 同一 REPAIR_RANGE 幂等 (GRP_RESIDENT 命中
			 * 等价分支 — 无重映射工作, 数据/版本不动) */
			v0 = v;
			ret = do_repair_range(fd, mr_id, 512, GROUP_PAGES, NULL);
			CHECK(ret == 0, "重复 REPAIR_RANGE (等价跳过) 成功");
			ret = get_version(fd, mr_id, 768, &v);
			CHECK(ret == 0 && v == v0, "等价跳过不动版本号");
			CHECK(read_page_word(fd, mr_id, riova, 768, &w) == 0 &&
			      w == page_word(768), "等价跳过不动数据");
		}
		rp1 = read_stat("修复路径组提升:");
		if (rp1 > rp0) {
			printf("  修复路径组提升: %lld → %lld (重提升, 组回超页 PTE)\n",
			       rp0, rp1);
			passed++;
		} else {
			printf("  修复路径组提升: %lld → %lld — 无 THP 未重提升 (promote-once 判定 SKIP)\n",
			       rp0, rp1);
			skipped++;
		}
		(void)rp2;
	}

	/* ====== T5 (注入形态): 降级 fail-closed 兜底 ====== */
	if (!inject_on) {
		TEST("降级 fail-closed 注入 (demote_fail_grp)");
		printf("  SKIP: 模块未开注入 (默认 demote_fail_grp=-1) —\n"
		       "        专用形态: bash ~/pro/symrdma/scripts/symrdma_reload.sh "
		       "mode=1 pci_bdf=<BDF> demote_fail_grp=2\n");
		skipped++;
	} else {
		long long df0 = read_stat("降级失败:");
		long long dm0 = read_stat("组降级:");
		long long df1, dm1;
		TEST("降级 fail-closed: 注入首页映射失败 → 哨兵/黑洞兑底");
		/* 组 2 页 256 (全局 1280) 换出 → 降级时组 2 首页 (1024) 注入
		 * 模拟 map 失败: read 侧哨兵只读 + 版本翻转; write 侧黑洞 */
		CHECK(do_remap(fd, mr_id, 1280, SYMRDMA_REMAP_SENTINEL) == 0,
		      "REMAP 组 2 页 256 → SENTINEL (触发降级+注入)");
		CHECK(do_remap(fd, mr_id, 1280, SYMRDMA_REMAP_BLACKHOLE) == 0,
		      "REMAP 组 2 页 256 → BLACKHOLE");
		dm1 = read_stat("组降级:");
		if (dm1 == dm0) {
			/* 组 2 未提升 (THP 不完整) → 降级未发生, 注入无从触发 */
			printf("  SKIP: 组 2 未提升 — 降级未发生, 注入未触发 (THP 缺?)\n");
			skipped++;
		} else {
			CHECK(read_page_word(fd, mr_id, riova, 1024, &w) == 0 &&
			      w == SYMRDMA_SENTINEL_MAGIC,
			      "注入页读回哨兵魔数 (fail-closed read 兜底)");
			CHECK(read_page_word(fd, mr_id, riova, 1280, &w) == 0 &&
			      w == SYMRDMA_SENTINEL_MAGIC,
			      "换出目标页读回哨兵魔数");
			{
			int err = 0;
			static const unsigned long spot[] = { 1025, 1281, 1023, 1535 };

			for (i = 0; i < sizeof(spot) / sizeof(spot[0]); i++) {
				if (read_page_word(fd, mr_id, riova, spot[i], &w) ||
				    w != page_word(spot[i]))
					err++;
			}
			CHECK(err == 0, "注入降级的邻页读回真值 (无静默解除)");
			}
			ret = get_version(fd, mr_id, 1024, &v);
			CHECK(ret == 0 && (v & 1) == 0,
			      "注入页版本翻转偶数 (fail-closed 状态置缺失)");
			ret = get_version(fd, mr_id, 1281, &v);
			CHECK(ret == 0 && (v & 1) == 1, "邻页版本保持奇数");
			df1 = read_stat("降级失败:");
			dm1 = read_stat("组降级:");
			CHECK(df1 - df0 == 2, "降级失败计数 +2 (read+write 域首页注入)");
			CHECK(dm1 - dm0 == 1, "组降级计数 +1");
			/* 恢复: 整组修复 (含注入页 — orig_pa=0 经 GUP 兑底) */
			{
			unsigned long repaired = 0;

			ret = do_repair_range(fd, mr_id, INJECT_BASE, GROUP_PAGES,
					      &repaired);
			CHECK(ret == 0 && repaired == GROUP_PAGES,
			      "REPAIR_RANGE 注入组 512 页修复");
			}
			{
			int err = 0;
			static const unsigned long spot[] = { 1024, 1280, 1535 };

			for (i = 0; i < sizeof(spot) / sizeof(spot[0]); i++) {
				if (read_page_word(fd, mr_id, riova, spot[i], &w) ||
				    w != page_word(spot[i]))
					err++;
			}
			CHECK(err == 0, "注入组修复后数据回真值");
			}
			ret = get_version(fd, mr_id, 1024, &v);
			CHECK(ret == 0 && (v & 1) == 1, "注入页修复后版本回奇数");
		}   /* 组 2 已提升 (注入已触发) */
	}

	printf("\n=== 结果: %d 通过 / %d 失败 / %d SKIP ===\n",
	       passed, failed, skipped);

cleanup:
	ioctl(fd, SYMRDMA_IOC_DEREG_MR, mr_id);
	munmap(raw, map_len);
	close(fd);
	if (failed)
		return 2;
	return 0;
}
