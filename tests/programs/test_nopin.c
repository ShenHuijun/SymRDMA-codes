/*
 * test_nopin.c — SymRDMA Level 8: no-pin 注册验证
 *
 * 验证论文 §4.1 "Create MR 不 pin" (ib_umem_get_nopin):
 *   1. ★ 决定性: RLIMIT_MEMLOCK=0 下注册成功 — pin 版 ib_umem_get
 *      会 GUP 并计入 locked_vm 额度 → 超限必失败; no-pin 分支在
 *      限额检查之前返回 → 必成功
 *   2. 注册后 MADV_PAGEOUT 物理页真正归还系统 (VMA Rss 下降 +
 *      VMA Swap 增长) — pin 版物理页因 refcount 留在 RAM, Rss 不降
 *
 * 环境要求: identity_mtt=1 (注册走 no-pin 路径) + swap。
 * 注意: 不挂 LD_PRELOAD — 直接验证 mlx5_ib 的 identity no-pin 注册路径。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <errno.h>
#include <infiniband/verbs.h>
/* SymRDMA MR 标记位 (P4): 与 lib/libsymrdma.h 同值 —
 * uverbs optional 位 1<<21, mlx5 据此走 identity MTT 分支 */
#define SYMRDMA_ACCESS_IDENTITY (1 << 21)

#ifndef MADV_PAGEOUT
#define MADV_PAGEOUT 21
#endif

#define NPAGES   64
#define BUF_SIZE (NPAGES * 4096UL)

static int passed = 0, failed = 0;

#define CHECK(cond, msg) do { \
	if (cond) { printf("  PASS: %s\n", msg); passed++; } \
	else      { printf("  FAIL: %s (%s)\n", msg, strerror(errno)); failed++; } \
} while (0)

/* 解析 /proc/self/smaps 中 buf VMA 的 Rss / Swap (kB) */
static void get_vma_stats(unsigned long addr, long long *rss, long long *swp)
{
	FILE *f = fopen("/proc/self/smaps", "r");
	char line[256];
	unsigned long start, end;
	int in_vma = 0;

	*rss = *swp = -1;
	if (!f)
		return;
	while (fgets(line, sizeof(line), f)) {
		if (!in_vma && sscanf(line, "%lx-%lx", &start, &end) == 2) {
			in_vma = (addr >= start && addr < end);
			continue;
		}
		if (!in_vma)
			continue;
		if (sscanf(line, "Rss: %lld", rss) == 1)
			continue;
		if (sscanf(line, "Swap: %lld", swp) == 1)
			break;
	}
	fclose(f);
}

int main(void)
{
	unsigned char *buf;
	struct ibv_device **dev_list;
	struct ibv_context *ctx;
	struct ibv_pd *pd;
	struct ibv_mr *mr;
	struct rlimit zero_limit = {0, 0};
	long long rss0, swp0, rss1, swp1, rss2, swp2;
	int num, i, ret, tries;

	printf("=== SymRDMA Level 8: no-pin 注册验证 (ib_umem_get_nopin) ===\n");

	/* Step 1: RDMA 上下文 (排除用户态库 malloc 对 RSS 的干扰) */
	dev_list = ibv_get_device_list(&num);
	if (!dev_list || num == 0) {
		printf("  SKIP: 无 RDMA 设备\n");
		return 0;
	}
	ctx = ibv_open_device(dev_list[0]);
	if (!ctx) { printf("  SKIP: open_device 失败\n"); return 1; }
	pd = ibv_alloc_pd(ctx);
	if (!pd) { printf("  SKIP: alloc_pd 失败\n"); return 1; }

	/* Step 2: 分配 + touch (全部驻留) */
	buf = mmap(NULL, BUF_SIZE, PROT_READ | PROT_WRITE,
		   MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (buf == MAP_FAILED) { perror("mmap"); return 1; }
	memset(buf, 0xAB, BUF_SIZE);

	get_vma_stats((unsigned long)buf, &rss0, &swp0);
	printf("[1] %d 页驻留: VMA Rss=%lld kB Swap=%lld kB\n",
	       NPAGES, rss0, swp0);
	CHECK(rss0 >= (long long)NPAGES * 4 && swp0 == 0,
	      "基线: 64 页驻留, 无 swap");

	/* Step 3: ★ RLIMIT_MEMLOCK=0 下注册 — pin 版必失败, no-pin 必成功 */
	if (setrlimit(RLIMIT_MEMLOCK, &zero_limit)) {
		printf("  SKIP: setrlimit 失败 (%s)\n", strerror(errno));
		return 1;
	}
	printf("[2] RLIMIT_MEMLOCK=0 (locked_vm 额度耗尽) → 注册\n");
	mr = ibv_reg_mr(pd, buf, BUF_SIZE,
			IBV_ACCESS_LOCAL_WRITE |
			IBV_ACCESS_REMOTE_READ |
			IBV_ACCESS_REMOTE_WRITE |
			SYMRDMA_ACCESS_IDENTITY);
	CHECK(mr != NULL,
	      "★ RLIMIT_MEMLOCK=0 下注册成功 — 未 pin (pin 版超限必失败)");
	if (!mr) {
		ibv_dealloc_pd(pd);
		ibv_close_device(ctx);
		munmap(buf, BUF_SIZE);
		return 1;
	}

	/* Step 4: 换出 — 物理页真正归还系统 (Rss 降 + Swap 涨) */
	ret = madvise(buf, BUF_SIZE, MADV_PAGEOUT);
	CHECK(ret == 0, "madvise(MADV_PAGEOUT) 64 页");

	/* 轮询等待换出完成 (最多 5s) */
	rss1 = rss0;
	for (tries = 0; tries < 50; tries++) {
		get_vma_stats((unsigned long)buf, &rss1, &swp1);
		if (rss1 >= 0 && swp1 >= (long long)NPAGES * 4 / 2)
			break;
		usleep(100000);
	}
	printf("[3] 换出后: VMA Rss=%lld kB Swap=%lld kB\n", rss1, swp1);
	CHECK(rss1 >= 0 && rss1 <= rss0 / 2,
	      "★ Rss 大幅下降 — 换出页真正释放 (pin 版 Rss 不降)");
	CHECK(swp1 >= (long long)NPAGES * 4 / 2,
	      "★ Swap 增长 — 页内容确实写入 swap");

	/* Step 5: CPU 触摸换回 (可恢复性) */
	for (i = 0; i < NPAGES; i++)
		buf[i * 4096] = 0xAB;
	get_vma_stats((unsigned long)buf, &rss2, &swp2);
	printf("[4] CPU 触摸后: VMA Rss=%lld kB Swap=%lld kB\n", rss2, swp2);
	CHECK(rss2 >= (long long)NPAGES * 4,
	      "CPU 触摸后页面换回 (可恢复)");

	ibv_dereg_mr(mr);
	ibv_dealloc_pd(pd);
	ibv_close_device(ctx);
	ibv_free_device_list(dev_list);
	munmap(buf, BUF_SIZE);

	printf("\n========================================\n");
	printf("Level 8 结果: %d 通过, %d 失败, %d 总计\n",
	       passed, failed, passed + failed);
	printf("========================================\n");
	return failed > 0 ? 1 : 0;
}
