/*
 * racebw_repro.c — L1d host-b 停机现场的服务器侧 churn 复现 
 *
 * 背景: group_gates_20260919_190235 L1d racebw — 服务器 (host-b) 在
 * ~2 分钟 ≤512K churn (~41k REPAIR + ~100 PREP madvise 循环) 后, 4M 用例
 * 首个 1024 页 REPAIR_RANGE 处停机 (SIR 无应答 5s 超时 → 对端进程消失
 * → 机器 SSH KEX 挂)。本程序剥离 RDMA/SIR 网络面, 直接以 ioctl 复刻
 * 服务器侧内核 churn 序列, 用于在健康机器上隔离复现:
 *
 *   PREP  = madvise(span 16MB, MADV_DONTNEED)   (racebw server_prep, minor)
 *   REPAIR= ioctl(SYMRDMA_IOC_REPAIR_RANGE)      (SIR sir_serve_repair 同体)
 *
 * 模式 (-m):
 *   gate  — 复刻整场门禁序列: 2B/16/128/1K (各 2 batch × 4096 单页修复)
 *           → 8K (2×2048×2页) → 64K (11×256×16页) → 512K (38×32×128页)
 *           → 4M (1×4×1024页)。每 loop 一场, -l 控制场数。
 *   4m    — 纯 4M 模式: PREP + 4×REPAIR_RANGE(1024) × loop。
 *   churn — 纯 ≤1K 模式: PREP + 4096×REPAIR_RANGE(1) × loop。
 *
 * MR 形态与 racebw server 完全一致:
 *   mmap 32MB MAP_ANONYMOUS|MAP_PRIVATE|MAP_NORESERVE + MADV_NOHUGEPAGE,
 *   不预触摸 (注册时全组缺失 →  注册期 GRP_ABSENT/哨兵化),
 *   symrdma_mr_register (REG_MR + GET_IOVA + identity ibv_mr +
 *   bind_version 多页版本表)。
 *
 * 监控输出: 每 batch 打印进度与耗时; 单次 ioctl > 500ms 打印 "!!! SLOW"
 * (早期停机信号); 每 10 loop 打印 MemFree。
 * 退出: 完成 -l 场数或 -T 秒到时 → DEREG (正常收尾路径) → 退出。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include "libsymrdma.h"      /* 部署时与 lib 同层 (build.sh 平铺同步) */

/* SYMRDMA_IOC_REPAIR_RANGE / struct symrdma_ioc_repair_range:
 * 与 kernel/symrdma.h 同步的本地拷贝 (test_group_mapping 同型做法 —
 * 避免 diag 程序对内核头路径的依赖) */
#define SYMRDMA_IOC_MAGIC 'S'
struct symrdma_ioc_repair_range_local {
	int             mr_id;
	unsigned long   page_idx;
	unsigned long   npages;
};
#define SYMRDMA_IOC_REPAIR_RANGE_LOCAL \
	_IOWR(SYMRDMA_IOC_MAGIC, 11, struct symrdma_ioc_repair_range_local)

#define REGION_SZ   (32UL * 1024 * 1024)   /* racebw: 2×16MB span */
#define SPAN_BYTES  (16UL * 1024 * 1024)
#define SPAN_PAGES  (SPAN_BYTES / 4096)    /* 4096 */

#ifndef MADV_NOHUGEPAGE
#define MADV_NOHUGEPAGE 15
#endif

static struct symrdma_ctx sctx;
static struct symrdma_mr smr;
static unsigned char *g_buf;

static double now_us(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1e6 + ts.tv_nsec / 1e3;
}

static void memfree_line(void)
{
	FILE *f = fopen("/proc/meminfo", "r");
	char k[64];
	unsigned long v;
	char u[16];

	if (!f)
		return;
	while (fscanf(f, "%63s %lu %15s", k, &v, u) == 3) {
		if (!strcmp(k, "MemFree:")) {
			printf("    [mem] MemFree = %lu kB\n", v);
			break;
		}
	}
	fclose(f);
}

/* 单次 REPAIR_RANGE (SIR sir_serve_repair 的内核等价体)。
 * 返回 0 成功 (repaired=实际页数), -1 ioctl 失败 (打印 errno)。 */
static int repair_range(unsigned long page_idx, unsigned long npages,
			unsigned long *repaired_out, double *dt_out)
{
	struct symrdma_ioc_repair_range_local rr = {
		.mr_id = smr.mr_id,
		.page_idx = page_idx,
		.npages = npages,
	};
	double t0 = now_us();
	int rc;

	rc = ioctl(sctx.fd, SYMRDMA_IOC_REPAIR_RANGE_LOCAL, &rr);
	*dt_out = now_us() - t0;
	if (rc) {
		printf("    !!! REPAIR_RANGE(%lu,+%lu) 失败 errno=%d (%s)\n",
		       page_idx, npages, errno, strerror(errno));
		return -1;
	}
	if (rr.npages == 0 || rr.npages > npages) {
		printf("    !!! REPAIR_RANGE(%lu,+%lu) 契约违约 npages=%lu\n",
		       page_idx, npages, rr.npages);
		return -1;
	}
	if (repaired_out)
		*repaired_out = rr.npages;
	if (*dt_out > 500000.0)   /* >0.5s: 停机前兆 */
		printf("    !!! SLOW REPAIR_RANGE(%lu,+%lu) %.1f ms\n",
		       page_idx, npages, *dt_out / 1000.0);
	return 0;
}

/* PREP minor: madvise DONTNEED 整个 minor span (服务端 server_prep 等价) */
static int prep_minor(void)
{
	double t0 = now_us();

	if (madvise(g_buf, SPAN_BYTES, MADV_DONTNEED)) {
		printf("    !!! PREP madvise 失败 errno=%d (%s)\n",
		       errno, strerror(errno));
		return -1;
	}
	if (now_us() - t0 > 500000.0)
		printf("    !!! SLOW PREP %.1f ms (notifier 重映射窗口)\n",
		       (now_us() - t0) / 1000.0);
	return 0;
}

/* 一场门禁形态的 churn (≤512K 各尺寸 + 4M), 返回修复调用总数 */
static unsigned long run_gate_pass(int verbose)
{
	unsigned long total = 0, rep, dt_max = 0;
	double dt;
	int b, k;

	/* 2B/16/128/1K: 2 batch × 4096 单页修复 (与 racebw 客户端 ≤4KB
	 * 哨兵路径逐页 SIR REPAIR 等价 — SIR 侧同为 REPAIR_RANGE(1)) */
	for (b = 0; b < 2; b++) {
		if (prep_minor())
			return total;
		for (k = 0; k < 4096; k++) {
			if (repair_range(k, 1, &rep, &dt))
				return total;
			total++;
			if (dt > dt_max)
				dt_max = dt;
		}
		if (verbose)
			printf("    [2B/16/128/1K] batch %d: 4096 单页修复 "
			       "(max %.1f ms)\n", b, dt_max / 1000.0);
	}
	/* 8K: 2 batch × 2048 × 2 页 */
	for (b = 0; b < 2; b++) {
		if (prep_minor())
			return total;
		for (k = 0; k < 2048; k++) {
			if (repair_range(2 * k, 2, &rep, &dt))
				return total;
			total++;
		}
		if (verbose)
			printf("    [8K] batch %d: 2048×2页\n", b);
	}
	/* 64K: 11 batch × 256 × 16 页 */
	for (b = 0; b < 11; b++) {
		if (prep_minor())
			return total;
		for (k = 0; k < 256; k++) {
			if (repair_range(16 * k, 16, &rep, &dt))
				return total;
			total++;
		}
	}
	/* 512K: 38 batch × 32 × 128 页 (段批) */
	for (b = 0; b < 38; b++) {
		if (prep_minor())
			return total;
		for (k = 0; k < 32; k++) {
			if (repair_range(128 * k, 128, &rep, &dt))
				return total;
			total++;
		}
	}
	if (verbose)
		printf("    [≤512K churn 完成] 累计修复调用 %lu\n", total);

	/* 4M: PREP + 4 × 1024 页 (首个整组修复 — host-b 停机点) */
	if (prep_minor())
		return total;
	for (k = 0; k < 4; k++) {
		printf("    [4M] REPAIR_RANGE(%d, 1024) …\n", 1024 * k);
		fflush(stdout);
		if (repair_range(1024 * k, 1024, &rep, &dt))
			return total;
		total++;
		printf("    [4M] op %d: %lu 页 %.1f ms\n",
		       k, rep, dt / 1000.0);
		fflush(stdout);
	}
	return total;
}

int main(int argc, char **argv)
{
	const char *mode = "gate";
	long loops = 1, timeout_s = 600;
	int opt, i, rc = 0;

	while ((opt = getopt(argc, argv, "m:l:T:")) != -1) {
		switch (opt) {
		case 'm': mode = optarg; break;
		case 'l': loops = atol(optarg); break;
		case 'T': timeout_s = atol(optarg); break;
		default:
			fprintf(stderr,
				"usage: %s [-m gate|4m|churn] [-l loops] "
				"[-T timeout_s]\n", argv[0]);
			return 1;
		}
	}
	setvbuf(stdout, NULL, _IOLBF, 0);

	printf("=== racebw_repro mode=%s loops=%ld timeout=%lds ===\n",
	       mode, loops, timeout_s);

	/* MR 形态复刻: 不预触摸 + NOHUGEPAGE */
	g_buf = mmap(NULL, REGION_SZ, PROT_READ | PROT_WRITE,
		     MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE, -1, 0);
	if (g_buf == MAP_FAILED) {
		perror("mmap");
		return 1;
	}
	madvise(g_buf, REGION_SZ, MADV_NOHUGEPAGE);

	if (symrdma_open(&sctx)) {
		printf("symrdma_open 失败\n");
		return 2;
	}

	/* verbs: pd 仅为 ibv_reg_mr (identity MTT) 与版本 MR 注册所需,
	 * 无 QP/无流量 */
	{
		struct ibv_device **l = ibv_get_device_list(NULL);
		struct ibv_context *ctx;
		struct ibv_pd *pd;

		if (!l || !l[0]) {
			printf("无 RDMA 设备\n");
			return 2;
		}
		ctx = ibv_open_device(l[0]);
		if (!ctx) { printf("ibv_open_device 失败\n"); return 2; }
		pd = ibv_alloc_pd(ctx);
		if (!pd) { printf("ibv_alloc_pd 失败\n"); return 2; }

		if (symrdma_mr_register(&sctx, pd, g_buf, REGION_SZ, &smr)) {
			printf("symrdma_mr_register 失败\n");
			return 1;
		}
		if (!smr.version_mr) {
			printf("!! 版本 MR 未绑定 — 与 racebw server 形态不符\n");
		} else {
			printf("MR 就绪: id=%d buf=%p/%zu "
			       "read_iova=0x%llx vt=%d页\n",
			       smr.mr_id, g_buf, REGION_SZ,
			       (unsigned long long)smr.read_iova,
			       (int)(REGION_SZ / 4096 * 4 / 4096 + 1));
		}
	}

	memfree_line();

	for (i = 0; i < loops && rc == 0; i++) {
		unsigned long t0 = now_us(), n;

		printf("--- pass %d/%ld ---\n", i + 1, loops);
		if (!strcmp(mode, "gate")) {
			n = run_gate_pass(1);
		} else if (!strcmp(mode, "4m")) {
			int k;

			if (prep_minor())
				break;
			for (k = 0; k < 4; k++) {
				unsigned long rep;
				double dt;

				if (repair_range(1024 * k, 1024, &rep, &dt))
					break;
				printf("    [4M] op %d: %lu 页 %.1f ms\n",
				       k, rep, dt / 1000.0);
			}
			n = 4;
		} else {   /* churn */
			int k;
			unsigned long rep;
			double dt, dmax = 0;

			if (prep_minor())
				break;
			for (k = 0; k < 4096; k++) {
				if (repair_range(k, 1, &rep, &dt))
					break;
				if (dt > dmax)
					dmax = dt;
			}
			printf("    [churn] 4096 单页 (max %.1f ms)\n",
			       dmax / 1000.0);
			n = 4096;
		}
		printf("--- pass %d 完成: %lu 修复调用, %.1f s ---\n",
		       i + 1, n, (now_us() - t0) / 1e6);
		if ((i + 1) % 10 == 0)
			memfree_line();
		if ((now_us() - t0) / 1e6 > timeout_s) {
			printf("超时 %lds 到 — 提前收尾\n", timeout_s);
			break;
		}
	}

	printf("DEREG 收尾 …\n");
	symrdma_mr_deregister(&sctx, &smr);
	munmap(g_buf, REGION_SZ);
	symrdma_close(&sctx);
	printf("=== racebw_repro 完成 rc=%d ===\n", rc);
	return rc;
}
