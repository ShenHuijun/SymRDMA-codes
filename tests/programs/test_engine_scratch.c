/*
 * test_engine_scratch.c — SymRDMA Level 20: 引擎 scratch 锁纪律白盒单测
 * (P1-2 回归; 纯 CPU — 无 RDMA/无模块/无 LD_PRELOAD, 同 L16 形态)
 *
 * 白盒: 直接 #include 引擎编译单元以触达 static npr_scratch_get /
 * scratch_mu (引擎内部符号不出动态符号表, 黑盒无法注入 mmap 失败)。
 * nprdma.c 提供的外部符号 (sym_fd / g_real_reg_mr_iova2 / debug_on /
 * symrdma_open_locked / npr_pin_once) 与引擎引用的 sir_* API 以桩实现 —
 * 本测试不建 SIR 通道、不触碰 verbs 数据路径, 只驱动 scratch 创建的
 * 失败退出路径。
 *
 * 背景 (P1-2): npr_scratch_get 的 mmap 失败分支旧代码持
 * scratch_mu 返回 → 单次 ENOMEM 之后, 任何后续远端写验证 (其他线程/
 * 其他 context, fast-path 闩锁未命中者) 进入 scratch_mu 永久死锁。
 * 判定: 注入 (NPRDMA_FAULT_SCRATCH_MMAP=1) 触发失败路径后, 以
 * pthread_mutex_trylock 检测 scratch_mu 未被持有 (旧代码 EBUSY → FAIL)。
 *
 * 用法: 直接运行 (无参数, 退出码 0=PASS)。勿挂 LD_PRELOAD (引擎符号
 * 双定义; 本单测自含引擎编译单元)。
 */
#define _GNU_SOURCE   /* dlvsym (引擎编译单元需) — 必须先于任何系统头 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <infiniband/verbs.h>

/* 白盒直含引擎编译单元 (双布局: 本地 tests/programs/ 两层深
 * ../../nprdma/; 远端 ~/pro/symrdma/test/ 一层深 ../nprdma/ — 同 Makefile
 * LIBDIR/SIRDIR 自适应语义, 但 include 需在源内以 __has_include 判定) */
#if __has_include("../../nprdma/nprdma_engine.c")
#include "../../nprdma/nprdma_engine.c"
#else
#include "../nprdma/nprdma_engine.c"
#endif

static int passed, failed;

#define CHECK(cond, msg) do { \
	if (cond) { printf("  PASS: %s\n", msg); passed++; } \
	else      { printf("  FAIL: %s (errno=%d)\n", msg, errno); failed++; } \
} while (0)

/* T3 工作线程参数 (带看门狗调用 — 旧 bug 形态下持锁泄漏 → 调用永久
 * 死锁; 回归必须 FAIL 而非 HANG, 超时判失败) */
struct t3_arg {
	struct npr_ctx_entry ce;
	struct ibv_qp qp;
	int rc;
};
static void *t3_worker(void *p)
{
	struct t3_arg *a = p;

	a->rc = npr_scratch_get(&a->ce, &a->qp);
	return NULL;
}

/* ---- nprdma.c 外部符号桩 (引擎引用, 本测试不接入拦截层) ---- */
int sym_fd = -1;
struct ibv_mr *(*g_real_reg_mr_iova2)(struct ibv_pd *, void *, size_t,
				      uint64_t, unsigned int);
int debug_on(void)
{
	return 0;
}
int symrdma_open_locked(void)
{
	return -1;   /* 桩: 无 /dev/symrdma — scratch 内核 MR 注册跳过 */
}
void npr_pin_once(int mr_id, uint64_t va, size_t len)
{
	(void)mr_id;
	(void)va;
	(void)len;
}

/* ---- sir API 桩 (引擎数据路径引用; 本测试不驱动) ---- */
int sir_remote_lookup(uint32_t data_rkey, struct sir_export *out)
{
	(void)data_rkey;
	(void)out;
	errno = ENOENT;
	return -1;
}
int sir_remote_repair(uint32_t data_rkey, unsigned long page_idx, int dir,
		      uint32_t off, uint32_t len, void *data)
{
	(void)data_rkey;
	(void)page_idx;
	(void)dir;
	(void)off;
	(void)len;
	(void)data;
	errno = ENOSYS;
	return -1;
}
int sir_remote_atomic(uint32_t data_rkey, uint64_t va, int op,
		      uint64_t compare, uint64_t swap_or_add, uint64_t *old_out)
{
	(void)data_rkey;
	(void)va;
	(void)op;
	(void)compare;
	(void)swap_or_add;
	(void)old_out;
	errno = ENOSYS;
	return -1;
}

/* trylock 后归位: 成功即证明锁未被持有 (旧代码持锁泄漏 → EBUSY) */
static int scratch_mu_free(void)
{
	int rc = pthread_mutex_trylock(&scratch_mu);

	if (rc == 0)
		pthread_mutex_unlock(&scratch_mu);
	return rc == 0;
}

int main(void)
{
	struct ibv_qp qp = {0};   /* pd=NULL → regfn 不可用形态安全 */
	struct npr_ctx_entry ce = {0};
	int rc;

	/* 行缓冲: 挂死/被杀时已产出结论可见 (test.sh stdbuf 同款语义) */
	setvbuf(stdout, NULL, _IOLBF, 0);

	printf("=== Level 20: 引擎 scratch 锁纪律白盒单测 (P1-2) ===\n");

	/* T1: mmap 失败注入 — 失败退出路径的锁纪律 (P1-2 核心回归:
	 * 旧代码 ce->no_scratch=1 后持 scratch_mu 返回 → 后续任何写验证
	 * 死锁; 本测试曾以旧代码复现 trylock=EBUSY) */
	setenv("NPRDMA_FAULT_SCRATCH_MMAP", "1", 1);
	rc = npr_scratch_get(&ce, &qp);
	CHECK(rc == -1 && ce.no_scratch == 1 && scratch_mu_free(),
	      "T1 注入 mmap 失败: 返回 -1 + 闩锁 + scratch_mu 已释放");
	unsetenv("NPRDMA_FAULT_SCRATCH_MMAP");

	/* T2: 闩锁快速路径 — 二次调用不触碰锁 (旧代码同语义, 回归确认) */
	rc = npr_scratch_get(&ce, &qp);
	CHECK(rc == -1 && ce.no_scratch == 1, "T2 二次调用走闩锁快速路径");

	/* T3: 无注入 + regfn 不可用 (独立进程 dlvsym 无 RTLD_NEXT 提供者)
	 * → "scratch 创建失败" 退出路径既有锁纪律回归确认。
	 * 带看门狗线程调用 (旧 bug 形态: T1 持锁泄漏 → 本调用永久死锁;
	 * 回归须 FAIL 而非 HANG — 2s 超时判失败)。 */
	{
		pthread_t tid;
		struct t3_arg a = {0};
		struct timespec ts;
		int jrc;

		a.qp.pd = NULL;
		pthread_create(&tid, NULL, t3_worker, &a);
		clock_gettime(CLOCK_REALTIME, &ts);
		ts.tv_sec += 2;
		jrc = pthread_timedjoin_np(tid, NULL, &ts);
		if (jrc != 0) {
			/* 旧 bug 形态: 永久死锁 (超时) — 判 FAIL 并退出,
			 * 工作线程随进程退出回收 */
			CHECK(0, "T3 regfn 不可用退出路径: 2s 内完成 "
			      "(旧代码 = scratch_mu 死锁)");
		} else {
			CHECK(a.rc == -1 && a.ce.no_scratch == 1 &&
			      scratch_mu_free(),
			      "T3 regfn 不可用退出路径: 完成 + scratch_mu 已释放");
		}
	}

	printf("\n========================================\n");
	printf("Level 20: %d 通过, %d 失败\n", passed, failed);
	printf("========================================\n");
	return failed > 0 ? 1 : 0;
}
