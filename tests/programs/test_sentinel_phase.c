/*
 * test_sentinel_phase.c — 哨兵扫描原语相位单测 (R2, v0.29.0)
 *
 * 纯 CPU 单测 (无 RDMA/模块/ibverbs): 固化 sir/sentinel.h 共享原语的
 * 相位语义, 及 lib 侧切换 (buf_is_sentinel 加 base 参数) 与旧 phase-0
 * 实现的字节级等价性 — REFACTOR 第 2 批门禁 "相位专项单测 (非对齐读
 * 回填比对)"。
 *
 *   T1 相位期望值: 4 相位旋转表 — v0.22.0 bug 10 (读偏移 3585 实测
 *      [BE AD DE EF] = 0xefdeadbe)
 *   T2 非对齐回填检测: 旧 phase-0 漏检 / 相位感知命中 (bug 10 场景:
 *      读起点 3585, 次页缺失, 缺失段自页边界 4096 起)
 *   T3 页对齐等价性: 随机缓冲上 sentinel_is_hit(页对齐 base) 与旧
 *      实现 (chunk u32 == MAGIC + len<4 前缀 memcmp) 逐字节等价
 *   T4 首缺失页定位: 页边界取整 (bug 2/4) + 无哨兵兜底 base
 *   T5 全量修复扫描: 页去重/升序/计数 + 失败即停 -1 + 无哨兵 0
 *   T6 len<4 前缀: 相位 0 与旧 pfx 等价 + 非对齐相位行为
 *   T7 版本表页数公式: symrdma_vt_pages 边界 (R7)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "sentinel.h"
#include "vtpages.h"

static int fails;

#define CHECK(cond, name) do {						\
	if (cond) {							\
		printf("  PASS %s\n", name);				\
	} else {							\
		printf("  FAIL %s (line %d)\n", name, __LINE__);	\
		fails++;						\
	}								\
} while (0)

/* 旧 lib phase-0 实现 oracle (v0.29.0 切换前的 buf_is_sentinel) */
static int old_buf_is_sentinel(const void *data, size_t len)
{
	size_t off;

	if (len < 4) {
		static const unsigned char pfx[4] = {0xef, 0xbe, 0xad, 0xde};

		return len >= 1 && memcmp(data, pfx, len) == 0;
	}
	for (off = 0; off + 4 <= len; off += SYMRDMA_TLP_CHUNK_SIZE) {
		const uint32_t *p = (const uint32_t *)((const char *)data + off);

		if (*p == SYMRDMA_SENTINEL_MAGIC)
			return 1;
	}
	return 0;
}

/* 在 buf 的 [off, off+len) 写入远端 [base+off, base+off+len) 的哨兵
 * 字节序列: pat[(addr+k)&3] (哨兵页按 u32 0xdeadbeef 填充的内存序) */
static void fill_sentinel(unsigned char *buf, size_t off, size_t len,
			  uint64_t base)
{
	static const unsigned char pat[4] = {0xef, 0xbe, 0xad, 0xde};
	size_t k;

	for (k = 0; k < len; k++)
		buf[off + k] = pat[(base + off + k) & 3];
}

/* 确定性 PRNG (xorshift64) */
static uint64_t rng_state = 0x20260917ULL;
static uint64_t rng(void)
{
	rng_state ^= rng_state << 13;
	rng_state ^= rng_state >> 7;
	rng_state ^= rng_state << 17;
	return rng_state;
}

/* ---- T1 相位期望值 ---- */
static void t1_expect(void)
{
	CHECK(sentinel_expect(0x1000) == 0xdeadbeefu, "T1 相位0 = 0xdeadbeef");
	CHECK(sentinel_expect(0x1001) == 0xefdeadbeu, "T1 相位1 = 0xefdeadbe");
	CHECK(sentinel_expect(0x1002) == 0xbeefdeadu, "T1 相位2 = 0xbeefdead");
	CHECK(sentinel_expect(0x1003) == 0xadbeefdeu, "T1 相位3 = 0xadbeefde");
	CHECK(sentinel_expect(3585) == 0xefdeadbeu,
	      "T1 读偏移 3585 (bug 10 实测场景)");
}

/* ---- T2 非对齐回填检测 (v0.22.0 bug 10 场景) ----
 * 读 remote [3585, 3585+2048) 跨页 0/1, 页 1 缺失: DMA 回填 [0,511)
 * 真实数据 + [511,2048) 哨兵 (缺失段自绝对页边界 4096 起)。
 * 旧 phase-0: chunk 512 处 u32 = 0xefdeadbe ≠ MAGIC → 漏检;
 * 相位感知: expect(3585+512=4097) = 0xefdeadbe → 命中。 */
static void t2_unaligned(void)
{
	unsigned char buf[2048];
	uint64_t base = 3585;

	memset(buf, 0x11, sizeof(buf));
	fill_sentinel(buf, 511, sizeof(buf) - 511, base);

	CHECK(old_buf_is_sentinel(buf, sizeof(buf)) == 0,
	      "T2 旧 phase-0 实现漏检 (缺陷复现)");
	CHECK(sentinel_is_hit(buf, sizeof(buf), base) == 1,
	      "T2 相位感知命中");
	CHECK(sentinel_first_page(buf, sizeof(buf), base) == 4096,
	      "T2 首缺失页 = 绝对页边界 4096 (bug 2/4)");
}

/* ---- T3 页对齐等价性 (随机缓冲, 页对齐 base) ---- */
static void t3_equiv(void)
{
	unsigned char buf[8192];
	int i, hits_old = 0, hits_new = 0;

	for (i = 0; i < 3000; i++) {
		size_t len = rng() % 8200;
		uint64_t base = (rng() % 64) * SYMRDMA_PAGE_SIZE;
		int hit_old, hit_new;

		if (i % 2 == 0) {
			/* 1/2: 注入页对齐哨兵段 — chunk 起点限定在 len 内
			 * (保证命中样本覆盖; 随机长度截断到缓冲尾) */
			size_t off, slen, avail;

			if (len < 512)
				len = 512 + rng() % 512;
			off = (rng() % (len / SYMRDMA_TLP_CHUNK_SIZE)) *
			      SYMRDMA_TLP_CHUNK_SIZE;
			avail = sizeof(buf) - off;
			slen = 1 + rng() % 1024;
			memset(buf, (int)(rng() | 1), sizeof(buf));
			fill_sentinel(buf, off,
				      slen < avail ? slen : avail, base);
		} else {
			/* 其余: 随机数据 (含偶发魔数巧合 — 双方判定一致) */
			size_t k;

			for (k = 0; k < sizeof(buf); k++)
				buf[k] = (unsigned char)rng();
		}
		hit_old = old_buf_is_sentinel(buf, len);
		hit_new = sentinel_is_hit(buf, len, base);
		if (hit_old != hit_new) {
			printf("  FAIL T3 等价性违背 i=%d len=%zu base=%llu "
			       "(old=%d new=%d)\n", i, len,
			       (unsigned long long)base, hit_old, hit_new);
			fails++;
			return;
		}
		hits_old += hit_old;
		hits_new += hit_new;
	}
	CHECK(hits_old == hits_new && hits_old > 1000,
	      "T3 等价性 3000 组 (含哨兵命中样本)");
}

/* ---- T4 首缺失页定位 ---- */
static void t4_first_page(void)
{
	unsigned char buf[3 * SYMRDMA_PAGE_SIZE];
	uint64_t base = SYMRDMA_PAGE_SIZE;   /* 读起点 = 页 1 边界 */

	memset(buf, 0x22, sizeof(buf));
	/* 无哨兵 → 兜底 base */
	CHECK(sentinel_first_page(buf, sizeof(buf), base) == base,
	      "T4 无哨兵 → base");
	/* 页 2 缺失: 哨兵自绝对地址 8192 (缓冲偏移 4096) 起 */
	fill_sentinel(buf, SYMRDMA_PAGE_SIZE, SYMRDMA_PAGE_SIZE, base);
	CHECK(sentinel_first_page(buf, sizeof(buf), base) == 2 * SYMRDMA_PAGE_SIZE,
	      "T4 哨兵 chunk → 缺失页绝对页起点 (非 chunk 起点)");
	/* len<4 无 chunk 检查 → 兜底 base (同原 npr_sentinel_loc) */
	CHECK(sentinel_first_page(buf, 3, base) == base, "T4 len<4 → base");
}

/* ---- T5 全量修复扫描 (页去重/升序/失败即停) ---- */
struct t5_log {
	unsigned long pages[16];
	int n;
	int fail_on;   /* 第 fail_on 次调用失败 (-1 = 永不) */
};

static int t5_repair_cb(void *ud, unsigned long pg)
{
	struct t5_log *l = ud;

	l->pages[l->n++] = pg;
	if (l->fail_on > 0 && l->n == l->fail_on)
		return -1;
	return 0;
}

static void t5_repair_all(void)
{
	unsigned char buf[3 * SYMRDMA_PAGE_SIZE];
	uint64_t base = 0, region = 0;
	struct t5_log l;
	int rc;

	/* 页 0 与页 2 各注入一段哨兵 (页 1 干净); 页 0 内多个 chunk
	 * 命中 → 去重为一页 */
	memset(buf, 0x33, sizeof(buf));
	fill_sentinel(buf, 0, 512, base);
	fill_sentinel(buf, 2 * SYMRDMA_PAGE_SIZE + 256, 512, base);
	memset(&l, 0, sizeof(l));
	rc = sentinel_repair_all(buf, sizeof(buf), base, region,
				 t5_repair_cb, &l);
	CHECK(rc == 2, "T5 修复页数 = 2");
	CHECK(l.n == 2 && l.pages[0] == 0 && l.pages[1] == 2,
	      "T5 页去重 + 升序 [0, 2]");

	/* 失败即停: 首页修复失败 → -1, 后续页不再修复 */
	memset(&l, 0, sizeof(l));
	l.fail_on = 1;
	rc = sentinel_repair_all(buf, sizeof(buf), base, region,
				 t5_repair_cb, &l);
	CHECK(rc == -1 && l.n == 1, "T5 修复失败 → -1 即停");

	/* 无哨兵 → 0 */
	memset(buf, 0x44, sizeof(buf));
	memset(&l, 0, sizeof(l));
	rc = sentinel_repair_all(buf, sizeof(buf), base, region,
				 t5_repair_cb, &l);
	CHECK(rc == 0 && l.n == 0, "T5 无哨兵 → 0 (调用方误用形态)");

	/* region_base 非零: 页号相对导出基址 (引擎 exp_addr 形态 —
	 * base 落在导出区内: absolute 2*PAGE = region 页 1, 哨兵在
	 * base+256 → 页号 1) */
	memset(buf, 0x55, sizeof(buf));
	fill_sentinel(buf, 256, 256, 2 * SYMRDMA_PAGE_SIZE);
	memset(&l, 0, sizeof(l));
	rc = sentinel_repair_all(buf, SYMRDMA_PAGE_SIZE, 2 * SYMRDMA_PAGE_SIZE,
				 SYMRDMA_PAGE_SIZE, t5_repair_cb, &l);
	CHECK(rc == 1 && l.n == 1 && l.pages[0] == 1,
	      "T5 页号相对 region_base (exp_addr 形态)");
}

/* ---- T6 len<4 前缀 ( C2) ---- */
static void t6_prefix(void)
{
	const unsigned char hit0[3]  = {0xef, 0xbe, 0xad};
	const unsigned char miss0[3] = {0xef, 0xbe, 0x00};
	const unsigned char hit1[2]  = {0xbe, 0xad};   /* base=1: pat[1..2] */

	CHECK(sentinel_is_hit(hit0, 3, 0) == 1, "T6 相位0 前缀命中");
	CHECK(sentinel_is_hit(miss0, 3, 0) == 0, "T6 相位0 前缀不命中");
	CHECK(old_buf_is_sentinel(hit0, 3) == 1 &&
	      old_buf_is_sentinel(miss0, 3) == 0,
	      "T6 相位0 与旧 pfx memcmp 等价");
	/* base=1 (非对齐): 期望序列 pat[1..] = {be, ad}; 旧 phase-0
	 * 恒按 {ef, be,...} → 漏检 */
	CHECK(sentinel_is_hit(hit1, 2, 1) == 1, "T6 相位1 前缀命中");
	CHECK(old_buf_is_sentinel(hit1, 2) == 0,
	      "T6 旧实现相位1 漏检 (相位感知的差异面)");
	CHECK(sentinel_is_hit(hit1, 0, 1) == 0, "T6 len=0 → 0");
}

/* ---- T7 版本表页数公式 (R7) ---- */
static void t7_vt_pages(void)
{
	CHECK(symrdma_vt_pages(0) == 0, "T7 0 页 → 0");
	CHECK(symrdma_vt_pages(1) == 1, "T7 1 页 → 1");
	CHECK(symrdma_vt_pages(1024) == 1, "T7 1024 页 → 1 (边界)");
	CHECK(symrdma_vt_pages(1025) == 2, "T7 1025 页 → 2");
	CHECK(symrdma_vt_pages(2048) == 2, "T7 2048 页 → 2 (边界)");
	CHECK(symrdma_vt_pages(2049) == 3, "T7 2049 页 → 3");
	CHECK(symrdma_vt_pages(128 * 1024) == 128,
	      "T7 131072 数据页 (512MB) → 128 版本表页");
	CHECK(SYMRDMA_VERS_PER_PAGE == 1024UL, "T7 每页 1024 版本");
}

int main(void)
{
	printf("=== 哨兵扫描原语相位单测 (sir/sentinel.h, R2 v0.29.0) ===\n");
	t1_expect();
	t2_unaligned();
	t3_equiv();
	t4_first_page();
	t5_repair_all();
	t6_prefix();
	t7_vt_pages();
	if (fails) {
		printf("=== 失败: %d 项 ===\n", fails);
		return 1;
	}
	printf("=== 全部通过 (T1-T7) ===\n");
	return 0;
}
