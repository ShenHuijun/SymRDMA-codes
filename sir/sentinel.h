/* SPDX-License-Identifier: GPL-2.0 */
/*
 * sentinel.h — 哨兵魔数扫描原语 (共享工具, 论文 §3.1.1)
 *
 * libsymrdma (lib/) 与 libnprdma (nprdma/) 此前各有一份 256B TLP chunk
 * 哨兵扫描: 引擎 3 份 (npr_buf_is_sentinel / npr_sentinel_loc /
 * npr_repair_all_missing, 另 npr_write_check 内联第 4 份) + lib 2 份
 * (buf_is_sentinel / libsymrdma_remote 大读逐页双层循环) — 本头文件
 * 收敛为单一实现 (REFACTOR R2), 仿 pinbm.h 惯例置于 sir/
 * (lib/nprdma 共享编译单元目录, 双方 Makefile 均 -I../sir 且 build.sh
 * 均同步)。仅头文件 (static inline), 不产生编译单元。
 *
 * 相位语义 (bug 10, 引擎侧既有 / lib 侧本次对齐): 哨兵页按
 * u32 0xdeadbeef 填充, 内存字节序列 [EF BE AD DE] 周期 4 — 非对齐读
 * (数据首地址 %4 ≠ 0) 回填的哨兵数据首 4B 是旋转相位 (读偏移 3585
 * 实测 [BE AD DE EF]), 固定相位 (phase-0) 比较漏检 → 哨兵魔数当真实
 * 数据交付。本原语一律按 chunk 的绝对远端地址旋转期望值。
 *
 * lib 侧切换的隐含前提转显式: lib 路径 base (read_iova + 页对齐
 * page_idx*PAGE_SIZE, 或远端导出基址 + 页对齐偏移) 恒页对齐 ⇒ 相位
 * 恒 0 — 切换前后字节级等价 (tests/programs/test_sentinel_phase 单测
 * 固化, 含随机缓冲旧实现 oracle 比对); base 非页对齐时本原语仍正确
 * (lib 旧实现静默漏检)。
 */
#ifndef SYMRDMA_SENTINEL_H
#define SYMRDMA_SENTINEL_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* 协议常量 (与 kernel/symrdma.h 同步) — #ifndef 守卫: libsymrdma.h /
 * nprdma_internal.h 的同名同值定义先到者胜, 双侧包含次序无关 */
#ifndef SYMRDMA_SENTINEL_MAGIC
#define SYMRDMA_SENTINEL_MAGIC 0xdeadbeef
#endif
#ifndef SYMRDMA_TLP_CHUNK_SIZE
#define SYMRDMA_TLP_CHUNK_SIZE 256
#endif
#ifndef SYMRDMA_PAGE_SIZE
#define SYMRDMA_PAGE_SIZE 4096
#endif

/* 哨兵魔数相位期望值 (bug 10): 按 chunk 绝对地址旋转 —
 * addr%4=0 → 0xdeadbeef; =1 → 0xefdeadbe (=2 → 0xbeefdead, =3 →
 * 0xadbeefde, 即 [BE AD DE EF] 等 u32 小端读回值)。 */
static inline uint32_t sentinel_expect(uint64_t addr)
{
	unsigned int sh = (addr & 3) * 8;

	return (SYMRDMA_SENTINEL_MAGIC >> sh) |
	       (sh ? (SYMRDMA_SENTINEL_MAGIC << (32 - sh)) : 0);
}

/* 下一个采样偏移迭代器 — 绝对 256B 边界网格 + 首页/
 * 尾页强制覆盖。原实现网格相对数据起点 (off += 256), base 非页对齐时
 * 跨页读的后续页可能完全不采样 (例: base%4096=4000, len=200 → 仅检
 * 查首 4B, 第二页 [4096,4200) 零采样 → 第二页换出哨兵化漏检, 混合数
 * 据被当作有效读接受)。
 * 规则:
 *   off == (size_t)-1 → 首个采样点 = 0 (覆盖头段, base 非对齐时)
 *   否则 base+off 已 256B 对齐 → +256; 未对齐 → 上取整到下一个绝对
 *   256B 边界 (256 | 4096, 故每个被跨越的页在网格内必有边界)
 *   网格尽头: 若尾页 (base+len-1 所在页) 尚无采样点且尾部 ≥4B,
 *   追加 len-4 (尾部强制采样)
 * 返回 [0, len-4] 内的采样偏移; 无更多采样点返回 (size_t)-1。 */
static inline size_t sentinel_next_sample(uint64_t base, size_t len,
					  size_t off)
{
	uint64_t abs, next;
	size_t last_off;

	if (len < 4)
		return (size_t)-1;
	last_off = len - 4;
	if (off == (size_t)-1)
		return 0;
	abs = base + off;
	next = (abs % SYMRDMA_TLP_CHUNK_SIZE == 0)
		       ? abs + SYMRDMA_TLP_CHUNK_SIZE
		       : (abs / SYMRDMA_TLP_CHUNK_SIZE + 1) *
			     SYMRDMA_TLP_CHUNK_SIZE;
	if (next > base + last_off) {
		/* 网格尽头 — 尾页强制采样: 最后采样点与尾页不同页时补
		 * len-4 (同页则尾页已有覆盖) */
		uint64_t tail = base + last_off;

		if (tail / SYMRDMA_PAGE_SIZE != abs / SYMRDMA_PAGE_SIZE &&
		    last_off > off)
			return last_off;
		return (size_t)-1;
	}
	return (size_t)(next - base);
}

/* 命中判定: [data, data+len) 是远端 [base, base+len) 的 DMA 镜像时,
 * 任一 256B chunk 的对齐 u32 为相位哨兵 → 1。
 * 论文 §3.1.1: "checking any aligned bytes within each 256 B chunk
 * suffices, checking per page is unsafe" — 读期间换出时前段 TLP 可能
 * 是真实数据, 首 4 字节检查会漏检。
 * len<4 前缀路径 (历史 C2): 哨兵页字节 = pat[(base+k)&3], 逐字节比对;
 * 假阳性 (数据恰同前缀) 走修复路径, 以版本奇偶兜底, 与 ≥4B 假阳性
 * 语义一致。base≡0 时与旧 lib memcmp(pfx, len) (pfx={ef,be,ad,de})
 * 字节级等价。 */
static inline int sentinel_is_hit(const void *data, size_t len, uint64_t base)
{
	size_t off;

	if (len < 4) {
		static const unsigned char pat[4] = {0xef, 0xbe, 0xad, 0xde};
		const unsigned char *b = data;
		size_t k;

		for (k = 0; k < len; k++)
			if (b[k] != pat[(base + k) & 3])
				return 0;
		return len >= 1;
	}
	/* 绝对 256B 边界网格 (原相对起点网格跨页漏检) */
	for (off = sentinel_next_sample(base, len, (size_t)-1);
	     off != (size_t)-1;
	     off = sentinel_next_sample(base, len, off)) {
		uint32_t v;

		memcpy(&v, (const char *)data + off, sizeof(v));
		if (v == sentinel_expect(base + off))
			return 1;
	}
	return 0;
}

/* 首个缺失页定位: 首个哨兵 chunk 所在页的绝对页起点 (远端地址空间);
 * 无哨兵 → base。
 * 缺失粒度是页而非 chunk (bug 2/4): 哨兵区域从缺失页起始
 * (绝对页边界) 开始, 而非首个哨兵 chunk (256B 相对步进)。调用方
 * (引擎 npr_sentinel_loc / npr_write_check) 据此算页号与 miss_off:
 * 头段 [base, first) 由驻留页 DMA 正确落地保留, 尾段 [first, …) 落在
 * 缺失页 → 内联修复只取回/重放尾段。 */
static inline uint64_t sentinel_first_page(const void *data, size_t len,
					   uint64_t base)
{
	size_t off;

	/* 绝对 256B 边界网格 (原相对起点网格跨页漏检) */
	for (off = sentinel_next_sample(base, len, (size_t)-1);
	     off != (size_t)-1;
	     off = sentinel_next_sample(base, len, off)) {
		uint32_t v;

		memcpy(&v, (const char *)data + off, sizeof(v));
		if (v == sentinel_expect(base + off))
			return (base + off) / SYMRDMA_PAGE_SIZE *
			       SYMRDMA_PAGE_SIZE;
	}
	return base;
}

/* 全量缺失页修复: 扫描全部 chunk, 对每个含哨兵 chunk 的页 (升序、
 * 页去重 — 256B chunk 不跨 4KB 页边界, 连续去重 = 页去重) 调
 * repair_page(ud, 页号); 页号 = (命中 chunk 绝对地址 − region_base)
 * / PAGE_SIZE, 即相对导出区基址的页号 (引擎 exp_addr 形态 / lib
 * 远端 mr->buf 形态同构)。
 * 返回修复页数 (>0); 无哨兵 → 0; 修复失败 → -1 (立即停止, 后续页
 * 不再修复)。
 *  (bug 6): 一次收敛替代「每次重放修一页」— 跨多缺失页的
 * 大读不再受 3 次尝试上限截断 (引擎 npr_repair_all_missing); lib
 * 远端大读无版本表路径旧逐页双层循环收敛至此 (R2)。 */
static inline int sentinel_repair_all(const void *data, size_t len,
				      uint64_t base, uint64_t region_base,
				      int (*repair_page)(void *ud,
							 unsigned long pg),
				      void *ud)
{
	unsigned long last_pg = (unsigned long)-1;
	size_t off;
	int n = 0;

	/* 绝对 256B 边界网格 (原相对起点网格跨页漏检) */
	for (off = sentinel_next_sample(base, len, (size_t)-1);
	     off != (size_t)-1;
	     off = sentinel_next_sample(base, len, off)) {
		uint32_t v;
		unsigned long pg;

		memcpy(&v, (const char *)data + off, sizeof(v));
		if (v != sentinel_expect(base + off))
			continue;
		pg = (unsigned long)((base + off - region_base) /
				     SYMRDMA_PAGE_SIZE);
		if (pg != last_pg) {
			if (repair_page(ud, pg))
				return -1;
			last_pg = pg;
			n++;
		}
	}
	return n;
}

#endif /* SYMRDMA_SENTINEL_H */
