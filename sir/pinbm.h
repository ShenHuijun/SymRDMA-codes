/* SPDX-License-Identifier: GPL-2.0 */
/*
 * pinbm.h — 在飞 pin 粘性位图缓存 (共享工具, 论文 §3.2 临时 pin 语义)
 *
 * libsymrdma (lib/libsymrdma.c) 与 libnprdma (nprdma/nprdma.c) 各有一份
 * "pin 粘性缓存": 位图镜像内核 pin 状态 → 稳态零 syscall; 预算满
 * (-ENOSPC) → UNPIN(len=0) 全量释放后重试一次 (引入, 此前为
 * 两份近乎相同的实现 — 本头文件去重)。
 *
 * 放置于 sir/ 目录: 借用 sir/ 作为 lib/nprdma 共享编译单元目录的既有
 * 约定 (两边 Makefile 均 -I../sir 且 build.sh 均同步) — 本头
 * 文件是纯工具, 非 SIR 协议本体。
 *
 * 仅头文件 (static inline), 不产生编译单元; 调用方持有各自容器
 * (mr_entry / pin_cache_ent) 与锁, 本文件只负责位图原语与 PIN span
 * 循环 (含 ENOSPC 重试语义) — 修复 pin 策略时只需改这里。
 */
#ifndef SYMRDMA_PINBM_H
#define SYMRDMA_PINBM_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>

/* 位图容量增长起点 (页); 双方实现原值一致, 保持行为不变 */
#define PINBM_INIT_CAP 64UL

/* 粘性 pin 位图 (调用方容器内嵌; pinned 由 pinbm_set 维护) */
struct pinbm {
	unsigned long  *bm;      /* 已 pin 位图 (索引 = 页号) */
	unsigned long   cap;     /* 位图容量 (页) */
	unsigned long   pinned;  /* 已 pin 页数 */
};

/* 位图增长到覆盖页号 need (inclusive); 0 成功, -1 OOM。
 *  修复: memset 起点误用 unsigned long* 元素步进 (×8 字节) —
 * 实际写入起点 = cap 字节而非 cap/8 字节, 从非零 cap 扩容时越界写堆
 * (malloc 元数据损坏 → "malloc(): invalid size")。潜伏自 ,
 * 本地 pin 跨度 >64 页 (位图首次扩容) 才触发 — racebw 4MB 本地 MR
 * (1024 页) 首次踩中。改显式字节偏移。 */
static inline int pinbm_grow(struct pinbm *b, unsigned long need)
{
	unsigned long ncap = b->cap ? b->cap : PINBM_INIT_CAP;
	unsigned long *nbm;

	if (need < b->cap)
		return 0;
	while (ncap <= need)
		ncap *= 2;
	nbm = realloc(b->bm, ncap / 8);
	if (!nbm)
		return -1;
	memset((char *)nbm + b->cap / 8, 0, (ncap - b->cap) / 8);
	b->bm = nbm;
	b->cap = ncap;
	return 0;
}

static inline void pinbm_set(struct pinbm *b, unsigned long i)
{
	if (!(b->bm[i / 64] & (1UL << (i % 64)))) {
		b->bm[i / 64] |= (1UL << (i % 64));
		b->pinned++;
	}
}

/* 全量释放 (预算淘汰): UNPIN(len=0) + 清位图; up 由调用方按其 mr_id 填好 */
static inline void pinbm_drop_all(struct pinbm *b, int fd,
				  struct symrdma_ioc_pin *up)
{
	ioctl(fd, SYMRDMA_IOC_UNPIN_PAGES, up);
	if (b->bm)
		memset(b->bm, 0, b->cap / 8);
	b->pinned = 0;
}

/* pin 一个页区间 [i0, i1] (粘性): 对位图中未 pin 的连续子段逐段调
 * pin_one(ud, 起始页号, 页数) (调用方组 ioctl 参数 — va_base/mr_id 由
 * ud 上下文携带, 两边容器不同); drop_all(ud) 为 ENOSPC 全量释放。
 * 返回 0 = 已覆盖 (含缓存命中); -1 = pin 不可用 (调用方降级继续 —
 * 与无屏障行为等价, 不影响正确性, 仅保留既有竞态窗口)。
 * 调用方持自身锁 (两边缓存各自一把互斥锁, 语义不变)。 */
static inline int pinbm_pin_span(struct pinbm *b, unsigned long i0,
				 unsigned long i1,
				 int (*pin_one)(void *ud, unsigned long s,
						unsigned long n),
				 void (*drop_all)(void *ud), void *ud)
{
	unsigned long s;
	int retried = 0;

retry:
	for (s = i0; s <= i1; s++) {
		unsigned long t, i;

		if (b->bm[s / 64] & (1UL << (s % 64)))
			continue;
		for (t = s; t <= i1; t++)
			if (b->bm[t / 64] & (1UL << (t % 64)))
				break;
		if (pin_one(ud, s, t - s))
			goto out_err;
		for (i = s; i < t; i++)
			pinbm_set(b, i);
		s = t ? t - 1 : t;   /* 外层 s++ 跳到首个已 pin 位 */
	}
	return 0;

out_err:
	if (errno == ENOSPC && !retried) {
		retried = 1;
		drop_all(ud);
		goto retry;
	}
	return -1;
}

#endif /* SYMRDMA_PINBM_H */
