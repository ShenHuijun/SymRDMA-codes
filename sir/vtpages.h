/* SPDX-License-Identifier: GPL-2.0 */
/*
 * vtpages.h — 版本表页数公式 (共享工具, 论文 §3.1.2 Version MR)
 *
 * (npages + 1023) / 1024 此前三份手写 (libsymrdma.c bind_version /
 * libsymrdma.c deregister vsize 重算 / nprdma.c reg 拦截) — 收敛于此
 * (REFACTOR R7)。1024 = 每页 1024 个 4B 版本 (4096B 页);
 * 内核侧同公式在 kernel/symrdma_version.c (用户态头不入内核, 保持
 * 独立)。仿 pinbm.h 惯例置于 sir/ 共享目录, 仅头文件。
 */
#ifndef SYMRDMA_VTPAGES_H
#define SYMRDMA_VTPAGES_H

#include <stddef.h>

/* 每页版本号数 (4B/版本 × 4096B 页; 与内核 symrdma.h "每页 1024" 同步) */
#ifndef SYMRDMA_VERS_PER_PAGE
#define SYMRDMA_VERS_PER_PAGE 1024UL
#endif

/* 版本表覆盖 npages 个数据页所需页数 (ceil 除法) */
static inline unsigned long symrdma_vt_pages(unsigned long npages)
{
	return (npages + SYMRDMA_VERS_PER_PAGE - 1) / SYMRDMA_VERS_PER_PAGE;
}

#endif /* SYMRDMA_VTPAGES_H */
