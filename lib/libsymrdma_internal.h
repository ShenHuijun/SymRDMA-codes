/* SPDX-License-Identifier: GPL-2.0 */
/*
 * libsymrdma_internal.h — libsymrdma 内部共享声明 (模块化拆分)
 *
 * 拆分结构 (原单文件 libsymrdma.c 两职责):
 *   libsymrdma.c         — 本地 MR: 注册/注销/Version MR 绑定 + 本地乐观
 *                          读/写 (哨兵检测 + seqlock) + 批量写/预检
 *   libsymrdma_remote.c  — 远端 MR (透明 API 远端形态): SIR 自动修复 +
 *                          远端版本直读 + 远端乐观读/写
 *   libsymrdma_internal.h — 共享原语 (本文件)
 */
#ifndef LIBSYMRDMA_INTERNAL_H
#define LIBSYMRDMA_INTERNAL_H

#include <stdint.h>
#include <stddef.h>
#include "libsymrdma.h"

/* 内部符号 — 静态库内跨编译单元, 不进最终链接符号表导出面 */
#if defined(__GNUC__)
#define SYMRDMA_INTERNAL __attribute__((visibility("hidden")))
#else
#define SYMRDMA_INTERNAL
#endif

/* ---- 哨兵检测 (libsymrdma.c 定义, 两路径共用) ----
 * 256B TLP chunk 粒度 (论文 §3.1.1); len<4 按魔数前缀逐字节比对。
 * R2: base = data[0] 对应的远端地址 — 相位感知扫描
 * (sir/sentinel.h); lib 路径 base 恒页对齐 (read_iova/导出基址 +
 * 页对齐偏移) ⇒ 相位 0, 与旧无 base 签名字节级等价 (隐含前提转
 * 显式, test_sentinel_phase 单测固化)。 */
SYMRDMA_INTERNAL int buf_is_sentinel(const void *data, size_t len,
				     uint64_t base);

/* ----  flush-before-unmap 屏障 (libsymrdma.c 定义) ----
 * 本地缓冲 DMA 在飞 pin (粘性缓存, 论文 §3.2 临时 pin 语义):
 * local_span = 本地接收/发送缓冲 (_p 变体的 local_mr)。
 * 返回 0 = 已覆盖; -1 = 不可用 (降级)。 */
SYMRDMA_INTERNAL int symrdma_pin_local_span(struct symrdma_ctx *ctx,
					    struct symrdma_mr *local_mr,
					    const void *local, size_t len);

/* ---- 单次 RDMA Read (signaled 控制, 论文 §3.1.1 批量用) ----
 * signaled=0 时 post 后立即返回 (不产生 CQE, 由调用方批量收尾)。 */
SYMRDMA_INTERNAL int rdma_read_once_flags(struct ibv_qp *qp, struct ibv_cq *cq,
					  void *local, uint32_t lkey,
					  uintptr_t remote_addr, uint32_t rkey,
					  size_t len, int signaled);
SYMRDMA_INTERNAL int rdma_read_once(struct ibv_qp *qp, struct ibv_cq *cq,
				    void *local, uint32_t lkey,
				    uintptr_t remote_addr, uint32_t rkey,
				    size_t len);

/* ---- 远端 MR 路径 (libsymrdma_remote.c 定义; mr->remote=1 分派) ---- */

struct symrdma_ctx;
struct symrdma_mr;

SYMRDMA_INTERNAL int symrdma_read_remote(struct symrdma_ctx *ctx,
					 struct ibv_qp *qp, struct ibv_cq *cq,
					 struct symrdma_mr *mr,
					 unsigned long page_idx, size_t len,
					 void *local, uint32_t lkey);
SYMRDMA_INTERNAL int symrdma_write_remote(struct symrdma_ctx *ctx,
					  struct ibv_qp *qp, struct ibv_cq *cq,
					  struct symrdma_mr *mr,
					  unsigned long page_idx, size_t len,
					  const void *local, uint32_t lkey);

#endif /* LIBSYMRDMA_INTERNAL_H */
