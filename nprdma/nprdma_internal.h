/* SPDX-License-Identifier: GPL-2.0 */
/*
 * nprdma_internal.h — libnprdma 内部共享声明 (模块化拆分)
 *
 * 拆分结构 (原单文件 nprdma.c 三职责):
 *   nprdma.c         — verbs 拦截层: reg/dereg_mr 双注册、QP/CQ 3× 深度、
 *                      post_send/poll_cq 包装、本地预检
 *   nprdma_engine.c  — 透明引擎 (M2): 远端 MR one-sided 读/写验证 +
 *                      SIR 自动修复 + outq 保序 CQE 交付
 *   nprdma_internal.h — 两者的共享类型与接口 (本文件)
 *
 * 引擎导出 API (nprdma.c 调用):
 *   npr_ctx_get / npr_cq_get / npr_outq_pop / npr_resolve /
 *   npr_engine_submit / npr_write_rkey_rewrite / npr_atomic_submit
 */
#ifndef NPRDMA_INTERNAL_H
#define NPRDMA_INTERNAL_H

/* 内部符号 — 跨编译单元但不出 .so 动态符号表 (与应用符号空间隔离) */
#if defined(__GNUC__)
#define NPRDMA_INTERNAL __attribute__((visibility("hidden")))
#else
#define NPRDMA_INTERNAL
#endif

#include <stdint.h>
#include <stddef.h>
#include <pthread.h>
#include <infiniband/verbs.h>
#include "sir.h"

/* ---- 常量 (与 kernel/symrdma.h 同步) ----
 * R2: SYMRDMA_PAGE_SIZE / SYMRDMA_TLP_CHUNK_SIZE /
 * SYMRDMA_SENTINEL_MAGIC 由共享头提供 (#ifndef 守卫, 双侧同值);
 * 原 NPR_TLP_CHUNK_SIZE / NPR_SENTINEL_MAGIC 随哨兵扫描三循环合一
 * 删除 (sir/sentinel.h)。 */
#include "sentinel.h"

/* ---- SymRDMA ioctl (与 kernel/symrdma.h 同步) ---- */
#define SYMRDMA_IOC_MAGIC 'S'

struct symrdma_ioc_reg_mr {
	unsigned long long va_start, len;
	int mr_id;
};
struct symrdma_ioc_repair {
	int mr_id;
	unsigned long page_idx;
};
/* 版本表绑定用户 pinned 页 (论文 §3.1.2 Version MR) */
struct symrdma_ioc_set_version_page {
	int mr_id;
	unsigned long long version_va;
	unsigned long version_len;   /* 版本表页数 (0 = 自动) */
};

/* flush-before-unmap 屏障 (论文 §3.2 临时 pin 语义) —
 * 本地缓冲 DMA 在飞 pin。UNPIN len=0 释放该 MR 全部 pin。 */
struct symrdma_ioc_pin {
	int mr_id;
	unsigned long long va;
	unsigned long long len;
};

#define SYMRDMA_IOC_REG_MR    _IOWR(SYMRDMA_IOC_MAGIC, 1, struct symrdma_ioc_reg_mr)
#define SYMRDMA_IOC_DEREG_MR  _IOW(SYMRDMA_IOC_MAGIC,  2, int)
#define SYMRDMA_IOC_REPAIR    _IOWR(SYMRDMA_IOC_MAGIC,  6, struct symrdma_ioc_repair)
#define SYMRDMA_IOC_SET_VERSION_PAGE _IOW(SYMRDMA_IOC_MAGIC, 8, struct symrdma_ioc_set_version_page)
/* 在飞 pin 屏障 (cmd 9/10, 与 kernel/symrdma.h 同步) */
#define SYMRDMA_IOC_PIN_PAGES   _IOWR(SYMRDMA_IOC_MAGIC, 9, struct symrdma_ioc_pin)
#define SYMRDMA_IOC_UNPIN_PAGES _IOWR(SYMRDMA_IOC_MAGIC, 10, struct symrdma_ioc_pin)

/* 在飞 pin 页预算 (与内核 SYMRDMA_PIN_BUDGET_PAGES 同步) */
#define NPR_PIN_BUDGET_PAGES  8192

/* SymRDMA MR 标记位 (P4 / ) — 详见 nprdma.c 注释 */
#define SYMRDMA_ACCESS_IDENTITY (1 << 21)
#define SYMRDMA_ACCESS_WREG (1 << 22)

/* ---- nprdma.c (拦截层) 提供给引擎的内部接口 ---- */

/* /dev/symrdma fd (惰性打开; 调用方自行持锁约定见实现) */
extern NPRDMA_INTERNAL int sym_fd;

/* 真实 ibv_reg_mr_iova2 (reg 拦截解析后缓存; 引擎 scratch/版本 MR 直调) */
extern NPRDMA_INTERNAL struct ibv_mr *(*g_real_reg_mr_iova2)(struct ibv_pd *, void *, size_t,
					     uint64_t, unsigned int);

/* NPRDMA_DEBUG 环境开关 */
NPRDMA_INTERNAL int debug_on(void);

/* /dev/symrdma open (调用方须持 lock) */
NPRDMA_INTERNAL int symrdma_open_locked(void);

/* ---- 引擎数据结构 (两文件共享字段访问) ---- */

/* outq: 已解析待交付的 WC FIFO (保序) */
struct npr_wc_node {
	struct ibv_wc wc;
	struct npr_wc_node *next;
};

/* 跟踪 CQ (经 ibv_create_cq 拦截创建) */
struct npr_cq_entry {
	struct ibv_cq *cq;
	int drift;                       /* 混合流量/解析失败 → 透传退化 */
	struct npr_wc_node *outq_head, *outq_tail;
	struct npr_cq_entry *next;
};

/* 每跟踪 op 的写源快照上限 (signaled ≤4KB, 引擎头注释设计值;
 *  修复: 原数组误写为 256B (256*256/256), 257B–4KB 的远端写
 * 全部静默透传绕过验证 — 黑洞吸收即静默丢失, 与告警文案矛盾)。 */
#define NPR_SRC_MAX 4096

/* 活动 tracked op (每 QP 至多 1) */
struct npr_track {
	struct ibv_qp *qp;
	struct ibv_cq *send_cq;
	struct ibv_send_wr wr;           /* 拷贝 (sg_list 指向 sge[0]) */
	struct ibv_sge sge;
	int is_read;
	int forced_sig;                  /* 原 unsignaled → 强制 signaled */
	uint32_t repair_rkey;            /* SIR 修复请求 rkey (导出匹配键) */
	uint32_t read_rkey;              /* 回读用数据 rkey (0=无) */
	uint64_t exp_addr;               /* 导出区基址 (页号计算) */
	uint64_t remote_addr;
	uint32_t len;
	uint8_t  src[NPR_SRC_MAX];       /* 写源快照 (≤4KB 修正) */
};

/* per-QP 引擎状态 */
struct npr_qp_state {
	struct ibv_qp *qp;
	int has_active;
	struct npr_track active;
	struct npr_qp_state *next;
};

/* per-context: real 函数指针 + 跟踪 CQ 表 + QP 状态表 */
struct npr_ctx_entry {
	struct ibv_context *ctx;
	int (*real_post_send)(struct ibv_qp *qp, struct ibv_send_wr *wr,
			      struct ibv_send_wr **bad_wr);
	int (*real_poll_cq)(struct ibv_cq *cq, int num_entries,
			    struct ibv_wc *wc);
	struct npr_cq_entry *cqs;
	struct npr_qp_state *qps;
	/* 写路径 scratch (辅助回读目标; 惰性创建) */
	void *scratch_buf;
	struct ibv_mr *scratch_mr;
	int scratch_mr_id;
	int no_scratch;                  /* 创建失败 → 写验证禁用 */
	struct npr_ctx_entry *next;
};

/* per-context 引擎表头 (引擎内定义/维护; 拦截层只读遍历) */
extern NPRDMA_INTERNAL struct npr_ctx_entry *npr_ctx_list;

/* ---- 引擎导出 API ---- */

NPRDMA_INTERNAL struct npr_ctx_entry *npr_ctx_get(struct ibv_context *ctx);
NPRDMA_INTERNAL struct npr_cq_entry *npr_cq_get(struct npr_ctx_entry *ce, struct ibv_cq *cq);
NPRDMA_INTERNAL int npr_outq_pop(struct npr_cq_entry *ce, struct ibv_wc *wc);

/* 解析活动 op (验证 → 修复 → 重放)。返回 0 正常; -1 漂移。 */
NPRDMA_INTERNAL int npr_resolve(struct npr_ctx_entry *ce, struct npr_qp_state *qs);

/* 引擎提交: 远端 one-sided op。返回 1 = 已接管; 0 = 透传。
 * R6: exp_out/have_out 出参 (可 NULL) — 透传且已成功 lookup 时带回
 * 快照, 供 rkey 重写复用 (免二次全价 lookup)。 */
NPRDMA_INTERNAL int npr_engine_submit(struct npr_ctx_entry *ce, struct ibv_qp *qp,
		      struct ibv_send_wr *w,
		      struct sir_export *exp_out, int *have_out);

/* 未跟踪远端写提交前 rkey 重写 (write 区域)。
 * R6: exp_have 非空 = 复用 submit 已取快照; NULL = 自行 lookup。 */
NPRDMA_INTERNAL void npr_write_rkey_rewrite(const struct ibv_send_wr *w,
			    struct ibv_send_wr *one,
			    const struct sir_export *exp_have);

/* 远端原子 (SIR 双端 RPC)。返回 1 = 已处理; 0 = 透传; -1 = 拒绝。 */
NPRDMA_INTERNAL int npr_atomic_submit(struct npr_ctx_entry *ce, struct ibv_qp *qp,
		      struct ibv_send_wr *w);

/* 单次裸 pin (无缓存 — 引擎 scratch 等一次性场景; nprdma.c 定义,
 *  flush-before-unmap 屏障) */
NPRDMA_INTERNAL void npr_pin_once(int mr_id, uint64_t va, size_t len);

#endif /* NPRDMA_INTERNAL_H */
