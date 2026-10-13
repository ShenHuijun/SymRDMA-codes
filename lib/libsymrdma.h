/* SPDX-License-Identifier: GPL-2.0 */
/*
 * libsymrdma.h — SymRDMA 用户态库 (P1: Sentinel 自动检测 + Remote Seqlock)
 *
 * 论文 §3.1 乐观 one-sided 读:
 *   len ≤ 4KB: RDMA Read → 哨兵检测 → 命中则 REPAIR → 重读
 *   len > 4KB: seqlock — 读前后各取一次版本号, 前后一致且为奇数才接受,
 *              否则 (换出竞态) REPAIR → 重读
 *
 * 版本号语义 (论文 §3.1.2): 奇数=驻留, 偶数=缺失。
 *
 * 注: 哨兵检测当前检查返回数据首 4 字节 (论文为每 256B TLP chunk 检查,
 *     简化实现)。
 */
#ifndef LIBSYMRDMA_H
#define LIBSYMRDMA_H

#include <stdint.h>
#include <stddef.h>
#include <sys/mman.h>
#include <infiniband/verbs.h>

#define SYMRDMA_SENTINEL_MAGIC     0xdeadbeef
/* 每 256B TLP chunk 检查哨兵 (论文 §3.1.1) */
#define SYMRDMA_TLP_CHUNK_SIZE     256

/* SymRDMA MR 标记位 (P4): ibv_reg_mr 的 access_flags 自定义位
 * (uverbs optional 范围 20-29, bit 21 空闲)。libnprdma/libsymrdma 注册
 * SymRDMA MR 时 OR 此位 → mlx5 内核据此走 identity MTT 分支;
 * 普通应用不带位 → 原版路径 (论文 "unaffected")。 */
#define SYMRDMA_ACCESS_IDENTITY   (1 << 21)
/* 显式写区域标记 (OFED identity_womr 判据改为本位, 旧
 * "无 REMOTE_READ" 启发式误伤 perftest 的 LOCAL_WRITE-only 源 MR) */
#define SYMRDMA_ACCESS_WREG       (1 << 22)
#define SYMRDMA_PAGE_SIZE          4096
/* ≤4KB 用哨兵检测, >4KB 用 seqlock (论文 §3.1.2 阈值策略) */
#define SYMRDMA_SENTINEL_THRESHOLD 4096
#define SYMRDMA_MAX_RETRIES        3

/* ---- SymRDMA ioctl (与 kernel/symrdma.h 保持同步) ---- */
#define SYMRDMA_IOC_MAGIC 'S'

struct symrdma_ioc_reg_mr {
	unsigned long long va_start, len;
	int mr_id;
};
struct symrdma_ioc_get_iova {
	int mr_id;
	unsigned long page_idx;
	unsigned long long read_iova, write_iova;
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
/* 版本表绑定用户 pinned 页 (论文 §3.1.2 Version MR 远端直读) */
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

#define SYMRDMA_IOC_REG_MR      _IOWR(SYMRDMA_IOC_MAGIC, 1, struct symrdma_ioc_reg_mr)
#define SYMRDMA_IOC_DEREG_MR    _IOW(SYMRDMA_IOC_MAGIC,  2, int)
#define SYMRDMA_IOC_GET_IOVA    _IOWR(SYMRDMA_IOC_MAGIC, 4, struct symrdma_ioc_get_iova)
#define SYMRDMA_IOC_REPAIR      _IOWR(SYMRDMA_IOC_MAGIC,  6, struct symrdma_ioc_repair)
#define SYMRDMA_IOC_GET_VERSION _IOWR(SYMRDMA_IOC_MAGIC,  7, struct symrdma_ioc_get_version)
#define SYMRDMA_IOC_SET_VERSION_PAGE _IOW(SYMRDMA_IOC_MAGIC, 8, struct symrdma_ioc_set_version_page)
/* 在飞 pin 屏障 (cmd 9/10, 与 kernel/symrdma.h 同步) */
#define SYMRDMA_IOC_PIN_PAGES   _IOWR(SYMRDMA_IOC_MAGIC, 9, struct symrdma_ioc_pin)
#define SYMRDMA_IOC_UNPIN_PAGES _IOWR(SYMRDMA_IOC_MAGIC, 10, struct symrdma_ioc_pin)

/* 在飞 pin 页预算 (与内核 SYMRDMA_PIN_BUDGET_PAGES 同步; 超预算 PIN
 * 返回 -ENOSPC → 库全量 unpin 后重试) */
#define SYMRDMA_PIN_BUDGET_PAGES  8192

/* ---- 库对象 ---- */

struct symrdma_ctx {
	int fd;             /* /dev/symrdma */
};

struct symrdma_mr {
	int      mr_id;     /* ioctl MR id */
	uint64_t read_iova; /* = 用户 VA (恒等映射, MTT identity 兼容) */
	uint64_t write_iova;
	void    *buf;
	size_t   len;
	struct ibv_mr *ibv_mr; /* 标准 verbs MR (identity_mtt 下 MTT 条目 = VA) */

	/* Version MR (论文 §3.1.2) — 版本表用户 pinned 页,
	 * 内核经 kmap_atomic 写入, 用户侧注册为 MR (REMOTE_READ) →
	 * 远端 RDMA 直读 (替代 CPU ioctl GET_VERSION)。 */
	void           *version_buf;  /* 版本表用户页 VA (4B/页版本号) */
	struct ibv_mr  *version_mr;   /* Version MR (rkey 供远端直读) */
	int             version_buf_mr_id;  /* 版本表页自身 SymRDMA mr_id */

	/* 远端 MR 视图 (symrdma_mr_import_remote) — MR 属对端
	 * 进程 (owner), 本进程无 ioctl/版本表. 修复经 SIR 通道请求 owner
	 * 在其进程内 ioctl REPAIR; 版本号经数据 QP 远端 RDMA 直读 owner
	 * 的 Version MR (4B/页). 其余字段 (mr_id/read_iova/...) 未用. */
	int              remote;       /* 1 = 远端视图 */
	uint32_t         rkey;         /* 对端数据 MR rkey (REMOTE_READ) */
	uint32_t         wkey;         /* 对端写 MR rkey (REMOTE_WRITE) */
	uint64_t         v_addr;       /* 对端版本表 VA (4B/页; 0=无) */
	uint32_t         v_rkey;       /* 对端 Version MR rkey (0=无) */
	struct symrdma_mr *scratch;    /* 本端 scratch 页 (版本读目标) */
};

/* 写区域 MR (P1.5/): REMOTE_WRITE 无 REMOTE_READ 的 ibv MR。
 * OFED 补丁 (identity_mtt_write_offset) 将其 MTT 条目填 VA+32GB,
 * 使 RDMA Write 经 IOMMU 命中 write_iova — 驻留→真实PA, 缺失→黑洞页。 */
struct symrdma_mr_write {
	struct ibv_mr *ibv_mr; /* write-only MR (rkey 供 RDMA Write 远端) */
};

/* 打开/关闭 /dev/symrdma; 返回 0 成功, <0 失败 */
int symrdma_open(struct symrdma_ctx *ctx);
void symrdma_close(struct symrdma_ctx *ctx);

/* 导入远端 MR 视图 (透明 API 的远端形态, 论文 §3.1/§3.2).
 * 调用方从自身连接代码取得对端 MR 描述 (rkey/wkey/addr/len 及可选的
 * Version MR v_rkey/v_addr) 后, 以同一 struct symrdma_mr 传给
 * symrdma_read/symrdma_write/... — 读/写命中哨兵/版本翻转时自动经
 * SIR 通道请求对端 owner 修复 (env SYMRDMA_PEER 会合键, 通道内部
 * 自动建立), 随后重放. 返回 0 成功; <0 失败.
 *
 * 内部建立: 本进程侧需 SIR 通道就绪 — 库按 env SYMRDMA_PEER 惰性
 * sir_init (pd->context), 首次修复请求时自动建立控制连接; owner
 * 侧需已导出其 MR (libnprdma 自动导出 / libsymrdma 调用方显式
 * sir_export_add, 见 sir/sir.h). */
int symrdma_mr_import_remote(struct symrdma_ctx *ctx, struct ibv_pd *pd,
			     struct symrdma_mr *mr,
			     uint32_t rkey, uint32_t wkey,
			     uint64_t addr, size_t len,
			     uint32_t v_rkey, uint64_t v_addr);

/* 注册: ioctl REG_MR + ibv_reg_mr (双注册, 生产形态由 P3 拦截替换) */
int symrdma_mr_register(struct symrdma_ctx *ctx, struct ibv_pd *pd,
			void *buf, size_t len, struct symrdma_mr *mr);
int symrdma_mr_deregister(struct symrdma_ctx *ctx, struct symrdma_mr *mr);

/* 绑定 Version MR (论文 §3.1.2) — 版本表用户 pinned 页 +
 * SET_VERSION_PAGE + REMOTE_READ MR; 供手动注册 (L4) 的调用方复用 */
int symrdma_mr_bind_version(struct symrdma_ctx *ctx, struct ibv_pd *pd,
			    struct symrdma_mr *mr);

/* 修复单页 (ioctl REPAIR): 重新解析 VA 并重映射 IOMMU.
 * 仅限本进程 MR (mr->remote=0); 远端 MR 修复由 symrdma_read/write
 * 内部自动经 SIR 通道完成. */
int symrdma_repair_page(struct symrdma_ctx *ctx, struct symrdma_mr *mr,
			unsigned long page_idx);

/* 读取单页版本号 (绑定了 Version MR 时本地直读版本表,
 * 零 ioctl — 论文 §3.1.2 "8 bytes per page" 开销; 否则回退 ioctl) */
int symrdma_get_version(struct symrdma_ctx *ctx, struct symrdma_mr *mr,
			unsigned long page_idx, uint32_t *version);

/* Version MR rkey (论文 §3.1.2: 远端 one-sided RDMA 直读版本表);
 * 未绑定 (版本表 > 1 页) 返回 0 */
static inline uint32_t symrdma_version_rkey(const struct symrdma_mr *mr)
{
	return mr->version_mr ? mr->version_mr->rkey : 0;
}

/*
 * 乐观 one-sided 读 (论文 §3.1):
 *   ≤ 4KB: RDMA Read → 哨兵检测 → 命中则 REPAIR → 按版本号判定:
 *          奇数 (驻留) → 重读一次接受 (假阳性按论文 §3.1.1 修复语义处理)
 *   > 4KB: seqlock — 覆盖范围逐页取 v1 (任一偶数 → 先修复) → RDMA Read
 *          → 逐页 v2 (任一页变化或偶数 → REPAIR → 重读; 论文 8B/page)
 * 最多重试 SYMRDMA_MAX_RETRIES 次。
 * 返回: 0 数据一致; <0 失败 (重试耗尽 errno=EAGAIN)
 */
int symrdma_read(struct symrdma_ctx *ctx, struct ibv_qp *qp,
		 struct ibv_cq *cq, struct symrdma_mr *mr,
		 unsigned long page_idx, size_t len,
		 void *local, uint32_t lkey);

/* symrdma_read/write + 本地页故障预检 (论文 §3.1.1) —
 * 发出前检查 local buffer 页版本 (本地直读, 10ns/页), 偶数 (缺失)
 * 先 REPAIR local → 避免 DMA 写被黑洞吸收的静默错误与 1 RTT 重试。
 * local_mr 可为 NULL (等价无预检版本)。 */
int symrdma_read_p(struct symrdma_ctx *ctx, struct ibv_qp *qp,
		   struct ibv_cq *cq, struct symrdma_mr *mr,
		   unsigned long page_idx, size_t len,
		   void *local, uint32_t lkey,
		   struct symrdma_mr *local_mr);

/* 注册/注销写区域 MR (REMOTE_WRITE 无 REMOTE_READ → MTT=VA+偏移) */
int symrdma_write_mr_register(struct ibv_pd *pd, void *buf, size_t len,
			      struct symrdma_mr_write *wmr);
void symrdma_write_mr_deregister(struct symrdma_mr_write *wmr);

/*
 * one-sided RDMA Write + 验证 (论文 §3.1.1 图 5b/5c/():
 *   len ≤ 4KB: 写后读回比对 — 读到哨兵 (黑洞吸收) → REPAIR → 重写重读
 *   len > 4KB: seqlock — 写前逐页版本 (偶数 → REPAIR)、写后版本比对
 *              (变化/偶数 → REPAIR → 重写，≤3 次)
 * remote = mr->read_iova + page_idx*PAGE (写区域 MTT 索引),
 * 数据来自 local (lkey, len 字节)。
 * 驻留 → 写真实 PA; 缺失 (换出) → 黑洞吸收 → 检测 → 修复 → 落地。
 * 返回: 0 成功; <0 失败 (重试耗尽 errno=EAGAIN)
 */
int symrdma_write(struct symrdma_ctx *ctx, struct ibv_qp *qp,
		  struct ibv_cq *cq, struct symrdma_mr *mr,
		  struct symrdma_mr_write *wmr,
		  unsigned long page_idx, size_t len,
		  const void *local, uint32_t lkey);

/* symrdma_write + 本地页故障预检 (写源页, 论文 §3.1.1) */
int symrdma_write_p(struct symrdma_ctx *ctx, struct ibv_qp *qp,
		    struct ibv_cq *cq, struct symrdma_mr *mr,
		    struct symrdma_mr_write *wmr,
		    unsigned long page_idx, size_t len,
		    const void *local, uint32_t lkey,
		    struct symrdma_mr *local_mr);

/* 裸写 (无验证) — 供底层机制测试 (黑洞吸收) 与内部路径复用 */
int symrdma_write_raw(struct ibv_qp *qp, struct ibv_cq *cq,
		      struct symrdma_mr *mr, struct symrdma_mr_write *wmr,
		      unsigned long page_idx, size_t len,
		      const void *local, uint32_t lkey);

/* 批量 one-sided Write (论文 §3.1.1 批量 unsignaled Write) —
 * 前 N-1 条 Write/Read 用 unsignaled WR, 最后 1 条 signaled —
 * 摊销 PCIe Write→Read flush (论文 1.5µs/次)。
 *
 * local:  npages*len 连续写源 (已映射)
 * verify: npages*len 已映射 buffer (辅助 Read 读回目标, 不能覆盖源)
 * 返回: 0 全部落地; <0 失败
 */
int symrdma_write_batch(struct symrdma_ctx *ctx, struct ibv_qp *qp,
			struct ibv_cq *cq, struct symrdma_mr *mr,
			struct symrdma_mr_write *wmr,
			const unsigned long *pages, int npages,
			size_t len, const void *local, uint32_t lkey,
			void *verify, uint32_t verify_lkey);

/* ---- §3.3 Relaxed Ordering  ---- */

/* order 提示位 (论文 §3.3: 复用 ibv_send_wr 保留位语义;
 * 本库以 flags 参数暴露, 供异步/批量路径使用) */
#define SYMRDMA_ORDER_BEFORE (1u << 28)  /* 本操作须在先前在飞行操作之后 */
#define SYMRDMA_ORDER_AFTER  (1u << 29)  /* 后续操作须等本操作完成 */

/* 在飞行地址区间 (论文 §3.3 重叠内存启发式): 记录最近提交但未确认
 * 完成的区间; 新请求与在飞行区间重叠时按依赖排队。当前同步 API
 * 每次操作返回即完成 (在飞行恒空), 语义自然满足 — 为异步/批量
 * 路径提供基础设施。 */
struct symrdma_inflight {
	uintptr_t start;
	uintptr_t end;
	int       active;
};

void symrdma_inflight_record(struct symrdma_inflight *inf,
			     uintptr_t start, uintptr_t end);
void symrdma_inflight_clear(struct symrdma_inflight *inf);
int  symrdma_inflight_overlap(const struct symrdma_inflight *inf,
			      uintptr_t start, uintptr_t end);

#endif /* LIBSYMRDMA_H */
