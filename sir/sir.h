/* SPDX-License-Identifier: GPL-2.0 */
/*
 * sir.h — SymRDMA 库内建 SIR 通道 (Server-Initiated Repair, 自动双向修复)
 *
 *  把论文 §3.2 的双向修复协议从 test 代码 (test_sir.c) 下沉为
 * 库内建通道, 供 libsymrdma (透明 API 形态) 与 libnprdma (LD_PRELOAD
 * 拦截形态) 共用:
 *
 *   角色对称: 每个进程同时是发起方 (requester) 与持有方 (owner/service)。
 *   双向:     读方向修复 (owner REPAIR 后 ≤1KB 内联回数据 / requester 重放读)
 *             写方向修复 (≤1KB 数据内联在请求, owner REPAIR+落地 / requester 重放写)
 *   自动建立: 控制 QP 由库内部建立 — 进程按 env SYMRDMA_PEER (或显式 key)
 *             经会合文件 (锁选举 a/b) 相互发现、对连、交换导出 MR 表。
 *
 * 修复数据面取舍 (v1): ≤SIR_INLINE_MAX(1KB) 经控制通道内联 (论文 §3.2
 * 小消息内联语义, 免重放 RTT); >1KB 走 owner ioctl REPAIR + requester
 * 重放乐观操作 (数据面语义等价于论文 RREP/WREP 反向 RDMA, 免反向推/拉
 * 对 scratch buffer 与客户端 rkey 的要求; 反向 RDMA 变体已在 L7 验证,
 * 留作协议选项待性能回归接线)。
 *
 * 控制通道 (每进程单例): 控制 RC QP + 整页控制 MR×2 + 每进程一条
 * 服务线程 (论文 §3.2 "one additional thread")。控制消息二进制
 * (magic/type/tag), tag 高位带本侧角色 → 双向并发请求可正确归属。
 *
 * 构建: libsymrdma.a 含 sir.o; libnprdma.so 直接编译本文件。
 */
#ifndef LIBSIR_H
#define LIBSIR_H

#include <stdint.h>
#include <stddef.h>
#include <infiniband/verbs.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- 常量 ---- */

/* 内联数据阈值 (论文 §3.2: ≤1KB 经控制通道内联) */
#define SIR_INLINE_MAX    1024
#define SIR_PAGE_SIZE     4096

/* 区间修复单请求最大页数 (; 防御损坏/恶意消息; 65536 页 = 256MB) */
#define SIR_RANGE_MAX     65536ULL

/* 控制消息 buffer 页粒度 (SymRDMA IOMMU 注册以页为粒度, 小 buffer 会
 * 静默注册失败 — 教训见注释) */
#define SIR_MSG_SIZE      4096

/* 会合目录 (env SYMRDMA_SIR_DIR 覆盖) */
#define SIR_DIR_DEFAULT   "/tmp/symrdma_sir_auto"

/* ---- 方向位 ---- */
#define SIR_F_READ        1
#define SIR_F_WRITE       2
/* 远端原子方向位 (论文 §3.4 双端 RPC; 与 READ/WRITE 位互斥)
 * CAS: data[0..7]=compare, data[8..15]=swap (len=16)
 * FAA: data[0..7]=addend (len=8) */
#define SIR_F_ATOMIC_CAS  4
#define SIR_F_ATOMIC_FAA  8

/* ---- 消息 ---- */
#define SIR_MAGIC         0x53595244u   /* "SYRD" */

enum sir_msg_type {
	SIR_MSG_KEYMAP      = 1,  /* owner → requester: 导出 MR 描述 */
	SIR_MSG_REPAIR      = 2,  /* requester → owner: 修复请求 (dir/off/len;
	                           *   WR 且 ≤INLINE: data 内联在请求) */
	SIR_MSG_REPAIR_OK   = 3,  /* owner → requester: 成功
	                           *   (RD 且 len≤INLINE: 数据内联在应答) */
	SIR_MSG_REPAIR_FAIL = 4,  /* owner → requester: 失败 */
	SIR_MSG_QUIT        = 5,
	/* 远端原子 (论文 §3.4) — addr=目标 VA (绝对),
	 * flags=CAS/FAA, data=操作数; 应答 data[0..7]=旧值 */
	SIR_MSG_ATOMIC      = 6,  /* requester → owner: 原子请求 */
	SIR_MSG_ATOMIC_OK   = 7,  /* owner → requester: 成功 (旧值内联) */
};

/* 头部固定 64B + 内联负载 (控制 buffer 4KB, 负载区 1KB) */
#define SIR_HEADER_SZ     64
#define SIR_PAYLOAD_OFF   SIR_HEADER_SZ

struct sir_msg {
	uint32_t magic;
	uint32_t type;
	uint32_t tag;        /* 请求 tag; 应答回带. bit31 = 本侧角色位 */
	uint32_t flags;      /* SIR_F_READ / SIR_F_WRITE */
	uint32_t rkey;       /* KEYMAP: data rkey (导出表主键) */
	uint32_t wkey;       /* KEYMAP: write MR rkey */
	uint64_t addr;       /* KEYMAP: 数据区 VA; ATOMIC: 目标 VA (绝对) */
	uint64_t mlen;       /* KEYMAP: 数据区长度 */
	uint32_t v_rkey;     /* KEYMAP: Version MR rkey (0=无) */
	uint32_t status;     /* REPAIR_OK=0 / FAIL=errno */
	uint64_t page_idx;   /* REPAIR: 页号 */
	uint32_t off;        /* REPAIR: 页内偏移 */
	uint32_t len;        /* REPAIR: 数据长度 (≤SIR_INLINE_MAX 且不跨页) */
	uint32_t mr_id;      /* KEYMAP: owner 侧 ioctl MR id (owner REPAIR 用) */
	uint8_t  data[SIR_INLINE_MAX];   /* REPAIR 内联负载 */
};

/* ---- 导出 MR 描述 (owner 侧) ---- */

struct sir_export {
	uint32_t data_rkey;    /* REMOTE_READ 数据 MR (主键) */
	uint32_t write_rkey;   /* 写 MR (REMOTE_WRITE, MTT=VA+32GB) */
	uint64_t addr;         /* 数据区 VA */
	uint64_t len;
	uint32_t v_rkey;       /* Version MR rkey (远端版本直读; 0=无) */
	uint64_t v_addr;       /* 版本表 VA (每页 4B, index=页号) */
	int      mr_id;        /* 本进程 /dev/symrdma ioctl MR id (owner REPAIR) */
	struct sir_export *next;
};

/* ---- API (进程级单例) ---- */

/* 初始化 SIR 通道 (进程单例, 可多次调用幂等):
 *   ctx/pd — 控制 QP 资源 (可 NULL: 仅查询导出/远端表, 不建通道)
 *   key    — 对端会合键; NULL 或空 → 取 env SYMRDMA_PEER; 仍空 → 禁用
 *   sym_fd — 本进程 /dev/symrdma fd (owner REPAIR 通道; <0 = 无,
 *            此时导出的 MR 无法被远端修复, 服务侧自动降级)
 * 返回 0 成功 (或通道不可用但库可继续); -1 参数错误。
 * 内部: 惰性建立 — 首调用仅注册本进程 (发布/服务线程推迟到首个导出或
 * 首个远端查找)。 */
int sir_init(struct ibv_context *ctx, struct ibv_pd *pd,
	     const char *key, int sym_fd);

/* owner: 导出 MR (数据 rkey 唯一); 0 成功 */
int  sir_export_add(const struct sir_export *e);
void sir_export_del(uint32_t data_rkey);
/* owner: 撤销 write_rkey 导出 (写区域 MR dereg 时同步清理 —
 * 已合并条目仅清 wkey 位; 独立 wkey 条目整条移除) */
void sir_export_del_wkey(uint32_t write_rkey);

/* requester: 按对端导出表匹配 (会合文件刷新 + 必要时机建通道)。
 *  语义改为锁内拷出快照 (out 为调用方栈/成员变量) — 旧形态
 * 返回指向内部 peers 链表的指针, 解锁后任何并发刷新 (其他线程的
 * lookup) 会 free 重建链表 → 使用者拿到悬空指针 (UAF)。 */
int  sir_remote_lookup(uint32_t data_rkey, struct sir_export *out);

/* 主动触发自动建连 (幂等; 对端未出现时后台重试) — 供库调用方
 * (如 import 远端 MR 时) 提前建连, 免首笔修复请求的建连延迟 */
int  sir_ensure_start(void);

/* requester: 阻塞式远端修复请求.
 *   dir  = SIR_F_READ / SIR_F_WRITE; off/len 页内偏移/长度;
 *          len≤SIR_INLINE_MAX 且 off+len ≤ SIR_PAGE_SIZE (不跨页).
 *   data — WR 方向: 入 (修复数据内联); RD 方向: 出 (内联回数据).
 *          非内联请求传 NULL, len=0.
 * 返回 0 成功 (RD 内联时 data 已填充); -1 失败 (errno 置位). */
int sir_remote_repair(uint32_t data_rkey, unsigned long page_idx, int dir,
		      uint32_t off, uint32_t len, void *data);

/* requester: 区间修复 (论文 §3.2 大消息全跨度修复): 一次控制
 * RTT 修复连续 npages 页 — owner 侧循环 ioctl REPAIR (无网络 RTT/页)。
 * 语义依据: 论文 §3.2 "target pins the corresponding remote buffer" —
 * 修复粒度为消息跨度而非单页; 消解逐页控制 RTT (~140µs/页) 对大消息
 * 故障吞吐的支配 (论文 Fig 12 大消息形态的关键)。
 * 约束: npages ≥ 1; off/len 仅 npages == 1 时有效 (内联数据仅单页语义);
 * 非内联调用传 NULL, len=0。
 * 返回 0 成功; -1 失败 (errno 置位). */
int sir_remote_repair_range(uint32_t data_rkey, unsigned long page_idx,
			    unsigned long npages, int dir,
			    uint32_t off, uint32_t len, void *data);

/* requester: 阻塞式远端原子 (论文 §3.4 双端 RPC).
 *   op   = SIR_F_ATOMIC_CAS (compare=compare, swap=swap_or_add) /
 *          SIR_F_ATOMIC_FAA (addend=swap_or_add).
 *   va   — owner 侧目标 VA (绝对地址, 8 字节对齐).
 *   old_out — 成功时返回旧值 (远端 CPU lock cmpxchg/xadd; 可 NULL).
 * 换出页由远端 CPU 经正常 MMU 缺页换入执行 (无部分执行风险);
 * 执行后 owner 侧 ioctl REPAIR 刷新 IOMMU 映射.
 * 返回 0 成功; -1 失败 (errno 置位). */
int sir_remote_atomic(uint32_t data_rkey, uint64_t va, int op,
		      uint64_t compare, uint64_t swap_or_add, uint64_t *old_out);

/* 优雅停止服务线程 (进程退出前可选) */
void sir_fini(void);

/* 状态 (调试/测试断言): 通道已建立? / 服务请求计数 */
int  sir_is_connected(void);
long sir_service_count(void);

#ifdef __cplusplus
}
#endif

#endif /* LIBSIR_H */
