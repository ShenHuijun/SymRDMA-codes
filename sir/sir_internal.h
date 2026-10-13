/* SPDX-License-Identifier: GPL-2.0 */
/*
 * sir_internal.h — SIR 通道内部共享声明 (模块化拆分)
 *
 * 拆分结构 (原单文件 sir/sir.c 四职责, 按论文 §3.2 的角色边界):
 *   sir.c          — 核心: 进程级状态/初始化/导出表管理 + 客户端
 *                    (requester: 远端修复/原子 RPC, 请求排队)
 *   sir_channel.c  — 通道建立: 会合文件 (角色选举/导出表发布/对端发现)
 *                    + 控制 QP (真实 verbs, 转发内联拦截) + RTS 对连
 *                    + 建连线程 (容忍对端晚到)
 *   sir_service.c  — owner 服务: 控制通道收发原语 (post/recv/send_raw)
 *                    + REPAIR/ATOMIC 请求处理 + 服务线程 (独占控制 CQ)
 *   sir_internal.h — 共享: 状态结构/请求结构/全局变量/跨单元原型
 *
 * 全局锁约定: g_mu 保护 S 的全部字段与请求队列; 服务线程/客户端
 * (requester)/建连线程 均经 g_mu 串行化 (建连线程的 channel 建立
 * 资源准备在锁外, 发布/复位在锁内 — 见 sir_ensure_channel 注释)。
 * 符号可见性: 内部符号 hidden, 不进 .so 动态符号表; sir.h 公开 API
 * (sir_init / sir_export 系列 / sir_remote 系列 / sir_fini) 保持导出。
 */
#ifndef SIR_INTERNAL_H
#define SIR_INTERNAL_H

#include <pthread.h>
#include <time.h>
#include <stdint.h>
#include <infiniband/verbs.h>
#include "sir.h"

#if defined(__GNUC__)
#define SIR_INTERNAL __attribute__((visibility("hidden")))
#else
#define SIR_INTERNAL
#endif

/* ---- ioctl (owner REPAIR; 与 kernel/symrdma.h 同步) ---- */
#define SYMRDMA_IOC_MAGIC 'S'
struct symrdma_ioc_reg_mr {
	unsigned long long va_start, len;
	int mr_id;
};
struct symrdma_ioc_repair {
	int mr_id;
	unsigned long page_idx;
};
/* 区间批量修复 (与 kernel/symrdma.h 同步): in mr_id/page_idx/
 * npages; out npages = 实际修复页数 (部分成功 < 入参)。 */
struct symrdma_ioc_repair_range {
	int mr_id;
	unsigned long page_idx;
	unsigned long npages;
};
/* P1-1 回归注入用 (与 kernel/symrdma.h 同步): REMAP 单页 —
 * mode 0=REAL, 1=SENTINEL, 2=BLACKHOLE。仅 sir_service.c 故障注入
 * (REPAIR 后重哨兵化) 触碰, 库正常路径不使用。 */
struct symrdma_ioc_remap {
	int mr_id;
	unsigned long page_idx;
	int mode;
};
#define SYMRDMA_IOC_REMAP    _IOW(SYMRDMA_IOC_MAGIC,  3, struct symrdma_ioc_remap)
#define SYMRDMA_IOC_REG_MR   _IOWR(SYMRDMA_IOC_MAGIC, 1, struct symrdma_ioc_reg_mr)
#define SYMRDMA_IOC_DEREG_MR _IOW(SYMRDMA_IOC_MAGIC,  2, int)
#define SYMRDMA_IOC_REPAIR   _IOWR(SYMRDMA_IOC_MAGIC,  6, struct symrdma_ioc_repair)
#define SYMRDMA_IOC_REPAIR_RANGE _IOWR(SYMRDMA_IOC_MAGIC, 11, struct symrdma_ioc_repair_range)

/* SymRDMA MR 标记位 (与 lib/libsymrdma.h 同值) */
#define SIR_ACCESS_IDENTITY (1 << 21)

#define SIR_CQ_DEPTH        32
#define SIR_ROLE_LOCK       ".lock"
#define SIR_CONNECT_TICKS   300     /* 10ms × 300 = 3s 对端等待上限 */
#define SIR_WAIT_MS         10

/* TCP 网络会合: 信息 blob 上限 (与文件形态行格式同源, 含 gid 行;
 * 每条 E 行 ~80B → 容量 ~50 条导出, 测试/引擎规模内) */
#define SIR_TCP_BLOB_MAX    4096
/* 导出表拉取节流: GET 短路窗口 (ms) — sir_remote_lookup 高频调用时免
 * 每 lookup 一次 TCP RTT; 对端导出变更的可见延迟上界即该值 (拉取式) */
#define SIR_TCP_PULL_TTL_MS 50

/* OFED 用 IBV_QP_MTU, rdma-core 用 IBV_QP_PATH_MTU (同 test_sir) */
#ifndef IBV_QP_MTU
#define IBV_QP_MTU IBV_QP_PATH_MTU
#endif

/* ---- requester 请求 (排队到服务线程代发) ---- */
struct sir_req {
	uint32_t rkey;
	unsigned long page_idx;
	unsigned long npages;  /* 区间修复 (论文 §3.2 大消息全跨度
				       * 修复): [page_idx, page_idx+npages); 1 = 单页 */
	uint64_t va;         /* ATOMIC: 目标 VA (绝对) */
	int dir;
	uint32_t off;
	uint32_t len;
	uint8_t  data[SIR_INLINE_MAX];
	uint32_t tag;
	int      done;
	int      ret;
	struct sir_msg reply;
	struct sir_req *next;
};

/* ---- 进程级状态 (单例; g_mu 保护全部字段) ---- */
struct sir_state {
	int      inited;
	int      enabled;
	int      connected;
	int      serving;
	int      no_range_ioctl;   /* 内核无 REPAIR_RANGE (旧模块
				    * ENOTTY) → sir_serve_repair 降级逐页
				    * REPAIR 循环; 缓存避免每请求重试 */
	struct ibv_context *ctx;
	struct ibv_pd *pd;
	char     key[128];
	char     role;
	char     path[512];
	int      sym_fd;

	/* TCP 网络会合 (env SYMRDMA_SIR_TCP; 未设置时全零/文件形态)
	 * use_tcp=1: 会合经 TCP 握手 (listen 端 role=a / connect 端 role=b,
	 * init 时已定 — sir_elect_role 粘性直接返回), 导出表经 GET 拉取
	 * (TTL 节流), 对端 qp/gid/up 均来自对端 blob。文件路径 (写/读 info
	 * 文件) 在 use_tcp 下不执行 — 单机 L12/L13 回归形态零改动。 */
	int      use_tcp;
	int      tcp_listen;      /* 1=listen:<port> (role a) / 0=connect */
	char     tcp_host[128];   /* connect 目标 (listen 模式为空) */
	int      tcp_port;
	int      sgid_index;      /* SYMRDMA_SIR_GID (控制 QP sgid, 默认 0) */
	int      tcp_fd;          /* 会合连接 (握手成功后发布; -1=无) */
	char     info_blob[SIR_TCP_BLOB_MAX];  /* 自身发布 blob (write_own_info 重建) */
	size_t   info_len;
	int64_t  last_pull_ms;    /* 上次导出表拉取 (CLOCK_MONOTONIC ms; TTL 节流) */
	/* 对端信息 (TCP 模式; 握手/拉取填充。文件模式的 peer_flags 走局部变量) */
	unsigned peer_qp;
	int      peer_up;
	uint8_t  peer_gid[16];    /* 对端控制 QP dgid (跨机 RoCEv2 必需) */
	int      peer_gid_valid;

	struct sir_export *exports;
	struct sir_export *peers;
	struct timespec    peer_mtime;   /* 对端导出表缓存 (mtime 感知) */

	/* 控制通道 */
	struct ibv_qp *ctl_qp;
	struct ibv_cq *ctl_cq;
	struct ibv_mr *in_mr, *out_mr;
	uint8_t *ctl_in, *ctl_out;
	int      in_id, out_id;
	int      have_recv;
	int      rts_done;         /* 自身控制 QP 已 RTS (文件 up 标志) */
	struct sir_msg saved;      /* 缓存一个 RECV 消息 (完成序竞态) */
	int      saved_valid;

	pthread_t thread;          /* 服务线程 */
	pthread_t conn;            /* 建连线程 (容忍对端晚到, 非阻塞) */
	int      conn_running;
	int      quit;

	uint32_t tag_hi;
	uint32_t pending_tag;
	struct sir_req *pending_req;    /* 已发出待应答的请求 (保留在队列中) */
	uint32_t next_tag;
	struct sir_req *req_head, *req_tail;

	long     served;
	long     requested;
};

/* ---- 全局单例与锁 (sir.c 定义) ---- */
extern SIR_INTERNAL struct sir_state *S;
extern SIR_INTERNAL pthread_mutex_t g_mu;
extern SIR_INTERNAL pthread_cond_t  g_cv;

/* ---- 跨单元原型 ---- */

/* 调试开关 (SYMRDMA_SIR_DEBUG; 定义在 sir.c) */
SIR_INTERNAL int sir_dbg(void);

/* 日志宏 (仅 SYMRDMA_SIR_DEBUG 时输出; 三单元共用) */
#define sir_log(fmt, ...) do {                                          \
	if (sir_dbg())                                                   \
		fprintf(stderr, "[sir] " fmt "\n", ##__VA_ARGS__);        \
} while (0)

/* 会合文件 I/O (sir_channel.c; core 导出表变更/建连发布共用, 调用方持 g_mu)
 *  use_tcp 时 write=重建内存 blob / read=GET 拉取 (TTL), 无文件 I/O */
SIR_INTERNAL void sir_peer_info_path(char *buf, size_t n);
SIR_INTERNAL int  sir_write_own_info(void);
SIR_INTERNAL void sir_read_peer_info_locked(void);

/* TCP 会合连接关闭 (sir_channel.c; sir_fini/异常清理用, 调用方持 g_mu) */
SIR_INTERNAL void sir_tcp_close_locked(void);
/* TCP 会合机遇式 GET 服务 (sir_channel.c; 服务线程 idle 路径调用,
 * 调用方持 g_mu) */
SIR_INTERNAL void sir_tcp_opportunistic_locked(void);
/* 真实 verbs 符号加载 (sir_channel.c; sir_init TCP 分支预加载 — 首次
 * export_add 的 blob 构建早于建连) */
SIR_INTERNAL void sir_load_fns(void);

/* 异步自动建连 (sir_channel.c; core 导出后/修复前触发, 幂等) */
SIR_INTERNAL void sir_start_connector(void);

/* 服务线程入口 (sir_service.c; sir_channel.c 建线程) */
SIR_INTERNAL void *sir_thread_main(void *arg);

#endif /* SIR_INTERNAL_H */
