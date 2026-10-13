/* SPDX-License-Identifier: GPL-2.0 */
/*
 * nprdma.c — libnprdma: LD_PRELOAD 拦截 libibverbs (P3/M2, v0.18.0)
 *
 * 拦截 ibv_reg_mr / ibv_dereg_mr，透明注入 SymRDMA IOMMU 注册：
 *   - ibv_reg_mr   → 真实注册 + ioctl REG_MR (双 IOVA 映射 + MMU notifier)
 *   - ibv_dereg_mr → ioctl DEREG_MR + 真实注销
 *
 * 应用完全无感知：无需修改代码，无需链接 libsymrdma。
 *
 * v0.18.0 (M2): 内建 SIR 自动双向修复 (依赖 sir/sir.c, 同译入 .so):
 *   - owner 自动服务: reg_mr (REMOTE_READ) → ioctl REG_MR + Version MR
 *     (REMOTE_READ, v_rkey/v_addr 导出) → sir_export_add 自动建通道/服务线程
 *     (写区域 MR 同 VA 二次注册 → 合并 write_rkey; ioctl REG_MR 同区间去重)
 *   - 透明引擎 (远端 MR one-sided 读/写验证 + 自动修复 + CQE 保序):
 *     post_send 分类: 本地 MR → 既有预检; 远端 (rkey 命中对端导出表) →
 *     验证路径; 其余透传。poll_cq 拦截: 活动跟踪 op 同步解析 —
 *     READ: 256B chunk 哨兵扫描 → ≤1KB 内联取回 / owner REPAIR+重放;
 *     WRITE (signaled ≤4KB): 辅助回读比对快照 → 未落地 → ≤1KB 内联 WR
 *     修复 / 重写。合成/缓存 WC 经 outq 保序交付, 应用可见 CQE 数量不变
 *     (原 unsignaled 强制 signaled 供验证, CQE 由引擎吞掉)。
 *
 * 降级策略: /dev/symrdma 不可用或 REG_MR 失败 → 静默回退纯 verbs 行为;
 * 远端引擎: 未设 SYMRDMA_PEER (SIR 禁用) / 未知 rkey / 多 SGE /
 * unsignaled 远端写 / >4KB 远端写 → 透传 (v0.20.0: 透传远端写提交前
 * rkey 重写 write_rkey — 缺失页黑洞吸收, 不再写穿 RW 哨兵页;
 * 远端原子不再透传 — SIR 双端 RPC, 论文 §3.4)。
 *
 * v0.20.0 (偏差 1 补全 + 透明原子):
 *   - 透传远端写 (unsignaled/>4KB/多 SGE/漂移) rkey 重写 write_rkey:
 *     identity MTT 下缺失页 DMA 写落黑洞, 消除全局哨兵魔数污染;
 *   - 远端原子 (IBV_WR_ATOMIC_CAS/FAA, rkey 命中导出表) → SIR 双端
 *     RPC: 远端 CPU lock cmpxchg/xadd (换出页走 MMU 缺页), 旧值写回
 *     本地 buffer, signaled WR 合成 WC 经 outq 保序交付; RPC 失败 →
 *     拒绝 WR (post_send 返回 EINVAL — 不安全下发 NIC)。
 *
 * 构建: make → libnprdma.so (含 ../sir/sir.c)
 * 使用: LD_PRELOAD=~/pro/symrdma/nprdma/libnprdma.so ./your_app
 *       (默认 flag 模式: 仅显式 NPRDMA_MR_SYMRDMA 位的 MR 转换;
 *        env NPRDMA_INTERCEPT=all → 全拦截; SYMRDMA_PEER=<key> 双进程
 *        一致 → SIR 自动修复激活)
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>   /* offsetof (D3 verbs_context 反推) */
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <infiniband/verbs.h>
#include "sir.h"
#include "nprdma_internal.h"
#include "pinbm.h"   /* 共享 pin 位图原语 (需 symrdma_ioc_pin 定义; sir/ 共享目录) */
#include "vtpages.h"    /* 版本表页数公式 (R7, v0.29.0) */

/* verbs.h 将 ibv_reg_mr 定义为内联路由宏 (__builtin_constant_p 分派) —
 * 拦截导出符号需先取消宏定义 */
#undef ibv_reg_mr
/* SymRDMA MR 标记位 (P4, v0.11.0): 与 lib/libsymrdma.h 的
 * SYMRDMA_ACCESS_IDENTITY 同值 — uverbs optional 位 1<<21。
 * 转发真实 ibv_reg_mr 时 OR 此位 → mlx5 内核据此走 identity MTT;
 * 普通应用 (未挂 LD_PRELOAD) 不带位 → 原版路径 (论文 "unaffected")。 */
#define SYMRDMA_ACCESS_IDENTITY (1 << 21)
/* SYMRDMA_ACCESS_WREG (1<<22, v0.23.1): 显式写区域标记 → OFED
 * identity_womr 判据 (旧: 无 REMOTE_READ 启发式误伤 perftest 的
 * LOCAL_WRITE-only 源 buffer → 黑洞拒读 → LOC_PROT, TESTING §5.2)。
 * 仅两类 MR 置位: ①纯写 MR (REMOTE_WRITE 无 REMOTE_READ, 原
 * identity_womr 语义不变); ②混合 MR 的写区域辅助 MR。普通
 * LOCAL_WRITE-only MR (send 源/接收 buffer) 不置位 → MTT=VA 读区,
 * 页翻转后 NIC 读源命中可读哨兵而非只写黑洞。 */
#define SYMRDMA_ACCESS_WREG (1 << 22)

/* v0.23.1: 主 MR 注册的实际 access — identity 标记 + 显式写区域标记。
 * WREG 规则与旧 identity_womr 启发式对 REMOTE_WRITE 载体的行为完全
 * 一致 (REMOTE_WRITE 无 REMOTE_READ → 写区), 仅不再误伤
 * LOCAL_WRITE-only 源 MR (perftest ibv_wr 源/接收 buffer)。 */
static unsigned int symrdma_eff_access(unsigned int access)
{
	unsigned int eff = access | SYMRDMA_ACCESS_IDENTITY;

	if ((access & IBV_ACCESS_REMOTE_WRITE) &&
	    !(access & IBV_ACCESS_REMOTE_READ))
		eff |= SYMRDMA_ACCESS_WREG;
	return eff;
}



/* ---- 内部状态 ---- */

int sym_fd = -1;                    /* /dev/symrdma, 惰性打开 (internal.h 共享) */
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static int n_registered = 0;
/* 真实 ibv_reg_mr_iova2 (reg 拦截共用; Version MR 注册也用它 — 直调
 * 函数指针, 不经符号解析/自拦截) */
struct ibv_mr *(*g_real_reg_mr_iova2)(struct ibv_pd *, void *, size_t,
					     uint64_t, unsigned int);   /* internal.h 共享 */

/* ibv_mr* → SymRDMA mr_id 映射 (应用 MR 数量少, 线性查找足够) */
struct mr_entry {
	struct ibv_mr *ibv_mr;
	int mr_id;
	uintptr_t va_start;      /* v0.14.0: post_send 预检定位页 */
	size_t len;
	void *version_buf;       /* Version MR 版本表 (本地直读 ~ns) */
	size_t version_buf_len;  /* 版本表映射长度 */
	int version_buf_mr_id;
	struct ibv_mr *version_ibv_mr;   /* v0.18.0: Version MR (REMOTE_READ,
	                                  *  导出 v_rkey 供远端直读) */
	int ioctl_shared;        /* v0.18.0: 同区间去重 — 复用首条的 mr_id,
	                          *  dereg 跳过 ioctl DEREG */
	uint32_t exp_rkey;       /* v0.18.0: 已导出的 data_rkey (dereg 撤导出) */
	uint32_t exp_wkey;       /* v0.19.0: 已导出的 write_rkey (dereg 撤导出) */
	struct ibv_mr *write_ibv_mr;     /* v0.19.0: 混合 MR 的写区域辅助 MR
	                                  *  (REMOTE_READ+REMOTE_WRITE — 主 MR
	                                  *  MTT=VA 供读, 辅 MR MTT=VA+32GB 供写,
	                                  *  论文 §3.1.1 Read/Write MR 分离) */
	/* v0.25.0: 在飞 pin 位图缓存 (镜像内核 pin 状态, 稳态零 syscall;
	 * 索引 = 页号相对 va_start; 原语见 sir/pinbm.h, v0.26.0 去重) */
	struct pinbm             pin;
	struct mr_entry *next;
};
static struct mr_entry *mr_list = NULL;

/* v0.26.0: lkey/rkey 单条目 memo — post_send 热路径 (npr_pin_wr/
 * npr_local_precheck) 原为每 SGE/每 WR 两次 O(MR) 全表扫描; 应用通常
 * 反复用同一 MR (perftest/Spark 均如此), 单条目缓存命中即免扫描。
 * 失效: symrdma_dereg_mr 中比对清除 (mr_entry 释放前)。 */
static struct mr_entry *g_memo_lkey;
static struct mr_entry *g_memo_rkey;

/* 按 lkey 查 MR (memo → 线性回退) */
static struct mr_entry *mr_find_by_lkey(uint32_t lkey)
{
	struct mr_entry *e;

	if (g_memo_lkey && g_memo_lkey->ibv_mr &&
	    g_memo_lkey->ibv_mr->lkey == lkey)
		return g_memo_lkey;
	for (e = mr_list; e; e = e->next)
		if (e->ibv_mr && e->ibv_mr->lkey == lkey)
			break;
	g_memo_lkey = e;
	return e;
}

/* 按 rkey 查 MR (memo → 线性回退) */
static struct mr_entry *mr_find_by_rkey(uint32_t rkey)
{
	struct mr_entry *e;

	if (g_memo_rkey && g_memo_rkey->ibv_mr &&
	    g_memo_rkey->ibv_mr->rkey == rkey)
		return g_memo_rkey;
	for (e = mr_list; e; e = e->next)
		if (e->ibv_mr && e->ibv_mr->rkey == rkey)
			break;
	g_memo_rkey = e;
	return e;
}

int debug_on(void)
{
	return getenv("NPRDMA_DEBUG") != NULL;
}

/* ---- v0.23.2: 拦截模式分离 (NPRDMA_INTERCEPT); v0.23.3 默认翻转 (28) ----
 *
 *  flag (默认): 用户自决定 — 仅 app 显式带 SYMRDMA_ACCESS_IDENTITY 位
 *              (1<<21, 见 nprdma/libnprdma.h) 的 MR 转换; 其余**纯透传**
 *              (vanilla pinned MTT=dma IOVA, 不注入任何位)。
 *              语义分层: 不挂 preload 的进程 / 挂了但未标记的 MR / 挂了但
 *              模块未加载的进程 — 行为全部与原生 RDMA 一致 → preload 可
 *              常驻部署 (profile/容器镜像)。
 *  all:        全拦截 — 进程内所有 ibv_reg_mr 注入 IDENTITY 位并转
 *              SymRDMA (IOMMU 双映射 + notifier + auto-export)。
 *              perftest 等未修改应用显式开启即透明获得 SymRDMA
 *              (论文 §4.1 透明引擎语义; WREG 修复保证源读不撞黑洞)。
 *
 *  与 OFED identity_mtt 参数独立 (0=按位/1=全局强制, 加载时固定):
 *  推荐保持 0 — 两种模式均在 per-MR 位语义下工作, 引擎外进程不受影响。
 *  flag 模式透传的 MR 不进引擎表 (post_send/poll_cq 对未知 MR 天然
 *  透传降级), 且无 IOMMU 依赖 → 引擎降级/卸载也安全。
 *  v0.23.3 模块可用性前置探测 (28): real reg 注入位**之前**探测
 *  /dev/symrdma, 不可用 → 本次进程所有 MR 剥位纯透传。闭环原缺陷:
 *  real reg 已注入位 → OFED 建 identity MTT 后 ioctl 失败无法回退 →
 *  访问 DMAR fault ("降级不完整") — 对 all 模式同样生效 (挂 preload
 *  未装模块从"全坏"变"全透传")。
 */
#define NPRDMA_INTERCEPT_ALL  0
#define NPRDMA_INTERCEPT_FLAG 1
static int g_intercept_mode = NPRDMA_INTERCEPT_FLAG;
static int g_intercept_inited;

static int intercept_mode(void)
{
	const char *m;

	if (g_intercept_inited)
		return g_intercept_mode;
	g_intercept_inited = 1;
	m = getenv("NPRDMA_INTERCEPT");
	if (m && strcmp(m, "all") == 0) {
		g_intercept_mode = NPRDMA_INTERCEPT_ALL;
		if (debug_on())
			fprintf(stderr,
				"[nprdma] 拦截模式=all (全拦截 — 所有 MR 转 SymRDMA)\n");
	} else {
		if (m && *m && strcmp(m, "flag") != 0 && strcmp(m, "optin") != 0 &&
		    debug_on())
			fprintf(stderr,
				"[nprdma] NPRDMA_INTERCEPT='%s' 未知 → 默认 flag\n", m);
	}
	return g_intercept_mode;
}

int symrdma_open_locked(void)
{
	if (sym_fd >= 0)
		return 0;
	sym_fd = open("/dev/symrdma", O_RDWR);
	return sym_fd >= 0 ? 0 : -1;
}

/* ---- v0.23.3: 模块可用性前置探测 (28) + v0.24.6 功能探测 ---- */
static int g_sym_unavailable_warned;

/* 剥离 SymRDMA 专用水位位 (IDENTITY 1<<21 / WREG 1<<22) → vanilla access */
static unsigned int vanilla_access(unsigned int access)
{
	return access & ~(SYMRDMA_ACCESS_IDENTITY | SYMRDMA_ACCESS_WREG);
}

/* 必须在 real reg 注入位**之前**调用: 注入位后 OFED 即建 identity MTT
 * (不 pin), 此刻 ioctl 失败已无法回退 (identity MTT 无 IOMMU 映射 →
 * DMAR fault)。v0.24.6: 探测从"设备可 open"升级为"REG_MR 真能成功"
 * (一次性 1 页 REG_MR+DEREG_MR 往返, 结果按进程缓存) — 封闭28 延伸
 * 缺口: 设备在但 ioctl REG_MR 失败 (iommu_map ENOMEM/ENODEV 等) 时,
 * identity MTT 已建立而 IOMMU 映射缺失 → 后续 DMA 全部 fault。
 * 降级一次性 stderr 告警 (非 debug 也打印, 不逐 MR 刷屏)。 */
static int symrdma_probe_reg(void)
{
	static int cached = -1;   /* -1=未探测 0=不可用 1=可用 */
	void *pg;
	struct symrdma_ioc_reg_mr req;
	int id;

	if (cached >= 0)
		return cached;
	if (symrdma_open_locked() != 0)
		goto fail;
	pg = mmap(NULL, SYMRDMA_PAGE_SIZE, PROT_READ | PROT_WRITE,
		  MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (pg == MAP_FAILED)
		goto fail;
	memset(&req, 0, sizeof(req));
	req.va_start = (unsigned long long)(uintptr_t)pg;
	req.len = SYMRDMA_PAGE_SIZE;
	id = ioctl(sym_fd, SYMRDMA_IOC_REG_MR, &req);
	if (id >= 0) {
		/* #5: REG_MR 成功时 ioctl 返回 0, 真实 id 经
		 * copy_to_user 写回 req.mr_id (symrdma_dev.c REG_MR 分支) —
		 * 原代码按返回值注销, 实际注销的是 0 号 MR (可能属于其他
		 * 进程), probe 自己注册的 MR 反而泄漏 */
		ioctl(sym_fd, SYMRDMA_IOC_DEREG_MR, req.mr_id);
		munmap(pg, SYMRDMA_PAGE_SIZE);
		cached = 1;
		return cached;
	}
	munmap(pg, SYMRDMA_PAGE_SIZE);
fail:
	cached = 0;
	if (!g_sym_unavailable_warned) {
		g_sym_unavailable_warned = 1;
		fprintf(stderr,
			"[nprdma] SymRDMA 模块不可用或 REG_MR 失败 — 本次进程 MR 纯透传 (vanilla RDMA)\n");
	} else if (debug_on()) {
		fprintf(stderr, "[nprdma] 模块探测失败 → 透传\n");
	}
	return cached;
}

static int symrdma_available(void)
{
	return symrdma_probe_reg();
}

/* 注册: ioctl REG_MR (双 IOVA 映射 + MMU notifier) + 版本表绑定, 不 pin。
 * pd: 注册方 PD (Version MR ibv 注册需); 同 VA 区间二次注册去重 (写区域
 * MR 场景 — 同一 buffer 的 read MR + write MR 共享一个 ioctl mr_id)。
 * 注意: 真实 ibv 调用 (version_ibv_mr 注册) 必须在锁外 — 真实实现链
 * (compat) 会再入本 wrapper, 持锁则自死锁 (L7 实测)。 */
static int symrdma_reg_mr(struct mr_entry *e, struct ibv_pd *pd)
{
	struct symrdma_ioc_reg_mr req = {
		.va_start = (unsigned long long)e->va_start,
		.len = (unsigned long long)e->len,
	};
	int ret = -1;
	/* 锁外补齐的 version ibv MR (pd + buffer 由锁内收集) */
	void *vb = NULL;
	size_t vsize = 0;

	/* SymRDMA 以页为粒度 — 长度向上取整到整页
	 * (32B 等小 buffer 的 npages=0 会导致 REG_MR 静默失败,
	 *  control buffer 无 IOMMU 映射 → SEND DMA fault, Level 7 实测) */
	req.len = (req.len + 4095) & ~4095ULL;

	pthread_mutex_lock(&lock);
	if (symrdma_open_locked() == 0) {
		/* v0.18.0: 同 (va,len) 区间去重 — 复用首条的 ioctl mr_id
		 * (双 MR 场景: notifier 去重按 mm; 双重 iommu_map 同 IOVA
		 * 会冲突, 实测双表互相踩) */
		struct mr_entry *x;
		int shared = 0;

		for (x = mr_list; x; x = x->next) {
			if (x->va_start == e->va_start && x->len == e->len &&
			    x->mr_id >= 0) {
				e->mr_id = x->mr_id;
				e->ioctl_shared = 1;
				shared = 1;
				break;
			}
		}
		if (shared ||
		    ioctl(sym_fd, SYMRDMA_IOC_REG_MR, &req) == 0) {
			if (!shared)
				e->mr_id = req.mr_id;
			n_registered++;
			ret = 0;

			/* v0.14.0/1: Version MR 版本表绑定 (论文 §3.1.2)。
			 * version ibv MR 注册在锁外完成 (见函数尾)。 */
			{
				struct symrdma_ioc_reg_mr vreq;
				struct symrdma_ioc_set_version_page sv;
				unsigned long npages = req.len / SYMRDMA_PAGE_SIZE;
				/* R7 (v0.29.0): 页数公式收敛至 sir/vtpages.h */
				unsigned long vt_pages = symrdma_vt_pages(npages);

				vsize = vt_pages * SYMRDMA_PAGE_SIZE;
				vb = mmap(NULL, vsize, PROT_READ | PROT_WRITE,
					  MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
				if (vb != MAP_FAILED) {
					memset(vb, 0, vsize);
					/* D2 (同 lib 侧 C3): mlock 失败 (no-pin 环境
					 * RLIMIT_MEMLOCK=0 必败) → 版本页可换出。跳过: 按
					 * "无 version_buf"透传 (与既有降级语义一致)。 */
					if (mlock(vb, vsize) != 0) {
						munmap(vb, vsize);
						vb = MAP_FAILED;
					} else {
						memset(&vreq, 0, sizeof(vreq));
						vreq.va_start = (unsigned long long)(uintptr_t)vb;
						vreq.len = vsize;
						memset(&sv, 0, sizeof(sv));
						sv.mr_id = e->mr_id;
						sv.version_va = (unsigned long long)(uintptr_t)vb;
						sv.version_len = vt_pages;
						if (ioctl(sym_fd, SYMRDMA_IOC_REG_MR, &vreq) == 0 &&
						    ioctl(sym_fd, SYMRDMA_IOC_SET_VERSION_PAGE, &sv) == 0) {
							e->version_buf = vb;
							e->version_buf_mr_id = vreq.mr_id;
							e->version_buf_len = vsize;
						} else {
							munmap(vb, vsize);
							vb = MAP_FAILED;
						}
					}
				}
				if (vb == MAP_FAILED)
					vsize = 0;
			}
		}
	}
	pthread_mutex_unlock(&lock);

	/* 锁外: version ibv MR 注册 (REMOTE_READ → 导出 v_rkey; 真实实现
	 * 链可能再入本 wrapper — 持锁自死锁, 见 L7 实测) */
	if (ret == 0 && vb && vsize && pd && g_real_reg_mr_iova2) {
		e->version_ibv_mr = g_real_reg_mr_iova2(pd, vb, vsize,
						       (uint64_t)(uintptr_t)vb,
						       IBV_ACCESS_REMOTE_READ |
						       SYMRDMA_ACCESS_IDENTITY);
		if (!e->version_ibv_mr) {
			/* 版本 MR 注册失败: 回退不绑定 (导出无 v_rkey) */
			if (sym_fd >= 0 && e->version_buf_mr_id >= 0)
				ioctl(sym_fd, SYMRDMA_IOC_DEREG_MR,
				      e->version_buf_mr_id);
			munmap(e->version_buf, e->version_buf_len);
			e->version_buf = NULL;
			e->version_buf_mr_id = -1;
			e->version_buf_len = 0;
		}
	}
	return ret;
}

static void symrdma_dereg_mr(struct mr_entry *e)
{
	struct ibv_mr *vmr = NULL;
	struct ibv_mr *wmr = NULL;
	void *vbuf = NULL;
	size_t vlen = 0;

	pthread_mutex_lock(&lock);
	if (sym_fd >= 0) {
		if (e->version_buf_mr_id >= 0)
			ioctl(sym_fd, SYMRDMA_IOC_DEREG_MR, e->version_buf_mr_id);
		if (!e->ioctl_shared && e->mr_id >= 0)
			ioctl(sym_fd, SYMRDMA_IOC_DEREG_MR, e->mr_id);
	}
	if (e->exp_rkey)
		sir_export_del(e->exp_rkey);
	if (e->exp_wkey)
		sir_export_del_wkey(e->exp_wkey);
	/* v0.25.0: 释放在飞 pin 位图缓存 (内核 DEREG 已释放全部 pin 引用,
	 * 位图随 MR 条目一并消失); v0.26.0: 同时清 lkey/rkey memo */
	free(e->pin.bm);
	e->pin.bm = NULL;
	e->pin.cap = 0;
	e->pin.pinned = 0;
	if (g_memo_lkey == e)
		g_memo_lkey = NULL;
	if (g_memo_rkey == e)
		g_memo_rkey = NULL;
	/* 收集锁外工作 (真实 ibv 调用不可持锁 — compat 链再入自死锁) */
	vmr = e->version_ibv_mr;
	wmr = e->write_ibv_mr;
	vbuf = e->version_buf;
	vlen = e->version_buf_len;
	e->version_ibv_mr = NULL;
	e->write_ibv_mr = NULL;
	e->version_buf = NULL;
	n_registered--;
	pthread_mutex_unlock(&lock);

	if (vmr) {
		static int (*real_dereg)(struct ibv_mr *);
		if (!real_dereg)
			real_dereg = dlvsym(RTLD_NEXT, "ibv_dereg_mr", "IBVERBS_1.1");
		if (real_dereg)
			real_dereg(vmr);
	}
	if (wmr) {
		static int (*real_dereg2)(struct ibv_mr *);
		if (!real_dereg2)
			real_dereg2 = dlvsym(RTLD_NEXT, "ibv_dereg_mr", "IBVERBS_1.1");
		if (real_dereg2)
			real_dereg2(wmr);
	}
	if (vbuf)
		munmap(vbuf, vlen ? vlen : SYMRDMA_PAGE_SIZE);
}

/* ---- v0.18.0/19.0: owner 自动导出 (SIR 服务就绪 + 写区域分离) ----
 *
 * 论文 §3.1.1: 每个应用 MR 建立独立 Read MR (缺失页→哨兵) 与 Write MR
 * (缺失页→黑洞)。本函数按应用注册的 access flags 自动补齐:
 *   - REMOTE_READ MR → 导出 data_rkey (主键) + Version MR v_rkey;
 *   - REMOTE_READ+REMOTE_WRITE (混合 MR) → 自动注册写区域辅助 MR
 *     (同 VA, access 去 REMOTE_READ → OFED identity_womr → MTT=VA+32GB),
 *     导出 write_rkey — 引擎写路径 rkey 重写后缺失页 DMA 写被黑洞吸收,
 *     消除 identity MTT 下写穿 RW 哨兵页的全局魔数污染 (偏差 1 修复);
 *   - REMOTE_WRITE-only (纯写 MR) → 直接导出 write_rkey, 由 sir.c
 *     合并逻辑并入同 VA 区间的既有数据导出 (v0.18.0 既有逻辑,
 *     v0.18.1 重构时提前 return 丢失 — 本次修复接线)。
 * 辅助 MR 注册失败 → write_rkey=0, 退回 v0.18.x 行为 (验证路径修复兑底)。
 */
static void npr_auto_export(struct mr_entry *e, struct ibv_pd *pd,
			    struct ibv_context *ctx, int access)
{
	struct sir_export exp = {0};
	int has_read  = (access & IBV_ACCESS_REMOTE_READ) != 0;
	int has_write = (access & IBV_ACCESS_REMOTE_WRITE) != 0 &&
			(access & IBV_ACCESS_LOCAL_WRITE) != 0;

	/* v0.21.2: 绑定必须在 early-return 之前 — 纯本地 MR 的客户端
	 * (如 L13 的 LOCAL_WRITE 接收 buffer) 不导出任何东西, 但仍需要
	 * SIR 通道向对端发起修复请求; sym_fd 不绑定则连接线程永远
	 * EAGAIN 重试, 通道永不通 (实测: 控制 buffer 无 IOMMU 映射 →
	 * SEND LOC_PROT_ERR; v0.20.0 在 基准机 上靠 VA 碰撞侥幸工作) */
	sir_init(ctx, pd, NULL, sym_fd);
	if (!has_read && !has_write)
		return;   /* 纯本地 MR: 无远端访问, 不导出 */
	if (has_read) {
		exp.data_rkey = e->ibv_mr->rkey;
		exp.addr  = (uint64_t)e->va_start;
		exp.len   = (uint64_t)e->len;
		exp.mr_id = e->mr_id;
		if (e->version_ibv_mr) {
			exp.v_rkey = e->version_ibv_mr->rkey;
			exp.v_addr = (uint64_t)(uintptr_t)e->version_buf;
		}
	}
	if (has_write) {
		if (has_read && g_real_reg_mr_iova2) {
			/* 混合 MR: 写区域辅助 MR (无 REMOTE_READ → MTT=VA+32GB)。
			 * 不需 ioctl — 双 IOVA IOMMU 映射由主 MR 的 symrdma MR
			 * 已建, 辅助 MR 只是新的 MKEY (写路径翻译键)。 */
			e->write_ibv_mr =
				g_real_reg_mr_iova2(pd, (void *)e->va_start,
						    e->len,
						    (uint64_t)e->va_start,
						    (access & ~IBV_ACCESS_REMOTE_READ) |
						    SYMRDMA_ACCESS_IDENTITY |
						    SYMRDMA_ACCESS_WREG);
			if (e->write_ibv_mr)
				exp.write_rkey = e->write_ibv_mr->rkey;
			else if (debug_on())
				fprintf(stderr,
					"[nprdma] 写区域辅助 MR 注册失败 — 写路径退数据 MKEY (v0.18.x 行为)\n");
		} else if (!has_read) {
			/* 纯写 MR: 主 MR 注册时已置 WREG (symrdma_eff_access),
			 * MTT=VA+32GB, 直接导出 wkey → sir.c 合并进同区间数据导出 */
			exp.write_rkey = e->ibv_mr->rkey;
			if (!exp.addr) {
				exp.addr  = (uint64_t)e->va_start;
				exp.len   = (uint64_t)e->len;
				exp.mr_id = e->mr_id;
			}
		}
	}
	if (sir_export_add(&exp) == 0) {
		if (exp.data_rkey)
			e->exp_rkey = exp.data_rkey;
		if (exp.write_rkey)
			e->exp_wkey = exp.write_rkey;
	}
	if (debug_on())
		fprintf(stderr,
			"[nprdma] 自动导出 MR rkey=0x%x wkey=0x%x addr=%p len=%zu (owner 服务就绪)\n",
			exp.data_rkey, exp.write_rkey, (void *)e->va_start, e->len);
}

/* ---- 拦截: ibv_reg_mr / ibv_reg_mr_iova2 ----
 *
 * 重入保护: libibverbs/provider 内部也可能调用这些符号 (如 libmlx5 的
 * dr_send_ring_alloc) — 嵌套调用直接透传, 不做 SymRDMA 注册。
 *
 * v0.26.0: 两入口的公共体提取为 npr_reg_mr_common (此前 ~70 行重复:
 * 模式判别/可用性探测/真实注册+注入/引擎表登记/自动导出, 仅日志名与
 * iova 实参不同 — 修一处漏一处的隐患)。 */
static __thread int in_reg_mr;

static struct ibv_mr *npr_reg_mr_common(struct ibv_pd *pd, void *addr,
					size_t length, uint64_t iova,
					unsigned int access, const char *name)
{
	static struct ibv_mr *(*real_fn)(struct ibv_pd *, void *, size_t,
					 uint64_t, unsigned int);
	struct ibv_mr *mr;
	struct mr_entry *e;

	if (!real_fn) {
		real_fn = dlvsym(RTLD_NEXT, "ibv_reg_mr_iova2", "IBVERBS_1.8");
		g_real_reg_mr_iova2 = real_fn;
	}
	if (!real_fn)
		return NULL;

	if (in_reg_mr)              /* 内部嵌套调用 → 透传 */
		return real_fn(pd, addr, length, iova, access);

	/* flag 模式: app 未显式带 IDENTITY 位 → 纯透传 (vanilla pinned,
	 * 不注入任何位 — 降级安全; 引擎表不含此 MR, 数据面透传降级) */
	if (intercept_mode() == NPRDMA_INTERCEPT_FLAG &&
	    !(access & SYMRDMA_ACCESS_IDENTITY)) {
		if (debug_on())
			fprintf(stderr,
				"[nprdma] flag 模式透传 MR %p:%zu (无 IDENTITY 位)\n",
				addr, length);
		return real_fn(pd, addr, length, iova, access);
	}

	/* v0.23.3: 模块可用性前置探测 — 不可用则剥位透传 (含显式位 MR) */
	if (!symrdma_available())
		return real_fn(pd, addr, length, iova, vanilla_access(access));

	in_reg_mr = 1;
	mr = real_fn(pd, addr, length, iova, symrdma_eff_access(access));
	in_reg_mr = 0;
	if (!mr)
		return NULL;

	/* 透明注入: SymRDMA 双 IOVA 映射 (失败静默降级) */
	e = calloc(1, sizeof(*e));
	if (e) {
		e->ibv_mr = mr;
		e->va_start = (uintptr_t)addr;
		e->len = length;
		e->version_buf_mr_id = -1;
		e->mr_id = -1;
		if (symrdma_reg_mr(e, pd) == 0) {
			pthread_mutex_lock(&lock);
			e->next = mr_list;
			mr_list = e;
			pthread_mutex_unlock(&lock);
			if (debug_on())
				fprintf(stderr,
					"[nprdma] %s(%p, %zu) → SymRDMA mr_id=%d (当前 %d 个)\n",
					name, addr, length, e->mr_id,
					n_registered);
			npr_auto_export(e, pd, pd->context, (int)access);
		} else {
			if (debug_on())
				fprintf(stderr,
					"[nprdma] %s(%p, %zu): SymRDMA 注册失败 — 透明降级\n",
					name, addr, length);
			free(e);
		}
	}
	return mr;
}

/* ibv_reg_mr_iova2: 宏路由的可选范围路径 + 直接调用方 */
struct ibv_mr *ibv_reg_mr_iova2(struct ibv_pd *pd, void *addr, size_t length,
				uint64_t iova, unsigned int access)
{
	return npr_reg_mr_common(pd, addr, length, iova, access,
				 "ibv_reg_mr_iova2");
}

/* ---- 拦截: ibv_reg_mr ----
 *
 * 注: 不能 dlsym(RTLD_NEXT, "ibv_reg_mr") — 该符号有 IBVERBS_1.0/1.1
 * 双版本, RTLD_NEXT 解析到旧 ABI 兼容实现 (__ibv_reg_mr_1_0), 把新
 * struct ibv_pd 当旧结构解引用 → 段错误 (gdb 实测)。
 * 新 ABI 默认实现本身就是转发 ibv_reg_mr_iova2, 直接调用它。 */
struct ibv_mr *ibv_reg_mr(struct ibv_pd *pd, void *addr, size_t length,
			  int access)
{
	return npr_reg_mr_common(pd, addr, length, (uint64_t)(uintptr_t)addr,
				 (unsigned int)access, "ibv_reg_mr");
}

/* ---- 拦截: ibv_dereg_mr ---- */

int ibv_dereg_mr(struct ibv_mr *mr)
{
	/* 同 ibv_reg_mr: 双版本符号 (IBVERBS_1.0/1.1), dlvsym 显式取新 ABI */
	static int (*real_fn)(struct ibv_mr *);
	struct mr_entry *e = NULL, **pp;

	if (!real_fn)
		real_fn = dlvsym(RTLD_NEXT, "ibv_dereg_mr", "IBVERBS_1.1");
	if (!real_fn)
		return -1;
	if (debug_on())
		fprintf(stderr, "[nprdma] ibv_dereg_mr 进入\n");

	pthread_mutex_lock(&lock);
	for (pp = &mr_list; *pp; pp = &(*pp)->next) {
		if ((*pp)->ibv_mr == mr) {
			e = *pp;
			*pp = e->next;
			break;
		}
	}
	pthread_mutex_unlock(&lock);

	if (e) {
		/* D4: 先 ibv_dereg (撤 MTT) 再撤 SymRDMA IOMMU 映射 —
		 * 先让 NIC 忘记 MR 再撤翻译, 消除 stale-MTT + 无 IOMMU 映射
		 * 的瞬态 DMA fault 窗口 (与 libsymrdma 顺序一致) */
		if (debug_on())
			fprintf(stderr, "[nprdma] ibv_dereg_mr 调 real_fn...\n");
		int rc = real_fn(mr);
		if (debug_on())
			fprintf(stderr, "[nprdma] ibv_dereg_mr real_fn → %d\n", rc);

		symrdma_dereg_mr(e);
		if (debug_on())
			fprintf(stderr,
				"[nprdma] ibv_dereg_mr → SymRDMA DEREG mr_id=%d (当前 %d 个)\n",
				e->mr_id, n_registered);
		free(e);
		return rc;
	}
	return real_fn(mr);
}

/* ---- 拦截: ibv_alloc_pd (v0.18.0: 记录首 PD → SIR 通道资源) ---- */

struct ibv_pd *ibv_alloc_pd(struct ibv_context *context)
{
	static struct ibv_pd *(*real_fn)(struct ibv_context *);
	struct ibv_pd *pd;

	if (!real_fn)
		real_fn = dlvsym(RTLD_NEXT, "ibv_alloc_pd", "IBVERBS_1.1");
	if (!real_fn)
		return NULL;
	pd = real_fn(context);
	if (pd) {
		/* SIR 惰性初始化 (key = env SYMRDMA_PEER; 未设 → 禁用)。
		 * sym_fd 此刻可能未开 — sir_init 迟绑定 (后续 reg 再补)。 */
		sir_init(context, pd, NULL, -1);
		/* 主动触发自动建连 (幂等; 对端晚到由后台重试兜底) */
		sir_ensure_start();
		if (debug_on())
			fprintf(stderr, "[nprdma] ibv_alloc_pd → SIR 就绪 (peer=%s)\n",
				getenv("SYMRDMA_PEER") ? getenv("SYMRDMA_PEER") : "<未设>");
	}
	return pd;
}

/* ---- v0.25.0: flush-before-unmap 屏障 (在飞页 pin, 粘性缓存) ----
 *
 * 论文 §3.2 临时 pin 语义: 本地缓冲参与 DMA (READ 目标 / WRITE·SEND
 * 源 / 自环远端地址) 前 ioctl PIN_PAGES — 内核 GUP 取页引用并标记在飞,
 * notifier 对在飞页延迟哨兵化 (PA 因引用恒有效): 消除 unmap→map 窗口
 * (L14 access_err 根因) 与哨兵/黑洞吸收 (L14 corrupt "整页零" 根因)。
 * pin 以 MR 为域粘性保持 (内核预算封顶), 本地位图缓存镜像内核状态 →
 * 稳态零 syscall; -ENOSPC → 全量 UNPIN(len=0) + 清位图 + 重试一次。
 * SYMRDMA_NO_PIN=1 关闭 (A/B 对照旧行为)。
 * 位图增长/span 循环/ENOSPC 重试原语在 sir/pinbm.h (v0.26.0 与
 * libsymrdma 去重 — 此前两份相同实现)。 */
static int pin_disabled = -1;
static pthread_mutex_t pin_mu = PTHREAD_MUTEX_INITIALIZER;

static int npr_pin_is_disabled(void)
{
	if (pin_disabled < 0)
		pin_disabled = getenv("SYMRDMA_NO_PIN") ? 1 : 0;
	return pin_disabled;
}

/* PIN_PAGES 单段回调 (pinbm_pin_span 用; e = mr_entry 上下文) */
static int npr_pin_ioc_one(void *ud, unsigned long s, unsigned long n)
{
	struct mr_entry *e = ud;
	struct symrdma_ioc_pin p = {
		.mr_id = e->mr_id,
		.va  = (unsigned long long)(e->va_start +
					    s * SYMRDMA_PAGE_SIZE),
		.len = (unsigned long long)n * SYMRDMA_PAGE_SIZE,
	};

	return ioctl(sym_fd, SYMRDMA_IOC_PIN_PAGES, &p) ? -1 : 0;
}

/* UNPIN(len=0) 全量释放回调 (ENOSPC 预算淘汰) */
static void npr_pin_ioc_drop_all(void *ud)
{
	struct mr_entry *e = ud;
	struct symrdma_ioc_pin up = { .mr_id = e->mr_id };

	if (sym_fd >= 0 && e->mr_id >= 0)
		ioctl(sym_fd, SYMRDMA_IOC_UNPIN_PAGES, &up);
}

/* pin 一个 span (粘性缓存): 位图未覆盖的连续子段逐段 PIN_PAGES。
 * 返回 0 = 已覆盖; -1 = 不可用 (降级继续 — 与无屏障行为等价)。 */
static int npr_pin_span(struct mr_entry *e, uintptr_t addr, size_t len)
{
	uintptr_t base = e->va_start;
	unsigned long i0, i1;
	int ret;

	if (npr_pin_is_disabled() || sym_fd < 0 || e->mr_id < 0 || !len)
		return -1;
	if (addr < base || addr + len <= addr || addr + len > base + e->len)
		return -1;

	pthread_mutex_lock(&pin_mu);
	i0 = (addr - base) / SYMRDMA_PAGE_SIZE;
	i1 = (addr + len - 1 - base) / SYMRDMA_PAGE_SIZE;
	if (pinbm_grow(&e->pin, i1)) {
		pthread_mutex_unlock(&pin_mu);
		return -1;
	}
	ret = pinbm_pin_span(&e->pin, i0, i1,
			     npr_pin_ioc_one, npr_pin_ioc_drop_all, e);
	pthread_mutex_unlock(&pin_mu);
	return ret;
}

/* 单次裸 pin (无缓存 — 引擎 scratch 等一次性场景, 尽力而为) */
NPRDMA_INTERNAL void npr_pin_once(int mr_id, uint64_t va, size_t len)
{
	struct symrdma_ioc_pin p = {
		.mr_id = mr_id,
		.va = va,
		.len = len,
	};

	if (npr_pin_is_disabled() || sym_fd < 0 || mr_id < 0)
		return;
	ioctl(sym_fd, SYMRDMA_IOC_PIN_PAGES, &p);
}

/* 对 WR 的本地 DMA 参与页做在飞 pin:
 *  - 全部 SGE (READ 本地目标 / WRITE·SEND 本地源 — 本地 NIC DMA 读/写);
 *  - 自环远端地址 (rkey 命中本进程 MR — 单机自环 QP 的远端页即本地页,
 *    覆盖 L13/L14 自环写目标与读源)。
 * 跨机远端页 (rkey 未命中) 无法 pin — 远端验证/修复路径兑底 (既有语义)。 */
static void npr_pin_wr(struct ibv_send_wr *w)
{
	int i;

	if (npr_pin_is_disabled())
		return;

	for (i = 0; w->sg_list && i < w->num_sge; i++) {
		struct mr_entry *e = mr_find_by_lkey(w->sg_list[i].lkey);

		if (e)
			npr_pin_span(e, (uintptr_t)w->sg_list[i].addr,
				     w->sg_list[i].length);
	}

	if ((w->opcode == IBV_WR_RDMA_READ ||
	     w->opcode == IBV_WR_RDMA_WRITE) && w->sg_list && w->num_sge > 0) {
		struct mr_entry *e;
		size_t total = 0;
		int k;

		e = mr_find_by_rkey(w->wr.rdma.rkey);
		if (!e)
			return;
		for (k = 0; k < w->num_sge; k++)
			total += w->sg_list[k].length;
		npr_pin_span(e, (uintptr_t)w->wr.rdma.remote_addr, total);
	}
}

/* 本地预检 (v0.14.2 语义, 原样保留): 命中本进程 MR → 版本直读预修复 */
static void symrdma_precheck_repair(struct mr_entry *e, unsigned long pg)
{
	if (((uint32_t *)e->version_buf)[pg] & 1)
		return;
	{
		struct symrdma_ioc_repair rp = {
			.mr_id = e->mr_id,
			.page_idx = pg,
		};
		if (ioctl(sym_fd, SYMRDMA_IOC_REPAIR, &rp) == 0 && debug_on())
			fprintf(stderr,
				"[nprdma] post_send 预修复页 %lu (mr_id=%d)\n",
				pg, e->mr_id);
	}
}

/* 本地 MR 判定 + 预检 (原 v0.14.0/D5/D8 逻辑) */
static void npr_local_precheck(struct ibv_qp *qp, struct ibv_send_wr *wr)
{
	(void)qp;   /* 预检按 rkey/lkey 全表扫描, qp 不参与 (消除 -Wunused) */

	if (wr->opcode == IBV_WR_RDMA_READ) {
		struct mr_entry *e = mr_find_by_rkey(wr->wr.rdma.rkey);

		if (e && e->version_buf && wr->sg_list && wr->num_sge > 0) {
			uintptr_t remote = wr->wr.rdma.remote_addr;
			unsigned long np = (wr->sg_list[0].length +
					    SYMRDMA_PAGE_SIZE - 1) /
					   SYMRDMA_PAGE_SIZE;
			unsigned long p;

			for (p = 0; p < np; p++) {
				uintptr_t addr = remote + p * SYMRDMA_PAGE_SIZE;

				if (addr < e->va_start ||
				    addr >= e->va_start + e->len)
					continue;
				symrdma_precheck_repair(e,
					(addr - e->va_start) / SYMRDMA_PAGE_SIZE);
			}
		}
	} else if (wr->opcode == IBV_WR_RDMA_WRITE) {
		int i;

		for (i = 0; wr->sg_list && i < wr->num_sge; i++) {
			uintptr_t src = wr->sg_list[i].addr;
			unsigned long np = (wr->sg_list[i].length +
					    SYMRDMA_PAGE_SIZE - 1) /
					   SYMRDMA_PAGE_SIZE;
			unsigned long p;
			struct mr_entry *e2 =
				mr_find_by_lkey(wr->sg_list[i].lkey);

			if (!e2 || !e2->version_buf)
				continue;
			for (p = 0; p < np; p++) {
				uintptr_t addr = src + p * SYMRDMA_PAGE_SIZE;

				if (addr < e2->va_start ||
				    addr >= e2->va_start + e2->len)
					continue;
				symrdma_precheck_repair(e2,
					(addr - e2->va_start) / SYMRDMA_PAGE_SIZE);
			}
		}
	}
}

/* D8: per-context real post_send 表 (v0.14.0, 声明前移供 post_send 用) */
struct symrdma_ctx_entry {
	struct ibv_context *ctx;
	int (*real_post_send)(struct ibv_qp *qp, struct ibv_send_wr *wr,
			      struct ibv_send_wr **bad_wr);
	struct symrdma_ctx_entry *next;
};
static struct symrdma_ctx_entry *ctx_list;

static int symrdma_post_send(struct ibv_qp *qp, struct ibv_send_wr *wr,
			     struct ibv_send_wr **bad_wr);

/* poll_cq 拦截 (v0.18.0 M2) */
static int symrdma_poll_cq(struct ibv_cq *cq, int num_entries,
			   struct ibv_wc *wc)
{
	struct npr_ctx_entry *ce;
	struct npr_cq_entry *cqe;
	int delivered = 0;

	for (ce = npr_ctx_list; ce; ce = ce->next)
		if (ce->ctx == cq->context)
			break;
	if (!ce || !ce->real_poll_cq)
		return 0;   /* v0.24.6: 旧返回 ENOSYS(38) 会被应用当"38 个完成"
			    * 消费 → 垃圾 WC; 未登记 CQ 按空轮询处理 */
	cqe = npr_cq_get(ce, cq);
	if (cqe->drift) {
		/* v0.22.0 (bug 8): 漂移前已入 outq 的 WC (含 drift 前交付的
		 * 应用原始完成/致命错误 WC) 必须按序先交付 — 否则它们永久滞留
		 * (drift 直取透传拿不到 outq) → 应用轮询死转。 */
		while (delivered < num_entries &&
		       npr_outq_pop(cqe, &wc[delivered]))
			delivered++;
		if (delivered)
			return delivered;
		return ce->real_poll_cq(cq, num_entries, wc);
	}

	/* ① outq 先交付 (保序) */
	while (delivered < num_entries && npr_outq_pop(cqe, &wc[delivered]))
		delivered++;
	/* ② 活动 op 同步解析 */
	{
		struct npr_qp_state *q;

		for (q = ce->qps; q; q = q->next)
			if (q->has_active && q->active.send_cq == cq) {
				if (npr_resolve(ce, q))
					return delivered ? delivered :
					       ce->real_poll_cq(cq, num_entries,
								wc);
				break;
			}
	}
	/* ③ outq 继续 */
	while (delivered < num_entries && npr_outq_pop(cqe, &wc[delivered]))
		delivered++;
	/* ④ 真实 CQ 直取 (untracked 完成) */
	while (delivered < num_entries) {
		int n = ce->real_poll_cq(cq, 1, &wc[delivered]);

		if (n <= 0)
			break;
		delivered++;
	}
	return delivered;
}

static int symrdma_post_send(struct ibv_qp *qp, struct ibv_send_wr *wr,
			     struct ibv_send_wr **bad_wr)
{
	int (*real)(struct ibv_qp *, struct ibv_send_wr *,
		    struct ibv_send_wr **) = NULL;
	struct symrdma_ctx_entry *dce;
	struct npr_ctx_entry *nce = NULL;
	struct ibv_send_wr *w;

	/* D8: 查本 context 的 real post_send (只追加表, 无锁读) */
	for (dce = ctx_list; dce; dce = dce->next)
		if (dce->ctx == qp->context) {
			real = dce->real_post_send;
			break;
		}
	if (!real)
		return ENOSYS;   /* 理论不可达: 包装按 context 注册 */
	for (nce = npr_ctx_list; nce; nce = nce->next)
		if (nce->ctx == qp->context)
			break;
	if (!nce)
		nce = npr_ctx_get(qp->context);

	/* 逐 WR 处理 (链拆单提交; 语义与链等价, 错误中止于失败 WR) */
	for (w = wr; w; w = w->next) {
		struct ibv_send_wr one = *w, *bad = NULL;
		int ret;

		one.next = NULL;
		if (w->opcode == IBV_WR_RDMA_READ ||
		    w->opcode == IBV_WR_RDMA_WRITE) {
			struct sir_export exp;   /* R6: submit 透传时带出的快照 */
			int have = 0;

			npr_pin_wr(w);                  /* v0.25.0 在飞 pin */
			npr_local_precheck(qp, w);      /* 本地 MR 预检 (不变) */
			if (npr_engine_submit(nce, qp, w, &exp, &have))
				continue;               /* 引擎已提交 */
			/* v0.20.0: 未跟踪远端写 → write 区域 rkey 重写
			 * (R6: 复用 submit 已取的导出快照, 免二次全价 lookup) */
			npr_write_rkey_rewrite(w, &one, have ? &exp : NULL);
		} else if (w->opcode == IBV_WR_ATOMIC_CMP_AND_SWP ||
			   w->opcode == IBV_WR_ATOMIC_FETCH_AND_ADD) {
			/* v0.20.0 (论文 §3.4): 远端原子 → SIR 双端 RPC */
			int rc = npr_atomic_submit(nce, qp, w);

			if (rc == 1)
				continue;               /* RPC 已完成 */
			if (rc < 0) {
				*bad_wr = w;
				return EINVAL;  /* 不可安全下发 NIC */
			}
		} else if (w->sg_list && w->num_sge) {
			npr_pin_wr(w);   /* SEND 源等本地 DMA 页 */
		}
		ret = real(qp, &one, &bad);
		if (ret) {
			*bad_wr = w;
			return ret;
		}
	}
	return 0;
}

/* ---- §4.1 拦截层增强 (v0.14.0): QP/CQ 管理 ----
 *
 * 论文 §4.1 "QP management": 应用创建 QP 时 SymRDMA 预置 3× 队列深度
 * (每个应用 WR 翻译为至多 3 个内部 WR) + 预留控制 MR (64B×depth)。
 * 当前 libnprdma 尚未做 WQE 翻译, 3× 深度为论文要求的预留形态:
 * 应用感知到的深度不变 (传参原值), 底层实际 3×, 应用功能不受影响。
 *
 * 拦截 ibv_create_qp/ibv_destroy_qp/ibv_create_cq/ibv_destroy_cq,
 * 对称管理 + 重入保护 (libibverbs/provider 内部调用透传)。
 *
 * (per-context real post_send 表声明见上文 M2 引擎节)
 */

static __thread int in_create_qp;
static __thread int in_create_cq;

struct ibv_qp *ibv_create_qp(struct ibv_pd *pd,
			     struct ibv_qp_init_attr *init_attr)
{
	static struct ibv_qp *(*real_fn)(struct ibv_pd *,
					 struct ibv_qp_init_attr *);
	struct ibv_qp_init_attr a;
	struct ibv_qp *qp;

	if (!real_fn)
		real_fn = dlvsym(RTLD_NEXT, "ibv_create_qp", "IBVERBS_1.1");
	if (!real_fn)
		return NULL;

	if (in_create_qp)              /* 内部嵌套调用 → 透传 */
		return real_fn(pd, init_attr);

	/* 3× 队列深度 (论文 §4.1) — 应用传参原值不受影响 */
	memcpy(&a, init_attr, sizeof(a));
	a.cap.max_send_wr *= 3;
	a.cap.max_recv_wr *= 3;
	a.cap.max_send_sge *= 1;
	a.cap.max_recv_sge *= 1;

	in_create_qp = 1;
	qp = real_fn(pd, &a);
	in_create_qp = 0;
	if (!qp && (a.cap.max_send_wr != init_attr->cap.max_send_wr ||
		    a.cap.max_recv_wr != init_attr->cap.max_recv_wr)) {
		/* v0.24.6: 3× 深度失败回退原参数 — 大队列应用 (3× 超出设备
		 * 上限/资源) 不因拦截层放大而创建失败 */
		in_create_qp = 1;
		qp = real_fn(pd, init_attr);
		in_create_qp = 0;
		if (qp && debug_on())
			fprintf(stderr,
				"[nprdma] 3× 深度创建失败, 回退原参数 (max_send_wr=%u)\n",
				init_attr->cap.max_send_wr);
	}
	if (qp && debug_on())
		fprintf(stderr,
			"[nprdma] ibv_create_qp → 深度 %u→%u (3×, 论文 §4.1)\n",
			init_attr->cap.max_send_wr, a.cap.max_send_wr);
	/* §4.1 post_send / M2 poll_cq 拦截: 此时 provider ops 已就位
	 * (QP 由 provider 创建), 替换 context->ops 函数指针 → 内联
	 * ibv_post_send/ibv_poll_cq 经本包装。(open_device 时替换过早:
	 * provider 可能未设 ops, 默认实现递归 — 实测)
	 * D8: 每 context 一表项; 原指针非本包装才替换, 防自递归。 */
	if (qp) {
		struct symrdma_ctx_entry *e;
		struct npr_ctx_entry *ne;
		int found = 0;

		pthread_mutex_lock(&lock);
		/* F3: 引擎表 (ne) 先于 dce 表获取 — 引擎的 real_post_send
		 * 必须在 ops 替换前从原指针捕获 (v0.18.1 漏设 → 引擎跟踪 op
		 * 经 NULL 函数指针跳 0x0 段错误, L13 gdb 定位) */
		ne = npr_ctx_get(qp->context);
		for (e = ctx_list; e; e = e->next)
			if (e->ctx == qp->context) {
				found = 1;
				break;
			}
		if (!found &&
		    qp->context->ops.post_send != symrdma_post_send) {
			e = calloc(1, sizeof(*e));
			if (e) {
				e->ctx = qp->context;
				e->real_post_send = qp->context->ops.post_send;
				e->next = ctx_list;
				ctx_list = e;
				if (ne && !ne->real_post_send)
					ne->real_post_send = e->real_post_send;
				qp->context->ops.post_send = symrdma_post_send;
				if (debug_on())
					fprintf(stderr,
						"[nprdma] 替换 context->ops.post_send (论文 §4.1 内联函数拦截)\n");
			}
		} else if (found && e && ne && !ne->real_post_send) {
			/* 同 context 已有 dce 表项 (首个 QP 建于他处/早期版本): 补齐引擎表 */
			ne->real_post_send = e->real_post_send;
		}
		/* M2: poll_cq 同法替换 (每 context 一次) */
		if (ne && !ne->real_poll_cq &&
		    qp->context->ops.poll_cq != symrdma_poll_cq) {
			ne->real_poll_cq = qp->context->ops.poll_cq;
			qp->context->ops.poll_cq = symrdma_poll_cq;
			if (debug_on())
				fprintf(stderr,
					"[nprdma] 替换 context->ops.poll_cq (M2 CQ 拦截)\n");
		}
		pthread_mutex_unlock(&lock);
	}
	return qp;
}

int ibv_destroy_qp(struct ibv_qp *qp)
{
	static int (*real_fn)(struct ibv_qp *);
	int ret;

	if (!real_fn)
		real_fn = dlvsym(RTLD_NEXT, "ibv_destroy_qp", "IBVERBS_1.1");
	if (!real_fn)
		return -1;
	ret = real_fn(qp);
	if (debug_on())
		fprintf(stderr, "[nprdma] ibv_destroy_qp → %d\n", ret);
	return ret;
}

struct ibv_cq *ibv_create_cq(struct ibv_context *context, int cqe,
			     void *cq_context, struct ibv_comp_channel *channel,
			     int comp_vector)
{
	static struct ibv_cq *(*real_fn)(struct ibv_context *, int, void *,
					 struct ibv_comp_channel *, int);
	struct ibv_cq *cq;
	int cqe_x3;

	if (!real_fn)
		real_fn = dlvsym(RTLD_NEXT, "ibv_create_cq", "IBVERBS_1.1");
	if (!real_fn)
		return NULL;

	if (in_create_cq)
		return real_fn(context, cqe, cq_context, channel, comp_vector);

	/* CQ 容量同步 3× (论文 §4.1: 与 QP 3× 深度配套, 否则 QP 创建
	 * 因 max_send_wr > CQ 容量而 EINVAL — v0.14.0 实测) */
	cqe_x3 = cqe * 3;
	in_create_cq = 1;
	cq = real_fn(context, cqe_x3, cq_context, channel, comp_vector);
	in_create_cq = 0;
	if (cq) {
		/* M2: 登记跟踪 CQ (poll 拦截按 CQ 过滤) */
		struct npr_ctx_entry *ne = npr_ctx_get(context);

		if (ne)
			npr_cq_get(ne, cq);
		if (debug_on())
			fprintf(stderr,
				"[nprdma] ibv_create_cq → cqe %d→%d (3×, 论文 §4.1)\n",
				cqe, cqe_x3);
	}
	return cq;
}

int ibv_destroy_cq(struct ibv_cq *cq)
{
	static int (*real_fn)(struct ibv_cq *);
	int ret;

	if (!real_fn)
		real_fn = dlvsym(RTLD_NEXT, "ibv_destroy_cq", "IBVERBS_1.1");
	if (!real_fn)
		return -1;
	ret = real_fn(cq);
	if (debug_on())
		fprintf(stderr, "[nprdma] ibv_destroy_cq → %d\n", ret);
	return ret;
}

/* ---- D3: ibv_create_cq_ex 拦截 ----
 *
 * ibv_create_cq_ex 是 static inline (内部调 verbs_context 的
 * create_cq_ex 函数指针), 符号拦截无效 — 拦截 ibv_open_device,
 * 返回后替换 provider 的 verbs_context->create_cq_ex (verbs_context
 * 由 provider 在 open 时分配并填好, 无 legacy ops 的惰性时序问题)。
 * cqe ×3 与普通 create_cq 同 (论文 §4.1 QP 3× 配套)。
 * SRQ: 接收侧 WR 不做翻译, 无需 3×, 不拦截。 */
static struct ibv_cq_ex *(*g_real_create_cq_ex)(
	struct ibv_context *context, struct ibv_cq_init_attr_ex *cq_attr);

static struct ibv_cq_ex *symrdma_create_cq_ex(struct ibv_context *context,
					      struct ibv_cq_init_attr_ex *cq_attr)
{
	struct ibv_cq_init_attr_ex a;

	if (!g_real_create_cq_ex)
		return NULL;
	memcpy(&a, cq_attr, sizeof(a));
	a.cqe *= 3;
	if (debug_on())
		fprintf(stderr, "[nprdma] ibv_create_cq_ex → cqe %u→%u (3×)\n",
			cq_attr->cqe, a.cqe);
	return g_real_create_cq_ex(context, &a);
}

struct ibv_context *ibv_open_device(struct ibv_device *device)
{
	static struct ibv_context *(*real_fn)(struct ibv_device *);
	struct verbs_context *vctx;
	struct ibv_context *ctx;

	if (!real_fn)
		real_fn = dlvsym(RTLD_NEXT, "ibv_open_device", "IBVERBS_1.1");
	if (!real_fn)
		return NULL;

	ctx = real_fn(device);
	if (!ctx)
		return NULL;

	/* struct ibv_context 是 verbs_context 的最后一个成员
	 * (verbs.h "Must be last field"), 由此反推扩展结构 */
	vctx = (struct verbs_context *)
		((char *)ctx - offsetof(struct verbs_context, context));
	if (vctx->create_cq_ex) {
		g_real_create_cq_ex = vctx->create_cq_ex;
		vctx->create_cq_ex = symrdma_create_cq_ex;
		if (debug_on())
			fprintf(stderr,
				"[nprdma] 替换 verbs_context->create_cq_ex (D3)\n");
	}
	return ctx;
}
