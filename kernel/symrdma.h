/* SPDX-License-Identifier: GPL-2.0 */
/*
 * symrdma.h — SymRDMA 内核模块内部头文件
 *
 * SymRDMA: Enabling In-Situ Remote Virtual Memory Sharing
 * 基于 IOMMU 的乐观 RDMA，访问未 pin 的应用内存。
 *
 * 核心设计:
 *   - 双 IOVA 范围: 每个 MR 拥有 read_iova 和 write_iova 两个独立的 IOVA 基地址
 *     Read IOVA  → 哨兵页(RO) | 真实PA(RW)
 *     Write IOVA → 黑洞页(WO) | 真实PA(RW)
 *   - MMU notifier 换出时分别映射到哨兵/黑洞（不同 IOVA，不覆盖）
 *   - 惰性换入: 不主动检测换入，通过 REPAIR ioctl 或 RDMA 检测哨兵后触发修复
 *
 * 验证模式 (DOMAIN_VERIFY):
 *   - 自建 IOMMU domain (iommu_domain_alloc)，不绑定 PCI 设备
 *   - 通过 READ_IOVA ioctl 验证 IOMMU 页表正确性
 *   - 生产模式 (DOMAIN_NIC): 附加到 mlx5 NIC 的 IOMMU domain
 */
#ifndef _SYMRDMA_H
#define _SYMRDMA_H

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/slab.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <uapi/asm-generic/ioctl.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/version.h>
#include <linux/iommu.h>
#include <linux/pci.h>
#include <linux/mmu_notifier.h>
#include <linux/hashtable.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>    /* 驻留重映射工作项 */
#include <linux/stacktrace.h>   /* notifier 取证栈回溯 */
#include <linux/sched.h>        /* TASK_COMM_LEN */
#include <linux/mutex.h>
#include <linux/kref.h>
#include <linux/atomic.h>
#include <linux/idr.h>
#include <asm/page.h>

/* ---- 哨兵 & 黑洞页 ---- */
#define SYMRDMA_SENTINEL_MAGIC      0xdeadbeef

/* 每 256B TLP chunk 粒度检查 (论文 §3.1.1) */
#define SYMRDMA_TLP_CHUNK_SIZE      256

/* 哨兵/黑洞 与 seqlock 的切换阈值 (论文 §3.1.2) */
#define SYMRDMA_SENTINEL_THRESHOLD  4096  /* 4KB */

/* 版本号常量 (论文 §3.1.2): 奇数=驻留, 偶数=缺失 */
#define SYMRDMA_VERSION_INIT_RESIDENT  1
#define SYMRDMA_VERSION_INIT_ABSENT    0

/*
 * Write MR IOVA 偏移量: write_iova = read_iova + 此偏移
 * 使用 32GB 确保 Read 和 Write IOVA 范围不会在 IOMMU domain 中重叠。
 * 在验证模式下 IOMMU domain 是空的，不会冲突。
 */
#define SYMRDMA_MR_WRITE_OFFSET     (1UL << 35)  /* 32GB */

/* ---- IOMMU domain 模式 ---- */
enum symrdma_domain_mode {
	SYMRDMA_DOMAIN_VERIFY = 0,  /* 自建 domain，用于验证测试 */
	SYMRDMA_DOMAIN_NIC    = 1,  /* 附加到 mlx5 NIC 的 domain */
};

/* ---- /dev/symrdma ioctl 定义 ---- */
#define SYMRDMA_IOC_MAGIC  'S'

enum symrdma_remap_mode {
	SYMRDMA_REMAP_REAL      = 0,
	SYMRDMA_REMAP_SENTINEL  = 1,
	SYMRDMA_REMAP_BLACKHOLE = 2,
};

/* ioctl 命令 */
#define SYMRDMA_IOC_REG_MR      _IOWR(SYMRDMA_IOC_MAGIC, 1, struct symrdma_ioc_reg_mr)
#define SYMRDMA_IOC_DEREG_MR    _IOW(SYMRDMA_IOC_MAGIC,  2, int)
#define SYMRDMA_IOC_REMAP       _IOW(SYMRDMA_IOC_MAGIC,  3, struct symrdma_ioc_remap)
#define SYMRDMA_IOC_GET_IOVA    _IOWR(SYMRDMA_IOC_MAGIC, 4, struct symrdma_ioc_get_iova)
#define SYMRDMA_IOC_READ_IOVA   _IOWR(SYMRDMA_IOC_MAGIC, 5, struct symrdma_ioc_read_iova)
#define SYMRDMA_IOC_REPAIR      _IOWR(SYMRDMA_IOC_MAGIC,  6, struct symrdma_ioc_repair)
#define SYMRDMA_IOC_GET_VERSION _IOWR(SYMRDMA_IOC_MAGIC,  7, struct symrdma_ioc_get_version)
/* 论文 §3.1.2 Version MR: 版本表绑定到用户 pinned 页 → 注册为普通 MR,
 * 远端可 RDMA 直读 (替代 CPU ioctl 查询)。cmd 8 。 */
#define SYMRDMA_IOC_SET_VERSION_PAGE _IOW(SYMRDMA_IOC_MAGIC, 8, struct symrdma_ioc_set_version_page)
/* flush-before-unmap 屏障 (论文 §3.2 临时 pin 语义):
 * PIN_PAGES — 把本地缓冲页标记为在飞 (GUP pin 引用 + IOMMU 保持真实 PA),
 * notifier 对在飞页延迟哨兵化/版本翻转 (消除 unmap→map 窗口与在飞 DMA
 * 的相撞源, L14 access_err/corrupt 与 L15 Phase B 竞态的同源根因);
 * UNPIN_PAGES — 释放 pin 并补完延迟转换 (PTE 已换出 → 哨兵/黑洞 + 版本
 * 翻转; PA 变化 → 重映射新 PA)。len=0 的 UNPIN = 释放该 MR 全部 pin。
 * cmd 9/10 。 */
#define SYMRDMA_IOC_PIN_PAGES   _IOWR(SYMRDMA_IOC_MAGIC, 9, struct symrdma_ioc_pin)
#define SYMRDMA_IOC_UNPIN_PAGES _IOWR(SYMRDMA_IOC_MAGIC, 10, struct symrdma_ioc_pin)
/* 区间批量修复 (改进方向, 论文 §3.2 全跨度修复):
 * 单次 ioctl 修复 [page_idx, page_idx+npages) — 整段批量 GUP + gather
 * 批量 IOTLB flush (逐页 ioctl 为 ~7-10µs/页, 主要开销是每页
 * 2 次 strict unmap flush)。out: npages = 实际修复页数 (GUP 前缀语义,
 * 部分成功时 < 入参; 0 页成功返回 -EAGAIN)。cmd 11。 */
#define SYMRDMA_IOC_REPAIR_RANGE _IOWR(SYMRDMA_IOC_MAGIC, 11, struct symrdma_ioc_repair_range)

/* MAPBENCH (cmd 12): 组粒度重映射微基准 — L19 对同一满组
 * (512 页, 2MB 对齐) 依次实测三形态映射/撤销成本 (B 轴量化):
 *   mode 0 =  逐页形态 (unmap_fast+map_atomic 逐页, 16 页/块 sync)
 *   mode 1 = sg 段批 (整段 unmap_fast + iommu_map_sg_atomic run 合并
 *            + 单次 sync — Phase 1 路径)
 *   mode 2 = 2MB 超页单条 map_atomic/unmap (+ 恢复) — Phase 2 上界
 * 前置: 组为逐页形态且 512 页全 RESIDENT (orig_pa 在位; 调用方先
 * REPAIR_RANGE 或注册后由内核降级)。out: ns_total = 所有 iter 计时
 * 之和, map_ops = 完成 iter 数。 */
#define SYMRDMA_IOC_MAPBENCH _IOWR(SYMRDMA_IOC_MAGIC, 12, struct symrdma_ioc_mapbench)

/* ioctl 参数结构体 */

/* REG_MR: 注册一个 IOMMU 内存区域 */
struct symrdma_ioc_reg_mr {
	u64     va_start;       /* in:  用户空间 VA 起始地址 */
	u64     len;            /* in:  长度 (字节) */
	int     mr_id;          /* out: 分配的 MR id */
};

/* SET_VERSION_PAGE (论文 §3.1.2 Version MR):
 * 把版本表绑定到用户 pinned 页 (每页 4 字节版本号) — 版本号由内核
 * notifier/REPAIR 经 kmap_atomic 写入, 用户侧将同一页注册为普通 MR
 * (REMOTE_READ) → 远端可 one-sided RDMA 直读版本表。
 * version_va 须 mlock (防换出); version_len = 版本表页数 (每页 1024
 * 个 4B 版本;  多页化, 0 = 按 npages 计算)。 */
struct symrdma_ioc_set_version_page {
	int             mr_id;
	u64             version_va;     /* in: 用户版本表 VA (4B/页版本号) */
	unsigned long   version_len;    /* in: 版本表页数 (0 = 自动) */
};

/* REMAP: 重映射单个页面 */
struct symrdma_ioc_remap {
	int             mr_id;
	unsigned long   page_idx;
	int             mode;   /* 0=REAL, 1=SENTINEL, 2=BLACKHOLE */
};

/* GET_IOVA: 获取某页的读写 IOVA 地址 */
struct symrdma_ioc_get_iova {
	int             mr_id;
	unsigned long   page_idx;
	u64             read_iova;      /* out */
	u64             write_iova;     /* out */
};

/* READ_IOVA: 通过 IOMMU 读取 4 字节 (Level 1 验证核心接口) */
struct symrdma_ioc_read_iova {
	int             mr_id;
	u64             iova;           /* in:  要读取的 IOVA 地址 */
	size_t          offset;         /* in:  页内偏移 (须 4 字节对齐) */
	u32             value;          /* out: 读取到的 4 字节值 */
};

/* REPAIR: 显式修复一个页面 (换入检测) */
struct symrdma_ioc_repair {
	int             mr_id;
	unsigned long   page_idx;
};

/* REPAIR_RANGE: in mr_id/page_idx/npages; out npages = 实际
 * 修复页数 (部分成功 < 入参; 内部按 SYMRDMA_REPAIR_RANGE_MAX 分块)。 */
struct symrdma_ioc_repair_range {
	int             mr_id;
	unsigned long   page_idx;
	unsigned long   npages;
};

/* MAPBENCH (cmd 12): mode 0/1/2 见 SYMRDMA_IOC_MAPBENCH 注释 */
enum symrdma_mapbench_mode {
	SYMRDMA_MB_PERPAGE = 0,   /* 逐页形态基线 */
	SYMRDMA_MB_SG      = 1,   /* Phase 1: 段批 unmap + sg 映射 */
	SYMRDMA_MB_SUPER   = 2,   /* Phase 2: 2MB 超页单条映射 */
};

struct symrdma_ioc_mapbench {
	int             mr_id;
	unsigned long   page_idx;    /* in: 组首页号 (须 512 对齐) */
	unsigned long   iters;       /* in: 迭代次数 (>0) */
	int             mode;        /* in: enum symrdma_mapbench_mode */
	u64             ns_total;    /* out: 计时总和 (ns) */
	unsigned long   map_ops;     /* out: 完成 iter 数 */
};

/* 区间修复单次 ioctl 页数上限 (内核侧内部分块, 调用方可传任意 npages);
 * pages 数组 4096×8B = 32KB (kvcalloc)。 */
#define SYMRDMA_REPAIR_RANGE_MAX  4096

/* PIN_PAGES/UNPIN_PAGES (flush-before-unmap 屏障):
 * 本地缓冲 DMA 在飞 pin。va/len 按页取整并裁剪到 MR 范围; UNPIN 的
 * len=0 语义为释放该 MR 全部 pin 区间 (用户态预算淘汰用)。 */
struct symrdma_ioc_pin {
	int             mr_id;
	u64             va;             /* in: 用户 VA 起始 */
	u64             len;            /* in: 字节 (UNPIN 时 0 = 全部) */
};

/* GET_VERSION: 读取某页的版本号 (论文 §3.1.2 remote seqlock)
 * 奇数=驻留, 偶数=缺失。P1: 用户态 seqlock 检查通道。
 * 注: 当前为 CPU 侧读取; 真正的远端 RDMA 读版本表需 mmap 元数据页 (P2)。 */
struct symrdma_ioc_get_version {
	int             mr_id;
	unsigned long   page_idx;
	u32             version;        /* out */
};

/* ---- 前向声明 ---- */
struct symrdma_dev;
struct symrdma_mr;
struct symrdma_page_entry;
struct symrdma_mm_state;

/* ----  notifier 取证与驻留重映射 (外部页失效源调查) ----
 *
 * 背景 (发现): 测试床存在外部页失效源 (EDR 代理嫌疑,
 * mlocked 匿名页仍被周期性 invalidate ≈5 次/s) → 旧 notifier 对任何
 * invalidate_range_start 一律哨兵化+版本翻转, 与引擎预修复的
 * unmap→map 窗口相撞 → 4MB 写 LOC_PROT。
 *
 * 取证: invalidate_range_start 记录 (comm/pid/range/调用栈) 到环形
 * 缓冲, /proc/symrdma 可读 — 用于定位失效源调用者。
 * 驻留重映射 (论文 §3.1.1 语义修正): start 仍立即哨兵化 (旧 PA 防
 * 悬挂), 但把 range 记入 pending; invalidate_range_end 排空并调度
 * 工作项探测 PTE — 页仍驻留 (迁移/COW/NUMA/PROTNONE) 则直接重映射
 * 新真实 PA + 版本恢复奇数, 不再制造哨兵-修复循环; 真换出 (GUP
 * FOLL_NOFAULT 失败) 保持哨兵, 由 REPAIR 兑底。
 */
#define SYMRDMA_NOTIF_RING_SIZE  64   /* 取证环形缓冲条数 */
#define SYMRDMA_NOTIF_STACK_DEPTH 6   /* 每事件回溯帧数 */

struct symrdma_notif_event {
	u64           jiffies;
	u32           pid;
	u32           tgid;
	u32           npages;                     /* range 覆盖页数 */
	u32           nr_stack;                   /* 有效帧数 */
	unsigned long start;
	unsigned long end;
	unsigned long stack[SYMRDMA_NOTIF_STACK_DEPTH];
	char          comm[TASK_COMM_LEN];
};

/* start 记录 → end 排空 → 工作项驻留重映射的区间表 */
#define SYMRDMA_PENDING_NR 16
struct symrdma_pending_range {
	unsigned long start, end;
};

/* ----  flush-before-unmap 屏障 (在飞页 pin) ----
 *
 * 论文 §3.2 临时 pin 语义的实现载体: 用户态 (P1 库 _p 变体 / libnprdma
 * 引擎) 在本地缓冲参与 DMA 前调 PIN_PAGES; 内核 GUP 取页引用并标记
 * 在飞。GUP 引用保证物理页在 pin 期间不被回收/复用 (PTE 仍可被换出,
 * L3-10 语义), 因此 notifier 对在飞页**延迟**哨兵化是安全的 — IOMMU
 * 保持真实 PA, 无 unmap→map 窗口 (L14 access_err 根因), 无黑洞吸收
 * (L14 corrupt "整页零" 根因), 无版本翻转 (远端 seqlock 无假失效)。
 * UNPIN/注销时探测 PTE 补完延迟转换。
 *
 * pin 以 MR 为域粘性保持 (预算封顶), 用户态以位图缓存镜像内核状态 —
 * 稳态零 syscall; 预算满 (-ENOSPC) 时用户态 UNPIN(len=0) 全量释放后
 * 重试。内核绝不在用户态背后自动淘汰 (缓存一致性归用户态)。
 */
/* 每 MR pin 页数预算 (8192 页 = 32MB; 套件最大单 MR 4MB, 余量充分) */
#define SYMRDMA_PIN_BUDGET_PAGES  8192

/* 单个 pin 区间 (mr->pin_list; st->lock 保护) */
struct symrdma_pin_node {
	unsigned long           idx0;       /* 起始页号 (MR 内) */
	unsigned long           nr;         /* 页数 */
	struct page             **pages;    /* GUP 引用数组 (nr 个) */
	struct list_head        node;
};

/* ---- 每个 (dev, mm) 一个 notifier ---- */
struct symrdma_mm_state {
	struct mmu_notifier     mn;         /* 唯一的 notifier */
	struct symrdma_dev      *dev;       /* 所属设备 (统计计数器用) */
	struct mm_struct        *mm;        /* 地址空间 (引用由 mmu_notifier 管理) */
	struct list_head        mr_list;    /* 该 mm 下的 MR 链表 */
	spinlock_t              lock;       /* 保护 mr_list */
	struct list_head        node;       /* dev->mm_states 链表节点 */
	int                     mr_count;   /* 活跃 MR 数 (归零时释放) */
	/* 历史: st 生命周期引用 — 每个 attached MR 持 1 份附着
	 * 引用 (attach init/get; 拆卸时由 unlink 执行者 put); ioctl 数据路径
	 * 经 symrdma_mm_state_get (mm_state_lock 内原子 get) 临时持有。
	 * 归零 → symrdma_mm_state_release: cancel_work_sync + kfree_rcu。
	 * 闭合: DEREG 摘最后 MR 的 kfree_rcu(st) 与同进程在飞 ioctl (持 mr
	 * kref 但裸持 st 指针) 的 st->lock 使用窗口 — UNPIN 锁外探测段
	 * (mmap_read_lock + 逐页 follow_page) 毫秒级, 可跨 RCU 宽限期。 */
	struct kref             ref;
	bool                    detached;   /* detach 已接管清理 — 5.11/5.12
	                                     * 的 mmu_notifier_unregister 会重入 ops->release
	                                     * (语义变更在 5.13+), release 据此 no-op 防
	                                     * 双重释放/毒指针写 (soft lockup 根因) */
	/* 驻留重映射 (lock 保护 pending_*; work_queued 与
	 * schedule_work 同锁内原子 — 防 release/cancel 竞态 UAF) */
	struct symrdma_pending_range pending[SYMRDMA_PENDING_NR];
	int                     pending_head;
	int                     notif_depth;  /* start 嵌套深度 */
	bool                    work_queued;
	struct work_struct      resident_work;
	struct rcu_head         rcu;        /* §4.1 release 回调 kfree_rcu 延迟释放 */
};

/* ---- 全局设备状态 ---- */
struct symrdma_dev {
	struct pci_dev          *pdev;          /* mlx5 PCI 设备 */
	struct iommu_domain     *iommu_domain;  /* IOMMU domain */
	struct device           *dev;           /* &pdev->dev 或 NULL(verify模式) */
	int                     domain_mode;    /* DOMAIN_VERIFY 或 DOMAIN_NIC */

	/* 哨兵页: 填充 0xdeadbeef，用于 Read MR 故障检测 */
	struct page             *sentinel_page;
	u64                     sentinel_pa;    /* 物理地址 */

	/* 黑洞页: 吸收写入，用于 Write MR 故障吸收 */
	struct page             *blackhole_page;
	u64                     blackhole_pa;

	/* IOMMU 组粒度 (2MB) 映射 — 2MB 哨兵/黑洞**区** (512 页),
	 * 服务全缺失组的单条 2MB 超页映射 (G1: 组降级后逐页仍映射单页,
	 * sentinel_pa/blackhole_pa 等值检查对降级页保持有效)。
	 * 区域分配失败 (order-9 碎片化) → huge_ok=0, 全回退逐页 (现状)。 */
	struct page             *sentinel_region;
	u64                     sentinel_region_pa;
	struct page             *blackhole_region;
	u64                     blackhole_region_pa;
	int                     huge_ok;   /* iommu_huge 参数 && 区域就位 */
	int                     repair_sg; /* repair_sg 参数: 0=NO_SG (逐页交错) */
	int                     demote_fail_grp; /* L19 注入: 组降级首页模拟失败 (-1=关) */

	/* 活跃 MR 列表 (IOMMU 级别) */
	struct list_head        mr_list;
	spinlock_t              mr_lock;
	int                     mr_count;

	/* 旧预留 pfn pin 哈希表已由区间制 pin (symrdma_pin.c)
	 * 取代 — 无调用方, 移除 (历史 注记的预留需求已由本机制承接) */

	/* per-mm notifier 状态 — 每个 mm 只注册一个 notifier */
	struct list_head        mm_states;
	spinlock_t              mm_state_lock;

	/* MR id → mr 指针映射 (供 /dev/symrdma ioctl 使用) */
	struct idr              mr_idr;
	int                     mr_id_counter;

	/* (mn_attach "查找/创建 + notifier 注册"全流程互斥 —
	 * 注册失败清理期间并发 attach 不得把 MR 挂入待销毁的 mm_state */
	struct mutex            attach_lock;

	/* /dev/symrdma */
	struct miscdevice       miscdev;

	/* /proc/symrdma */
	struct proc_dir_entry   *proc_entry;

	/* 统计计数器 (P0: swap-out 真实触发验证) */
	struct {
		atomic64_t notifier_calls;     /* mmu_notifier 回调次数 */
		atomic64_t pages_swapped_out;  /* 换出重映射页数 */
		atomic64_t repair_ok;          /* REPAIR 成功次数 */
		atomic64_t repair_fail;        /* REPAIR 失败次数 (-EAGAIN) */
		atomic64_t process_exits;      /* 进程退出触发的 notifier release 次数 (§4.1) */
		atomic64_t released_mrs;       /* 进程退出时自动释放的 MR 数 (§4.1) */
		/* 外部页失效源取证/驻留重映射 */
		atomic64_t notif_events;       /* 取证记录数 */
		atomic64_t resident_restored;  /* 驻留失效恢复数 (迁移/COW/NUMA 等) */
		atomic64_t resident_absent;    /* 确认真缺失 (保持哨兵) */
		atomic64_t pending_overflow;   /* pending 表溢出次数 */
		/* flush-before-unmap 屏障 */
		atomic64_t pin_pages;          /* 当前在飞 pin 页数 (预算封顶) */
		atomic64_t pin_ok;             /* PIN ioctl 成功区间数 */
		atomic64_t pin_enospc;         /* 预算满拒给次数 */
		atomic64_t pin_deferred;       /* notifier 延迟哨兵化页数 */
		atomic64_t pin_transitions;    /* unpin 补完的延迟转换页数 */
		/* IOMMU 组粒度映射 */
		atomic64_t huge_resident;      /* 注册提升的驻留组数 (THP/PUD) */
		atomic64_t huge_absent;        /* 注册提升的缺失组数 (哨兵/黑洞区) */
		atomic64_t group_demotes;      /* 组降级次数 (2MB→512×4KB) */
		atomic64_t demote_fail;        /* 降级 GFP_ATOMIC 失败 (fail-closed) */
		atomic64_t group_repromote;   /* 修复路径组重提升次数 (含等价跳过) */
	} stats;

	/* notifier 取证环形缓冲 (invalidate_range_start 写入,
	 * /proc/symrdma 读取 — 始终开启, 事件量级 ≈ 失效频率, 开销可忽略) */
	struct symrdma_notif_event notif_ring[SYMRDMA_NOTIF_RING_SIZE];
	unsigned int              notif_head;
	spinlock_t                notif_lock;

	/* IOMMU 页大小 */
	unsigned long           iommu_pgsize;
};

/* ---- MR 描述符 ---- */
struct symrdma_mr {
	struct list_head        list;       /* dev->mr_list */
	struct list_head        mm_node;    /* mm_state->mr_list */
	struct symrdma_dev      *dev;

	/* 应用可见的 VA 范围 */
	u64                     va_start;
	u64                     va_end;

	/* 双 IOVA 范围 (核心设计)
	 *   read_iova  = va_start (恒等映射，兼容 MTT)
	 *   write_iova = va_start + SYMRDMA_MR_WRITE_OFFSET
	 */
	u64                     read_iova;
	u64                     write_iova;
	u64                     write_iova_offset;

	unsigned long           npages;

	/* 版本表: pinned 内核内存，每页 4 字节 (论文 §3.1.2)
	 *  SET_VERSION_PAGE 后可绑定用户 pinned 页 (version_pages),
	 * 用户侧注册为 MR → 远端 RDMA 直读 (Version MR)。
	 *  多页版本表 (每页 1024 个 4B 版本, 支持 >1024 页 MR)。 */
	u32                     *version_table;
	struct page             **version_pages; /* 用户版本表页数组 (绑定后) */
	unsigned long           version_npages;  /* 版本表覆盖的 MR 页数 */
	unsigned long           version_vt_pages;/* 版本表物理页数 (ceil/1024) */

	/* 所有者进程 */
	struct mm_struct        *mm;

	/* MR id (§4.1 进程退出清理: release 回调需从 idr 移除) */
	int                     mr_id;

	/* (MR 生命周期引用计数 — 初始引用由 idr 持有
	 * (在 idr 中即可被 find)；find_mr 对使用者 kref_get_unless_zero,
	 * 用毕 put；DEREG/release/注销路径移出 idr 后 put，归零时
	 * symrdma_mr_release 释放版本表/页表/mr。消除:
	 * ① 并发 DEREG 同 id 双重释放；② ioctl 持指针期间被释放的 UAF */
	struct kref             ref;

	/* 所属 mm_state (mn_attach 时设置) */
	struct symrdma_mm_state *mm_state;

	/* 并发拆卸仲裁: release 回调 (进程退出) / DEREG ioctl /
	 * 模块退出三条拆卸路径可能并发到达同一 MR — 首个持 dev->mr_lock
	 * 置位者是唯一清理者 (list 摘除 / unmap / kref_put 各恰一次);
	 * 其余路径直接跳过, 防双重 list_del (毒指针写 → SLUB 损坏) 与
	 * 双重 kref_put (引用下溢 → 释放后使用)。 */
	bool                    torn_down;

	/* 逐页 IOMMU 状态 */
	struct symrdma_page_entry *pages;

	/* 组粒度映射状态 (kvzalloc, DIV_ROUND_UP(npages,512) 条;
	 * NULL = 组机制不可用 → 全逐页) */
	struct symrdma_group_entry *groups;

	/* 在飞 pin 区间链表 + 页数计数 (st->lock 保护 — inflight
	 * 计数被 notifier 在同锁下读取; GUP/put_page 等可睡眠操作在锁外) */
	struct list_head        pin_list;
	unsigned long           pinned_pages;
};

/* ----  IOMMU 组粒度 (2MB) 混合映射 ----
 *
 * 关键硬件事实 (5.11
 * intel-iommu 源码实测): dma_pte_clear_range 遇超页 PTE **整片清除**
 * (无 split_large_page) — ① 逐页 unmap 超页映射会静默解除整组 512 页
 * 映射 (状态机崩坏), 故一切 per-page 状态转换路径必须先组降级;
 * ② 降级自身所需"整组撤销"恰好由该行为天然满足 (unmap 2MB 一次到位)。
 *
 * 组模型: groups[] 按 MR 页号 >>9 索引; 仅"2MB VA 对齐且满 512 页"的组
 * 可提升 (头尾残组/混合组恒 GRP_NONE = 逐页, 与现状语义逐字节一致)。
 * 状态转换不变式: 组状态在 st->lock 下读写, 降级为纯映射变换
 * (不动 pages[] 状态/版本号)。 */
#define SYMRDMA_GROUP_SHIFT  9                        /* 512 页 */
#define SYMRDMA_GROUP_PAGES  (1UL << SYMRDMA_GROUP_SHIFT)
#define SYMRDMA_GROUP_SIZE   (SYMRDMA_GROUP_PAGES << PAGE_SHIFT)   /* 2MB */

enum symrdma_group_state {
	GRP_NONE     = 0,   /* 逐页映射 (残组/混合组/已降级) */
	GRP_RESIDENT = 1,   /* 2MB 超页 → 真实 PA (base_pa, 读/写双侧) */
	GRP_ABSENT   = 2,   /* 2MB 超页 → 哨兵区(read)/黑洞区(write) */
};

struct symrdma_group_entry {
	phys_addr_t             base_pa;   /* GRP_RESIDENT: 2MB 对齐真实基址 */
	enum symrdma_group_state state;
};

/* 逐页 IOMMU 状态 */
enum symrdma_page_state {
	PAGE_RESIDENT   = 0,  /* 映射到真实 PA → 正常访问 */
	PAGE_SENTINEL   = 1,  /* 映射到哨兵页 → RDMA 读检测魔数 */
	PAGE_BLACKHOLE  = 2,  /* 映射到黑洞页 → RDMA 写被吸收 */
};

/* 驻留恢复探测失败上限 (恢复工作项对 absent 页的重复探测治理,
 * L14 实测 10s 内 "确认真缺失" 达 4.3M 次: 同一批
 * absent 页在每次工作项重扫中被反复 follow_page 探测。连续探测失败达
 * 上限的页在后续扫描中跳过 — 真换出页本就不是工作项可恢复的对象
 * (换入无 notifier 事件), REPAIR/PIN 是其兑底恢复路径; 页恢复驻留映射
 * 时清零, 回到可探测态)。 */
#define SYMRDMA_PROBE_FAIL_MAX 2

struct symrdma_page_entry {
	phys_addr_t             orig_pa;        /* 原始物理地址 */
	enum symrdma_page_state read_state;     /* Read IOVA 映射状态 */
	enum symrdma_page_state write_state;    /* Write IOVA 映射状态 */
	u16                     inflight;       /* 在飞 pin 覆盖计数
	                                         * (>0 时 notifier 延迟哨兵化,
	                                         *  pin 引用保证 PA 恒有效) */
	u16                     probe_fail;     /* 驻留探测连续失败计数
	                                         * (≥ PROBE_FAIL_MAX 跳过探测,
	                                         *  恢复驻留时清零) */
};

/* ---- 函数声明 ---- */

/* iommu.c */
int  symrdma_iommu_init(struct symrdma_dev *dev, int mode);
void symrdma_iommu_cleanup(struct symrdma_dev *dev);
int  symrdma_iommu_map_page(struct symrdma_dev *dev, unsigned long iova,
			    phys_addr_t pa, int prot);
void symrdma_iommu_unmap_page(struct symrdma_dev *dev, unsigned long iova);
void symrdma_unmap_mr_pages(struct symrdma_dev *dev, struct symrdma_mr *mr,
			    unsigned long npages);   /* R3: 双 IOVA 逐页 unmap */
void symrdma_unmap_mr_pages_touched(struct symrdma_dev *dev,
				    struct symrdma_mr *mr);   /* G1: 注册失败全量清理 */
int  symrdma_gup_write_first(unsigned long va, unsigned long nr,
			     struct page **pages, bool whole_span);   /* R4 */
int  symrdma_map_mr_pages(struct symrdma_dev *dev, struct symrdma_mr *mr,
			  struct mm_struct *mm);
int  symrdma_iommu_read_iova(struct symrdma_dev *dev, struct symrdma_mr *mr,
			     u64 iova, size_t offset, u32 *out);
int  symrdma_repair_page(struct symrdma_dev *dev, struct symrdma_mr *mr,
			 unsigned long page_idx);
int  symrdma_repair_range(struct symrdma_dev *dev, struct symrdma_mr *mr,
			  unsigned long page_idx, unsigned long npages,
			  unsigned long *repaired);   /* */
int  symrdma_group_demote_locked(struct symrdma_dev *dev,
				 struct symrdma_mr *mr, unsigned long grp);   /* */
void symrdma_group_ensure_split_locked(struct symrdma_dev *dev,
				       struct symrdma_mr *mr,
				       unsigned long page_idx);   /* 页所在组超页→降级 */
void symrdma_group_ensure_split_range_locked(struct symrdma_dev *dev,
					     struct symrdma_mr *mr,
					     unsigned long start_idx,
					     unsigned long end_idx);   /* 区间覆盖组批量降级 */
int  symrdma_iommu_mapbench(struct symrdma_dev *dev, struct symrdma_mr *mr,
			    struct symrdma_ioc_mapbench *req);   /* , cmd 12 */
void symrdma_remap_to_sentinel(struct symrdma_dev *dev, struct symrdma_mr *mr,
			       unsigned long start_idx, unsigned long end_idx);
void symrdma_remap_to_blackhole(struct symrdma_dev *dev, struct symrdma_mr *mr,
				unsigned long start_idx, unsigned long end_idx);
int symrdma_remap_to_real(struct symrdma_dev *dev, struct symrdma_mr *mr,
			   unsigned long page_idx, phys_addr_t pa);
phys_addr_t symrdma_va_to_pa(struct page *page, unsigned long va);   /* notifier 驻留重映射复用 */

/* mr.c */
int  symrdma_reg_mr(struct symrdma_dev *dev, struct mm_struct *mm,
		    u64 va_start, u64 len, struct symrdma_mr **out_mr);
bool symrdma_mr_teardown_begin(struct symrdma_dev *dev,
			       struct symrdma_mr *mr);
void symrdma_dereg_mr(struct symrdma_dev *dev, struct symrdma_mr *mr);
void symrdma_mr_release(struct kref *ref);   /* (引用归零回调 */

/* notifier.c */
int  symrdma_mn_attach(struct symrdma_mr *mr);
void symrdma_mn_detach(struct symrdma_mr *mr);
/* 历史: mm_state 生命周期引用 — 附着引用由 attach/detach/release
 * 维护 (每 MR 1 份, unlink 执行者 put); ioctl 数据路径 get/put 临时
 * 引用 (mm_state_lock 内原子, 归零 cancel_work_sync + kfree_rcu)。 */
struct symrdma_mm_state *symrdma_mm_state_get(struct symrdma_mr *mr);
void symrdma_mm_state_put(struct symrdma_mm_state *st);
void symrdma_mm_state_release(struct kref *ref);

/* pin.c —  flush-before-unmap 屏障 (重写原预留 pfn 哈希表:
 * 该表无调用方, 由区间制 pin 取代 — 历史 注记的"跨请求 pin 保持"
 * 需求即本机制) */
int  symrdma_pin_range(struct symrdma_dev *dev, struct symrdma_mr *mr,
		       u64 va, u64 len);
int  symrdma_unpin_range(struct symrdma_dev *dev, struct symrdma_mr *mr,
			 u64 va, u64 len);
void symrdma_pin_release_all(struct symrdma_mr *mr);

/* version.c */
int  symrdma_version_alloc(struct symrdma_mr *mr);
void symrdma_version_init(struct symrdma_mr *mr);
void symrdma_version_free(struct symrdma_mr *mr);
u32  symrdma_version_read(struct symrdma_mr *mr, unsigned long page_idx);
void symrdma_version_set(struct symrdma_mr *mr, unsigned long page_idx, u32 val);
void symrdma_version_inc(struct symrdma_mr *mr, unsigned long page_idx);
int  symrdma_version_bind_user_page(struct symrdma_dev *dev,
				    struct symrdma_mr *mr,
				    unsigned long version_va,
				    unsigned long version_len);

/* 无副作用驻留判定 (iommu.c 导出, version.c 绑定用户页用) */
struct page *symrdma_follow_page_nofault(struct mm_struct *mm, unsigned long va);

/* proc.c */
int  symrdma_proc_init(struct symrdma_dev *dev);
void symrdma_proc_cleanup(struct symrdma_dev *dev);

/* nic.c —— mlx5 NIC 发现与 IOMMU domain 附加 */
struct pci_dev *symrdma_find_mlx5(void);
struct pci_dev *symrdma_find_mlx5_by_bdf(const char *bdf);
bool symrdma_nic_is_passthrough(struct pci_dev *pdev);
int  symrdma_attach_nic_domain(struct symrdma_dev *dev, struct pci_dev *pdev);
void symrdma_detach_nic_domain(struct symrdma_dev *dev);

/* dev.c —— /dev/symrdma 字符设备 */
int  symrdma_dev_init(struct symrdma_dev *dev);
void symrdma_dev_cleanup(struct symrdma_dev *dev);

/* ---- 内联辅助函数 ---- */

/* 检查数据偏移处是否是哨兵魔数 (论文 §3.1.1: 每 256B TLP chunk 检查) */
static inline int page_is_sentinel(const void *data, size_t offset)
{
	u32 val;
	memcpy(&val, data + offset, sizeof(val));
	return val == SYMRDMA_SENTINEL_MAGIC;
}

#endif /* _SYMRDMA_H */
