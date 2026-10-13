/* SPDX-License-Identifier: GPL-2.0 */
/*
 * libsymrdma.c — SymRDMA 用户态库实现 (P1)
 *
 * 乐观 one-sided 读 (论文 §3.1):
 *   - 正常路径: 1 次 RDMA Read, 零 ioctl
 *   - 换出竞态: 检测哨兵/版本变化 → ioctl REPAIR → 重读 (≤3 次)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include "libsymrdma.h"
#include "libsymrdma_internal.h"
/* 库内建 SIR 通道 (远端 MR 自动修复) */
#include "sir.h"
/* 在飞 pin 粘性位图缓存 (共享原语; 需在 libsymrdma.h 的 ioctl
 * 定义之后包含) */
#include "pinbm.h"   /* 共享 pin 位图原语 (sir/ 共享编译单元目录) */
#include "sentinel.h"   /* 哨兵扫描原语 (R2: 与 libnprdma 单一实现) */
#include "vtpages.h"    /* 版本表页数公式 (R7) */

/* ----  flush-before-unmap 屏障 (在飞页 pin, 粘性缓存) ----
 *
 * 论文 §3.2 临时 pin 语义: 本地缓冲参与 DMA (RDMA Read 目标 / Write
 * 源 / 自环远端地址) 前 ioctl PIN_PAGES — 内核 GUP 取页引用并标记在飞,
 * notifier 对在飞页延迟哨兵化 (PA 因引用恒有效): 消除 unmap→map 窗口
 * (L14 access_err 根因) 与哨兵/黑洞吸收 (L14 corrupt "整页零" 根因)。
 *
 * pin 以 (fd, mr_id) 为域粘性保持 (内核 SYMRDMA_PIN_BUDGET_PAGES 封
 * 顶), 本地位图缓存镜像内核状态 → 稳态零 syscall; -ENOSPC → 全量
 * UNPIN(len=0) + 清位图 + 重试一次。SYMRDMA_NO_PIN=1 关闭 (A/B 对照
 * 旧行为)。位图/span 循环原语见 sir/pinbm.h (与 libnprdma 去重)。
 */
struct pin_cache_ent {
	int                      fd;
	int                      mr_id;
	uint64_t                 va_base;    /* MR va_start (= 注册 buf) */
	struct pinbm             bm;         /* 已 pin 位图 (pinbm 原语) */
	struct pin_cache_ent     *next;
};
static struct pin_cache_ent *pin_cache;
static pthread_mutex_t pin_mu = PTHREAD_MUTEX_INITIALIZER;
static int pin_disabled = -1;      /* -1 = 未初始化 */

static int pin_is_disabled(void)
{
	if (pin_disabled < 0)
		pin_disabled = getenv("SYMRDMA_NO_PIN") ? 1 : 0;
	return pin_disabled;
}

static struct pin_cache_ent *pin_cache_get(int fd, int mr_id, uint64_t va_base)
{
	struct pin_cache_ent *e;

	for (e = pin_cache; e; e = e->next)
		if (e->fd == fd && e->mr_id == mr_id)
			return e;
	e = calloc(1, sizeof(*e));
	if (!e)
		return NULL;
	e->fd = fd;
	e->mr_id = mr_id;
	e->va_base = va_base;
	e->next = pin_cache;
	pin_cache = e;
	return e;
}

/* 位图/span 循环原语在 pinbm.h (pinbm_grow/pinbm_set/pinbm_pin_span/
 * pinbm_drop_all); 下方回调把 ioctl 参数组装与共享原语衔接 (* 去重 — 此前与 nprdma.c 各有一份相同实现)。 */

struct pin_ioc_ctx {
	int      fd;
	int      mr_id;
	uint64_t va_base;    /* MR va_start (页号 × PAGE_SIZE → va) */
};

/* PIN_PAGES 单段回调 (pinbm_pin_span 用; 返回非零 = ioctl 失败) */
static int pin_ioc_one(void *ud, unsigned long s, unsigned long n)
{
	struct pin_ioc_ctx *c = ud;
	struct symrdma_ioc_pin p = {
		.mr_id = c->mr_id,
		.va  = c->va_base + (uint64_t)s * SYMRDMA_PAGE_SIZE,
		.len = (unsigned long long)n * SYMRDMA_PAGE_SIZE,
	};

	return ioctl(c->fd, SYMRDMA_IOC_PIN_PAGES, &p) ? -1 : 0;
}

/* UNPIN(len=0) 全量释放回调 (ENOSPC 预算淘汰) */
static void pin_ioc_drop_all(void *ud)
{
	struct pin_ioc_ctx *c = ud;
	struct symrdma_ioc_pin up = { .mr_id = c->mr_id };

	ioctl(c->fd, SYMRDMA_IOC_UNPIN_PAGES, &up);
}

/* pin 一个 span (粘性): 对位图中未 pin 的连续子段逐段 ioctl PIN_PAGES。
 * 循环与 ENOSPC 重试语义在 pinbm.h (去重)。返回 0 = 已覆盖
 * (含缓存命中); -1 = pin 不可用 (调用方降级继续 — 与无屏障行为等价,
 * 不影响正确性语义, 仅保留既有竞态窗口)。 */
static int symrdma_pin_span(struct symrdma_ctx *ctx, int mr_id,
			    uint64_t va_base, uintptr_t va, size_t len)
{
	struct pin_cache_ent *e;
	struct pin_ioc_ctx c = {
		.fd = ctx->fd,
		.mr_id = mr_id,
		.va_base = va_base,
	};
	unsigned long i0, i1;
	int ret;

	if (pin_is_disabled() || !ctx || ctx->fd < 0 || mr_id < 0 || !len)
		return -1;
	if (va < va_base)
		return -1;

	pthread_mutex_lock(&pin_mu);
	e = pin_cache_get(ctx->fd, mr_id, va_base);
	if (!e) {
		pthread_mutex_unlock(&pin_mu);
		return -1;
	}

	i0 = (va - va_base) / SYMRDMA_PAGE_SIZE;
	i1 = (va + len - 1 - va_base) / SYMRDMA_PAGE_SIZE;
	if (pinbm_grow(&e->bm, i1)) {
		pthread_mutex_unlock(&pin_mu);
		return -1;
	}
	ret = pinbm_pin_span(&e->bm, i0, i1, pin_ioc_one, pin_ioc_drop_all, &c);
	pthread_mutex_unlock(&pin_mu);
	return ret;
}

/* 注销清理 (symrdma_mr_deregister 调用) */
static void symrdma_pin_cache_drop(struct symrdma_ctx *ctx, int mr_id)
{
	struct pin_cache_ent *e, **pp;

	if (pin_disabled < 0)
		pin_disabled = getenv("SYMRDMA_NO_PIN") ? 1 : 0;

	pthread_mutex_lock(&pin_mu);
	for (pp = &pin_cache; (e = *pp); pp = &e->next) {
		if (e->fd == ctx->fd && e->mr_id == mr_id) {
			struct symrdma_ioc_pin up = {
				.mr_id = mr_id, .va = 0, .len = 0,
			};

			pinbm_drop_all(&e->bm, ctx->fd, &up);
			*pp = e->next;
			free(e->bm.bm);
			free(e);
			break;
		}
	}
	pthread_mutex_unlock(&pin_mu);
}

/* 本地接收/发送缓冲 pin (_p 变体的 local_mr; 同 precheck 范围守卫,
 *  屏障 — plain read/write 保持  机制语义不 pin) */
SYMRDMA_INTERNAL int symrdma_pin_local_span(struct symrdma_ctx *ctx,
					    struct symrdma_mr *local_mr,
					    const void *local, size_t len)
{
	if (!local_mr || !local_mr->buf || local_mr->remote)
		return -1;
	if ((uintptr_t)local < (uintptr_t)local_mr->buf ||
	    (uintptr_t)local + len >
	    (uintptr_t)local_mr->buf + local_mr->len)
		return -1;
	return symrdma_pin_span(ctx, local_mr->mr_id,
				(uint64_t)(uintptr_t)local_mr->buf,
				(uintptr_t)local, len);
}

/* ---- 打开/关闭 ---- */

int symrdma_open(struct symrdma_ctx *ctx)
{
	ctx->fd = open("/dev/symrdma", O_RDWR);
	if (ctx->fd < 0)
		return -1;
	return 0;
}

void symrdma_close(struct symrdma_ctx *ctx)
{
	if (ctx->fd >= 0)
		close(ctx->fd);
	ctx->fd = -1;
}

/* ---- MR 注册/注销 ---- */

int symrdma_mr_register(struct symrdma_ctx *ctx, struct ibv_pd *pd,
			void *buf, size_t len, struct symrdma_mr *mr)
{
	struct symrdma_ioc_reg_mr reg = {
		.va_start = (unsigned long long)buf,
		.len = (unsigned long long)len,
	};
	struct symrdma_ioc_get_iova iova = { .page_idx = 0 };

	memset(mr, 0, sizeof(*mr));
	mr->mr_id = -1;
	mr->buf = buf;
	mr->len = len;

	if (ioctl(ctx->fd, SYMRDMA_IOC_REG_MR, &reg))
		goto err;
	mr->mr_id = reg.mr_id;

	iova.mr_id = mr->mr_id;
	if (ioctl(ctx->fd, SYMRDMA_IOC_GET_IOVA, &iova))
		goto err;
	mr->read_iova  = iova.read_iova;
	mr->write_iova = iova.write_iova;

	mr->ibv_mr = ibv_reg_mr(pd, buf, len,
				IBV_ACCESS_LOCAL_WRITE |
				IBV_ACCESS_REMOTE_READ |
				IBV_ACCESS_REMOTE_WRITE |
				SYMRDMA_ACCESS_IDENTITY);  /* P4: 按 MR 标记 */
	if (!mr->ibv_mr)
		goto err;

	/* Version MR (论文 §3.1.2) — 见 symrdma_mr_bind_version()。
	 * (不再限 ≤1024 页 —  多页版本表支持任意大小 MR
	 * (原实现对 >1024 页静默回退 ioctl 通道, 与多页支持不一致);
	 * 绑定失败 (如 mlock 受限) 自动回退, 见 bind_version。 */
	symrdma_mr_bind_version(ctx, pd, mr);

	return 0;

err:
	symrdma_mr_deregister(ctx, mr);
	return -1;
}

/*
 * 绑定 Version MR (论文 §3.1.2): 版本表用户 pinned 页,
 * 内核绑定 (SET_VERSION_PAGE) 后经 kmap_atomic 写入; 用户侧注册为
 * SymRDMA MR (REMOTE_READ) → 远端 RDMA 直读版本表。
 * 版本表 ≤ 1 页 (覆盖 ≤ 1024 页 MR); 超限/失败静默回退 ioctl 通道。
 * 供 symrdma_mr_register 与手动注册的调用方 (L4) 复用。
 */
int symrdma_mr_bind_version(struct symrdma_ctx *ctx, struct ibv_pd *pd,
			    struct symrdma_mr *mr)
{
	struct symrdma_ioc_reg_mr reg = {0};
	struct symrdma_ioc_set_version_page sv = {0};
	unsigned long npages, vt_pages, vsize;

	/* 已绑定判断用 version_mr (version_buf 可能未初始化 — 调用方
	 * 未清零 smr 时  段错误实测) */
	if (mr->version_mr)
		return 0;

	/* (修复执行中发现): 失败路径 dereg 前必须归位 — 调用方
	 * memset 后 version_buf_mr_id==0, 若 REG_MR 失败走 fail 会误
	 * dereg mr_id 0 (他人 MR)。 */
	mr->version_buf_mr_id = -1;

	/* 多页版本表 (每页 1024 个 4B 版本, 支持任意大小 MR) */
	npages = mr->len / SYMRDMA_PAGE_SIZE;
	/* R7: 页数公式收敛至 sir/vtpages.h symrdma_vt_pages */
	vt_pages = symrdma_vt_pages(npages);
	vsize = vt_pages * SYMRDMA_PAGE_SIZE;

	mr->version_buf = mmap(NULL, vsize, PROT_READ | PROT_WRITE,
				MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (mr->version_buf == MAP_FAILED) {
		mr->version_buf = NULL;
		return -1;
	}
	memset(mr->version_buf, 0, vsize);
	/* : mlock 失败 (RLIMIT_MEMLOCK 不足; no-pin 环境 =0 必败)
	 * → 版本页可被换出 → notifier 把版本表 MR 的 IOMMU 映射改写为
	 * 哨兵 → 远端直读版本 0xdeadbeef (奇数) 误判驻留。回退: 不绑定
	 * Version MR, symrdma_get_version 自动走 GET_VERSION ioctl 通道。 */
	if (mlock(mr->version_buf, vsize)) {
		fprintf(stderr,
			"  [libsymrdma] mlock 版本表失败 (errno=%d) — 不绑定 Version MR, 回退 ioctl 版本通道\n",
			errno);
		munmap(mr->version_buf, vsize);
		mr->version_buf = NULL;
		return -1;
	}

	/* 版本表页自身也要 SymRDMA IOMMU 映射 (identity MTT
	 * 下远端 DMA 读版本表经 IOMMU 翻译) */
	reg.va_start = (unsigned long long)(uintptr_t)mr->version_buf;
	reg.len = vsize;
	if (ioctl(ctx->fd, SYMRDMA_IOC_REG_MR, &reg))
		goto fail;
	mr->version_buf_mr_id = reg.mr_id;

	sv.mr_id = mr->mr_id;
	sv.version_va = (unsigned long long)(uintptr_t)mr->version_buf;
	sv.version_len = vt_pages;
	if (ioctl(ctx->fd, SYMRDMA_IOC_SET_VERSION_PAGE, &sv))
		goto fail;

	/* Version MR: REMOTE_READ 供远端 one-sided 直读 */
	mr->version_mr = ibv_reg_mr(pd, mr->version_buf, vsize,
				    IBV_ACCESS_REMOTE_READ |
				    SYMRDMA_ACCESS_IDENTITY);
	if (!mr->version_mr)
		goto fail;
	return 0;

fail:
	if (mr->version_buf_mr_id >= 0)
		ioctl(ctx->fd, SYMRDMA_IOC_DEREG_MR, mr->version_buf_mr_id);
	mr->version_buf_mr_id = -1;
	munmap(mr->version_buf, vsize);
	mr->version_buf = NULL;
	return -1;
}

int symrdma_mr_deregister(struct symrdma_ctx *ctx, struct symrdma_mr *mr)
{
	int ret = 0;

	/* 在飞 pin 缓存清理 (远端视图无本地 pin 缓存, 跳过;
	 * 内核 DEREG 也会释放全部 pin, 此处同步位图缓存 + 释放条目) */
	if (!mr->remote)
		symrdma_pin_cache_drop(ctx, mr->mr_id);

	/* 远端视图 — 仅释放本端 scratch (owner 侧 MR 不归本进程) */
	if (mr->remote) {
		if (mr->scratch) {
			struct symrdma_mr *s = mr->scratch;
			void *b = s->buf;

			mr->scratch = NULL;
			ret |= symrdma_mr_deregister(ctx, s);
			if (b)
				munmap(b, SYMRDMA_PAGE_SIZE);
			free(s);
		}
		memset(mr, 0, sizeof(*mr));
		mr->mr_id = -1;
		return ret;
	}

	if (mr->version_mr)
		ret |= ibv_dereg_mr(mr->version_mr);
	mr->version_mr = NULL;
	if (mr->version_buf) {
		/* 版本表页: 注销其 SymRDMA MR + 内核已 put_page (version_free),
		 * 用户侧 munmap */
		if (mr->version_buf_mr_id >= 0)
			ret |= ioctl(ctx->fd, SYMRDMA_IOC_DEREG_MR,
				     mr->version_buf_mr_id);
		mr->version_buf_mr_id = -1;
		/* 多页版本表 (vsize 重算) */
		{
			unsigned long np = mr->len / SYMRDMA_PAGE_SIZE;
			/* R7: symrdma_vt_pages (sir/vtpages.h) */
			unsigned long vs = symrdma_vt_pages(np) * SYMRDMA_PAGE_SIZE;
			munmap(mr->version_buf, vs);
		}
		mr->version_buf = NULL;
	}
	if (mr->ibv_mr)
		ret |= ibv_dereg_mr(mr->ibv_mr);
	mr->ibv_mr = NULL;
	if (mr->mr_id >= 0)
		ret |= ioctl(ctx->fd, SYMRDMA_IOC_DEREG_MR, mr->mr_id);
	mr->mr_id = -1;
	return ret;
}

/* ---- 单页操作 ---- */

int symrdma_repair_page(struct symrdma_ctx *ctx, struct symrdma_mr *mr,
			unsigned long page_idx)
{
	struct symrdma_ioc_repair req = {
		.mr_id = mr->mr_id,
		.page_idx = page_idx,
	};

	return ioctl(ctx->fd, SYMRDMA_IOC_REPAIR, &req) ? -1 : 0;
}

int symrdma_get_version(struct symrdma_ctx *ctx, struct symrdma_mr *mr,
			unsigned long page_idx, uint32_t *version)
{
	struct symrdma_ioc_get_version req = {
		.mr_id = mr->mr_id,
		.page_idx = page_idx,
	};

	/* 绑定 Version MR 后本地直读版本表 (零 ioctl,
	 * 论文 §3.1.2 远端读版本表 8B/页开销的本地形态) */
	if (mr->version_buf) {
		*version = ((uint32_t *)mr->version_buf)[page_idx];
		return 0;
	}

	if (ioctl(ctx->fd, SYMRDMA_IOC_GET_VERSION, &req))
		return -1;
	*version = req.version;
	return 0;
}

/* ---- 内部: 哨兵检测 ---- */

/*
 * 256B TLP chunk 粒度哨兵检测 (论文 §3.1.1): "checking any aligned
 * bytes within each 256 B chunk suffices, checking per page is unsafe" —
 * 读期间换出时, 前几个 TLP 可能是真实数据、后几个是哨兵; 只查首 4
 * 字节会漏检。每 256B chunk 查一个对齐位置即可。
 *
 * R2: 实现收敛至 sir/sentinel.h sentinel_is_hit — 相位感知
 * (引擎  bug 10 语义); base = data[0] 对应的远端地址。lib 路径
 * base 恒页对齐 (read_iova + 页对齐偏移) ⇒ 与旧 phase-0 实现字节级
 * 等价, 隐含前提转显式 (sir/sentinel.h 头注 + test_sentinel_phase)。
 * len<4 前缀逐字节比对 (历史 C2) 与假阳性语义 (版本奇偶兜底) 随迁
 * 共享头, 溯源注释见彼处。
 */
int buf_is_sentinel(const void *data, size_t len, uint64_t base)
{
	return sentinel_is_hit(data, len, base);
}

/* ---- 内部: 单次 RDMA Read (signaled 控制, 论文 §3.1.1 批量用) ---- */
int rdma_read_once_flags(struct ibv_qp *qp, struct ibv_cq *cq,
				void *local, uint32_t lkey,
				uintptr_t remote_addr, uint32_t rkey,
				size_t len, int signaled)
{
	struct ibv_sge sge = {
		.addr   = (uintptr_t)local,
		.length = (uint32_t)len,
		.lkey   = lkey,
	};
	struct ibv_send_wr wr = {0}, *bad_wr = NULL;
	struct ibv_wc wc;
	int n;

	memset(local, 0, len);
	wr.opcode              = IBV_WR_RDMA_READ;
	wr.sg_list             = &sge;
	wr.num_sge             = 1;
	wr.wr.rdma.remote_addr = remote_addr;
	wr.wr.rdma.rkey        = rkey;
	wr.send_flags          = signaled ? IBV_SEND_SIGNALED : 0;

	if (ibv_post_send(qp, &wr, &bad_wr)) {
		fprintf(stderr,
			"  [libsymrdma] READ post_send 失败 errno=%d (%s)\n",
			errno, strerror(errno));
		return -1;
	}
	if (!signaled)
		return 0;   /* unsignaled: 不产生 CQE */
	do {
		n = ibv_poll_cq(cq, 1, &wc);
	} while (n == 0);
	if (n < 0 || wc.status != IBV_WC_SUCCESS) {
		fprintf(stderr,
			"  [libsymrdma] READ 完成异常: n=%d status=%d vendor_err=0x%x byte_len=%u\n",
			n, n > 0 ? (int)wc.status : -1,
			n > 0 ? wc.vendor_err : 0,
			n > 0 ? wc.byte_len : 0);
		return -1;
	}
	return 0;
}

int rdma_read_once(struct ibv_qp *qp, struct ibv_cq *cq,
			  void *local, uint32_t lkey,
			  uintptr_t remote_addr, uint32_t rkey, size_t len)
{
	return rdma_read_once_flags(qp, cq, local, lkey, remote_addr, rkey,
				    len, 1);
}

/* ---- 写区域 MR + one-sided 写 ---- */

int symrdma_write_mr_register(struct ibv_pd *pd, void *buf, size_t len,
			      struct symrdma_mr_write *wmr)
{
	memset(wmr, 0, sizeof(*wmr));
	/* 写区域: REMOTE_WRITE 无 REMOTE_READ + 显式 WREG 标记 (* OFED 补丁据 WREG 位将 MTT 填 VA+偏移) */
	wmr->ibv_mr = ibv_reg_mr(pd, buf, len,
				 IBV_ACCESS_LOCAL_WRITE |
				 IBV_ACCESS_REMOTE_WRITE |
				 SYMRDMA_ACCESS_IDENTITY |
				 SYMRDMA_ACCESS_WREG);  /* P4 + 写区域标记 */
	return wmr->ibv_mr ? 0 : -1;
}

void symrdma_write_mr_deregister(struct symrdma_mr_write *wmr)
{
	if (wmr->ibv_mr)
		ibv_dereg_mr(wmr->ibv_mr);
	wmr->ibv_mr = NULL;
}

/* 底层 RDMA Write — signaled 控制 (论文 §3.1.1 批量 unsignaled 用) */
static int symrdma_write_raw_flags(struct ibv_qp *qp, struct ibv_cq *cq,
				   struct symrdma_mr *mr,
				   struct symrdma_mr_write *wmr,
				   unsigned long page_idx, size_t len,
				   const void *local, uint32_t lkey,
				   int signaled)
{
	struct ibv_sge sge = {
		.addr   = (uintptr_t)local,
		.length = (uint32_t)len,
		.lkey   = lkey,
	};
	struct ibv_send_wr wr = {0}, *bad_wr = NULL;
	struct ibv_wc wc;
	int n;

	wr.opcode              = IBV_WR_RDMA_WRITE;
	wr.sg_list             = &sge;
	wr.num_sge             = 1;
	wr.wr.rdma.remote_addr = mr->read_iova + page_idx * SYMRDMA_PAGE_SIZE;
	wr.wr.rdma.rkey        = wmr->ibv_mr->rkey;
	wr.send_flags          = signaled ? IBV_SEND_SIGNALED : 0;

	if (ibv_post_send(qp, &wr, &bad_wr))
		return -1;
	if (!signaled)
		return 0;   /* unsignaled: 不产生 CQE, 立即返回 */
	do {
		n = ibv_poll_cq(cq, 1, &wc);
	} while (n == 0);
	if (n < 0 || wc.status != IBV_WC_SUCCESS) {
		fprintf(stderr,
			"  [libsymrdma] WRITE 完成异常: n=%d status=%d vendor_err=0x%x\n",
			n, n > 0 ? (int)wc.status : -1,
			n > 0 ? wc.vendor_err : 0);
		return -1;
	}
	return 0;
}

/* 裸 RDMA Write (无验证) — 供底层机制测试与内部验证路径复用 */
int symrdma_write_raw(struct ibv_qp *qp, struct ibv_cq *cq,
			     struct symrdma_mr *mr, struct symrdma_mr_write *wmr,
			     unsigned long page_idx, size_t len,
			     const void *local, uint32_t lkey)
{
	return symrdma_write_raw_flags(qp, cq, mr, wmr, page_idx, len,
				       local, lkey, 1);
}

/*
 * 大写路径 seqlock 验证 (论文 §3.1.1 图 5c "Large-Write workflow with
 * Remote Seqlocks"，(加固)：
 *
 *   写前: 逐页读版本 — 任一覆盖页偶数 (缺失) → REPAIR 该页 → 重试
 *   写 : 单次 signaled RDMA Write (write_iova，缺失页被黑洞吸收)
 *   写后: 逐页比对版本 — 任一页 v2 != v1 或偶数 → 写期间发生换出竞态
 *         (写入可能被黑洞吸收而丢失) → REPAIR → 重写重验 (≤3 次)
 *
 * 与读路径的差别: 覆盖页数无 64 页上限 (v1 数组堆分配)；版本表未绑定
 * 的 MR 逐页 GET_VERSION ioctl (正确但慢，建议绑定 Version MR)。
 */
static int symrdma_write_seqlock(struct symrdma_ctx *ctx, struct ibv_qp *qp,
				 struct ibv_cq *cq, struct symrdma_mr *mr,
				 struct symrdma_mr_write *wmr,
				 unsigned long page_idx, size_t len,
				 const void *local, uint32_t lkey)
{
	unsigned long npages = (len + SYMRDMA_PAGE_SIZE - 1) / SYMRDMA_PAGE_SIZE;
	unsigned long mr_pages = mr->len / SYMRDMA_PAGE_SIZE;
	uint32_t *v1;
	int attempt, p;

	if (page_idx >= mr_pages || npages > mr_pages - page_idx) {
		fprintf(stderr,
			"  [libsymrdma] write seqlock: 页范围越界 (%lu+%lu > %lu)\n",
			page_idx, npages, mr_pages);
		errno = EINVAL;
		return -1;
	}

	v1 = malloc(npages * sizeof(*v1));
	if (!v1)
		return -1;

	for (attempt = 0; attempt < SYMRDMA_MAX_RETRIES; attempt++) {
		int changed = 0;
		uint32_t v2;

		/* 写前: 任一覆盖页缺失 → REPAIR (论文图 5c) */
		for (p = 0; p < (int)npages; p++) {
			if (symrdma_get_version(ctx, mr, page_idx + p, &v1[p]))
				goto out;
			if (!(v1[p] & 1)) {
				fprintf(stderr,
					"  [libsymrdma] write seqlock: 页 %lu 缺失 (v=%u) → REPAIR\n",
					page_idx + p, v1[p]);
				if (symrdma_repair_page(ctx, mr, page_idx + p))
					goto out;
				changed = 1;
			}
		}
		if (changed)
			continue;

		if (symrdma_write_raw(qp, cq, mr, wmr, page_idx, len,
				      local, lkey))
			goto out;

		/* 写后: 版本比对 — 任一页变化/偶数 → 竞态，REPAIR 后整轮重写 */
		changed = 0;
		for (p = 0; p < (int)npages; p++) {
			if (symrdma_get_version(ctx, mr, page_idx + p, &v2))
				goto out;
			if (v2 != v1[p] || !(v2 & 1)) {
				fprintf(stderr,
					"  [libsymrdma] write seqlock: 页 %lu 版本变化 %u→%u → REPAIR → 重写\n",
					page_idx + p, v1[p], v2);
				if (symrdma_repair_page(ctx, mr, page_idx + p))
					goto out;
				changed = 1;
				break;
			}
		}
		if (!changed) {
			free(v1);
			return 0;   /* 写落在驻留页，验证通过 */
		}
	}

out:
	free(v1);
	errno = EAGAIN;
	return -1;
}

/*
 * one-sided RDMA Write + 验证 (论文 §3.1.1 图 5b/5c/():
 *   len ≤ 4KB: 写后读回 read_iova 比对 — 读到魔数 (黑洞吸收/哨兵) →
 *              REPAIR → 重写重读 (≤3 次); 读到写入数据 → 落地成功
 *   len > 4KB: seqlock — 写前逐页版本 (偶数→REPAIR)、写后版本比对
 *              (变化/偶数 → REPAIR → 重写，≤3 次)
 *
 * 底层"黑洞吸收"机制本身由 L5 用 symrdma_write_raw 验证 (哨兵零污染);
 * 本函数提供论文语义: 写缺失页最终必须落地 (检测 → 修复 → 重写)。
 */
int symrdma_write(struct symrdma_ctx *ctx, struct ibv_qp *qp,
		  struct ibv_cq *cq, struct symrdma_mr *mr,
		  struct symrdma_mr_write *wmr,
		  unsigned long page_idx, size_t len,
		  const void *local, uint32_t lkey)
{
	/* 远端 MR — 经 SIR 通道自动修复 (owner ioctl REPAIR +
	 * 重放/内联); wmr 仅本地形态使用 */
	if (mr->remote)
		return symrdma_write_remote(ctx, qp, cq, mr, page_idx, len,
					    local, lkey);

	/* 写源快照: 辅助 Read 复用调用者 local (有 IOMMU 映射) —
	 * 不能用内部栈 buffer (identity 下无映射 → DMA fault 实测) */
	uint8_t snapshot[SYMRDMA_SENTINEL_THRESHOLD];
	unsigned long npages = (len + SYMRDMA_PAGE_SIZE - 1) / SYMRDMA_PAGE_SIZE;
	int attempt;

	/* 越界防护 (历史 C1 顺带加固): len=0 或页范围超出 MR */
	if (len == 0 || page_idx >= mr->len / SYMRDMA_PAGE_SIZE ||
	    npages > mr->len / SYMRDMA_PAGE_SIZE - page_idx) {
		errno = EINVAL;
		return -1;
	}

	if (len >= sizeof(snapshot)) {
		/* 大写路径: seqlock 版本验证 (论文图 5c, 历史 C1 修复;
		 * 论文口径 "≥4KB 走 seqlock", 原 > 使 4KB
		 * 整页写走哨兵 — 与 remote 读路径的 len >= THRESHOLD 统一) */
		return symrdma_write_seqlock(ctx, qp, cq, mr, wmr, page_idx,
					     len, local, lkey);
	}

	memcpy(snapshot, local, len);

	for (attempt = 0; attempt < SYMRDMA_MAX_RETRIES; attempt++) {
		if (symrdma_write_raw(qp, cq, mr, wmr, page_idx, len,
				      local, lkey))
			return -1;

		/* 辅助 Read: 读回 read_iova (真实/哨兵) 到 local (已映射) */
		if (rdma_read_once(qp, cq, (void *)local, lkey,
				   mr->read_iova + page_idx * SYMRDMA_PAGE_SIZE,
				   mr->ibv_mr->rkey, len))
			return -1;
		if (!memcmp(local, snapshot, len))
			return 0;   /* 落地成功 */

		/* 读到哨兵 (黑洞吸收) → 恢复快照 → REPAIR → 重写重读 */
		if (buf_is_sentinel(local, len,
				    mr->read_iova + page_idx * SYMRDMA_PAGE_SIZE)) {
			fprintf(stderr,
				"  [libsymrdma] write 验证: 页 %lu 命中哨兵 → REPAIR → 重写\n",
				page_idx);
			memcpy((void *)local, snapshot, len);
			if (symrdma_repair_page(ctx, mr, page_idx))
				return -1;
			continue;
		}
		/* 数据不匹配且非哨兵 — 不可恢复 */
		fprintf(stderr,
			"  [libsymrdma] write 验证失败: 页 %lu 数据不匹配\n",
			page_idx);
		errno = EIO;
		return -1;
	}

	errno = EAGAIN;
	return -1;
}

/*
 * 批量 one-sided Write (论文 §3.1.1 批量 unsignaled Write):
 *   - 连续小写 (len ≤ 4KB) 前 N-1 条用 unsignaled WR (无 CQE),
 *     最后 1 条 signaled → 单次 CQE 表示批次完成 — 摊销 PCIe
 *     Write→Read flush (论文: ~1.5µs/次, 小消息吞吐 -90%)
 *   - 验证 (辅助 Read) 同样批量: N-1 条 unsignaled + 1 signaled
 *   - 逐页比对快照; 哨兵 (黑洞吸收) → REPAIR → 重写重读 (≤3 次)
 *
 * local:  npages*len 连续写源 (已映射)
 * verify: npages*len 已映射 buffer (辅助 Read 读回目标, 不能覆盖源)
 * 返回: 0 全部落地; <0 失败 (errno=EAGAIN/EIO)
 */
int symrdma_write_batch(struct symrdma_ctx *ctx, struct ibv_qp *qp,
			struct ibv_cq *cq, struct symrdma_mr *mr,
			struct symrdma_mr_write *wmr,
			const unsigned long *pages, int npages,
			size_t len, const void *local, uint32_t lkey,
			void *verify, uint32_t verify_lkey)
{
	uint8_t *snap;
	int attempt, i, ret = -1;

	if (npages <= 0 || len > SYMRDMA_SENTINEL_THRESHOLD) {
		errno = EINVAL;
		return -1;
	}

	/* §3.3 重叠内存启发式: batch 内重叠页 (重复) 需依赖排队 —
	 * 当前实现要求页独立 (重复页请分次 batch 保证顺序) */
	for (i = 0; i < npages; i++) {
		int j;
		for (j = i + 1; j < npages; j++) {
			if (pages[i] == pages[j]) {
				errno = EINVAL;
				return -1;
			}
		}
	}

	snap = malloc((size_t)npages * len);
	if (!snap)
		return -1;
	memcpy(snap, local, (size_t)npages * len);

	for (attempt = 0; attempt < SYMRDMA_MAX_RETRIES; attempt++) {
		/* 批量写: N-1 unsignaled + 最后 1 signaled (其 CQE = 批次完成) */
		for (i = 0; i < npages; i++) {
			if (symrdma_write_raw_flags(qp, cq, mr, wmr, pages[i],
						    len,
						    (const char *)local + i * len,
						    lkey, i == npages - 1))
				goto out;
		}

		/* 批量辅助 Read: 读回 read_iova → verify */
		for (i = 0; i < npages; i++) {
			if (rdma_read_once_flags(qp, cq,
						 (char *)verify + i * len,
						 verify_lkey,
						 mr->read_iova + pages[i] * SYMRDMA_PAGE_SIZE,
						 mr->ibv_mr->rkey, len,
						 i == npages - 1))
				goto out;
		}

		/* 逐页比对: 哨兵 (黑洞吸收) 页 → REPAIR → 重写 (signaled) → 重读 */
		for (i = 0; i < npages; i++) {
			const void *got = (const char *)verify + i * len;

			if (!memcmp(got, snap + i * len, len))
				continue;
			if (buf_is_sentinel(got, len,
					    mr->read_iova + pages[i] * SYMRDMA_PAGE_SIZE)) {
				fprintf(stderr,
					"  [libsymrdma] write_batch: 页 %lu 命中哨兵 → REPAIR → 重写\n",
					pages[i]);
				if (symrdma_repair_page(ctx, mr, pages[i]))
					goto out;
				memcpy((char *)local + i * len, snap + i * len, len);
				if (symrdma_write_raw_flags(qp, cq, mr, wmr, pages[i],
							    len,
							    (const char *)local + i * len,
							    lkey, 1))
					goto out;
				if (rdma_read_once(qp, cq, (char *)verify + i * len,
						   verify_lkey,
						   mr->read_iova + pages[i] * SYMRDMA_PAGE_SIZE,
						   mr->ibv_mr->rkey, len))
					goto out;
				continue;
			}
			fprintf(stderr,
				"  [libsymrdma] write_batch 验证失败: 页 %lu 数据不匹配\n",
				pages[i]);
			errno = EIO;
			goto out;
		}

		/* 最终验证 (重写重读后) */
		ret = 0;
		for (i = 0; i < npages; i++) {
			if (memcmp((const char *)verify + i * len,
				   snap + i * len, len) != 0) {
				fprintf(stderr,
					"  [libsymrdma] write_batch 重写后仍不匹配: 页 %lu\n",
					pages[i]);
				ret = -1;
				errno = EIO;
				break;
			}
		}
		if (ret == 0)
			break;
	}

	if (ret != 0)
		errno = EAGAIN;
out:
	free(snap);
	return ret;
}

/* ---- §3.3 Relaxed Ordering  ---- */

void symrdma_inflight_record(struct symrdma_inflight *inf,
			     uintptr_t start, uintptr_t end)
{
	inf->start = start;
	inf->end = end;
	inf->active = 1;
}

void symrdma_inflight_clear(struct symrdma_inflight *inf)
{
	inf->active = 0;
}

int symrdma_inflight_overlap(const struct symrdma_inflight *inf,
			     uintptr_t start, uintptr_t end)
{
	if (!inf->active)
		return 0;
	/* 半开区间 [start, end) 重叠判定 */
	return start < inf->end && inf->start < end;
}

/* ---- 本地页故障预检 (论文 §3.1.1) ---- */

/* 预检 local buffer 覆盖页: 版本表本地直读 (论文 10ns/页),
 * 偶数 (缺失) → REPAIR local 页。返回 0 全部驻留/已修复。
 * (自动定位 local 在 local_mr 内的起始页 (原实现假定
 * local 从 MR 页 0 开始, local 位于 MR 中部时会修错页); local
 * 越出 local_mr 覆盖范围则跳过预检 (等价 NULL 行为)。 */
static int precheck_local_pages(struct symrdma_ctx *ctx,
				struct symrdma_mr *local_mr,
				const void *local, size_t len)
{
	unsigned long pstart, np, p;
	int attempts;

	if (!local_mr || !local_mr->buf)
		return 0;
	if ((uintptr_t)local < (uintptr_t)local_mr->buf ||
	    (uintptr_t)local + len >
	    (uintptr_t)local_mr->buf + local_mr->len)
		return 0;

	/* 在飞 pin 屏障 — 本地 DMA 页 pin (含 swap-in + 重映射
	 * + 版本恢复)。屏障后覆盖页版本恒为奇数 (notifier 延迟翻转),
	 * 下面的版本预检成为 pin 关闭/降级时的兑底。仅 _p 变体到达此处 —
	 * plain read/write 保持机制可观测语义 (L4/L5/L9 断言依赖)。 */
	symrdma_pin_local_span(ctx, local_mr, local, len);

	pstart = ((uintptr_t)local - (uintptr_t)local_mr->buf) /
		 SYMRDMA_PAGE_SIZE;
	np = (len + SYMRDMA_PAGE_SIZE - 1) / SYMRDMA_PAGE_SIZE;
	for (attempts = 0; attempts < SYMRDMA_MAX_RETRIES; attempts++) {
		int need = 0;

		for (p = 0; p < np; p++) {
			uint32_t v;

			if (symrdma_get_version(ctx, local_mr, pstart + p, &v))
				return -1;
			if (!(v & 1)) {
				fprintf(stderr,
					"  [libsymrdma] 预检: local 页 %lu 缺失 (v=%u) → REPAIR\n",
					pstart + p, v);
				if (symrdma_repair_page(ctx, local_mr, pstart + p))
					return -1;
				need = 1;
			}
		}
		if (!need)
			return 0;
	}
	errno = EAGAIN;
	return -1;
}

/*
 * symrdma_read + 本地页故障预检 (论文 §3.1.1): 发出前检查 local 接收页
 * 版本 (本地直读版本表, 10ns/页) — 偶数 (缺失) 先 REPAIR local → 避免
 * DMA 写 local 被黑洞吸收后读回全 0 的静默错误与 1 RTT 重试。
 * local_mr = local 所属 SymRDMA MR (可为 NULL = 无预检, 等价 symrdma_read)。
 */
int symrdma_read_p(struct symrdma_ctx *ctx, struct ibv_qp *qp,
		   struct ibv_cq *cq, struct symrdma_mr *mr,
		   unsigned long page_idx, size_t len,
		   void *local, uint32_t lkey,
		   struct symrdma_mr *local_mr)
{
	if (precheck_local_pages(ctx, local_mr, local, len))
		return -1;
	return symrdma_read(ctx, qp, cq, mr, page_idx, len, local, lkey);
}

/*
 * symrdma_write + 本地页故障预检 (写源页): 源缺失 → DMA 读源走哨兵
 * → 写入魔数; 预检先修复源页再发写。
 */
int symrdma_write_p(struct symrdma_ctx *ctx, struct ibv_qp *qp,
		    struct ibv_cq *cq, struct symrdma_mr *mr,
		    struct symrdma_mr_write *wmr,
		    unsigned long page_idx, size_t len,
		    const void *local, uint32_t lkey,
		    struct symrdma_mr *local_mr)
{
	if (precheck_local_pages(ctx, local_mr, local, len))
		return -1;
	return symrdma_write(ctx, qp, cq, mr, wmr, page_idx, len, local, lkey);
}
