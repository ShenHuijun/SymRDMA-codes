/*
 * test_odp_compare.c — SymRDMA Level 15: 硬件 ODP 同机对照 (论文 §5.2.1 Fig 11 / A.7)
 *
 * 动机 (): "SymRDMA 比 ODP 快 1–2 个数量级" 此前只有量级推断
 * (REPAIR ≈21µs vs 文献 ms 级), 无同机实测对照。CX-6 Dx rc_odp_caps 完整
 * 支持 READ/WRITE → 本测试在同一 NIC 上直接对比。
 *
 * 模式:
 *   test_odp_compare local [-d dev]    Phase A: 单机 loopback — 本地 ODP fault
 *                                      (论文 A.7: Local ODP Fault ~29µs 量级)
 *                                      vs SymRDMA 本地修复路径 (symrdma_read)
 *   test_odp_compare server [-d dev]   Phase B 服务端: 持 pinned/ODP/SymRDMA
 *                                      三个 MR, TCP 交换 QP 参数, 接受
 *                                      RES(触摸+修复)/PO(换出) 控制命令
 *   test_odp_compare client -c IP [-g gid] [-d dev] [-p port]
 *                                      Phase B 客户端: 远程 ODP fault 延迟
 *                                      (论文头条: initiator 停顿 ms–s 级)
 *                                      vs SymRDMA detect→repair→re-read 全链路
 *
 * ODP minor fault = 从未触摸的 MAP_NORESERVE 页; ODP major fault = 驻留页
 * madvise(PAGEOUT) (mincore/READ_IOVA 确认就位)。
 * SymRDMA 远程路径 = 裸读哨兵检测 + 控制 REPAIR + 重读 (SIR 同构近似,
 * SIR 控制 QP 只会更快)。
 *
 * 退出码: 0=PASS 1=FAIL (2=ODP 不可用, 部分跳过仍 0/1)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <infiniband/verbs.h>

#include "../lib/libsymrdma.h"

#ifndef MADV_PAGEOUT
#define MADV_PAGEOUT 21
#endif
#ifndef MADV_NOHUGEPAGE
#define MADV_NOHUGEPAGE 15
#endif
#ifndef IBV_QP_MTU
#define IBV_QP_MTU  IBV_QP_PATH_MTU
#endif
#ifndef IBV_ACCESS_ON_DEMAND
#define IBV_ACCESS_ON_DEMAND (1 << 6)
#endif

#define DEF_PORT     18715
#define PINNED_MB    8
#define ODP_MB       64
#define SYM_MB       48     /* minor 单调游标需 ≥20MB/半区 (4 尺寸行不重置) */
#define CQ_DEPTH     64
#define MAX_SIZE     (256 * 1024)
#define N_BASE       100
#define N_FAULT_BIG  10
#define GID_DEFAULT_LOOPBACK 0
#define GID_DEFAULT_NET      5
#define ODP_TIMEOUT_US 60000000ULL   /* ODP 长停顿观测窗口 (60s) */

static const size_t cmp_sizes[] = { 256, 4096, 65536, 256 * 1024 };
/* (诊断期曾改为 {256,64K,4K,256K} 判定楔死跟随性: 死亡点随 ODP 环
 * 移至 64K 行首 — 与尺寸无关, 确证 server 侧 mlx5 ODP stalled-QP 楔死;
 * 现已按尺寸重建连接, 顺序无关, 恢复升序。) */
#define NSIZES ((int)(sizeof(cmp_sizes) / sizeof(cmp_sizes[0])))
static const char *size_tag[] = { "256B", "4KB", "64KB", "256KB" };

/* minor 单调游标 (跨尺寸行不重置 — 否则后续行读到已驻留页, 测不到 fault) */
static uint64_t g_odp_minor_cursor, g_sym_minor_cursor;

/* L9 私有 READ_IOVA ioctl (sym 区 IOMMU 级就位检查) */
struct symrdma_ioc_read_iova_l15 {
	int mr_id;
	unsigned long long iova;
	unsigned long offset;
	unsigned int value;
};
#define SYMRDMA_IOC_READ_IOVA_L15 _IOWR(SYMRDMA_IOC_MAGIC, 5, struct symrdma_ioc_read_iova_l15)

/* ---- 通用帮助 (同 L9/L14) ---- */

static uint64_t now_us(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (uint64_t)tv.tv_sec * 1000000 + tv.tv_usec;
}


/* 环境适配 (双机测试床 双口卡实测): 机器按 PCI function 枚举出多个 mlx5
 * 设备, 取第一个可能命中 DOWN 口 — QP 建在死口上 DMA 走错 IOMMU domain
 * (DMAR fault reason 06)。优先选 port1 状态 ACTIVE 的设备; 查询失败保持
 * 原行为 (取第一个)。 */
static int mlx5_port_active(const char *name)
{
	char path[256];
	char buf[64];
	FILE *f;

	snprintf(path, sizeof(path),
		 "/sys/class/infiniband/%s/ports/1/state", name);
	f = fopen(path, "r");
	if (!f)
		return 1;
	if (!fgets(buf, sizeof(buf), f)) {
		fclose(f);
		return 1;
	}
	fclose(f);
	return strstr(buf, "ACTIVE") != NULL;
}

static struct ibv_device *find_rdma_device(const char *prefer)
{
	struct ibv_device **dev_list;
	struct ibv_device *dev = NULL;
	int num, i;

	dev_list = ibv_get_device_list(&num);
	if (!dev_list || num == 0)
		return NULL;
	for (i = 0; i < num; i++) {
		const char *name = ibv_get_device_name(dev_list[i]);

		if ((prefer && strstr(name, prefer)) ||
		    (!prefer && strstr(name, "mlx5"))) {
			if (!prefer || mlx5_port_active(name)) {
				dev = dev_list[i];
				break;
			}
			/* 无 prefer 且非 ACTIVE 的 mlx5 仅作回退, 继续找 ACTIVE 口 */
		}
		if (!dev)
			dev = dev_list[i];
	}
	return dev;
}

static struct ibv_qp *create_qp_rc(struct ibv_pd *pd, struct ibv_cq *cq)
{
	struct ibv_qp_init_attr attr = {0};
	struct ibv_qp *qp;
	struct ibv_qp_attr m = {0};

	attr.send_cq = cq;
	attr.recv_cq = cq;
	attr.qp_type = IBV_QPT_RC;
	attr.cap.max_send_wr = CQ_DEPTH;
	attr.cap.max_recv_wr = 8;
	attr.cap.max_send_sge = 1;
	attr.cap.max_recv_sge = 1;
	qp = ibv_create_qp(pd, &attr);
	if (!qp)
		return NULL;
	m.qp_state = IBV_QPS_INIT;
	m.pkey_index = 0;
	m.port_num = 1;
	m.qp_access_flags = IBV_ACCESS_REMOTE_READ | IBV_ACCESS_LOCAL_WRITE;
	if (ibv_modify_qp(qp, &m, IBV_QP_STATE | IBV_QP_PKEY_INDEX |
			  IBV_QP_PORT | IBV_QP_ACCESS_FLAGS)) {
		ibv_destroy_qp(qp);
		return NULL;
	}
	return qp;
}

static int qp_to_rts(struct ibv_qp *qp, uint32_t dest_qpn, int gid_idx,
		     const union ibv_gid *dgid, uint32_t rq_psn)
{
	struct ibv_qp_attr attr = {0};
	struct ibv_port_attr port;
	uint8_t mtu;

	/* b: path_mtu 硬编码 4096 在 active_mtu=1024 的测试床
	 * (host-a/8 实测) 上导致多包 (≥4KB) RDMA 读响应首包超端口 MTU
	 * 被丢弃 — client 永收不到响应 → 2.6s 重传耗尽 RESP_TIMEOUT。
	 * 曾被误诊为 "mlx5 ODP stalled-QP 楔死" (假象: 不过是 ≥4KB 行
	 * 永远失败, 与 ODP 无关; 256B 单包恒通过)。perftest 用
	 * min(active_mtu, 请求值) 故 4KB 一直正常。此处动态取
	 * min(port.active_mtu, 4096), 单机 loopback 形态同样成立。 */
	if (ibv_query_port(qp->context, 1, &port))
		return -1;
	mtu = port.active_mtu < IBV_MTU_4096 ? port.active_mtu : IBV_MTU_4096;

	attr.qp_state = IBV_QPS_RTR;
	attr.path_mtu = mtu;
	attr.dest_qp_num = dest_qpn;
	attr.rq_psn = rq_psn;
	attr.max_dest_rd_atomic = 1;
	attr.min_rnr_timer = 12;
	attr.ah_attr.port_num = 1;
	attr.ah_attr.is_global = 1;
	attr.ah_attr.grh.sgid_index = gid_idx;
	attr.ah_attr.grh.hop_limit = 1;
	attr.ah_attr.grh.dgid = *dgid;
	if (ibv_modify_qp(qp, &attr, IBV_QP_STATE | IBV_QP_MTU |
			  IBV_QP_DEST_QPN | IBV_QP_RQ_PSN |
			  IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER |
			  IBV_QP_AV))
		return -1;
	memset(&attr, 0, sizeof(attr));
	attr.qp_state = IBV_QPS_RTS;
	attr.sq_psn = 0;
	attr.timeout = 14;
	attr.retry_cnt = 7;
	attr.rnr_retry = 7;
	attr.max_rd_atomic = 1;
	if (ibv_modify_qp(qp, &attr, IBV_QP_STATE | IBV_QP_SQ_PSN |
			  IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT |
			  IBV_QP_RNR_RETRY | IBV_QP_MAX_QP_RD_ATOMIC))
		return -1;
	return 0;
}

/* posted RDMA Read + 等完成; 超时返回 -2 (ODP 长停顿观测窗口) */
static void qp_state_dump(struct ibv_qp *qp, const char *tag)
{
	struct ibv_qp_attr attr;
	struct ibv_qp_init_attr init;

	if (qp && !ibv_query_qp(qp, &attr, IBV_QP_STATE, &init))
		fprintf(stderr, "  [dbg] %s: QP state=%d\n", tag,
			attr.qp_state);
}

static int rdma_read_to(struct ibv_qp *qp, struct ibv_cq *cq,
			void *local, uint32_t lkey,
			uint64_t remote_addr, uint32_t rkey,
			size_t len, uint64_t timeout_us)
{
	struct ibv_sge sge = {
		.addr = (uintptr_t)local, .length = (uint32_t)len, .lkey = lkey,
	};
	struct ibv_send_wr wr = {0}, *bad = NULL;
	struct ibv_wc wc;
	uint64_t deadline = now_us() + timeout_us;
	int n;

	wr.opcode = IBV_WR_RDMA_READ;
	wr.sg_list = &sge;
	wr.num_sge = 1;
	wr.wr.rdma.remote_addr = remote_addr;
	wr.wr.rdma.rkey = rkey;
	wr.send_flags = IBV_SEND_SIGNALED;
	if (ibv_post_send(qp, &wr, &bad))
		return -1;
	do {
		n = ibv_poll_cq(cq, 1, &wc);
		if (n == 0 && now_us() > deadline)
			return -2;
	} while (n == 0);
	if (n < 0 || wc.status != IBV_WC_SUCCESS) {
		fprintf(stderr, "  [rdma] Read 异常 status=%d vendor_err=0x%x\n",
			n > 0 ? (int)wc.status : n,
			n > 0 ? wc.vendor_err : 0);
		return -1;
	}
	return 0;
}

/* ---- TCP 帮助 ---- */

static int tcp_listen(int port)
{
	int fd = socket(AF_INET, SOCK_STREAM, 0), one = 1;
	struct sockaddr_in a = {0};

	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	a.sin_family = AF_INET;
	a.sin_addr.s_addr = INADDR_ANY;
	a.sin_port = htons((uint16_t)port);
	if (bind(fd, (struct sockaddr *)&a, sizeof(a)) || listen(fd, 1)) {
		close(fd);
		return -1;
	}
	return fd;
}

static int tcp_dial(const char *ip, int port)
{
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in a = {0};

	a.sin_family = AF_INET;
	a.sin_port = htons((uint16_t)port);
	inet_pton(AF_INET, ip, &a.sin_addr);
	if (connect(fd, (struct sockaddr *)&a, sizeof(a))) {
		close(fd);
		return -1;
	}
	return fd;
}

static int send_all(int fd, const void *buf, size_t len)
{
	const char *p = buf;

	while (len) {
		ssize_t n = send(fd, p, len, 0);

		if (n <= 0)
			return -1;
		p += n;
		len -= (size_t)n;
	}
	return 0;
}

static int recv_all(int fd, void *buf, size_t len)
{
	char *p = buf;

	while (len) {
		ssize_t n = recv(fd, p, len, 0);

		if (n <= 0)
			return -1;
		p += n;
		len -= (size_t)n;
	}
	return 0;
}

static int send_line(int fd, const char *s)
{
	return send_all(fd, s, strlen(s));
}

static int recv_line(int fd, char *buf, size_t cap)
{
	size_t off = 0;

	while (off + 1 < cap) {
		char c;

		if (recv_all(fd, &c, 1))
			return -1;
		if (c == '\n')
			break;
		buf[off++] = c;
	}
	buf[off] = 0;
	return 0;
}

/* ---- 统计 ---- */

static void stats_report(const uint64_t *lat, int n, uint64_t *avg,
			 uint64_t *med, uint64_t *max)
{
	uint64_t tmp[N_BASE];
	uint64_t sum = 0, hi = 0;
	int i, j, k;

	for (i = 0; i < n; i++) {
		sum += lat[i];
		if (lat[i] > hi)
			hi = lat[i];
		tmp[i] = lat[i];
	}
	for (j = 0; j < n; j++)
		for (k = j + 1; k < n; k++)
			if (tmp[k] < tmp[j]) {
				uint64_t t = tmp[j];

				tmp[j] = tmp[k];
				tmp[k] = t;
			}
	*avg = sum / (unsigned)n;
	*med = tmp[n / 2];
	*max = hi;
}

/* VMA Swap kb (L3 语义)。注: mincore 对 swap-cache 页误报 resident
 * (PTE 已解除但页仍在 swap cache) — 不可作 PAGEOUT 就位判据 (8 号机实测) */
static long vma_swap_kb(const void *addr)
{
	FILE *f = fopen("/proc/self/smaps", "r");
	char line[256];
	unsigned long rs = 0, re = 0;
	long v = -1;

	if (!f)
		return -1;
	while (fgets(line, sizeof(line), f)) {
		if (sscanf(line, "%lx-%lx", &rs, &re) == 2)
			continue;
		long sv;
		if (sscanf(line, "Swap: %ld", &sv) == 1 &&
		    (unsigned long)addr >= rs && (unsigned long)addr < re) {
			v = sv;
			break;
		}
	}
	fclose(f);
	return v;
}

/* ODP major 就位: madvise PAGEOUT + 等 VMA Swap 增量 ≥ len/1024 kB */
static int wait_swapped_smaps(unsigned char *buf, size_t len)
{
	long base = vma_swap_kb(buf);
	long want;
	int tries;

	if (base < 0)
		return -1;
	want = base + (long)(len / 1024);
	madvise(buf, len, MADV_PAGEOUT);
	for (tries = 0; tries < 200; tries++) {
		long now = vma_swap_kb(buf);

		if (now >= want)
			return 0;
		if (tries % 20 == 19)
			madvise(buf, len, MADV_PAGEOUT);
		usleep(100000);
	}
	return -1;
}

/* ============ 共享参数块 (TCP 传递) ============ */

struct wire_params {
	uint32_t qpn, psn;
	uint32_t pad;
	union ibv_gid gid;
	uint64_t pinned_addr, odp_addr, sym_addr;
	uint32_t pinned_rkey, odp_rkey, sym_rkey;
	uint32_t sym_pages, odp_pages;
};

/* ============ Phase A: 单机 loopback ============ */

static int phase_a_run(const char *devname)
{
	struct symrdma_ctx ctx;
	struct ibv_device *dev;
	struct ibv_context *ibctx = NULL;
	struct ibv_pd *pd = NULL;
	struct ibv_cq *cq = NULL;
	struct ibv_qp *qp = NULL;
	struct symrdma_mr smr = { .mr_id = -1 };
	unsigned char *pin_buf = MAP_FAILED, *odp_buf = MAP_FAILED, *sym_buf = MAP_FAILED;
	unsigned char *local = MAP_FAILED;
	struct ibv_mr *pin_mr = NULL, *odp_mr = NULL, *local_mr = NULL;
	int local_ioctl_id = -1;
	size_t pin_len = (size_t)PINNED_MB << 20;
	size_t odp_len = (size_t)ODP_MB << 20;
	size_t sym_len = (size_t)SYM_MB << 20;
	uint64_t lat[N_BASE];
	uint64_t avg, med, mx;
	int i, s, rc = 0, odp_ok = 1;

	printf("=== SymRDMA Level 15 Phase A (单机 loopback): ODP vs SymRDMA ===\n");
	if (symrdma_open(&ctx)) {
		fprintf(stderr, "[dbg] /dev/symrdma 打开失败\n");
		return 1;
	}
	dev = find_rdma_device(devname);
	if (!dev || !(ibctx = ibv_open_device(dev)) || !(pd = ibv_alloc_pd(ibctx)) ||
	    !(cq = ibv_create_cq(ibctx, CQ_DEPTH, NULL, NULL, 0))) {
		fprintf(stderr, "[dbg] 设备初始化失败\n");
		rc = 1;
		goto out;
	}
	qp = create_qp_rc(pd, cq);
	if (!qp) { fprintf(stderr, "[dbg] create_qp 失败\n"); rc = 1; goto out; }
	{
		union ibv_gid g;
		struct ibv_port_attr pa;

		if (ibv_query_gid(ibctx, 1, 0, &g) || ibv_query_port(ibctx, 1, &pa) ||
		    qp_to_rts(qp, qp->qp_num, 0, &g, 0)) {
			fprintf(stderr, "[dbg] 自环 QP 失败\n");
			rc = 1;
			goto out;
		}
	}

	/* pinned 基线 MR (前 1MB 供基线读) */
	pin_buf = mmap(NULL, pin_len, PROT_READ | PROT_WRITE,
		       MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (pin_buf == MAP_FAILED) { rc = 1; goto out; }
	memset(pin_buf, 0xAB, pin_len);
	pin_mr = ibv_reg_mr(pd, pin_buf, pin_len,
			    IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ |
			    IBV_ACCESS_REMOTE_WRITE);
	if (!pin_mr) { fprintf(stderr, "[dbg] pinned reg 失败\n"); rc = 1; goto out; }

	/* ODP MR (NORESERVE, 不 pin; minor 从 32MB 起顺序推进) */
	odp_buf = mmap(NULL, odp_len, PROT_READ | PROT_WRITE,
		       MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (odp_buf == MAP_FAILED) { rc = 1; goto out; }
	madvise(odp_buf, odp_len, MADV_NOHUGEPAGE);
	odp_mr = ibv_reg_mr(pd, odp_buf, odp_len,
			    IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ |
			    IBV_ACCESS_ON_DEMAND);
	if (!odp_mr) {
		printf("  [SKIP] ODP 注册失败 (errno=%d) — ODP 列退化为 SKIP\n", errno);
		odp_ok = 0;
	}

	/* SymRDMA MR: 前半驻留 0xAB (major 用), 后半从未触摸 (minor 用) */
	sym_buf = mmap(NULL, sym_len, PROT_READ | PROT_WRITE,
		       MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (sym_buf == MAP_FAILED) { rc = 1; goto out; }
	memset(sym_buf, 0xAB, sym_len / 2);
	{
		struct symrdma_ioc_reg_mr reg = {
			.va_start = (unsigned long long)sym_buf,
			.len = sym_len,
		};
		struct symrdma_ioc_get_iova iova_req;

		if (ioctl(ctx.fd, SYMRDMA_IOC_REG_MR, &reg)) {
			fprintf(stderr, "[dbg] sym REG_MR 失败 errno=%d\n", errno);
			rc = 1;
			goto out;
		}
		iova_req.mr_id = reg.mr_id;
		iova_req.page_idx = 0;
		if (ioctl(ctx.fd, SYMRDMA_IOC_GET_IOVA, &iova_req)) {
			fprintf(stderr, "[dbg] GET_IOVA 失败\n");
			rc = 1;
			goto out;
		}
		smr.mr_id = reg.mr_id;
		smr.buf = sym_buf;
		smr.len = sym_len;
		smr.read_iova = iova_req.read_iova;
		smr.write_iova = iova_req.write_iova;
		smr.ibv_mr = ibv_reg_mr(pd, sym_buf, sym_len,
					IBV_ACCESS_LOCAL_WRITE |
					IBV_ACCESS_REMOTE_READ |
					IBV_ACCESS_REMOTE_WRITE |
					SYMRDMA_ACCESS_IDENTITY);
		if (!smr.ibv_mr) { fprintf(stderr, "[dbg] sym ibv_reg_mr 失败\n"); rc = 1; goto out; }
		if (symrdma_mr_bind_version(&ctx, pd, &smr)) {
			fprintf(stderr, "[dbg] bind_version 失败\n");
			rc = 1;
			goto out;
		}
	}

	/* 本地接收 buffer (双注册 + mlock) */
	local = mmap(NULL, MAX_SIZE, PROT_READ | PROT_WRITE,
		     MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (local == MAP_FAILED) { rc = 1; goto out; }
	memset(local, 0x5A, MAX_SIZE);
	mlock(local, MAX_SIZE);
	{
		struct symrdma_ioc_reg_mr reg = {
			.va_start = (unsigned long long)local,
			.len = MAX_SIZE,
		};

		if (ioctl(ctx.fd, SYMRDMA_IOC_REG_MR, &reg)) {
			fprintf(stderr, "[dbg] local REG_MR 失败\n");
			rc = 1;
			goto out;
		}
		local_ioctl_id = reg.mr_id;
		local_mr = ibv_reg_mr(pd, local, MAX_SIZE,
				      IBV_ACCESS_LOCAL_WRITE |
				      SYMRDMA_ACCESS_IDENTITY);
		if (!local_mr) { fprintf(stderr, "[dbg] local ibv_reg_mr 失败\n"); rc = 1; goto out; }
	}

	printf("\n| 尺寸 | pinned avg/med µs | ODP 基线 avg/med | ODP minor avg/med/max | "
	       "Sym minor avg/med/max | ODP major avg/med/max | Sym major avg/med/max |\n");
	printf("|------|-------------------|------------------|-----------------------|"
	       "-----------------------|-----------------------|-----------------------|\n");

	for (i = 0; i < NSIZES; i++) {
		size_t size = cmp_sizes[i];
		size_t rsize = (size + SYMRDMA_PAGE_SIZE - 1) / SYMRDMA_PAGE_SIZE *
			       SYMRDMA_PAGE_SIZE;   /* 页粒度对齐 */
		int npg = (int)(rsize / SYMRDMA_PAGE_SIZE);
		int n_big = (size <= 4096) ? 10 : N_FAULT_BIG;
		uint64_t minor_base;

		/* pinned 基线 */
		for (s = 0; s < N_BASE; s++) {
			uint64_t t0 = now_us();
			int r = rdma_read_to(qp, cq, local, local_mr->lkey,
					     (uint64_t)(uintptr_t)pin_buf,
					     pin_mr->lkey, size, 1000000);

			lat[s] = now_us() - t0;
			if (r) { fprintf(stderr, "pinned 读失败\n"); rc = 1; goto out; }
		}
		stats_report(lat, N_BASE, &avg, &med, &mx);
		printf("| %s | %6llu/%6llu ", size_tag[i],
		       (unsigned long long)avg, (unsigned long long)med);

		/* ODP 基线 (resident: 先触摸首 1MB) */
		if (odp_ok) {
			memset(odp_buf, 0xAB, 1 << 20);
			for (s = 0; s < N_BASE; s++) {
				uint64_t t0 = now_us();
				int r = rdma_read_to(qp, cq, local, local_mr->lkey,
						     (uint64_t)(uintptr_t)odp_buf,
						     odp_mr->lkey, size, 1000000);

				lat[s] = now_us() - t0;
				if (r) { fprintf(stderr, "ODP 基线读失败\n"); rc = 1; goto out; }
			}
			stats_report(lat, N_BASE, &avg, &med, &mx);
			printf("| %6llu/%6llu ", (unsigned long long)avg,
			       (unsigned long long)med);
		} else {
			printf("| %16s ", "SKIP");
		}

		/* ODP minor: 单调游标顺序推进 fresh 页 (跨行不重置) */
		minor_base = ((uint64_t)ODP_MB << 20) / 2;
		if (odp_ok) {
			uint64_t off = minor_base + g_odp_minor_cursor;
			g_odp_minor_cursor += (uint64_t)n_big * rsize;

			for (s = 0; s < n_big; s++) {
				uint64_t t0 = now_us();
				int r = rdma_read_to(qp, cq, local, local_mr->lkey,
						     (uint64_t)(uintptr_t)odp_buf + off,
						     odp_mr->lkey, size, ODP_TIMEOUT_US);

				lat[s] = now_us() - t0;
				if (r) {
					fprintf(stderr, "ODP minor 读失败 r=%d\n", r);
					rc = 1;
					goto out;
				}
				off += rsize;
			}
			stats_report(lat, n_big, &avg, &med, &mx);
			printf("| %7llu/%6llu/%6llu ", (unsigned long long)avg,
			       (unsigned long long)med, (unsigned long long)mx);
		} else {
			printf("| %21s ", "SKIP");
		}

		/* SymRDMA minor: sym 后半区从未触摸页, symrdma_read 自动修复 */
		{
			unsigned long sym_half_pg =
				(unsigned long)(sym_len / 2 / SYMRDMA_PAGE_SIZE);
			unsigned long p0 = sym_half_pg +
				(unsigned long)(g_sym_minor_cursor /
						SYMRDMA_PAGE_SIZE);

			g_sym_minor_cursor += (uint64_t)n_big * rsize;
			for (s = 0; s < n_big; s++) {
				unsigned long p = p0 +
					(unsigned long)s * (unsigned long)npg;
				uint64_t t0 = now_us();
				int r = symrdma_read(&ctx, qp, cq, &smr, p, size,
						     local, local_mr->lkey);

				lat[s] = now_us() - t0;
				if (r) { fprintf(stderr, "sym minor 读失败\n"); rc = 1; goto out; }
			}
			stats_report(lat, n_big, &avg, &med, &mx);
			printf("| %7llu/%6llu/%6llu ", (unsigned long long)avg,
			       (unsigned long long)med, (unsigned long long)mx);
		}

		/* ODP major: 4 片轮转, 驻留 0xAB → PAGEOUT → mincore 就位 → 读 */
		if (odp_ok) {
			for (s = 0; s < n_big; s++) {
				uint64_t off = minor_base +
					((uint64_t)ODP_MB << 20) / 4 +
					(uint64_t)(s % 4) * rsize * 2;
				uint64_t t0;
				int r;

				memcpy(odp_buf + off, pin_buf, rsize);
				if (wait_swapped_smaps(odp_buf + off, rsize))
					fprintf(stderr,
						"  [warn] ODP major 换出未就位 (样本 %d)\n",
						s);
				t0 = now_us();
				r = rdma_read_to(qp, cq, local, local_mr->lkey,
						 (uint64_t)(uintptr_t)odp_buf + off,
						 odp_mr->lkey, size, ODP_TIMEOUT_US);
				lat[s] = now_us() - t0;
				if (r) {
					fprintf(stderr, "ODP major 读失败 r=%d\n", r);
					rc = 1;
					goto out;
				}
			}
			stats_report(lat, n_big, &avg, &med, &mx);
			printf("| %7llu/%6llu/%6llu ", (unsigned long long)avg,
			       (unsigned long long)med, (unsigned long long)mx);
		} else {
			printf("| %21s ", "SKIP");
		}

		/* SymRDMA major: 前半 0xAB 区 → PAGEOUT → 就位 (IOMMU 哨兵) → 读 */
		{
			struct symrdma_ioc_read_iova_l15 rd;

			for (s = 0; s < n_big; s++) {
				unsigned long p = (unsigned long)(s % 4) *
						  (unsigned long)npg;
				uint64_t t0;
				int r, tries;

				madvise(sym_buf + (size_t)p * SYMRDMA_PAGE_SIZE,
					rsize, MADV_PAGEOUT);
				for (tries = 0; tries < 200; tries++) {
					memset(&rd, 0, sizeof(rd));
					rd.mr_id = smr.mr_id;
					rd.iova = smr.read_iova +
						(unsigned long long)p *
						SYMRDMA_PAGE_SIZE;
					if (!ioctl(ctx.fd, SYMRDMA_IOC_READ_IOVA_L15, &rd) &&
					    rd.value == SYMRDMA_SENTINEL_MAGIC)
						break;
					if (tries % 20 == 19)
						madvise(sym_buf + (size_t)p *
							SYMRDMA_PAGE_SIZE, rsize,
							MADV_PAGEOUT);
					usleep(100000);
				}
				t0 = now_us();
				r = symrdma_read(&ctx, qp, cq, &smr, p, size,
						 local, local_mr->lkey);
				lat[s] = now_us() - t0;
					if (r) { fprintf(stderr, "sym major 读失败\n"); rc = 1; goto out; }
			}
			stats_report(lat, n_big, &avg, &med, &mx);
			printf("| %7llu/%6llu/%6llu |\n",
			       (unsigned long long)avg, (unsigned long long)med,
			       (unsigned long long)mx);
		}
		fflush(stdout);
	}
	printf("\n[Phase A 判定] %s (ODP 列含硬件缺页处理; Sym 列为库自动路径)\n",
	       rc ? "FAIL" : "PASS");

out:
	if (local_mr)
		ibv_dereg_mr(local_mr);
	if (local_ioctl_id >= 0)
		ioctl(ctx.fd, SYMRDMA_IOC_DEREG_MR, local_ioctl_id);
	/* sym_mr == smr.ibv_mr: symrdma_mr_deregister 统一注销 (双注销 = UAF) */
	symrdma_mr_deregister(&ctx, &smr);
	if (odp_mr)
		ibv_dereg_mr(odp_mr);
	if (pin_mr)
		ibv_dereg_mr(pin_mr);
	if (qp)
		ibv_destroy_qp(qp);
	if (cq)
		ibv_destroy_cq(cq);
	if (pd)
		ibv_dealloc_pd(pd);
	if (ibctx)
		ibv_close_device(ibctx);
	if (pin_buf != MAP_FAILED)
		munmap(pin_buf, pin_len);
	if (odp_buf != MAP_FAILED)
		munmap(odp_buf, odp_len);
	if (sym_buf != MAP_FAILED)
		munmap(sym_buf, sym_len);
	if (local != MAP_FAILED)
		munmap(local, MAX_SIZE);
	symrdma_close(&ctx);
	return rc;
}

/* ============ Phase B: 跨机 client/server ============ */

static int iova_is_sentinel(int fd, int mr_id, uint64_t iova)
{
	struct symrdma_ioc_read_iova_l15 rd = {
		.mr_id = mr_id, .iova = iova, .offset = 0,
	};

	if (ioctl(fd, SYMRDMA_IOC_READ_IOVA_L15, &rd))
		return 0;
	return rd.value == SYMRDMA_SENTINEL_MAGIC;
}

static int server_run(const char *devname, int port)
{
	struct symrdma_ctx ctx;
	struct ibv_device *dev;
	struct ibv_context *ibctx = NULL;
	struct ibv_pd *pd = NULL;
	struct ibv_cq *cq = NULL;
	struct ibv_qp *qp = NULL;
	struct symrdma_mr smr = { .mr_id = -1 };
	struct wire_params wp, cp;
	int lfd, cfd = -1, sym_ioctl_id = -1, rc = 0;
	unsigned char *pin_buf = MAP_FAILED, *odp_buf = MAP_FAILED, *sym_buf = MAP_FAILED;
	struct ibv_mr *pin_mr = NULL, *odp_mr = NULL, *sym_mr = NULL;
	size_t pin_len = (size_t)PINNED_MB << 20;
	size_t odp_len = (size_t)ODP_MB << 20;
	size_t sym_len = (size_t)SYM_MB << 20;
	int odp_ok = 1;

	memset(&ctx, 0, sizeof(ctx));
	signal(SIGPIPE, SIG_IGN);
	printf("=== SymRDMA Level 15 server (port %d) ===\n", port);
	if (symrdma_open(&ctx)) {
		fprintf(stderr, "[dbg] /dev/symrdma 失败\n");
		return 1;
	}
	dev = find_rdma_device(devname);
	if (!dev || !(ibctx = ibv_open_device(dev)) || !(pd = ibv_alloc_pd(ibctx)) ||
	    !(cq = ibv_create_cq(ibctx, CQ_DEPTH, NULL, NULL, 0))) {
		fprintf(stderr, "[dbg] 设备初始化失败\n");
		rc = 1;
		goto out;
	}
	qp = create_qp_rc(pd, cq);
	if (!qp) { fprintf(stderr, "[dbg] create_qp 失败\n"); rc = 1; goto out; }

	pin_buf = mmap(NULL, pin_len, PROT_READ | PROT_WRITE,
		       MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (pin_buf == MAP_FAILED) { rc = 1; goto out; }
	memset(pin_buf, 0xAB, pin_len);
	pin_mr = ibv_reg_mr(pd, pin_buf, pin_len,
			    IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ |
			    IBV_ACCESS_REMOTE_WRITE);
	if (!pin_mr) { fprintf(stderr, "[dbg] pinned reg 失败\n"); rc = 1; goto out; }

	odp_buf = mmap(NULL, odp_len, PROT_READ | PROT_WRITE,
		       MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (odp_buf == MAP_FAILED) { rc = 1; goto out; }
	madvise(odp_buf, odp_len, MADV_NOHUGEPAGE);
	odp_mr = ibv_reg_mr(pd, odp_buf, odp_len,
			    IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ |
			    IBV_ACCESS_ON_DEMAND);
	if (!odp_mr) {
		printf("  [SKIP] ODP 注册失败 (errno=%d)\n", errno);
		odp_ok = 0;
	}

	sym_buf = mmap(NULL, sym_len, PROT_READ | PROT_WRITE,
		       MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (sym_buf == MAP_FAILED) { rc = 1; goto out; }
	madvise(sym_buf, sym_len, MADV_NOHUGEPAGE);
	memset(sym_buf, 0xAB, sym_len / 2);   /* 前半驻留 (major), 后半不触摸 (minor) */
	{
		struct symrdma_ioc_reg_mr reg = {
			.va_start = (unsigned long long)sym_buf,
			.len = sym_len,
		};
		struct symrdma_ioc_get_iova iova_req;

		if (ioctl(ctx.fd, SYMRDMA_IOC_REG_MR, &reg)) {
			fprintf(stderr, "[dbg] sym REG_MR 失败\n");
			rc = 1;
			goto out;
		}
		sym_ioctl_id = reg.mr_id;
		iova_req.mr_id = reg.mr_id;
		iova_req.page_idx = 0;
		if (ioctl(ctx.fd, SYMRDMA_IOC_GET_IOVA, &iova_req)) {
			fprintf(stderr, "[dbg] GET_IOVA 失败\n");
			rc = 1;
			goto out;
		}
		smr.mr_id = reg.mr_id;
		smr.buf = sym_buf;
		smr.len = sym_len;
		smr.read_iova = iova_req.read_iova;
		smr.write_iova = iova_req.write_iova;
		smr.ibv_mr = ibv_reg_mr(pd, sym_buf, sym_len,
					IBV_ACCESS_LOCAL_WRITE |
					IBV_ACCESS_REMOTE_READ |
					IBV_ACCESS_REMOTE_WRITE |
					SYMRDMA_ACCESS_IDENTITY);
		if (!smr.ibv_mr) { fprintf(stderr, "[dbg] sym ibv_reg_mr 失败\n"); rc = 1; goto out; }
		sym_mr = smr.ibv_mr;
	}

	lfd = tcp_listen(port);
	if (lfd < 0) { fprintf(stderr, "[dbg] listen 失败\n"); rc = 1; goto out; }
	printf("  等待 client ...\n");
	fflush(stdout);
	cfd = accept(lfd, NULL, NULL);
	if (cfd < 0) { fprintf(stderr, "[dbg] accept 失败\n"); rc = 1; goto out; }

	if (recv_all(cfd, &cp, sizeof(cp))) {
		fprintf(stderr, "[dbg] 握手失败\n");
		rc = 1;
		goto out;
	}
	{
		union ibv_gid g;

		if (ibv_query_gid(ibctx, 1, GID_DEFAULT_NET, &g)) {
			fprintf(stderr, "[dbg] query_gid 失败\n");
			rc = 1;
			goto out;
		}
		memset(&wp, 0, sizeof(wp));
		wp.qpn = qp->qp_num;
		wp.psn = 0;
		wp.gid = g;
		wp.pinned_addr = (uint64_t)(uintptr_t)pin_buf;
		wp.pinned_rkey = pin_mr->lkey;
		wp.odp_addr = odp_ok ? (uint64_t)(uintptr_t)odp_buf : 0;
		wp.odp_rkey = odp_ok ? odp_mr->lkey : 0;
		wp.odp_pages = (uint32_t)(odp_len / SYMRDMA_PAGE_SIZE);
		wp.sym_addr = (uint64_t)(uintptr_t)sym_buf;
		wp.sym_rkey = sym_mr->lkey;
		wp.sym_pages = (uint32_t)(sym_len / SYMRDMA_PAGE_SIZE);
		if (qp_to_rts(qp, cp.qpn, GID_DEFAULT_NET, &cp.gid, cp.psn)) {
			fprintf(stderr, "[dbg] RTR/RTS 失败\n");
			rc = 1;
			goto out;
		}
		if (send_all(cfd, &wp, sizeof(wp))) {
			fprintf(stderr, "[dbg] 发参数失败\n");
			rc = 1;
			goto out;
		}
	}
	printf("  client 已连 QP RTS; pinned=0x%llx odp=%s sym=0x%llx (%u 页)\n",
	       (unsigned long long)wp.pinned_addr, odp_ok ? "OK" : "SKIP",
	       (unsigned long long)wp.sym_addr, wp.sym_pages);

	for (;;) {
		char line[128], verb[8], mr[8];
		unsigned long long off;
		unsigned long len;

		if (recv_line(cfd, line, sizeof(line))) {
			fprintf(stderr, "[dbg] 控制连接断开\n");
			rc = 1;
			goto out;
		}
		if (!strncmp(line, "QUIT", 4)) {
			send_line(cfd, "OK\n");
			break;
		}
		/* QP: 诊断 — 回查 server 侧 QP 状态 + CQ 残留 (Phase B 停顿定位) */
		if (!strncmp(line, "QP", 2)) {
			struct ibv_qp_attr attr;
			struct ibv_qp_init_attr iattr;
			struct ibv_wc wc;
			int n;
			char buf[96];

			memset(&attr, 0, sizeof(attr));
			memset(&iattr, 0, sizeof(iattr));
			if (ibv_query_qp(qp, &attr, IBV_QP_STATE, &iattr))
				send_line(cfd, "ERR query\n");
			else {
				n = ibv_poll_cq(cq, 1, &wc);
				snprintf(buf, sizeof(buf),
					 "OK qp_state=%d wc=%d wc_status=%d\n",
					 attr.qp_state, n,
					 n > 0 ? (int)wc.status : -1);
				send_line(cfd, buf);
			}
			continue;
		}
		/* 格式: <VERB> <mr> <off> <len> (client 同构) */
		if (sscanf(line, "%7s %7s %llu %lu", verb, mr, &off, &len) != 4) {
			send_line(cfd, "ERR parse\n");
			continue;
		}
		if (!strcmp(mr, "sym")) {
			unsigned long p0 = (unsigned long)(off / SYMRDMA_PAGE_SIZE);
			unsigned long np = (len + SYMRDMA_PAGE_SIZE - 1) /
					   SYMRDMA_PAGE_SIZE;

			if (!strcmp(verb, "RES")) {
				unsigned long p;

				/* RES = 触摸 + 逐页 REPAIR (CPU 驻留 + IOMMU 同步) */
				memset(sym_buf + off, 0xAB, len);
				for (p = p0; p < p0 + np; p++)
					symrdma_repair_page(&ctx, &smr, p);
				send_line(cfd, "OK\n");
			} else {
				/* PO = madvise + 等 IOMMU 哨兵就位 (L9 语义) */
				int tries, ok = 0;

				madvise(sym_buf + off, len, MADV_PAGEOUT);
				for (tries = 0; tries < 200; tries++) {
					unsigned long p;
					int all = 1;

					for (p = p0; p < p0 + np; p++) {
						if (!iova_is_sentinel(ctx.fd,
								      sym_ioctl_id,
								      smr.read_iova +
								      (uint64_t)p *
								      SYMRDMA_PAGE_SIZE)) {
							all = 0;
							break;
						}
					}
					if (all) { ok = 1; break; }
					/* b: 整段重新 madvise - 原实现每 20 轮
					 * 只重试首个未就位页, 其余页只收到开头一次整段
					 * PAGEOUT; 刚 RES memset 过的脏页单次回收 pass
					 * 收不完 (部分进 writeback 后该 pass 跳过) ->
					 * 16 页 PO 卡死 7 页 (64KB Sym major 实测 9/16
					 * 就位后超时)。单页场景重试恒覆盖唯一页, 故 4KB
					 * 行从未暴露。 */
					if (tries % 20 == 0)
						madvise(sym_buf + off, len,
							MADV_PAGEOUT);
					usleep(100000);
				}
				if (!ok) {
					/* b 诊断: 超时后报告哨兵就位分布 (定位
					 * 64KB Sym major PO not-ready 卡在哪类页) */
					unsigned long p, ns = 0;

					for (p = p0; p < p0 + np; p++)
						if (iova_is_sentinel(ctx.fd,
								     sym_ioctl_id,
								     smr.read_iova +
								     (uint64_t)p *
								     SYMRDMA_PAGE_SIZE))
							ns++;
					fprintf(stderr,
						"[dbg] PO not-ready: 哨兵 %lu/%lu 页 (off=%llu len=%lu)\n",
						ns, np, off, len);
				}
				send_line(cfd, ok ? "OK\n" : "ERR not-ready\n");
			}
		} else if (!strcmp(mr, "odp") && odp_ok) {
			if (!strcmp(verb, "RES")) {
				memset(odp_buf + off, 0xAB, len);
				send_line(cfd, "OK\n");
/* ODP major PO: smaps Swap 增量判据 (mincore 误报), 上限 20s 同 L9 */
			} else {
				send_line(cfd,
					  wait_swapped_smaps(odp_buf + off, len) == 0 ?
					  "OK\n": "ERR not-ready\n");
			}
		} else if (!strcmp(mr, "pin")) {
			send_line(cfd, "OK\n");
		} else {
			send_line(cfd, "ERR mr\n");
		}
	}

out:
	if (cfd >= 0)
		close(cfd);
	/* sym_mr == smr.ibv_mr: symrdma_mr_deregister 统一注销 (双注销 = UAF) */
	symrdma_mr_deregister(&ctx, &smr);
	if (odp_mr)
		ibv_dereg_mr(odp_mr);
	if (pin_mr)
		ibv_dereg_mr(pin_mr);
	if (qp)
		ibv_destroy_qp(qp);
	if (cq)
		ibv_destroy_cq(cq);
	if (pd)
		ibv_dealloc_pd(pd);
	if (ibctx)
		ibv_close_device(ibctx);
	if (pin_buf != MAP_FAILED)
		munmap(pin_buf, pin_len);
	if (odp_buf != MAP_FAILED)
		munmap(odp_buf, odp_len);
	if (sym_buf != MAP_FAILED)
		munmap(sym_buf, sym_len);
	symrdma_close(&ctx);
	return rc;
}

/* client: 一次 sym 远程 fault 全链路测量 (detect→RES repair→reread)。
 * 返回 0 记录成功; 1 检测未命中哨兵 (竞态, 调用方重试); <0 致命 */
static int sym_remote_fault(struct ibv_qp *qp, struct ibv_cq *cq, void *local,
			    uint32_t lkey, int fd, uint64_t sym_addr,
			    uint32_t sym_rkey, uint64_t off, size_t rsize,
			    size_t size, uint32_t expect, uint64_t *out_us)
{
	char cmd[128], reply[64];
	uint64_t t0;
	uint32_t w0;
	int r;

	/* 先确保目标页处于 "换出+哨兵" 状态: RES (修复至一致) → PO (重新换出)。
	 * 背景: 工作项驻留恢复可能在 swap-out 进行中把 IOMMU 从哨兵
	 * 改回真实 PA (陈旧) — detect 永远读不到哨兵, 必须 RES+PO 重同步
	 * (实测 host-b, 属 flush-before-unmap 屏障缺失的表现) */
	snprintf(cmd, sizeof(cmd), "RES sym %llu %zu\n",
		 (unsigned long long)off, rsize);
	send_line(fd, cmd);
	if (recv_line(fd, reply, sizeof(reply)) || strncmp(reply, "OK", 2)) {
		fprintf(stderr, "  [sym] 预 RES 失败: %s\n", reply);
		return -1;
	}
	snprintf(cmd, sizeof(cmd), "PO sym %llu %zu\n",
		 (unsigned long long)off, rsize);
	send_line(fd, cmd);
	if (recv_line(fd, reply, sizeof(reply)) || strncmp(reply, "OK", 2)) {
		fprintf(stderr, "  [sym] 预 PO 失败: %s\n", reply);
		return -1;
	}

	t0 = now_us();
	r = rdma_read_to(qp, cq, local, lkey, sym_addr + off, sym_rkey,
			 size, 5000000);
	if (r) {
		fprintf(stderr, "  [sym] detect 读失败 r=%d\n", r);
		return -1;
	}
	memcpy(&w0, local, 4);
	if (w0 != SYMRDMA_SENTINEL_MAGIC) {
		/* 仍非哨兵 (竞态) — 调用方重试 */
		return 1;
	}
	snprintf(cmd, sizeof(cmd), "RES sym %llu %zu\n",
		 (unsigned long long)off, rsize);
	send_line(fd, cmd);
	if (recv_line(fd, reply, sizeof(reply)) || strncmp(reply, "OK", 2)) {
		fprintf(stderr, "  [sym] RES 失败: %s\n", reply);
		return -1;
	}
	r = rdma_read_to(qp, cq, local, lkey, sym_addr + off, sym_rkey,
			 size, 5000000);
	if (r) {
		fprintf(stderr, "  [sym] reread 失败 r=%d\n", r);
		return -1;
	}
	memcpy(&w0, local, 4);
	if (w0 != expect) {
		fprintf(stderr, "  [sym] 重读异常 got 0x%08x exp 0x%08x\n",
			w0, expect);
		return -1;
	}
	*out_us = now_us() - t0;
	return 0;
}

static int client_run(const char *devname, const char *ip, int port, int gid,
		      const char *size_filter)
{
	struct ibv_device *dev;
	struct ibv_context *ibctx = NULL;
	struct ibv_pd *pd = NULL;
	struct ibv_cq *cq = NULL;
	struct ibv_qp *qp = NULL;
	struct wire_params sp;
	int fd = -1, rc = 0;
	unsigned char *local = MAP_FAILED;
	struct ibv_mr *local_mr = NULL;
	uint64_t lat[N_BASE];
	uint64_t avg, med, mx;
	int i, s, odp_ok;

	/* b: 脚本层按尺寸重建连接 (run_odp_compare.sh), 本端仅跑
	 * 匹配尺寸的那一行 (连接间状态隔离, 便于单尺寸重跑)。背景:
	 * path_mtu 曾硬编码 4096 > 测试床 active_mtu 1024 → ≥4KB 读响应
	 * 首包被丢弃, 曾误诊为 "mlx5 ODP stalled-QP 楔死"; MTU 修复后
	 * (qp_to_rts 动态取 min(active_mtu, 4096)) 4 尺寸全 PASS,
	 * NIC 重载不再需要。 */
	printf("=== SymRDMA Level 15 client (%s:%d, GID%d) ===\n", ip, port, gid);
	dev = find_rdma_device(devname);
	if (!dev || !(ibctx = ibv_open_device(dev)) || !(pd = ibv_alloc_pd(ibctx)) ||
	    !(cq = ibv_create_cq(ibctx, CQ_DEPTH, NULL, NULL, 0))) {
		fprintf(stderr, "[dbg] 设备初始化失败\n");
		return 1;
	}
	qp = create_qp_rc(pd, cq);
	if (!qp) { fprintf(stderr, "[dbg] create_qp 失败\n"); return 1; }

	local = mmap(NULL, MAX_SIZE, PROT_READ | PROT_WRITE,
		     MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (local == MAP_FAILED) { rc = 1; goto out; }
	memset(local, 0x5A, MAX_SIZE);
	mlock(local, MAX_SIZE);
	local_mr = ibv_reg_mr(pd, local, MAX_SIZE, IBV_ACCESS_LOCAL_WRITE);
	if (!local_mr) { fprintf(stderr, "[dbg] local reg 失败\n"); rc = 1; goto out; }

	fd = tcp_dial(ip, port);
	if (fd < 0) { fprintf(stderr, "[dbg] 连接 server 失败\n"); rc = 1; goto out; }
	{
		struct wire_params cp;
		union ibv_gid g;

		memset(&cp, 0, sizeof(cp));
		cp.qpn = qp->qp_num;
		cp.psn = 0;
		if (ibv_query_gid(ibctx, 1, gid, &g)) {
			fprintf(stderr, "[dbg] query_gid 失败\n");
			rc = 1;
			goto out;
		}
		cp.gid = g;
		if (send_all(fd, &cp, sizeof(cp)) || recv_all(fd, &sp, sizeof(sp))) {
			fprintf(stderr, "[dbg] 握手失败\n");
			rc = 1;
			goto out;
		}
	}
	odp_ok = sp.odp_rkey != 0;
	if (qp_to_rts(qp, sp.qpn, gid, &sp.gid, sp.psn)) {
		fprintf(stderr, "[dbg] RTR/RTS 失败\n");
		rc = 1;
		goto out;
	}
	printf("  连接建立; pinned=0x%llx odp=%s sym=0x%llx\n",
	       (unsigned long long)sp.pinned_addr,
	       odp_ok ? "OK" : "SKIP", (unsigned long long)sp.sym_addr);

	printf("\n| 尺寸 | pinned avg/med µs | ODP 基线 avg/med | ODP minor avg/med/max | "
	       "Sym remote minor avg/med/max | ODP major avg/med/max | Sym remote major avg/med/max |\n");
	printf("|------|-------------------|------------------|-----------------------|"
	       "------------------------------|-----------------------|------------------------------|\n");

	for (i = 0; i < NSIZES; i++) {
		size_t size = cmp_sizes[i];
		size_t rsize = (size + SYMRDMA_PAGE_SIZE - 1) / SYMRDMA_PAGE_SIZE *
			       SYMRDMA_PAGE_SIZE;
		int n_big = (size <= 4096) ? 10 : N_FAULT_BIG;
		char cmd[128], reply[64];

		/* 尺寸过滤 (Phase B 按尺寸重建连接, 见 client_run 头注) */
		if (size_filter && (size_t)strtoul(size_filter, NULL, 0) != size)
			continue;

		/* pinned 基线 */
		for (s = 0; s < N_BASE; s++) {
			uint64_t t0 = now_us();
			int r = rdma_read_to(qp, cq, local, local_mr->lkey,
					     sp.pinned_addr, sp.pinned_rkey,
					     size, 1000000);

			lat[s] = now_us() - t0;
			if (r) {
				char reply[64];
				int tries;

				fprintf(stderr, "pinned 读失败 r=%d (size=%zu)\n",
					r, size);
				qp_state_dump(qp, "client");
				/* 诊断: server QP 状态 + CQ 残留 + 重试 ×3 */
				send_line(fd, "QP\n");
				if (!recv_line(fd, reply, sizeof(reply)))
					fprintf(stderr, "  [dbg] server: %s", reply);
				for (tries = 0; tries < 3; tries++) {
					t0 = now_us();
					r = rdma_read_to(qp, cq, local,
							 local_mr->lkey,
							 sp.pinned_addr,
							 sp.pinned_rkey, size,
							 5000000);
					fprintf(stderr,
						"  [dbg] 重试 %d: r=%d el=%lluus\n",
						tries, r,
						(unsigned long long)(now_us() - t0));
					qp_state_dump(qp, "retry");
					if (!r)
						break;
				}
				if (r) { rc = 1; goto out; }
			}
		}
		stats_report(lat, N_BASE, &avg, &med, &mx);
		printf("| %s | %6llu/%6llu ", size_tag[i],
		       (unsigned long long)avg, (unsigned long long)med);

		/* ODP 基线 (resident) */
		if (odp_ok) {
			snprintf(cmd, sizeof(cmd), "RES odp 0 %zu\n", rsize);
			send_line(fd, cmd);
			recv_line(fd, reply, sizeof(reply));
			for (s = 0; s < N_BASE; s++) {
				uint64_t t0 = now_us();
				int r = rdma_read_to(qp, cq, local, local_mr->lkey,
						     sp.odp_addr, sp.odp_rkey,
						     size, 1000000);

				lat[s] = now_us() - t0;
				if (r) { fprintf(stderr, "ODP 基线读失败\n"); rc = 1; goto out; }
			}
			stats_report(lat, N_BASE, &avg, &med, &mx);
			printf("| %6llu/%6llu ", (unsigned long long)avg,
			       (unsigned long long)med);
		} else {
			printf("| %16s ", "SKIP");
		}

		/* ODP minor: 服务端 NORESERVE 区单调游标 (fresh 页, 跨行不重置) */
		if (odp_ok) {
			uint64_t off = (uint64_t)sp.odp_pages / 2 *
				       SYMRDMA_PAGE_SIZE + g_odp_minor_cursor;
			g_odp_minor_cursor += (uint64_t)n_big * rsize;

			for (s = 0; s < n_big; s++) {
				uint64_t t0 = now_us();
				int r = rdma_read_to(qp, cq, local, local_mr->lkey,
						     sp.odp_addr + off,
						     sp.odp_rkey, size,
						     ODP_TIMEOUT_US);

				lat[s] = now_us() - t0;
				if (r) {
					fprintf(stderr, "ODP minor 读失败 r=%d\n", r);
					rc = 1;
					goto out;
				}
				off += rsize;
			}
			stats_report(lat, n_big, &avg, &med, &mx);
			printf("| %7llu/%6llu/%6llu ", (unsigned long long)avg,
			       (unsigned long long)med, (unsigned long long)mx);
		} else {
			printf("| %28s ", "SKIP");
		}

		/* SymRDMA 远程 minor: sym 后半区单调游标 (fresh, 跨行不重置) */
		{
			uint64_t half = (uint64_t)sp.sym_pages / 2 *
					SYMRDMA_PAGE_SIZE + g_sym_minor_cursor;

			g_sym_minor_cursor += (uint64_t)n_big * rsize;
			for (s = 0; s < n_big; s++) {
				uint64_t off = half + (uint64_t)s * rsize;

				for (;;) {
					uint64_t el;
					int r = sym_remote_fault(qp, cq, local,
								 local_mr->lkey,
								 fd, sp.sym_addr,
								 sp.sym_rkey, off,
								 rsize, size, 0xABABABABu,
								 &el);

					if (r < 0) { rc = 1; goto out; }
					if (r == 0) { lat[s] = el; break; }
					usleep(100000);   /* 检测未命中 — 重试 */
				}
			}
			stats_report(lat, n_big, &avg, &med, &mx);
			printf("| %7llu/%6llu/%6llu ", (unsigned long long)avg,
			       (unsigned long long)med, (unsigned long long)mx);
		}

		/* ODP major: PO (mincore 就位) → 读 */
		if (odp_ok) {
			uint64_t base = (uint64_t)sp.odp_pages / 2 *
					SYMRDMA_PAGE_SIZE;

			for (s = 0; s < n_big; s++) {
				uint64_t off = base + ((uint64_t)ODP_MB << 20) / 4 +
					       (uint64_t)(s % 4) * rsize;
				uint64_t t0;
				int r;

				/* 先 RES 弄脏 (零页/干净页 PAGEOUT 无效) 再 PO */
				snprintf(cmd, sizeof(cmd), "RES odp %llu %zu\n",
					 (unsigned long long)off, rsize);
				send_line(fd, cmd);
				if (recv_line(fd, reply, sizeof(reply)) ||
				    strncmp(reply, "OK", 2)) {
					fprintf(stderr, "ODP major RES 失败: %s\n", reply);
					rc = 1;
					goto out;
				}
				snprintf(cmd, sizeof(cmd), "PO odp %llu %zu\n",
					 (unsigned long long)off, rsize);
				send_line(fd, cmd);
				if (recv_line(fd, reply, sizeof(reply)) ||
				    strncmp(reply, "OK", 2)) {
					fprintf(stderr, "ODP major PO 失败: %s\n", reply);
					rc = 1;
					goto out;
				}
				t0 = now_us();
				r = rdma_read_to(qp, cq, local, local_mr->lkey,
						 sp.odp_addr + off, sp.odp_rkey,
						 size, ODP_TIMEOUT_US);
				lat[s] = now_us() - t0;
				if (r) {
					fprintf(stderr, "ODP major 读失败 r=%d\n", r);
					rc = 1;
					goto out;
				}
				{
					uint32_t w0;

					memcpy(&w0, local, 4);
					if (w0 != 0xABABABABu)
						fprintf(stderr,
							"  [warn] ODP major 数据 0x%08x (期望 0xABABABAB)\n",
							w0);
				}
			}
			stats_report(lat, n_big, &avg, &med, &mx);
			printf("| %7llu/%6llu/%6llu ", (unsigned long long)avg,
			       (unsigned long long)med, (unsigned long long)mx);
		} else {
			printf("| %28s ", "SKIP");
		}

		/* SymRDMA 远程 major: 前半 0xAB 区 PO (哨兵) → detect → RES → reread */
		{
			for (s = 0; s < n_big; s++) {
				uint64_t off = (uint64_t)(s % 4) * rsize;

				for (;;) {
					uint64_t el;
					int r = sym_remote_fault(qp, cq, local,
								 local_mr->lkey,
								 fd, sp.sym_addr,
								 sp.sym_rkey, off,
								 rsize, size, 0xABABABABu,
								 &el);

					if (r < 0) { rc = 1; goto out; }
					if (r == 0) { lat[s] = el; break; }
					usleep(100000);
				}
			}
			stats_report(lat, n_big, &avg, &med, &mx);
			printf("| %7llu/%6llu/%6llu |\n",
			       (unsigned long long)avg, (unsigned long long)med,
			       (unsigned long long)mx);
		}
		fflush(stdout);
	}
	send_line(fd, "QUIT\n");
	printf("\n[Phase B 判定] %s — Sym remote = detect + 控制 REPAIR + 重读 全链路\n",
	       rc ? "FAIL" : "PASS");

out:
	if (fd >= 0)
		close(fd);
	if (local_mr)
		ibv_dereg_mr(local_mr);
	if (qp)
		ibv_destroy_qp(qp);
	if (cq)
		ibv_destroy_cq(cq);
	if (pd)
		ibv_dealloc_pd(pd);
	if (ibctx)
		ibv_close_device(ibctx);
	if (local != MAP_FAILED)
		munmap(local, MAX_SIZE);
	return rc;
}

int main(int argc, char **argv)
{
	const char *dev = NULL, *ip = NULL, *size_filter = NULL;
	int port = DEF_PORT, gid = GID_DEFAULT_NET;

	if (argc < 2) {
		fprintf(stderr,
			"用法: test_odp_compare local [-d dev]\n"
			"      test_odp_compare server [-d dev] [-p port]\n"
			"      test_odp_compare client -c IP [-g gid] [-d dev] [-p port] [-s size]\n");
		return 2;
	}
	if (!strcmp(argv[1], "local"))
		return phase_a_run(dev);
	if (!strcmp(argv[1], "server")) {
		int i;

		for (i = 2; i < argc; i++) {
			if (!strcmp(argv[i], "-d") && i + 1 < argc)
				dev = argv[++i];
			if (!strcmp(argv[i], "-p") && i + 1 < argc)
				port = atoi(argv[++i]);
		}
		return server_run(dev, port);
	}
	if (!strcmp(argv[1], "client")) {
		int i;

		for (i = 2; i < argc; i++) {
			if (!strcmp(argv[i], "-c") && i + 1 < argc)
				ip = argv[++i];
			else if (!strcmp(argv[i], "-d") && i + 1 < argc)
				dev = argv[++i];
			else if (!strcmp(argv[i], "-g") && i + 1 < argc)
				gid = atoi(argv[++i]);
			else if (!strcmp(argv[i], "-p") && i + 1 < argc)
				port = atoi(argv[++i]);
			else if (!strcmp(argv[i], "-s") && i + 1 < argc)
				size_filter = argv[++i];
		}
		if (!ip) {
			fprintf(stderr, "client 需要 -c IP\n");
			return 2;
		}
		return client_run(dev, ip, port, gid, size_filter);
	}
	fprintf(stderr, "未知模式: %s\n", argv[1]);
	return 2;
}
