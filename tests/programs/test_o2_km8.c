/*
 * test_o2_km8.c — rereg fail-closed 与 REG_MR 校验修复的负例验证
 *
 * K-M8 (kernel/symrdma_mr.c): REG_MR len > 32GB (SYMRDMA_MR_WRITE_OFFSET)
 *   → 期望 -EINVAL (写 IOVA 与读区间重叠, 原先静默接受);
 *   va_start 非页对齐 → 期望 -EINVAL。
 * O-2 (ofed mlx5_ib mr.c rereg): 已带 identity 位的 MR 经 ibv_rereg_mr
 *   (仅 ACCESS/PD, 不带 TRANS) → 期望 EOPNOTSUPP (原先可静默变 pinned)。
 *
 * 环境: symrdma 模块已载 + mlx5_ib (O-2 版)。不挂 LD_PRELOAD (直测路径)。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <infiniband/verbs.h>

/* ---- SymRDMA ioctl (同 test_rdma_verify) ---- */
#define SYMRDMA_IOC_MAGIC       'S'
struct symrdma_ioc_reg_mr {
	unsigned long long va_start, len;
	int mr_id;
};
#define SYMRDMA_IOC_REG_MR      _IOWR(SYMRDMA_IOC_MAGIC, 1, struct symrdma_ioc_reg_mr)
#define SYMRDMA_IOC_DEREG_MR    _IOW(SYMRDMA_IOC_MAGIC,  2, int)

#define SYMRDMA_ACCESS_IDENTITY (1 << 21)
#define SYMRDMA_MR_WRITE_OFFSET (1UL << 35)   /* 32GB */

/* 老版 verbs.h 未导出 rereg 枚举 (OFED 内核侧支持, 值同 ib_verbs.h) */
#ifndef IB_MR_REREG_TRANS
#define IB_MR_REREG_TRANS   1
#endif
#ifndef IB_MR_REREG_PD
#define IB_MR_REREG_PD      2
#endif
#ifndef IB_MR_REREG_ACCESS
#define IB_MR_REREG_ACCESS  4
#endif
#ifndef EOPNOTSUPP
#define EOPNOTSUPP 95
#endif

static int passed = 0, failed = 0;
#define CHECK(cond, ...) do { \
	char _m[256]; snprintf(_m, sizeof(_m), __VA_ARGS__); \
	if (cond) { printf("  PASS: %s\n", _m); passed++; } \
	else      { printf("  FAIL: %s\n", _m); failed++; } \
} while (0)
#define CHECK2(cond, msg) do { \
	if (cond) { printf("  PASS: %s\n", msg); passed++; } \
	else      { printf("  FAIL: %s\n", msg); failed++; } \
} while (0)

static struct ibv_device *find_active_dev(void)
{
	struct ibv_device **list = ibv_get_device_list(NULL);
	for (int i = 0; list && list[i]; i++) {
		struct ibv_context *c = ibv_open_device(list[i]);
		struct ibv_port_attr p;
		if (!c)
			continue;
		if (!ibv_query_port(c, 1, &p) && p.state == IBV_PORT_ACTIVE) {
			ibv_close_device(c);
			return list[i];
		}
		ibv_close_device(c);
	}
	return NULL;
}

int main(void)
{
	int sym_fd, rc;
	struct symrdma_ioc_reg_mr reg = {0};

	printf("== K-M8: REG_MR 长度/对齐负例 ==\n");
	sym_fd = open("/dev/symrdma", O_RDWR);
	if (sym_fd < 0) {
		printf("SKIP: /dev/symrdma 打不开 (%s)\n", strerror(errno));
		return 77;
	}

	/* 1) len = 32GB + 4KB → 期望 EINVAL (原先静默接受, 写 IOVA 自叠) */
	{
		void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
			       MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
		if (p == MAP_FAILED) { printf("SKIP: mmap\n"); return 77; }
		memset(&reg, 0, sizeof(reg));
		reg.va_start = (unsigned long long)p;
		reg.len = SYMRDMA_MR_WRITE_OFFSET + 4096;
		rc = ioctl(sym_fd, SYMRDMA_IOC_REG_MR, &reg);
		CHECK(rc == -1 && errno == EINVAL,
		      "len > 32GB 被拒 (errno=%d, 期望 EINVAL=%d)", errno, EINVAL);
		munmap(p, 4096);
	}

	/* 2) len = 32GB (边界内) → 期望成功 (功能未被误伤) */
	{
		void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
			       MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
		if (p == MAP_FAILED) { printf("SKIP: mmap\n"); return 77; }
		memset(&reg, 0, sizeof(reg));
		reg.va_start = (unsigned long long)p;
		reg.len = SYMRDMA_MR_WRITE_OFFSET;
		rc = ioctl(sym_fd, SYMRDMA_IOC_REG_MR, &reg);
		CHECK(rc == 0, "len == 32GB (边界内) 注册成功");
		if (rc == 0) {
			int id = reg.mr_id;
			rc = ioctl(sym_fd, SYMRDMA_IOC_DEREG_MR, id);
			CHECK(rc == 0, "DEREG 清理");
		}
		munmap(p, 4096);
	}

	/* 3) va_start 非页对齐 → 期望 EINVAL */
	{
		void *p = mmap(NULL, 8192, PROT_READ | PROT_WRITE,
			       MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
		if (p == MAP_FAILED) { printf("SKIP: mmap\n"); return 77; }
		memset(&reg, 0, sizeof(reg));
		reg.va_start = (unsigned long long)p + 8;
		reg.len = 4096;
		rc = ioctl(sym_fd, SYMRDMA_IOC_REG_MR, &reg);
		CHECK(rc == -1 && errno == EINVAL,
		      "非页对齐 va_start 被拒 (errno=%d)", errno);
		munmap(p, 8192);
	}

	printf("\n== O-2: identity MR rereg 负例 ==\n");
	{
		struct ibv_device *dev = find_active_dev();
		struct ibv_context *ctx;
		struct ibv_pd *pd;
		struct ibv_mr *mr;
		void *buf;
		int ret;

		if (!dev) { printf("SKIP: 无 ACTIVE RDMA 设备\n"); return 77; }
		ctx = ibv_open_device(dev);
		pd = ctx ? ibv_alloc_pd(ctx) : NULL;
		buf = pd ? mmap(NULL, 4096, PROT_READ | PROT_WRITE,
				MAP_ANONYMOUS | MAP_PRIVATE, -1, 0)
			 : MAP_FAILED;
		if (!ctx || !pd || buf == MAP_FAILED) {
			printf("SKIP: verbs 资源创建失败\n");
			return 77;
		}

		mr = ibv_reg_mr(pd, buf, 4096,
				IBV_ACCESS_LOCAL_WRITE |
				IBV_ACCESS_REMOTE_READ |
				SYMRDMA_ACCESS_IDENTITY);
		CHECK(mr != NULL, "identity MR 注册成功");
		if (mr) {
			/* 仅 ACCESS 变更 (不带 TRANS): 原先走 UMR fast path
			 * 静默变 pinned; 修复后期望 EOPNOTSUPP */
			ret = ibv_rereg_mr(mr, IB_MR_REREG_ACCESS,
					   NULL, NULL, 0,
					   IBV_ACCESS_LOCAL_WRITE |
					   IBV_ACCESS_REMOTE_READ);
			/* 老版 libibverbs 返回 -errno (非 -1/-errno 组合) */
			CHECK(ret != 0 && errno == EOPNOTSUPP,
			      "identity MR rerg 被拒 (ret=%d errno=%d, 期望非零+95)",
			      ret, errno);
			ibv_dereg_mr(mr);
		}

		/* 正例对照: 普通 (无 identity 位) MR 的 rereg 不受影响 */
		mr = ibv_reg_mr(pd, buf, 4096,
				IBV_ACCESS_LOCAL_WRITE |
				IBV_ACCESS_REMOTE_READ);
		CHECK(mr != NULL, "普通 MR 注册成功");
		if (mr) {
			errno = 0;
			ret = ibv_rereg_mr(mr, IB_MR_REREG_ACCESS,
					   NULL, NULL, 0,
					   IBV_ACCESS_REMOTE_READ |
					   IBV_ACCESS_LOCAL_WRITE);
			CHECK(ret == 0,
			      "普通 MR rereg 仍成功 (ret=%d errno=%d) — 未误伤",
			      ret, errno);
			ibv_dereg_mr(mr);
		}
		munmap(buf, 4096);
		ibv_dealloc_pd(pd);
		ibv_close_device(ctx);
	}

	printf("\n结果: %d 通过, %d 失败\n", passed, failed);
	close(sym_fd);
	return failed ? 1 : 0;
}
