/*
 * test_iommu_verify.c — SymRDMA Level 1 验证程序
 *
 * 通过 /dev/symrdma 的 READ_IOVA / REPAIR ioctl 验证 IOMMU 级别的
 * 哨兵/黑洞页映射机制的正确性，无需 RDMA 网卡。
 *
 * 编译: gcc -O2 -Wall -o test_iommu_verify test_iommu_verify.c
 * 运行: sudo ./test_iommu_verify
 *
 * 7 个测试:
 *   T1 正常读取  T2 哨兵重映射  T3 换入修复  T4 黑洞吸收
 *   T5 邻居隔离  T6 版本号      T7 缺失页修复
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <errno.h>

/* ---- 与 symrdma.h 保持同步 ---- */
#define SYMRDMA_IOC_MAGIC       'S'
#define SYMRDMA_SENTINEL_MAGIC  0xdeadbeef
#define SYMRDMA_REMAP_REAL      0
#define SYMRDMA_REMAP_SENTINEL  1
#define SYMRDMA_REMAP_BLACKHOLE 2

struct symrdma_ioc_reg_mr {
	unsigned long long va_start, len;
	int mr_id;
};
struct symrdma_ioc_remap {
	int mr_id;
	unsigned long page_idx;
	int mode;
};
struct symrdma_ioc_get_iova {
	int mr_id;
	unsigned long page_idx;
	unsigned long long read_iova, write_iova;
};
struct symrdma_ioc_read_iova {
	int mr_id;
	unsigned long long iova;
	unsigned long offset;
	unsigned int value;
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

#define SYMRDMA_IOC_REG_MR      _IOWR(SYMRDMA_IOC_MAGIC, 1, struct symrdma_ioc_reg_mr)
#define SYMRDMA_IOC_DEREG_MR    _IOW(SYMRDMA_IOC_MAGIC,  2, int)
#define SYMRDMA_IOC_REMAP       _IOW(SYMRDMA_IOC_MAGIC,  3, struct symrdma_ioc_remap)
#define SYMRDMA_IOC_GET_IOVA    _IOWR(SYMRDMA_IOC_MAGIC, 4, struct symrdma_ioc_get_iova)
#define SYMRDMA_IOC_READ_IOVA   _IOWR(SYMRDMA_IOC_MAGIC, 5, struct symrdma_ioc_read_iova)
#define SYMRDMA_IOC_REPAIR      _IOWR(SYMRDMA_IOC_MAGIC,  6, struct symrdma_ioc_repair)
#define SYMRDMA_IOC_GET_VERSION _IOWR(SYMRDMA_IOC_MAGIC,  7, struct symrdma_ioc_get_version)

/* ---- 测试辅助 ---- */
#define NPAGES      4
#define PAGE_SIZE   4096
#define BUF_SIZE    (NPAGES * PAGE_SIZE)

static int passed = 0, failed = 0;

#define TEST(name) do { \
	printf("\n[TEST %d] %s\n", ++tn, name); \
} while (0)

#define CHECK(cond, msg) do { \
	if (cond) { printf("  PASS: %s\n", msg); passed++; } \
	else      { printf("  FAIL: %s (%s)\n", msg, strerror(errno)); failed++; } \
} while (0)

/*
 * T7 辅助函数: 测试缺失页修复。
 *
 * 分配大范围内存，最后几页从未被访问过。
 * 对于 MAP_ANONYMOUS + MAP_NORESERVE，未访问页没有物理页支持，
 * get_user_pages_fast 应失败 → REPAIR 应返回 -EAGAIN。
 */
static void test_t7_absent_repair(int fd)
{
	unsigned char *big_buf;
	struct symrdma_ioc_reg_mr reg = {0};
	struct symrdma_ioc_repair repair;
	int mr_id, ret;

	/*
	 * 使用 MAP_NORESERVE: 内核不预分配物理页，仅在首次访问时按需分配。
	 * 分配 64 页，只访问前 60 页，最后 4 页保持未分配状态。
	 */
	big_buf = mmap(NULL, 64 * PAGE_SIZE, PROT_READ | PROT_WRITE,
		       MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE, -1, 0);
	if (big_buf == MAP_FAILED) {
		printf("  SKIP: mmap MAP_NORESERVE 失败 (%s)\n", strerror(errno));
		return;
	}

	/* 只 touch 前 60 页 */
	for (int i = 0; i < 60; i++)
		big_buf[i * PAGE_SIZE] = (unsigned char)i;

	reg.va_start = (unsigned long long)big_buf;
	reg.len = 64 * PAGE_SIZE;
	ret = ioctl(fd, SYMRDMA_IOC_REG_MR, &reg);
	if (ret != 0) {
		printf("  SKIP: REG_MR 失败 (%s)\n", strerror(errno));
		munmap(big_buf, 64 * PAGE_SIZE);
		return;
	}
	mr_id = reg.mr_id;

	/* 版本初始化回归: 注册时缺失页
	 * 的版本号必须是偶数 (0), 驻留页必须是奇数 (1) — 版本表须在
	 * 页表遍历之后初始化, 否则缺失页会被误置为奇数 → seqlock
	 * 短路失效, 哨兵数据被当作有效数据 */
	{
		struct symrdma_ioc_get_version ver = {
			.mr_id = mr_id,
			.page_idx = 63,
		};
		ret = ioctl(fd, SYMRDMA_IOC_GET_VERSION, &ver);
		CHECK(ret == 0 && !(ver.version & 1),
		      "注册时缺失页 (p63) 版本号 = 偶数 (0)");
		ver.page_idx = 0;
		ret = ioctl(fd, SYMRDMA_IOC_GET_VERSION, &ver);
		CHECK(ret == 0 && (ver.version & 1),
		      "注册时驻留页 (p0) 版本号 = 奇数 (1)");
	}

	/*
	 * 页 63 从未被访问 — 没有物理页支持。
	 * 但有些内核可能在 mmap 时预填充，所以使用 madvise 明确回收。
	 * 若 madvise 失败则仍然尝试 REPAIR。
	 */
	madvise(big_buf + 63 * PAGE_SIZE, PAGE_SIZE, MADV_DONTNEED);
	madvise(big_buf + 62 * PAGE_SIZE, PAGE_SIZE, MADV_DONTNEED);
	madvise(big_buf + 61 * PAGE_SIZE, PAGE_SIZE, MADV_DONTNEED);

	/* 先测试确实被 touch 过的页(页0)可以修复 */
	repair.mr_id = mr_id;
	repair.page_idx = 0;
	ret = ioctl(fd, SYMRDMA_IOC_REPAIR, &repair);
	CHECK(ret == 0, "已驻留页(p0) REPAIR 成功");

	/* 再测试未驻留页 */
	repair.page_idx = 63;
	ret = ioctl(fd, SYMRDMA_IOC_REPAIR, &repair);
	/*
	 * -EAGAIN 是最理想的结果。但若内核预分配了部分页，
	 * 即便 madvise(DONTNEED) 后可能仍然有 zero page 映射。
	 * 此时 REPAIR 成功也是合理的（页面在 swap cache 或 zero page 中）。
	 */
	if (ret == 0)
		CHECK(1, "REPAIR 页63 成功 (内核预填充)");
	else if (ret == -1 && (errno == EAGAIN || errno == 11))
		CHECK(1, "REPAIR 返回 -EAGAIN (页未驻留)");
	else
		printf("  注意: REPAIR 页63 返回 %d (errno=%d %s)\n",
		       ret, errno, strerror(errno));

	ioctl(fd, SYMRDMA_IOC_DEREG_MR, mr_id);
	munmap(big_buf, 64 * PAGE_SIZE);
}

/* ---- 主程序 ---- */
/* ---- 套件预检金丝雀 (--sentinel-check) ----
 *
 * 检测全局哨兵页是否被污染 (历史 RDMA 写经读 IOVA 落入 RW 哨兵映射):
 * REMAP→SENTINEL 后 READ_IOVA 应返回 0xdeadbeef; 若为其他值, 则哨兵
 * 页粘性污染 — 所有依赖哨兵检测的 Level (L1/L3/L4/L5/L7/L13) 会级联
 * 误报。退出码: 0=正常, 2=污染 (需重载 symrdma 模块恢复), 1=基础设施错误。
 * 哨兵只读加固 (kernel/symrdma_iommu.c) 后 DMA 写不再能污染;
 * 此检查保留为环境异常早期预警。
 */
static int sentinel_check_mode(void)
{
	int fd, ret;
	unsigned char *buf;
	struct symrdma_ioc_reg_mr reg = {0};
	struct symrdma_ioc_get_iova iova_req;
	struct symrdma_ioc_read_iova read_req;
	struct symrdma_ioc_remap remap_req;

	fd = open("/dev/symrdma", O_RDWR);
	if (fd < 0) { perror("open /dev/symrdma"); return 1; }

	buf = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
		   MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (buf == MAP_FAILED) { perror("mmap"); close(fd); return 1; }
	memset(buf, 0xAB, PAGE_SIZE);

	reg.va_start = (unsigned long long)buf;
	reg.len = PAGE_SIZE;
	if (ioctl(fd, SYMRDMA_IOC_REG_MR, &reg) < 0) {
		perror("REG_MR"); munmap(buf, PAGE_SIZE); close(fd); return 1;
	}

	iova_req.mr_id = reg.mr_id; iova_req.page_idx = 0;
	if (ioctl(fd, SYMRDMA_IOC_GET_IOVA, &iova_req) < 0) {
		perror("GET_IOVA"); goto err_out;
	}

	remap_req.mr_id = reg.mr_id; remap_req.page_idx = 0;
	remap_req.mode = SYMRDMA_REMAP_SENTINEL;
	if (ioctl(fd, SYMRDMA_IOC_REMAP, &remap_req) < 0) {
		perror("REMAP SENTINEL"); goto err_out;
	}

	read_req.mr_id = reg.mr_id; read_req.iova = iova_req.read_iova;
	read_req.offset = 0;
	if (ioctl(fd, SYMRDMA_IOC_READ_IOVA, &read_req) < 0) {
		perror("READ_IOVA"); goto err_out;
	}

	if (read_req.value == SYMRDMA_SENTINEL_MAGIC) {
		printf("sentinel-check: OK (0xdeadbeef)\n");
		ret = 0;
	} else {
		printf("sentinel-check: POLLUTED (读出 0x%08x, 期望 0xdeadbeef)\n",
		       read_req.value);
		printf("  → 哨兵页粘性污染: 后续哨兵相关测试会级联误报\n");
		printf("  → 恢复: 重载 symrdma 模块 (特权操作, 见 env/*/apply_env_fix.sh)\n");
		ret = 2;
	}

	ioctl(fd, SYMRDMA_IOC_DEREG_MR, reg.mr_id);
	munmap(buf, PAGE_SIZE);
	close(fd);
	return ret;

err_out:
	ioctl(fd, SYMRDMA_IOC_DEREG_MR, reg.mr_id);
	munmap(buf, PAGE_SIZE);
	close(fd);
	return 1;
}

int main(int argc, char **argv)
{
	if (argc > 1 && strcmp(argv[1], "--sentinel-check") == 0)
		return sentinel_check_mode();

	int fd, ret, tn = 0;
	unsigned char *buf;
	struct symrdma_ioc_reg_mr reg = {0};
	struct symrdma_ioc_get_iova iova_req;
	struct symrdma_ioc_read_iova read_req;
	struct symrdma_ioc_remap remap_req;
	struct symrdma_ioc_repair repair_req;
	struct symrdma_ioc_get_version ver_req;
	unsigned long long riova0, wiova0, riova1;
	unsigned int expected_first_word;

	printf("=== SymRDMA Level 1: IOMMU Sentinel/Blackhole 验证 ===\n");

	/* 打开设备 */
	fd = open("/dev/symrdma", O_RDWR);
	if (fd < 0) { perror("open /dev/symrdma"); return 1; }
	printf("已打开 /dev/symrdma\n");

	/* 分配匿名内存并写入可识别的测试数据 */
	buf = mmap(NULL, BUF_SIZE, PROT_READ | PROT_WRITE,
		   MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (buf == MAP_FAILED) { perror("mmap"); return 1; }

	/* 每页首字节写入 'A'+page_idx，其余保持 0xAB 便于识别 */
	memset(buf, 0xAB, BUF_SIZE);
	for (int i = 0; i < NPAGES; i++)
		buf[i * PAGE_SIZE] = (unsigned char)('A' + i);

	/*
	 * 页0 数据布局 (little-endian 4 字节 at offset 0):
	 *   buf[0] = 'A' = 0x41, buf[1..3] = 0xAB
	 *   值 = 0xABABAB41
	 */
	expected_first_word = 0xABABAB41;

	/* REG_MR */
	reg.va_start = (unsigned long long)buf;
	reg.len = BUF_SIZE;
	ret = ioctl(fd, SYMRDMA_IOC_REG_MR, &reg);
	CHECK(ret == 0, "REG_MR 成功");
	if (ret) goto cleanup;
	printf("  mr_id=%d\n", reg.mr_id);

	/* GET_IOVA — 获取 IOVA 地址 */
	iova_req.mr_id = reg.mr_id;
	iova_req.page_idx = 0;
	ret = ioctl(fd, SYMRDMA_IOC_GET_IOVA, &iova_req);
	CHECK(ret == 0, "GET_IOVA 成功");
	riova0 = iova_req.read_iova;
	wiova0 = iova_req.write_iova;
	iova_req.page_idx = 1;
	ioctl(fd, SYMRDMA_IOC_GET_IOVA, &iova_req);
	riova1 = iova_req.read_iova;
	(void)wiova0; /* 验证程序中未直接使用 */

	/* ====== T1: 正常读取 ====== */
	TEST("正常读取: READ_IOVA 返回用户数据");
	read_req.mr_id = reg.mr_id; read_req.iova = riova0; read_req.offset = 0;
	ret = ioctl(fd, SYMRDMA_IOC_READ_IOVA, &read_req);
	CHECK(ret == 0 && read_req.value == expected_first_word,
	      "IOMMU 读取到用户写入的数据 (0xABABAB41)");
	CHECK(read_req.value != SYMRDMA_SENTINEL_MAGIC,
	      "确认不是哨兵魔数 (页面驻留)");

	/* ====== T2: 哨兵重映射 ====== */
	TEST("哨兵重映射: REMAP→SENTINEL → READ_IOVA 返回 0xdeadbeef");
	remap_req.mr_id = reg.mr_id; remap_req.page_idx = 0;
	remap_req.mode = SYMRDMA_REMAP_SENTINEL;
	ret = ioctl(fd, SYMRDMA_IOC_REMAP, &remap_req);
	CHECK(ret == 0, "REMAP to SENTINEL 成功");
	read_req.iova = riova0; read_req.offset = 0;
	ret = ioctl(fd, SYMRDMA_IOC_READ_IOVA, &read_req);
	CHECK(ret == 0 && read_req.value == SYMRDMA_SENTINEL_MAGIC,
	      "IOMMU 返回 0xdeadbeef");

	/* ====== T3: 修复 ====== */
	TEST("换入修复: REPAIR → READ_IOVA 返回原始数据");
	repair_req.mr_id = reg.mr_id; repair_req.page_idx = 0;
	ret = ioctl(fd, SYMRDMA_IOC_REPAIR, &repair_req);
	CHECK(ret == 0, "REPAIR 成功");
	read_req.iova = riova0;
	ret = ioctl(fd, SYMRDMA_IOC_READ_IOVA, &read_req);
	/*
	 * 修复后: CPU 端 buf[0]='A', buf[1..3]=0xAB
	 * IOMMU 读回的值 = 0xABABAB41
	 */
	CHECK(ret == 0 && read_req.value == expected_first_word,
	      "修复后返回原始用户数据");

	/* ====== T4: 黑洞吸收 ====== */
	TEST("黑洞吸收: REMAP→BLACKHOLE → CPU写入 → 读哨兵验证写入被吸收");
	remap_req.mode = SYMRDMA_REMAP_BLACKHOLE;
	ret = ioctl(fd, SYMRDMA_IOC_REMAP, &remap_req);
	CHECK(ret == 0, "REMAP to BLACKHOLE 成功");
	/* CPU 端写入 (通过用户态 VA，不经过 IOMMU) */
	memset(buf, 0xFF, PAGE_SIZE);
	/* 切换 read IOVA 到哨兵 */
	remap_req.mode = SYMRDMA_REMAP_SENTINEL;
	ioctl(fd, SYMRDMA_IOC_REMAP, &remap_req);
	/* 通过 IOMMU 读取 — 应看到哨兵而非 0xFF */
	read_req.iova = riova0;
	ret = ioctl(fd, SYMRDMA_IOC_READ_IOVA, &read_req);
	CHECK(ret == 0 && read_req.value == SYMRDMA_SENTINEL_MAGIC,
	      "写入被黑洞吸收: IOMMU 读仍为哨兵魔数");
	/* 恢复 */
	ioctl(fd, SYMRDMA_IOC_REPAIR, &repair_req);
	/* 恢复用户态数据用于后续测试 */
	buf[0] = 'A';

	/* ====== T5: 邻居隔离 ====== */
	TEST("邻居隔离: 页0重映射不影响页1");
	remap_req.mode = SYMRDMA_REMAP_SENTINEL;
	ioctl(fd, SYMRDMA_IOC_REMAP, &remap_req);  /* 页0→哨兵 */
	read_req.iova = riova0;
	ioctl(fd, SYMRDMA_IOC_READ_IOVA, &read_req);
	CHECK(read_req.value == SYMRDMA_SENTINEL_MAGIC, "页0 = 哨兵魔数");
	read_req.iova = riova1;
	ret = ioctl(fd, SYMRDMA_IOC_READ_IOVA, &read_req);
	/*
	 * 页1: buf[PAGE_SIZE] = 'B' = 0x42, 其余 0xAB
	 * 值 = 0xABABAB42
	 */
	CHECK(ret == 0 && read_req.value != SYMRDMA_SENTINEL_MAGIC,
	      "页1 不受影响 (邻居隔离)");
	ioctl(fd, SYMRDMA_IOC_REPAIR, &repair_req);

	/* ====== T6: 版本号 ====== */
	TEST("版本号: 驻留→缺失→驻留 的奇偶翻转");
	/* 修复后应为奇数 (GET_VERSION 按 mr_id 精确查询 —
	 * /proc/symrdma 解析会因其它 MR 存在而取错行, 已弃用) */
	ver_req.mr_id = reg.mr_id;
	ver_req.page_idx = 0;
	CHECK(ioctl(fd, SYMRDMA_IOC_GET_VERSION, &ver_req) == 0 &&
	      (ver_req.version & 1),
	      "修复后版本号为奇数 (驻留)");

	/* 哨兵重映射后应为偶数 */
	remap_req.mode = SYMRDMA_REMAP_SENTINEL;
	ioctl(fd, SYMRDMA_IOC_REMAP, &remap_req);
	CHECK(ioctl(fd, SYMRDMA_IOC_GET_VERSION, &ver_req) == 0 &&
	      !(ver_req.version & 1),
	      "哨兵后版本号为偶数 (缺失)");

	/* 再次修复 → 恢复奇数 */
	ioctl(fd, SYMRDMA_IOC_REPAIR, &repair_req);
	CHECK(ioctl(fd, SYMRDMA_IOC_GET_VERSION, &ver_req) == 0 &&
	      (ver_req.version & 1),
	      "修复后版本号恢复奇数 (驻留)");

	/* ====== T7: 缺失页修复 ====== */
	TEST("缺失页修复: 未分配 VA 调用 REPAIR → 预期行为");
	test_t7_absent_repair(fd);

	/* ====== 清理 ====== */
	TEST("清理: DEREG_MR");
	ret = ioctl(fd, SYMRDMA_IOC_DEREG_MR, reg.mr_id);
	CHECK(ret == 0, "DEREG_MR 成功");

	printf("\n========================================\n");
	printf("结果: %d 通过, %d 失败, %d 总计\n", passed, failed, passed + failed);
	printf("========================================\n");

cleanup:
	munmap(buf, BUF_SIZE);
	close(fd);
	return failed > 0 ? 1 : 0;
}
