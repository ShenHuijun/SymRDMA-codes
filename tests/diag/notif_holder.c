/* notif_holder.c — 外部页失效源调查诱饵 ()
 *
 * 用途: 注册一个 SymRDMA MR 并保持驻留 (mlockall) 睡眠, 让模块的
 * per-mm MMU notifier 挂在本进程上 — 期间测试床上任何外部页失效源
 * (EDR 代理/NUMA 均衡/THP 整理等) 触碰本进程地址空间时, 事件会被
 * notifier 取证环形缓冲记录 (comm/pid/调用栈), 经 /proc/symrdma 读取。
 *
 * 本进程自身不触发任何 madvise/munmap — 观察窗口内 /proc/symrdma
 * 出现的事件全部来自外部源 (基线对照见 scripts/investigate_invalidation.sh)。
 *
 * 用法: notif_holder <seconds> [size_mb]
 *   默认 30 秒, 64 MB 匿名私有区域, mlockall 驻留保证。
 * 编译: make notif_holder (无依赖, /dev/symrdma 即可运行)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <stdint.h>

struct symrdma_ioc_reg_mr { uint64_t va_start; uint64_t len; int mr_id; };
#define SYMRDMA_IOC_MAGIC 'S'
#define SYMRDMA_IOC_REG_MR _IOWR(SYMRDMA_IOC_MAGIC, 1, struct symrdma_ioc_reg_mr)

int main(int argc, char **argv)
{
	int fd, secs = 30;
	size_t sz = 64UL * 1024 * 1024;
	char *a, *p;
	long long id;

	if (argc > 1)
		secs = atoi(argv[1]);
	if (argc > 2)
		sz = (size_t)atol(argv[2]) * 1024 * 1024;
	if (secs <= 0)
		secs = 30;

	fd = open("/dev/symrdma", O_RDWR);
	if (fd < 0) {
		perror("open /dev/symrdma (模块未加载?)");
		return 1;
	}

	/* 驻留保证: 全部 mlock (锁定页不被 reclaim, 但 COW-break/
	 * 迁移类外部失效仍会触发 notifier — 正是调查目标) */
	if (mlockall(MCL_CURRENT | MCL_FUTURE) != 0)
		fprintf(stderr, "notif_holder: mlockall 失败 (继续, 页可换出)\n");

	a = mmap(NULL, sz, PROT_READ | PROT_WRITE,
		 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (a == MAP_FAILED) {
		perror("mmap");
		return 1;
	}
	/* 逐页触碰 + 写入可校验模式 (确保匿名页真实分配并驻留) */
	for (p = a; p < a + (long)sz; p += 4096)
		*(uint32_t *)p = 0x53594d52;   /* 'SYMR' */

	memset(&id, 0, sizeof(id));
	{
		struct symrdma_ioc_reg_mr r;
		memset(&r, 0, sizeof(r));
		r.va_start = (uint64_t)a;
		r.len = sz;
		if (ioctl(fd, SYMRDMA_IOC_REG_MR, &r) < 0) {
			perror("REG_MR");
			return 1;
		}
		id = r.mr_id;
	}

	printf("notif_holder: pid=%d MR %llu 个 @%p len=%zu MB, 持有 %d s "
	       "(本进程零内存操作, 观察窗口内事件全部来自外部源)\n",
	       getpid(), (unsigned long long)id, a, sz >> 20, secs);
	fflush(stdout);

	sleep(secs);

	printf("notif_holder: pid=%d 退出\n", getpid());
	return 0;
}
