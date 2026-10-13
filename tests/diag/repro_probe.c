/* 快速探针: 不同批大小的 REPAIR_RANGE 是否都崩 (定位触发条件) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include "libsymrdma.h"

#define SYMRDMA_IOC_MAGIC 'S'
struct rr_l { int mr_id; unsigned long page_idx; unsigned long npages; };
#define IOC_RR _IOWR(SYMRDMA_IOC_MAGIC, 11, struct rr_l)

#ifndef MADV_NOHUGEPAGE
#define MADV_NOHUGEPAGE 15
#endif

int main(int argc, char **argv)
{
	unsigned long npages = argc > 1 ? atol(argv[1]) : 2;
	unsigned long np = argc > 2 ? atol(argv[2]) : 1;
	struct symrdma_ctx sctx;
	struct symrdma_mr smr;
	struct ibv_device **l;
	struct ibv_context *ictx;
	struct ibv_pd *pd;
	unsigned char *buf;
	struct rr_l rr;
	int k;

	setvbuf(stdout, NULL, _IOLBF, 0);
	buf = mmap((void *)0x600000000000UL, 32UL*1024*1024,
		   PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE|MAP_NORESERVE, -1, 0);
	if (buf == MAP_FAILED) { perror("mmap"); return 1; }
	madvise(buf, 32UL*1024*1024, MADV_NOHUGEPAGE);
	if (symrdma_open(&sctx)) return 2;
	l = ibv_get_device_list(NULL);
	ictx = ibv_open_device(l[0]);
	pd = ibv_alloc_pd(ictx);
	if (symrdma_mr_register(&sctx, pd, buf, 32UL*1024*1024, &smr)) { printf("reg fail\n"); return 1; }
	printf("buf=%p (align2MB=%d) mr=%d vt=%d\n", buf,
	       !((unsigned long)buf & 0x1fffff), smr.mr_id, !!smr.version_mr);

	madvise(buf, 16UL*1024*1024, MADV_DONTNEED);
	for (k = 0; k < 32; k += np) {
		rr.mr_id = smr.mr_id; rr.page_idx = npages + k; rr.npages = np;
		printf("REPAIR_RANGE(%lu, %lu) …\n", rr.page_idx, np);
		if (ioctl(sctx.fd, IOC_RR, &rr)) {
			printf("  -> errno=%d (%s)\n", errno, strerror(errno));
			return 1;
		}
		printf("  -> repaired=%lu\n", rr.npages);
	}
	printf("ALL OK\n");
	return 0;
}
