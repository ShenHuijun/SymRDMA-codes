/* SPDX-License-Identifier: GPL-2.0 */

#ifndef CONTROL_FUTEX_H
#define CONTROL_FUTEX_H

#include <errno.h>
#include <linux/futex.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static inline int64_t crt_futex_now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (int64_t)ts.tv_sec * 1000000000LL + (int64_t)ts.tv_nsec;
}

static inline int crt_futex_wait(uint32_t *word, uint32_t expect,
				 int64_t deadline_ns)
{
	struct timespec ts;
	long rc;

	if (deadline_ns > 0) {
		int64_t rel = deadline_ns - crt_futex_now_ns();

		if (rel < 0)
			rel = 0;
		ts.tv_sec = (time_t)(rel / 1000000000LL);
		ts.tv_nsec = (long)(rel % 1000000000LL);
		rc = syscall(SYS_futex, (uint32_t *)word, FUTEX_WAIT_PRIVATE,
			     expect, &ts, NULL, 0);
	} else {
		rc = syscall(SYS_futex, (uint32_t *)word, FUTEX_WAIT_PRIVATE,
			     expect, NULL, NULL, 0);
	}
	if (rc == 0 || errno == EAGAIN)
		return 0;
	if (errno == ETIMEDOUT)
		return -ETIMEDOUT;
	if (errno == EINTR)
		return -EINTR;
	return -errno;
}

static inline int crt_futex_wake(uint32_t *word, int n)
{
	long rc;

	if (n <= 0)
		n = 0x7fffffff;
	rc = syscall(SYS_futex, (uint32_t *)word, FUTEX_WAKE_PRIVATE, n,
		     NULL, NULL, 0);
	return rc < 0 ? -errno : (int)rc;
}

#endif
