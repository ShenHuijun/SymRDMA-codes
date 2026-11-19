/* SPDX-License-Identifier: GPL-2.0 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "control_log.h"

static int crt_log_level_cached = -1;

int crt_log_level(void)
{
	if (crt_log_level_cached < 0) {
		const char *m = getenv("SYMRDMA_SIR_DEBUG");

		if (!m || !*m || !strcmp(m, "0") || !strcmp(m, "off"))
			crt_log_level_cached = 0;
		else if (m[0] >= '2' && m[0] <= '9' && !m[1])
			crt_log_level_cached = m[0] - '0';
		else
			crt_log_level_cached = 1;
	}
	return crt_log_level_cached;
}

int64_t crt_now_us(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (int64_t)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}

int64_t crt_now_ms(void)
{
	return crt_now_us() / 1000;
}

void crt_log_emit_buf(const char *buf, size_t n)
{
	size_t off = 0;

	while (off < n) {
		ssize_t w = write(2, buf + off, n - off);

		if (w < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		off += (size_t)w;
	}
}

void crt_log_emit(const char *fmt, ...)
{
	char buf[512];
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	if (n < 0)
		return;
	if ((size_t)n >= sizeof(buf)) {
		static const char mark[] = " …TRUNC";
		size_t keep = sizeof(buf) - sizeof(mark);

		memcpy(buf + keep, mark, sizeof(mark) - 1);
		n = (int)(keep + sizeof(mark) - 1);
	}
	crt_log_emit_buf(buf, (size_t)n);
}
