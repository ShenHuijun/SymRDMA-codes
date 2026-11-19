/* SPDX-License-Identifier: GPL-2.0 */

#ifndef CONTROL_LOG_H
#define CONTROL_LOG_H

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

#if defined(__GNUC__)
#define CRT_INTERNAL __attribute__((visibility("hidden")))
#else
#define CRT_INTERNAL
#endif

CRT_INTERNAL int crt_log_level(void);
CRT_INTERNAL int64_t crt_now_us(void);
CRT_INTERNAL int64_t crt_now_ms(void);

static inline int64_t crt_now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (int64_t)ts.tv_sec * 1000000000ll + ts.tv_nsec;
}

CRT_INTERNAL void crt_log_emit_buf(const char *buf, size_t n);
CRT_INTERNAL void crt_log_emit(const char *fmt, ...)
	__attribute__((format(printf, 1, 2)));

#define crt_log(fmt, ...) do {                                         \
	if (crt_log_level() > 0) {                                      \
		int64_t _ts = crt_now_us();                             \
		crt_log_emit("[ctrl %lld.%03lld] " fmt "\n",             \
			      (long long)(_ts / 1000000),                 \
			      (long long)((_ts / 1000) % 1000),           \
			      ##__VA_ARGS__);                             \
	}                                                                \
} while (0)

#endif
