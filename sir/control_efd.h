/* SPDX-License-Identifier: GPL-2.0 */

#ifndef CONTROL_EFD_H
#define CONTROL_EFD_H

#include <stdint.h>
#include <unistd.h>

static inline void crt_efd_write(int fd, uint64_t v)
{
	uint64_t one = v ? v : 1;

	if (fd >= 0)
		(void)!write(fd, &one, sizeof(one));
}

static inline void crt_efd_drain(int fd)
{
	uint64_t v;

	while (fd >= 0 && read(fd, &v, sizeof(v)) == (ssize_t)sizeof(v))
		;
}

#endif
