/* SPDX-License-Identifier: GPL-2.0 */

#ifndef CONTROL_ERR_H
#define CONTROL_ERR_H

#include <errno.h>

#include "control_log.h"

static inline int crt_violation(int *fail_closed, long *violations)
{
	(*violations)++;
	*fail_closed = 1;

	crt_log(" violation: fail_closed set (violations=%ld)", *violations);
	return -EPROTO;
}

#endif
