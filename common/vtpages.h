/* SPDX-License-Identifier: GPL-2.0 */

#ifndef SYMRDMA_VTPAGES_H
#define SYMRDMA_VTPAGES_H

#include <stddef.h>
#include "symrdma_abi.h"

static inline unsigned long symrdma_vt_pages(unsigned long npages)
{
	return (npages + SYMRDMA_VERS_PER_PAGE - 1) / SYMRDMA_VERS_PER_PAGE;
}

#endif
