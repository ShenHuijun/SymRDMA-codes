/* SPDX-License-Identifier: GPL-2.0 */

#ifndef SYMRDMA_REPAIR_SPAN_H
#define SYMRDMA_REPAIR_SPAN_H

#include <stdint.h>

#define SIR_F_READ        1
#define SIR_F_WRITE       2

#define SIR_REPAIR_BATCH_MAX  16

struct sir_repair_span {
	uint64_t page_idx;
	uint32_t npages;
	uint32_t dir;
	uint64_t xaddr;
	uint32_t xrkey;
	uint32_t xoff;
	uint32_t xlen;
	uint32_t rsv;
};

#endif
