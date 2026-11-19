/* SPDX-License-Identifier: GPL-2.0 */

#ifndef NPR_OP_H
#define NPR_OP_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <endian.h>
#include "sir.h"

/* Covers mlx5 max_sge/max_sge_rd (30); descriptors remain owned by value. */
#define NPR_OP_MAX_SGE 32

enum npr_op_kind {
	NPR_OP_READ = 0,
	NPR_OP_WRITE,
	NPR_OP_WRITE_IMM,
	NPR_OP_ATOMIC,
	NPR_OP_SEND,
	NPR_OP_SEND_IMM,
};

enum npr_remote_state { NPR_REMOTE_UNRESOLVED=0, NPR_REMOTE_FOUND, NPR_REMOTE_FOREIGN };

struct npr_sge {
	uint64_t addr;
	uint32_t length;
	uint32_t lkey;
};

struct npr_order_entry;
struct npr_rdv_owner;
struct mr_entry;

struct npr_op {
	struct npr_order_entry *order;
	struct npr_rdv_owner *rdv_owner;
	enum npr_op_kind kind;
	uint64_t remote_addr;
	uint32_t rkey;
	/* the write view's key: required on the write path (WRITE /
	 * WRITE_IMM / batch members), resolved only through npr_write_key();
	 * the repair carrier never uses it - it carries the read key by role */
	uint32_t wkey;
	unsigned num_sge;
	struct npr_sge sge[NPR_OP_MAX_SGE];
 /* Borrowed only under the order lease or concrete SOURCE use claim. */
 const struct mr_entry *local_mr[NPR_OP_MAX_SGE];
 /* CPU atomic result address authorized by the admission lease; zero rejects. */
 uint64_t atomic_sink_cpu;
	uint64_t len;

	unsigned signaled : 1;
 unsigned local_bound : 1;

	unsigned inline_ : 1;
	uint64_t wr_id;

	uint32_t flags;
	__be32 imm;
	uint64_t atom_compare_add;
	uint64_t atom_swap;
	unsigned atom_cas : 1;

	unsigned remote_state;
	struct sir_export exp;
};

static inline int npr_op_is_read(const struct npr_op *op)
{
	return op->kind == NPR_OP_READ;
}

static inline int npr_op_is_write(const struct npr_op *op)
{
	return op->kind == NPR_OP_WRITE || op->kind == NPR_OP_WRITE_IMM;
}

static inline int npr_op_is_send(const struct npr_op *op)
{
 return op->kind == NPR_OP_SEND || op->kind == NPR_OP_SEND_IMM;
}
static inline int npr_op_has_remote(const struct npr_op *op)
{
 return !npr_op_is_send(op);
}
static inline int npr_op_local_sink(const struct npr_op *op)
{
 return npr_op_is_read(op) || op->kind == NPR_OP_ATOMIC;
}
/* Map logical byte offsets, never assume adjacent virtual addresses or MRs. */
struct npr_sg_slice {
 unsigned index;
 uint64_t addr, length;
};
static inline int npr_sg_valid(const struct npr_op *op)
{
 uint64_t total=0;
 if(!op||!op->num_sge||op->num_sge>NPR_OP_MAX_SGE)return 0;
 for(unsigned i=0;i<op->num_sge;i++) {
  if(op->sge[i].addr>UINT64_MAX-op->sge[i].length||
     total>UINT64_MAX-op->sge[i].length)return 0;
  total+=op->sge[i].length;
 }
 return total==op->len;
}
static inline int npr_sg_at(const struct npr_op *op,uint64_t off,
                          uint64_t length,struct npr_sg_slice *out)
{
 if(!op||!out||op->num_sge>NPR_OP_MAX_SGE||off>=op->len||!length)return -1;
 for(unsigned i=0;i<op->num_sge;i++) {
  if(off>=op->sge[i].length){off-=op->sge[i].length;continue;}
  if(op->sge[i].addr>UINT64_MAX-off)return -1;
  out->index=i;out->addr=op->sge[i].addr+off;
  out->length=op->sge[i].length-off;
  if(out->length>length)out->length=length;
  return 0;
 }
 return -1;
}
static inline int npr_sg_copy(const struct npr_op *op,uint64_t off,
                            void *buffer,size_t length,int scatter)
{
 unsigned char *bytes=buffer;
 if(!op||off>op->len||length>op->len-off)return -1;
 while(length) {
  struct npr_sg_slice part;
  if(npr_sg_at(op,off,length,&part))return -1;
  if(scatter)memcpy((void *)(uintptr_t)part.addr,bytes,(size_t)part.length);
  else memcpy(bytes,(const void *)(uintptr_t)part.addr,(size_t)part.length);
  bytes+=part.length;off+=part.length;length-=(size_t)part.length;
 }
 return 0;
}
#endif
