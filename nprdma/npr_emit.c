/* SPDX-License-Identifier: GPL-2.0 */

#define _GNU_SOURCE
#include <string.h>
#include <errno.h>
#include <infiniband/verbs.h>
#include "nprdma_internal.h"
#include "npr_op.h"
#include "npr_identity.h"

int npr_emit_prepared(struct npr_ctx_entry *ce,struct ibv_qp *qp,
 const struct npr_op *op,struct npr_identity *id)
{
	struct ibv_sge sge[NPR_OP_MAX_SGE];
	struct ibv_send_wr wr;
	struct ibv_send_wr *bad = NULL;
	unsigned i;

	int rc;
	if (!ce->real_post_send) {npr_identity_abort(id);return ENOSYS;}
	memset(&wr, 0, sizeof(wr));
	switch (op->kind) {
	case NPR_OP_SEND:
		wr.opcode=IBV_WR_SEND;break;
	case NPR_OP_SEND_IMM:
		wr.opcode=IBV_WR_SEND_WITH_IMM;wr.imm_data=op->imm;break;
	case NPR_OP_READ:
		wr.opcode = IBV_WR_RDMA_READ;
		break;
	case NPR_OP_WRITE:
		wr.opcode = IBV_WR_RDMA_WRITE;
		break;
	case NPR_OP_WRITE_IMM:
		wr.opcode = IBV_WR_RDMA_WRITE_WITH_IMM;
		wr.imm_data = op->imm;
		break;
	case NPR_OP_ATOMIC:
		wr.opcode = op->atom_cas ? IBV_WR_ATOMIC_CMP_AND_SWP :
					   IBV_WR_ATOMIC_FETCH_AND_ADD;
		wr.wr.atomic.remote_addr = op->remote_addr;
		wr.wr.atomic.rkey = op->rkey;
		wr.wr.atomic.compare_add = op->atom_compare_add;
		wr.wr.atomic.swap = op->atom_swap;
		break;
	default:
		npr_identity_abort(id);return EINVAL;
	}
	for (i = 0; i < op->num_sge && i < NPR_OP_MAX_SGE; i++) {
		sge[i].addr = op->sge[i].addr;
		sge[i].length = op->sge[i].length;
		sge[i].lkey = op->sge[i].lkey;
		/* Keep the application lkey in the IR for ownership accounting;
		 * only the provider-facing copy selects the DMA direction view. */
        if(!op->inline_&&npr_data_lkey_owned(op,i,npr_op_local_sink(op),&sge[i].lkey)&&op->local_mr[i]){
         npr_identity_abort(id);return EACCES;
        }
	}
	wr.sg_list = op->num_sge ? sge : NULL;
	wr.num_sge = op->num_sge;
	wr.wr_id = id->token;
	if (npr_op_has_remote(op) && op->kind != NPR_OP_ATOMIC) {
		wr.wr.rdma.remote_addr = op->remote_addr;
		wr.wr.rdma.rkey = op->rkey;
		if (npr_op_is_read(op) && op->exp.app_rkey) {
			if (!(op->exp.app_access & IBV_ACCESS_REMOTE_READ))
				{npr_identity_abort(id);return EACCES;}
			wr.wr.rdma.rkey = op->exp.data_rkey;
		}
		if (npr_op_is_write(op)) {
			if (op->exp.app_rkey && !(op->exp.app_access & IBV_ACCESS_REMOTE_WRITE))
				{npr_identity_abort(id);return EACCES;}
			/* An application write lands on the write view, so
			 * the write key is required here; the read key is never a
			 * write key. A write without one is rejected fail-closed,
			 * counted, and never re-keyed onto the read view. */
			if (!op->wkey) {
				npr_engine_stat_inc(NPRDMA_ES_WRITE_NO_WKEY);
				npr_identity_abort(id);return EINVAL;
			}
			wr.wr.rdma.rkey = op->wkey;
		}
	}
	wr.send_flags = op->flags;
	if (op->inline_)
		wr.send_flags |= IBV_SEND_INLINE;
	if (op->signaled)
		wr.send_flags |= IBV_SEND_SIGNALED;
 wr.send_flags |= IBV_SEND_SIGNALED;
 rc=ce->real_post_send(qp,&wr,&bad);
 if(rc) npr_identity_abort(id);else npr_identity_accept(id);
 return rc;
}

int npr_emit_owned(struct npr_ctx_entry *ce,struct ibv_qp *qp,const struct npr_op *op,
 enum npr_identity_kind kind,void *owner)
{
 struct npr_identity_spec spec={.kind=kind,.lane=NPR_LANE_SQ,
  .user_wr_id=op->wr_id,.visible=op->signaled,.owner=owner};
 struct npr_identity *id;
 int rc;
 if((kind==NPR_ID_APP||kind==NPR_ID_AUX)&&owner) {
  const struct npr_inflight *e=owner;
  spec.caller_driven=!e->is_wwi&&!e->op.rdv_owner&&!e->pre_pin_n&&!e->async_check;
 }
 if(kind==NPR_ID_BATCH_MEMBER)spec.caller_driven=1;
 spec.opcode=npr_op_is_read(op)?IBV_WC_RDMA_READ:
  op->kind==NPR_OP_ATOMIC?(op->atom_cas?IBV_WC_COMP_SWAP:IBV_WC_FETCH_ADD):
  npr_op_is_send(op)?IBV_WC_SEND:IBV_WC_RDMA_WRITE;
 if(kind==NPR_ID_ORDER||kind==NPR_ID_BATCH_MEMBER) spec.order=op->order;
 id=npr_identity_prepare(ce,qp,qp->send_cq,&spec);
 if(!id) return errno?errno:ENOMEM;
 if(spec.order) npr_order_get(spec.order);
 if(kind==NPR_ID_APP||kind==NPR_ID_AUX||kind==NPR_ID_NOTIFY)
  ((struct npr_inflight *)owner)->native_refs++;
 if(kind==NPR_ID_BATCH_MEMBER&&owner) ((struct npr_qp_state *)owner)->batch_native_refs++;
 rc=npr_emit_prepared(ce,qp,op,id);
 if(rc&&spec.order) npr_order_put(spec.order);
 if(rc&&(kind==NPR_ID_APP||kind==NPR_ID_AUX||kind==NPR_ID_NOTIFY))
  ((struct npr_inflight *)owner)->native_refs--;
 if(rc&&kind==NPR_ID_BATCH_MEMBER&&owner) ((struct npr_qp_state *)owner)->batch_native_refs--;
 return rc;
}
int npr_emit_op(struct npr_ctx_entry *ce,struct ibv_qp *qp,const struct npr_op *op)
{return npr_emit_owned(ce,qp,op,op->order?NPR_ID_ORDER:NPR_ID_PASS,NULL);}
