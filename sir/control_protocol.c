/* SPDX-License-Identifier: GPL-2.0 */

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include "control_protocol.h"

static void put_u16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v >> 8);
	p[1] = (uint8_t)v;
}

static void put_u32(uint8_t *p, uint32_t v)
{
	put_u16(p, (uint16_t)(v >> 16));
	put_u16(p + 2, (uint16_t)v);
}

static void put_u64(uint8_t *p, uint64_t v)
{
	put_u32(p, (uint32_t)(v >> 32));
	put_u32(p + 4, (uint32_t)v);
}

static uint16_t get_u16(const uint8_t *p)
{
	return (uint16_t)((uint16_t)p[0] << 8 | p[1]);
}

static uint32_t get_u32(const uint8_t *p)
{
	return (uint32_t)get_u16(p) << 16 | get_u16(p + 2);
}

static uint64_t get_u64(const uint8_t *p)
{
	return (uint64_t)get_u32(p) << 32 | get_u32(p + 4);
}

CRT_INTERNAL int cproto_header_encode(uint8_t *buf, uint32_t cap,
				       const struct cproto_header *h)
{
	if (!buf || !h)
		return -EINVAL;
	if (h->magic != CONTROL_PROTO_MAGIC ||
	    h->version != CONTROL_PROTO_VERSION ||
	    h->header_len != CONTROL_HEADER_LEN)
		return -EINVAL;
	if (h->kind < CPROTO_RPC_REQUEST || h->kind > CPROTO_CONTROL_EVENT)
		return -EINVAL;
	if (h->flags != 0)
		return -EINVAL;
	if (h->session_id == 0)
		return -EINVAL;

	if ((h->kind == CPROTO_RPC_REQUEST ||
	     h->kind == CPROTO_RPC_RESPONSE) && h->request_id == 0)
		return -EINVAL;
	if (h->payload_len > CONTROL_PAYLOAD_MAX)
		return -EINVAL;
	if (cap < CONTROL_HEADER_LEN + h->payload_len)
		return -ENOSPC;

	put_u64(buf + CPROTO_OFF_MAGIC, h->magic);
	put_u16(buf + CPROTO_OFF_VERSION, h->version);
	put_u16(buf + CPROTO_OFF_HEADER_LEN, h->header_len);
	put_u16(buf + CPROTO_OFF_KIND, h->kind);
	put_u16(buf + CPROTO_OFF_FLAGS, h->flags);
	put_u32(buf + CPROTO_OFF_PAYLOAD_LEN, h->payload_len);
	put_u64(buf + CPROTO_OFF_SESSION_ID, h->session_id);
	put_u64(buf + CPROTO_OFF_REQUEST_ID, h->request_id);
	put_u64(buf + CPROTO_OFF_CREDIT_TOTAL, h->credit_total);
	put_u64(buf + CPROTO_OFF_GENERATION, h->generation);
	return (int)CONTROL_HEADER_LEN;
}

CRT_INTERNAL int cproto_header_decode(const uint8_t *buf, uint32_t byte_len,
				       struct cproto_header *out)
{
	if (!buf || !out || byte_len < CONTROL_HEADER_LEN)
		return -EPROTO;

	out->magic        = get_u64(buf + CPROTO_OFF_MAGIC);
	out->version      = get_u16(buf + CPROTO_OFF_VERSION);
	out->header_len   = get_u16(buf + CPROTO_OFF_HEADER_LEN);
	out->kind         = get_u16(buf + CPROTO_OFF_KIND);
	out->flags        = get_u16(buf + CPROTO_OFF_FLAGS);
	out->payload_len  = get_u32(buf + CPROTO_OFF_PAYLOAD_LEN);
	out->session_id   = get_u64(buf + CPROTO_OFF_SESSION_ID);
	out->request_id   = get_u64(buf + CPROTO_OFF_REQUEST_ID);
	out->credit_total = get_u64(buf + CPROTO_OFF_CREDIT_TOTAL);
	out->generation   = get_u64(buf + CPROTO_OFF_GENERATION);

	if (out->magic != CONTROL_PROTO_MAGIC)
		return -EPROTO;
	if (out->version != CONTROL_PROTO_VERSION)
		return -EPROTO;
	if (out->header_len != CONTROL_HEADER_LEN)
		return -EPROTO;
	if (byte_len != out->header_len + (uint64_t)out->payload_len)
		return -EPROTO;
	if (byte_len > CONTROL_SLOT_CAPACITY)
		return -EPROTO;
	if (out->session_id == 0)
		return -EPROTO;
	if (out->kind < CPROTO_RPC_REQUEST || out->kind > CPROTO_CONTROL_EVENT)
		return -EPROTO;
	if ((out->kind == CPROTO_RPC_REQUEST ||
	     out->kind == CPROTO_RPC_RESPONSE) && out->request_id == 0)
		return -EPROTO;
	if (out->flags != 0)
		return -EPROTO;
	return 0;
}

CRT_INTERNAL int cproto_op_get(const uint8_t *payload, uint32_t payload_len,
				uint32_t *op)
{
	if (!payload || !op || payload_len < 4)
		return -EPROTO;
	*op = get_u32(payload);
	switch (*op) {
	case CPROTO_OP_HELLO:
	case CPROTO_OP_PING:
	case CPROTO_OP_REPAIR_INLINE:
	case CPROTO_OP_REPAIR_REVERSE:
	case CPROTO_OP_REPAIR_BATCH:
	case CPROTO_OP_ATOMIC:
	case CPROTO_OP_EXPORT_SNAPSHOT:
	case CPROTO_OP_CREDIT:
 case CPROTO_OP_KEY_LOOKUP:
 case CPROTO_OP_QP_BIND_INIT:
 case CPROTO_OP_QP_BIND_ACK:
 case CPROTO_OP_QP_UNBIND:
 case CPROTO_OP_RDV_OFFER:case CPROTO_OP_RDV_WAIT:case CPROTO_OP_RDV_ACK:
 case CPROTO_OP_RDV_CANCEL:case CPROTO_OP_RDV_CANCEL_ACK:
 case CPROTO_OP_RDV_RETIRED:case CPROTO_OP_RDV_CAPS:case CPROTO_OP_RDV_CREDIT:case CPROTO_OP_RDV_CAPS_ACK:case CPROTO_OP_RDV_WWI_READY:case CPROTO_OP_RDV_WWI_RESULT:case CPROTO_OP_RDV_DRAIN_REQUEST:case CPROTO_OP_RDV_DRAIN_ACK:
		return 0;
	default:
		return -EPROTO;
	}
}

CRT_INTERNAL int cproto_hello_encode(uint8_t *payload, uint32_t cap,
				      const struct cproto_caps *c)
{
	if (!payload || !c)
		return -EINVAL;
	if (c->protocol_version != CONTROL_PROTO_VERSION)
		return -EINVAL;
	if (c->frame_capacity < CONTROL_HEADER_LEN + 4 ||
	    c->frame_capacity > CONTROL_SLOT_CAPACITY)
		return -EINVAL;
	if (c->request_credit < 1 || c->request_credit > CONTROL_WINDOW_MAX)
		return -EINVAL;
	if (c->worker_capacity < 1)
		return -EINVAL;
	if (c->reverse_read_credit < 1 ||
	    c->reverse_read_credit > CONTROL_REVERSE_WINDOW_MAX)
		return -EINVAL;
	if (c->reverse_write_credit < 1 ||
	    c->reverse_write_credit > CONTROL_REVERSE_WINDOW_MAX)
		return -EINVAL;
	if ((c->session_flags & ~(CPROTO_CAP_QP_BIND|CPROTO_CAP_RDV_DATA)) != 0 || ((c->session_flags&CPROTO_CAP_RDV_DATA)?(c->data_frame_credit<1||c->data_frame_credit>CONTROL_DATA_FRAME_CREDIT):c->data_frame_credit!=0))
		return -EINVAL;
	if (cap < 32)
		return -ENOSPC;

	put_u32(payload + 0,  c->protocol_version);
	put_u32(payload + 4,  c->frame_capacity);
	put_u32(payload + 8,  c->request_credit);
	put_u32(payload + 12, c->worker_capacity);
	put_u32(payload + 16, c->reverse_read_credit);
	put_u32(payload + 20, c->reverse_write_credit);
	put_u32(payload + 24, c->session_flags);
	put_u32(payload + 28, c->data_frame_credit);
	return 32;
}

CRT_INTERNAL int cproto_hello_decode(const uint8_t *payload, uint32_t len,
				      struct cproto_caps *c)
{
	if (!payload || !c || len != 32)
		return -EPROTO;
	c->protocol_version     = get_u32(payload + 0);
	c->frame_capacity       = get_u32(payload + 4);
	c->request_credit       = get_u32(payload + 8);
	c->worker_capacity      = get_u32(payload + 12);
	c->reverse_read_credit  = get_u32(payload + 16);
	c->reverse_write_credit = get_u32(payload + 20);
	c->session_flags        = get_u32(payload + 24);
	c->data_frame_credit                  = get_u32(payload + 28);

	if (c->protocol_version != CONTROL_PROTO_VERSION)
		return -EPROTO;
	if (c->frame_capacity < CONTROL_HEADER_LEN + 4 ||
	    c->frame_capacity > CONTROL_SLOT_CAPACITY)
		return -EPROTO;
	if (c->request_credit < 1 || c->request_credit > CONTROL_WINDOW_MAX)
		return -EPROTO;
	if (c->worker_capacity < 1)
		return -EPROTO;
	if (c->reverse_read_credit < 1 ||
	    c->reverse_read_credit > CONTROL_REVERSE_WINDOW_MAX)
		return -EPROTO;
	if (c->reverse_write_credit < 1 ||
	    c->reverse_write_credit > CONTROL_REVERSE_WINDOW_MAX)
		return -EPROTO;
	if ((c->session_flags & ~(CPROTO_CAP_QP_BIND|CPROTO_CAP_RDV_DATA)) != 0 || ((c->session_flags&CPROTO_CAP_RDV_DATA)?(c->data_frame_credit<1||c->data_frame_credit>CONTROL_DATA_FRAME_CREDIT):c->data_frame_credit!=0))
		return -EPROTO;
	return 0;
}

CRT_INTERNAL int cproto_ping_encode(uint8_t *payload, uint32_t cap,
				     uint64_t nonce)
{
	if (!payload)
		return -EINVAL;
	if (cap < 12)
		return -ENOSPC;
	put_u32(payload + 0, CPROTO_OP_PING);
	put_u64(payload + 4, nonce);
	return 12;
}

CRT_INTERNAL int cproto_ping_decode(const uint8_t *payload, uint32_t len,
				     uint64_t *nonce)
{
	if (!payload || !nonce || len != 12)
		return -EPROTO;
	if (get_u32(payload + 0) != CPROTO_OP_PING)
		return -EPROTO;
	*nonce = get_u64(payload + 4);
	return 0;
}

CRT_INTERNAL int cproto_repair_inline_req_encode(
	uint8_t *payload, uint32_t cap,
	const struct cproto_repair_inline *r, const uint8_t *data)
{
	uint32_t total;

	if (!payload || !r || r->len < 1 || (r->len > 0 && !data))
		return -EINVAL;
	if (r->rkey == 0 ||
	    (r->dir != CONTROL_DIR_READ && r->dir != CONTROL_DIR_WRITE))
		return -EINVAL;
	if (r->off >= CONTROL_PAGE_SIZE ||
	    r->off + (uint64_t)r->len > CONTROL_PAGE_SIZE)
		return -EINVAL;
	total = 32 + r->len;
	if (total > CONTROL_PAYLOAD_MAX)
		return -EINVAL;
	if (cap < total)
		return -ENOSPC;

	put_u32(payload + 0, CPROTO_OP_REPAIR_INLINE);
	put_u32(payload + 4, 0);
	put_u32(payload + 8, r->rkey);
	put_u32(payload + 12, r->dir);
	put_u64(payload + 16, r->page_idx);
	put_u32(payload + 24, r->off);
	put_u32(payload + 28, r->len);
	memcpy(payload + 32, data, r->len);
	return (int)total;
}

CRT_INTERNAL int cproto_repair_inline_req_decode(
	const uint8_t *payload, uint32_t len,
	struct cproto_repair_inline *r, const uint8_t **data)
{
	uint32_t op, rsv, dlen;

	if (!payload || !r || len < 32)
		return -EPROTO;
	op  = get_u32(payload + 0);
	rsv = get_u32(payload + 4);
	if (op != CPROTO_OP_REPAIR_INLINE || rsv != 0)
		return -EPROTO;
	r->rkey     = get_u32(payload + 8);
	r->dir      = get_u32(payload + 12);
	r->page_idx = get_u64(payload + 16);
	r->off      = get_u32(payload + 24);
	dlen        = get_u32(payload + 28);
	if (dlen < 1 || len != 32 + dlen)
		return -EPROTO;
	if (r->rkey == 0 ||
	    (r->dir != CONTROL_DIR_READ && r->dir != CONTROL_DIR_WRITE))
		return -EPROTO;
	if (r->off >= CONTROL_PAGE_SIZE ||
	    r->off + (uint64_t)dlen > CONTROL_PAGE_SIZE)
		return -EPROTO;
	r->len = dlen;
	if (data)
		*data = payload + 32;
	return 0;
}

CRT_INTERNAL int cproto_repair_inline_resp_encode(
	uint8_t *payload, uint32_t cap, int32_t status, uint32_t len,
	const uint8_t *data)
{
	uint32_t total;

	if (!payload || (len > 0 && !data))
		return -EINVAL;
	if (status != 0 && len != 0)
		return -EINVAL;
	total = 16 + len;
	if (total > CONTROL_PAYLOAD_MAX)
		return -EINVAL;
	if (cap < total)
		return -ENOSPC;

	put_u32(payload + 0, CPROTO_OP_REPAIR_INLINE);
	put_u32(payload + 4, (uint32_t)status);
	put_u32(payload + 8, len);
	put_u32(payload + 12, 0);
	if (len > 0)
		memcpy(payload + 16, data, len);
	return (int)total;
}

CRT_INTERNAL int cproto_repair_inline_resp_decode(
	const uint8_t *payload, uint32_t len, int32_t *status,
	uint32_t *dlen, const uint8_t **data)
{
	uint32_t op, st, n, rsv;

	if (!payload || !status || !dlen || len < 16)
		return -EPROTO;
	op  = get_u32(payload + 0);
	st  = get_u32(payload + 4);
	n   = get_u32(payload + 8);
	rsv = get_u32(payload + 12);
	if (op != CPROTO_OP_REPAIR_INLINE || rsv != 0)
		return -EPROTO;

	if (st != 0 && n != 0)
		return -EPROTO;
	if (st == 0 && len != 16 + n)
		return -EPROTO;
	if (st != 0 && len != 16)
		return -EPROTO;
	*status = (int32_t)st;
	*dlen = n;
	if (data)
		*data = n > 0 ? payload + 16 : NULL;
	return 0;
}

static int span_validate(uint32_t rkey, uint32_t dir, uint64_t npages,
			 uint32_t xrkey, uint32_t xoff, uint32_t xlen)
{
	if (rkey == 0 || xrkey == 0)
		return -1;
	if (dir != CONTROL_DIR_READ && dir != CONTROL_DIR_WRITE)
		return -1;
	if (npages < 1 || npages > CONTROL_RANGE_MAX)
		return -1;
	if (xoff >= CONTROL_PAGE_SIZE)
		return -1;
	if (xlen < 1 || xlen > (uint32_t)(npages * CONTROL_PAGE_SIZE))
		return -1;
	return 0;
}

CRT_INTERNAL int cproto_repair_reverse_req_encode(
	uint8_t *payload, uint32_t cap,
	const struct cproto_repair_reverse *r)
{
	if (!payload || !r)
		return -EINVAL;
	if (span_validate(r->rkey, r->dir, r->npages, r->xrkey, r->xoff,
			  r->xlen) != 0)
		return -EINVAL;
	if (r->rsv != 0)
		return -EINVAL;
	if (cap < 52)
		return -ENOSPC;

	put_u32(payload + 0, CPROTO_OP_REPAIR_REVERSE);
	put_u32(payload + 4, r->rsv);
	put_u32(payload + 8, r->rkey);
	put_u32(payload + 12, r->dir);
	put_u64(payload + 16, r->page_idx);
	put_u64(payload + 24, r->npages);
	put_u64(payload + 32, r->xaddr);
	put_u32(payload + 40, r->xrkey);
	put_u32(payload + 44, r->xoff);
	put_u32(payload + 48, r->xlen);
	return 52;
}

CRT_INTERNAL int cproto_repair_reverse_req_decode(
	const uint8_t *payload, uint32_t len,
	struct cproto_repair_reverse *r)
{
	uint32_t op;

	if (!payload || !r || len != 52)
		return -EPROTO;
	op = get_u32(payload + 0);
	if (op != CPROTO_OP_REPAIR_REVERSE)
		return -EPROTO;
	r->rkey     = get_u32(payload + 8);
	r->dir      = get_u32(payload + 12);
	r->page_idx = get_u64(payload + 16);
	r->npages   = get_u64(payload + 24);
	r->xaddr    = get_u64(payload + 32);
	r->xrkey    = get_u32(payload + 40);
	r->xoff     = get_u32(payload + 44);
	r->xlen     = get_u32(payload + 48);
	r->rsv      = get_u32(payload + 4);
	if (r->rsv != 0)
		return -EPROTO;
	if (span_validate(r->rkey, r->dir, r->npages, r->xrkey, r->xoff,
			  r->xlen) != 0)
		return -EPROTO;
	return 0;
}

CRT_INTERNAL int cproto_repair_resp_encode(uint8_t *payload, uint32_t cap,
					    int32_t status, uint32_t mlen)
{
	if (!payload)
		return -EINVAL;
	if (mlen > CONTROL_RANGE_MAX)
		return -EINVAL;
	if (cap < 16)
		return -ENOSPC;
	put_u32(payload + 0, CPROTO_OP_REPAIR_REVERSE);
	put_u32(payload + 4, (uint32_t)status);
	put_u32(payload + 8, mlen);
	put_u32(payload + 12, 0);
	return 16;
}

CRT_INTERNAL int cproto_repair_resp_decode(const uint8_t *payload,
					    uint32_t len, int32_t *status,
					    uint32_t *mlen)
{
	uint32_t op, st, m, rsv;

	if (!payload || !status || !mlen || len != 16)
		return -EPROTO;
	op  = get_u32(payload + 0);
	st  = get_u32(payload + 4);
	m   = get_u32(payload + 8);
	rsv = get_u32(payload + 12);
	if (op != CPROTO_OP_REPAIR_REVERSE || rsv != 0)
		return -EPROTO;
	if (m > CONTROL_RANGE_MAX)
		return -EPROTO;
	*status = (int32_t)st;
	*mlen = m;
	return 0;
}

CRT_INTERNAL int cproto_repair_batch_req_encode(
	uint8_t *payload, uint32_t cap, uint32_t rkey,
	const struct cproto_repair_span *spans, uint32_t nspan)
{
	uint32_t i, total;

	if (!payload || !spans)
		return -EINVAL;
	if (nspan < 1 || nspan > CONTROL_REPAIR_BATCH_MAX)
		return -EINVAL;
	total = 16 + 40 * nspan;
	if (total > CONTROL_PAYLOAD_MAX)
		return -EINVAL;
	if (cap < total)
		return -ENOSPC;
	if (rkey == 0)
		return -EINVAL;
	for (i = 0; i < nspan; i++)
		if (span_validate(rkey, spans[i].dir, spans[i].npages,
				  spans[i].xrkey, spans[i].xoff,
				  spans[i].xlen) != 0 || spans[i].rsv != 0)
			return -EINVAL;

	put_u32(payload + 0, CPROTO_OP_REPAIR_BATCH);
	put_u32(payload + 4, 0);
	put_u32(payload + 8, rkey);
	put_u32(payload + 12, nspan);
	for (i = 0; i < nspan; i++) {
		uint8_t *p = payload + 16 + 40 * i;

		put_u64(p + 0, spans[i].page_idx);
		put_u32(p + 8, spans[i].npages);
		put_u32(p + 12, spans[i].dir);
		put_u64(p + 16, spans[i].xaddr);
		put_u32(p + 24, spans[i].xrkey);
		put_u32(p + 28, spans[i].xoff);
		put_u32(p + 32, spans[i].xlen);
		put_u32(p + 36, spans[i].rsv);
	}
	return (int)total;
}

CRT_INTERNAL int cproto_repair_batch_req_decode(
	const uint8_t *payload, uint32_t len, uint32_t *rkey,
	struct cproto_repair_span *out, uint32_t max_span, uint32_t *nspan)
{
	uint32_t i, n, rk;

	if (!payload || !rkey || !nspan || len < 16)
		return -EPROTO;
	if (get_u32(payload + 0) != CPROTO_OP_REPAIR_BATCH)
		return -EPROTO;
	if (get_u32(payload + 4) != 0)
		return -EPROTO;
	rk = get_u32(payload + 8);
	if (rk == 0)
		return -EPROTO;
	n = get_u32(payload + 12);
	if (n < 1 || n > CONTROL_REPAIR_BATCH_MAX)
		return -EPROTO;
	if (len != 16 + 40 * (uint64_t)n)
		return -EPROTO;
	if (!out || n > max_span)
		return -EINVAL;
	for (i = 0; i < n; i++) {
		const uint8_t *p = payload + 16 + 40 * i;

		out[i].page_idx = get_u64(p + 0);
		out[i].npages   = get_u32(p + 8);
		out[i].dir      = get_u32(p + 12);
		out[i].xaddr    = get_u64(p + 16);
		out[i].xrkey    = get_u32(p + 24);
		out[i].xoff     = get_u32(p + 28);
		out[i].xlen     = get_u32(p + 32);
		out[i].rsv      = get_u32(p + 36);
		if (out[i].rsv != 0)
			return -EPROTO;
		if (span_validate(rk, out[i].dir, out[i].npages,
				  out[i].xrkey, out[i].xoff, out[i].xlen) != 0)
			return -EPROTO;
	}
	*rkey = rk;
	*nspan = n;
	return 0;
}

CRT_INTERNAL int cproto_repair_batch_resp_encode(
	uint8_t *payload, uint32_t cap, int32_t status,
	const uint32_t *span_status, uint32_t nspan)
{
	uint32_t i, total;

	if (!payload || !span_status)
		return -EINVAL;
	if (nspan < 1 || nspan > CONTROL_REPAIR_BATCH_MAX)
		return -EINVAL;
	total = 16 + 4 * nspan;
	if (total > CONTROL_PAYLOAD_MAX)
		return -EINVAL;
	if (cap < total)
		return -ENOSPC;

	put_u32(payload + 0, CPROTO_OP_REPAIR_BATCH);
	put_u32(payload + 4, (uint32_t)status);
	put_u32(payload + 8, nspan);
	put_u32(payload + 12, 0);
	for (i = 0; i < nspan; i++)
		put_u32(payload + 16 + 4 * i, span_status[i]);
	return (int)total;
}

CRT_INTERNAL int cproto_repair_batch_resp_decode(
	const uint8_t *payload, uint32_t len, int32_t *status,
	uint32_t *span_status, uint32_t max_span, uint32_t *nspan)
{
	uint32_t i, n, st;

	if (!payload || !status || !nspan || len < 16)
		return -EPROTO;
	if (get_u32(payload + 0) != CPROTO_OP_REPAIR_BATCH)
		return -EPROTO;
	if (get_u32(payload + 12) != 0)
		return -EPROTO;
	st = get_u32(payload + 4);
	n = get_u32(payload + 8);
	if (n < 1 || n > CONTROL_REPAIR_BATCH_MAX)
		return -EPROTO;
	if (len != 16 + 4 * (uint64_t)n)
		return -EPROTO;
	if (!span_status || n > max_span)
		return -EINVAL;
	for (i = 0; i < n; i++)
		span_status[i] = get_u32(payload + 16 + 4 * i);
	*status = (int32_t)st;
	*nspan = n;
	return 0;
}

CRT_INTERNAL int cproto_atomic_req_encode(uint8_t *payload, uint32_t cap,
					   const struct cproto_atomic *a)
{
	if (!payload || !a)
		return -EINVAL;
	if (a->rkey == 0)
		return -EINVAL;
	if (a->op != CONTROL_ATOMIC_CAS && a->op != CONTROL_ATOMIC_FAA)
		return -EINVAL;
	if ((a->va & 7) != 0)
		return -EINVAL;
	if (cap < 40)
		return -ENOSPC;

	put_u32(payload + 0, CPROTO_OP_ATOMIC);
	put_u32(payload + 4, 0);
	put_u32(payload + 8, a->rkey);
	put_u32(payload + 12, a->op);
	put_u64(payload + 16, a->va);
	put_u64(payload + 24, a->operand_a);
	put_u64(payload + 32, a->operand_b);
	return 40;
}

CRT_INTERNAL int cproto_atomic_req_decode(const uint8_t *payload,
					   uint32_t len,
					   struct cproto_atomic *a)
{
	uint32_t op, rsv;

	if (!payload || !a || len != 40)
		return -EPROTO;
	op  = get_u32(payload + 0);
	rsv = get_u32(payload + 4);
	if (op != CPROTO_OP_ATOMIC || rsv != 0)
		return -EPROTO;
	a->rkey      = get_u32(payload + 8);
	a->op        = get_u32(payload + 12);
	a->va        = get_u64(payload + 16);
	a->operand_a = get_u64(payload + 24);
	a->operand_b = get_u64(payload + 32);
	if (a->rkey == 0)
		return -EPROTO;
	if (a->op != CONTROL_ATOMIC_CAS && a->op != CONTROL_ATOMIC_FAA)
		return -EPROTO;
	if ((a->va & 7) != 0)
		return -EPROTO;
	return 0;
}

CRT_INTERNAL int cproto_atomic_resp_encode(uint8_t *payload, uint32_t cap,
					    int32_t status, uint64_t old_val)
{
	if (!payload)
		return -EINVAL;
	if (cap < 16)
		return -ENOSPC;
	put_u32(payload + 0, CPROTO_OP_ATOMIC);
	put_u32(payload + 4, (uint32_t)status);
	put_u64(payload + 8, status == 0 ? old_val : 0);
	return 16;
}

CRT_INTERNAL int cproto_atomic_resp_decode(const uint8_t *payload,
					    uint32_t len, int32_t *status,
					    uint64_t *old_val)
{
	uint32_t op, st;

	if (!payload || !status || len != 16)
		return -EPROTO;
	op = get_u32(payload + 0);
	st = get_u32(payload + 4);
	if (op != CPROTO_OP_ATOMIC)
		return -EPROTO;
	*status = (int32_t)st;
	if (old_val)
		*old_val = st == 0 ? get_u64(payload + 8) : 0;
	return 0;
}

CRT_INTERNAL int cproto_snapshot_encode(
	uint8_t *payload, uint32_t cap, const struct cproto_snap_chunk *h,
	const struct cproto_export_entry *entries)
{
	uint32_t i, total;

	if (!payload || !h)
		return -EINVAL;
	if (h->generation == 0)
		return -EINVAL;
	if (h->chunk_count < 1 ||
	    h->chunk_count > CONTROL_SNAPSHOT_CHUNKS_MAX)
		return -EINVAL;
	if (h->chunk_index >= h->chunk_count)
		return -EINVAL;

	if ((!h->entry_count && (h->chunk_count != 1 || h->chunk_index != 0)) ||
	    (h->entry_count && !entries) || h->rsv != 0)
		return -EINVAL;
	total = 24 + 48 * (uint64_t)h->entry_count;
	if (total > CONTROL_PAYLOAD_MAX)
		return -EINVAL;
	if (cap < total)
		return -ENOSPC;
	for (i = 0; i < h->entry_count; i++) {
		if ((entries[i].data_rkey == 0 && entries[i].write_rkey == 0) || entries[i].addr == 0 ||
		    entries[i].len < 1)
			return -EINVAL;
		if (entries[i].v_rkey == 0 && entries[i].v_addr != 0)
			return -EINVAL;
		if (entries[i].rsv != 0)
			return -EINVAL;
	}

	put_u32(payload + 0, CPROTO_OP_EXPORT_SNAPSHOT);
	put_u64(payload + 4, h->generation);
	put_u32(payload + 12, h->chunk_index);
	put_u32(payload + 16, h->chunk_count);
	put_u32(payload + 20, h->entry_count);
	for (i = 0; i < h->entry_count; i++) {
		uint8_t *p = payload + 24 + 48 * i;

		put_u32(p + 0, entries[i].data_rkey);
		put_u32(p + 4, entries[i].write_rkey);
		put_u32(p + 8, entries[i].v_rkey);
		put_u32(p + 12, entries[i].rsv);
		put_u64(p + 16, entries[i].addr);
		put_u64(p + 24, entries[i].len);
		put_u64(p + 32, entries[i].v_addr);
		put_u32(p + 40, entries[i].app_rkey);
		put_u32(p + 44, entries[i].app_access);
	}
	return (int)total;
}

CRT_INTERNAL int cproto_snapshot_decode(
	const uint8_t *payload, uint32_t len, struct cproto_snap_chunk *h,
	struct cproto_export_entry *out, uint32_t max_entries,
	uint32_t *n_entries)
{
	uint32_t i, n;

	if (!payload || !h || !n_entries || len < 24)
		return -EPROTO;
	if (get_u32(payload + 0) != CPROTO_OP_EXPORT_SNAPSHOT)
		return -EPROTO;
	h->generation  = get_u64(payload + 4);
	h->chunk_index = get_u32(payload + 12);
	h->chunk_count = get_u32(payload + 16);
	h->entry_count = get_u32(payload + 20);
	h->rsv         = 0;
	if (h->generation == 0)
		return -EPROTO;
	if (h->chunk_count < 1 ||
	    h->chunk_count > CONTROL_SNAPSHOT_CHUNKS_MAX)
		return -EPROTO;
	if (h->chunk_index >= h->chunk_count)
		return -EPROTO;
	n = h->entry_count;
	if (!n && (h->chunk_count != 1 || h->chunk_index != 0))
		return -EPROTO;
	if (len != 24 + 48 * (uint64_t)n)
		return -EPROTO;
	if ((n && !out) || n > max_entries)
		return -EINVAL;
	for (i = 0; i < n; i++) {
		const uint8_t *p = payload + 24 + 48 * i;

		out[i].data_rkey  = get_u32(p + 0);
		out[i].write_rkey = get_u32(p + 4);
		out[i].v_rkey     = get_u32(p + 8);
		out[i].rsv        = get_u32(p + 12);
		out[i].addr       = get_u64(p + 16);
		out[i].len        = get_u64(p + 24);
		out[i].v_addr     = get_u64(p + 32);
		out[i].app_rkey = get_u32(p + 40);
		out[i].app_access = get_u32(p + 44);
		if ((out[i].data_rkey == 0 && out[i].write_rkey == 0) || out[i].addr == 0 ||
		    out[i].len < 1)
			return -EPROTO;
		if (out[i].v_rkey == 0 && out[i].v_addr != 0)
			return -EPROTO;
		if (out[i].rsv != 0)
			return -EPROTO;
	}
	*n_entries = n;
	return 0;
}

CRT_INTERNAL int cproto_credit_encode(uint8_t *payload, uint32_t cap)
{
	if (!payload)
		return -EINVAL;
	if (cap < 8)
		return -ENOSPC;
	put_u32(payload + 0, CPROTO_OP_CREDIT);
	put_u32(payload + 4, 0);
	return 8;
}

CRT_INTERNAL int cproto_credit_decode(const uint8_t *payload, uint32_t len)
{
	if (!payload || len != 8)
		return -EPROTO;
	if (get_u32(payload + 0) != CPROTO_OP_CREDIT)
		return -EPROTO;
	if (get_u32(payload + 4) != 0)
		return -EPROTO;
	return 0;
}

/* A HELLO has a capability record rather than the normal opcode prefix. */
CRT_INTERNAL int cproto_control_op_get(const uint8_t *payload, uint32_t len, uint32_t *op)
{
 struct cproto_caps hello;
 if (!op) return -EINVAL;
 if (len == 32 && !cproto_hello_decode(payload, len, &hello)) {
  *op = CPROTO_OP_HELLO;
  return 0;
 }
 return cproto_op_get(payload, len, op);
}

CRT_INTERNAL int cproto_key_lookup_req_encode(uint8_t *p,uint32_t cap,uint32_t key)
{
 if(!p||!key)return -EINVAL;
 if(cap<8)return -ENOSPC;
 put_u32(p,CPROTO_OP_KEY_LOOKUP);put_u32(p+4,key);return 8;
}
CRT_INTERNAL int cproto_key_lookup_req_decode(const uint8_t *p,uint32_t len,uint32_t *key)
{
 if(!p||!key||len!=8||get_u32(p)!=CPROTO_OP_KEY_LOOKUP||!get_u32(p+4))return -EPROTO;
 *key=get_u32(p+4);return 0;
}
CRT_INTERNAL int cproto_key_lookup_resp_encode(uint8_t *p,uint32_t cap,uint32_t key,int32_t status,const struct cproto_export_entry *e)
{
 if(!p||!key||status<0||status>4095)return -EINVAL;
 if(cap<CPROTO_KEY_LOOKUP_REPLY_LEN)return -ENOSPC;
 if(!status&&(!e||(!e->data_rkey&&!e->write_rkey)||!e->addr||!e->len||e->addr>UINT64_MAX-e->len||
    e->rsv||(!e->v_rkey&&e->v_addr)||(key!=e->app_rkey&&key!=e->data_rkey&&key!=e->write_rkey)))return -EINVAL;
 memset(p,0,CPROTO_KEY_LOOKUP_REPLY_LEN);
 put_u32(p,CPROTO_OP_KEY_LOOKUP);put_u32(p+4,key);put_u32(p+8,(uint32_t)status);
 if(!status){
  put_u32(p+16,e->data_rkey);put_u32(p+20,e->write_rkey);put_u32(p+24,e->v_rkey);
  put_u64(p+32,e->addr);put_u64(p+40,e->len);put_u64(p+48,e->v_addr);
  put_u32(p+56,e->app_rkey);put_u32(p+60,e->app_access);
 }
 return CPROTO_KEY_LOOKUP_REPLY_LEN;
}
CRT_INTERNAL int cproto_key_lookup_resp_decode(const uint8_t *p,uint32_t len,uint32_t *key,int32_t *status,struct cproto_export_entry *e)
{
 uint8_t canonical[CPROTO_KEY_LOOKUP_REPLY_LEN];
 if(!p||!key||!status||!e||len!=CPROTO_KEY_LOOKUP_REPLY_LEN||get_u32(p)!=CPROTO_OP_KEY_LOOKUP)return -EPROTO;
 *key=get_u32(p+4);*status=(int32_t)get_u32(p+8);memset(e,0,sizeof(*e));
 if(!*status){
  e->data_rkey=get_u32(p+16);e->write_rkey=get_u32(p+20);e->v_rkey=get_u32(p+24);
  e->addr=get_u64(p+32);e->len=get_u64(p+40);e->v_addr=get_u64(p+48);
  e->app_rkey=get_u32(p+56);e->app_access=get_u32(p+60);
 }
 if(cproto_key_lookup_resp_encode(canonical,sizeof(canonical),*key,*status,e)<0||memcmp(p,canonical,sizeof(canonical)))return -EPROTO;
 return 0;
}

static int qp_gid_nonzero(const uint8_t *g)
{
	unsigned v = 0;
	for (unsigned i = 0; i < 16; i++)
		v |= g[i];
	return v != 0;
}
CRT_INTERNAL int cproto_qp_endpoint_valid(const struct sir_app_qp_endpoint *e)
{
	if (!e || !e->key.cookie || !e->key.generation ||
	    !e->route.connection_epoch || !e->bind_nonce ||
	    !e->route.local_qpn || e->route.local_qpn > 0xffffff ||
	    !e->route.peer_qpn || e->route.peer_qpn > 0xffffff ||
	    !e->route.port_num || e->policy != SIR_APP_QP_RENDEZVOUS_REQUIRED)
		return 0;
	if (e->route.kind == SIR_APP_QP_ROUTE_GID)
		return qp_gid_nonzero(e->route.local_gid) &&
		       qp_gid_nonzero(e->route.peer_gid);
	if (e->route.kind == SIR_APP_QP_ROUTE_LID)
		return e->route.local_lid && e->route.peer_lid &&
		       e->route.local_lid != 0xffff &&
		       e->route.peer_lid != 0xffff;
	return 0;
}
CRT_INTERNAL void cproto_qp_endpoint_put(uint8_t *p, const struct sir_app_qp_endpoint *e)
{
	put_u64(p, e->key.cookie);
	put_u64(p + 8, e->key.generation);
	put_u64(p + 16, e->route.connection_epoch);
	put_u64(p + 24, e->bind_nonce);
	put_u32(p + 32, e->route.local_qpn);
	put_u32(p + 36, e->route.peer_qpn);
	memcpy(p + 40, e->route.local_gid, 16);
	memcpy(p + 56, e->route.peer_gid, 16);
	put_u16(p + 72, e->route.local_lid);
	put_u16(p + 74, e->route.peer_lid);
	p[76] = e->route.port_num;
	p[77] = e->route.kind;
	p[78] = e->policy;
	p[79] = 0;
}
CRT_INTERNAL int cproto_qp_endpoint_get(const uint8_t *p, struct sir_app_qp_endpoint *e)
{
	memset(e, 0, sizeof(*e));
	e->key.cookie = get_u64(p);
	e->key.generation = get_u64(p + 8);
	e->route.connection_epoch = get_u64(p + 16);
	e->bind_nonce = get_u64(p + 24);
	e->route.local_qpn = get_u32(p + 32);
	e->route.peer_qpn = get_u32(p + 36);
	memcpy(e->route.local_gid, p + 40, 16);
	memcpy(e->route.peer_gid, p + 56, 16);
	e->route.local_lid = get_u16(p + 72);
	e->route.peer_lid = get_u16(p + 74);
	e->route.port_num = p[76];
	e->route.kind = p[77];
	e->policy = p[78];
	return !p[79] && cproto_qp_endpoint_valid(e) ? 0 : -EPROTO;
}
CRT_INTERNAL int cproto_qp_bind_encode(uint8_t *p, uint32_t cap, uint32_t op,
				       uint32_t status,
				       const struct sir_app_qp_endpoint *a,
				       const struct sir_app_qp_endpoint *b)
{
	uint32_t n = op == CPROTO_OP_QP_BIND_INIT ? CPROTO_QP_INIT_SIZE
						  : CPROTO_QP_PAIR_SIZE;
	if (!p || cap < n || !cproto_qp_endpoint_valid(a) || status > 4095)
		return -EINVAL;
	if (op == CPROTO_OP_QP_BIND_INIT) {
		if (status || b)
			return -EINVAL;
	} else if (op == CPROTO_OP_QP_BIND_ACK) {
		if (!status && !cproto_qp_endpoint_valid(b))
			return -EINVAL;
	} else if (op == CPROTO_OP_QP_UNBIND) {
		if (!status || status > SIR_APP_QP_DESTROY_PREPARE ||
		    !cproto_qp_endpoint_valid(b))
			return -EINVAL;
	} else
		return -EINVAL;
	memset(p, 0, n);
	put_u32(p, op);
	put_u32(p + 4, status);
	cproto_qp_endpoint_put(p + 8, a);
	if (n == CPROTO_QP_PAIR_SIZE && b)
		cproto_qp_endpoint_put(p + 88, b);
	return n;
}
CRT_INTERNAL int cproto_qp_bind_decode(const uint8_t *p, uint32_t len,
				       uint32_t *op, uint32_t *status,
				       struct sir_app_qp_endpoint *a,
				       struct sir_app_qp_endpoint *b)
{
	if (!p || !op || !status || !a || !b || len < 8)
		return -EPROTO;
	*op = get_u32(p);
	*status = get_u32(p + 4);
	memset(b, 0, sizeof(*b));
	if (*status > 4095)
		return -EPROTO;
	if (*op == CPROTO_OP_QP_BIND_INIT) {
		if (len != CPROTO_QP_INIT_SIZE || *status)
			return -EPROTO;
		return cproto_qp_endpoint_get(p + 8, a);
	}
	if (len != CPROTO_QP_PAIR_SIZE ||
	    (*op != CPROTO_OP_QP_BIND_ACK && *op != CPROTO_OP_QP_UNBIND) ||
	    cproto_qp_endpoint_get(p + 8, a))
		return -EPROTO;
	if (*op == CPROTO_OP_QP_UNBIND &&
	    (!*status || *status > SIR_APP_QP_DESTROY_PREPARE))
		return -EPROTO;
	if (*op == CPROTO_OP_QP_BIND_ACK && *status) {
		uint8_t v = 0;
		for (unsigned i = 88; i < len; i++)
			v |= p[i];
		return v ? cproto_qp_endpoint_get(p + 88, b) : 0;
	}
	return cproto_qp_endpoint_get(p + 88, b);
}

CRT_INTERNAL int cproto_rdv_credit_encode(uint8_t *p,uint32_t cap,uint64_t total)
{if(!p)return -EINVAL;if(cap<12)return -ENOSPC;put_u32(p,CPROTO_OP_RDV_CREDIT);put_u64(p+4,total);return 12;}
CRT_INTERNAL int cproto_rdv_credit_decode(const uint8_t *p,uint32_t n,uint64_t *total)
{if(!p||!total||n!=12||get_u32(p)!=CPROTO_OP_RDV_CREDIT)return -EPROTO;*total=get_u64(p+4);return 0;}
