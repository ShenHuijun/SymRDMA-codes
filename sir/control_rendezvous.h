/* SPDX-License-Identifier: GPL-2.0 */

#ifndef CONTROL_RENDEZVOUS_H
#define CONTROL_RENDEZVOUS_H

#include <stddef.h>
#include <stdint.h>

#include "control_log.h"

enum crdv_kind {
	CRDV_FILE = 0,
	CRDV_TCP_LISTEN,
	CRDV_TCP_CONNECT,
};

enum crdv_tcp_st {
	CRDV_TCP_IDLE = 0,
	CRDV_TCP_CONNECTING,
	CRDV_TCP_GREET_SEND,
	CRDV_TCP_GREET_RECV,
	CRDV_TCP_INFO_SEND,
	CRDV_TCP_UP_SEND,
	CRDV_TCP_DONE,
};

#define CRDV_GID_LEN   16
#define CRDV_BLOB_MAX  256
#define CRDV_LINE_MAX  64
#define CRDV_BACKOFF_MAX_MS 30000

struct crdv {
	uint8_t  kind;
	char     role;

	char     dir[512];
	char     key[128];

	char     tcp_host[128];
	int      tcp_port;
	int      sgid_index;
	int      listen_fd;
	int      conn_fd;
	uint8_t  tcp_st;
	int      greet_ok;
	uint8_t  outbuf[CRDV_BLOB_MAX + CRDV_LINE_MAX];
	size_t   out_len, out_off;
	uint8_t  inbuf[CRDV_BLOB_MAX + CRDV_LINE_MAX * 2];
	size_t   in_len;
	uint32_t info_expect;

	unsigned peer_qp;
	int      peer_up;
	int      peer_got;
	uint8_t  peer_gid[CRDV_GID_LEN];
	int      peer_gid_valid;

	unsigned own_qp;
	uint8_t  own_gid[CRDV_GID_LEN];
	int      own_gid_valid;
	int      own_up;

	int64_t  next_retry_ms;
	int      backoff_ms;
};

CRT_INTERNAL void crdv_init(struct crdv *rd, uint8_t kind, const char *dir,
			     const char *key, const char *tcp_host, int tcp_port,
			     int sgid_index);

CRT_INTERNAL void crdv_elect_role_file(struct crdv *rd);

CRT_INTERNAL void crdv_file_write_own(struct crdv *rd, unsigned qp_num,
				       const uint8_t *gid, int rts_done);

CRT_INTERNAL int crdv_file_read_peer(struct crdv *rd, unsigned *qp,
				      uint8_t *gid, int *gid_valid, int *up);

CRT_INTERNAL int crdv_tcp_listen(struct crdv *rd);

CRT_INTERNAL int crdv_tcp_reconnect(struct crdv *rd, int64_t now_ms);

CRT_INTERNAL int crdv_tcp_accept(struct crdv *rd);

CRT_INTERNAL int crdv_tcp_progress(struct crdv *rd, int readable,
				    int writable);

CRT_INTERNAL int crdv_tcp_peer_ready(const struct crdv *rd);

CRT_INTERNAL int crdv_tcp_want_write(const struct crdv *rd);

CRT_INTERNAL void crdv_tcp_conn_close(struct crdv *rd);

CRT_INTERNAL void crdv_set_own(struct crdv *rd, unsigned qp_num,
				const uint8_t *gid, int gid_valid, int rts_done);

CRT_INTERNAL void crdv_file_sync_own(struct crdv *rd);

CRT_INTERNAL int crdv_tcp_send_up(struct crdv *rd);

#endif
