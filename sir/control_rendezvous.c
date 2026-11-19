/* SPDX-License-Identifier: GPL-2.0 */

#define _GNU_SOURCE
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "control_rendezvous.h"

static void crdv_own_path(const struct crdv *rd, char *buf, size_t n)
{
	snprintf(buf, n, "%s/%s.%c.info", rd->dir, rd->key,
		 rd->role ? rd->role : 'a');
}

static void crdv_peer_path(const struct crdv *rd, char *buf, size_t n)
{
	snprintf(buf, n, "%s/%s.%c.info", rd->dir, rd->key,
		 rd->role == 'b' ? 'a' : 'b');
}

CRT_INTERNAL void crdv_elect_role_file(struct crdv *rd)
{
	char lockp[700];
	int fd;

	if (rd->role)
		return;
	snprintf(lockp, sizeof(lockp), "%s/%s.lock", rd->dir, rd->key);
	fd = open(lockp, O_CREAT | O_EXCL | O_WRONLY, 0600);
	if (fd >= 0) {
		close(fd);
		rd->role = 'a';
		crt_log("rendezvous: lock created pid=%d role=a", (int)getpid());
		return;
	}
	rd->role = 'b';
	crt_log("rendezvous: lock exists pid=%d role=b errno=%d", (int)getpid(),
		 errno);
}

static void crdv_file_write_unlocked(const struct crdv *rd)
{
	char fin[700], tmp[720];
	char blob[CRDV_BLOB_MAX];
	size_t n = 0;
	FILE *f;
	int i;

	if (!rd->role || !rd->key[0])
		return;
	n += (size_t)snprintf(blob + n, sizeof(blob) - n, "qp %u\n",
			      rd->own_qp);
	if (rd->own_gid_valid) {
		n += (size_t)snprintf(blob + n, sizeof(blob) - n, "gid ");
		for (i = 0; i < CRDV_GID_LEN; i++)
			n += (size_t)snprintf(blob + n, sizeof(blob) - n,
					      "%02x", rd->own_gid[i]);
		n += (size_t)snprintf(blob + n, sizeof(blob) - n, "\n");
	}
	if (rd->own_up)
		n += (size_t)snprintf(blob + n, sizeof(blob) - n, "up 1\n");
	crdv_own_path(rd, fin, sizeof(fin));
	snprintf(tmp, sizeof(tmp), "%s.tmp", fin);
	f = fopen(tmp, "w");
	if (!f)
		return;
	if (fwrite(blob, 1, n, f) != n || fflush(f)) {
		fclose(f);
		unlink(tmp);
		return;
	}
	fclose(f);
	if (rename(tmp, fin))
		unlink(tmp);
}

CRT_INTERNAL void crdv_file_write_own(struct crdv *rd, unsigned qp_num,
				       const uint8_t *gid, int rts_done)
{
	rd->own_qp = qp_num;
	if (gid)
		memcpy(rd->own_gid, gid, CRDV_GID_LEN);
	rd->own_gid_valid = gid ? 1 : 0;
	rd->own_up = rts_done;
	crdv_file_write_unlocked(rd);
}

CRT_INTERNAL void crdv_file_sync_own(struct crdv *rd)
{
	crdv_file_write_unlocked(rd);
}

CRT_INTERNAL void crdv_set_own(struct crdv *rd, unsigned qp_num,
				const uint8_t *gid, int gid_valid, int rts_done)
{
	rd->own_qp = qp_num;
	if (gid && gid_valid)
		memcpy(rd->own_gid, gid, CRDV_GID_LEN);
	rd->own_gid_valid = gid_valid && gid ? 1 : 0;
	rd->own_up = rts_done;
}

CRT_INTERNAL int crdv_file_read_peer(struct crdv *rd, unsigned *qp,
				      uint8_t *gid, int *gid_valid, int *up)
{
	char path[700], line[CRDV_LINE_MAX];
	FILE *f;
	int have_qp = 0, have_up = 0, have_gid = 0;

	*qp = 0;
	*up = 0;
	*gid_valid = 0;
	crdv_peer_path(rd, path, sizeof(path));
	f = fopen(path, "r");
	if (!f)
		return -1;
	while (fgets(line, sizeof(line), f)) {
		if (!strncmp(line, "qp ", 3)) {
			*qp = (unsigned)strtoul(line + 3, NULL, 0);
			have_qp = 1;
		} else if (!strncmp(line, "up ", 3)) {
			*up = (int)strtol(line + 3, NULL, 0);
			have_up = 1;
		} else if (!strncmp(line, "gid ", 4) &&
			   strlen(line + 4) >= 32) {
			int i, ok = 1;

			for (i = 0; i < CRDV_GID_LEN; i++) {
				unsigned v;

				if (sscanf(line + 4 + i * 2, "%2x", &v) != 1) {
					ok = 0;
					break;
				}
				gid[i] = (uint8_t)v;
			}
			have_gid = ok;
		}
	}
	fclose(f);
	*gid_valid = have_gid;
	return (have_qp && have_up) ? 0 : -1;
}

CRT_INTERNAL void crdv_init(struct crdv *rd, uint8_t kind, const char *dir,
			     const char *key, const char *tcp_host, int tcp_port,
			     int sgid_index)
{
	memset(rd, 0, sizeof(*rd));
	rd->kind = kind;
	rd->listen_fd = -1;
	rd->conn_fd = -1;
	rd->backoff_ms = 1000;
	if (dir)
		snprintf(rd->dir, sizeof(rd->dir), "%s", dir);
	if (key)
		snprintf(rd->key, sizeof(rd->key), "%s", key);
	if (tcp_host)
		snprintf(rd->tcp_host, sizeof(rd->tcp_host), "%s", tcp_host);
	rd->tcp_port = tcp_port;
	rd->sgid_index = sgid_index;
	if (kind == CRDV_TCP_LISTEN)
		rd->role = 'a';
	else if (kind == CRDV_TCP_CONNECT)
		rd->role = 'b';
}

CRT_INTERNAL int crdv_tcp_listen(struct crdv *rd)
{
	struct sockaddr_in a;
	int lfd, one = 1;

	if (rd->listen_fd >= 0)
		return 0;
	lfd = socket(AF_INET, SOCK_STREAM, 0);
	if (lfd < 0)
		return -errno;
	setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	memset(&a, 0, sizeof(a));
	a.sin_family = AF_INET;
	a.sin_addr.s_addr = htonl(INADDR_ANY);
	a.sin_port = htons((uint16_t)rd->tcp_port);
	if (bind(lfd, (struct sockaddr *)&a, sizeof(a)) || listen(lfd, 1)) {
		int e = errno;

		close(lfd);
		return -e;
	}
	rd->listen_fd = lfd;
	return 0;
}

static int crdv_tcp_connect_start(struct crdv *rd)
{
	struct addrinfo hints, *res = NULL;
	char portstr[16];
	int fd;

	snprintf(portstr, sizeof(portstr), "%d", rd->tcp_port);
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	if (getaddrinfo(rd->tcp_host, portstr, &hints, &res) || !res)
		return -ENOENT;
	fd = socket(res->ai_family, SOCK_STREAM, 0);
	if (fd < 0) {
		freeaddrinfo(res);
		return -errno;
	}
	fcntl(fd, F_SETFL, O_NONBLOCK);
	if (connect(fd, res->ai_addr, res->ai_addrlen) && errno != EINPROGRESS) {
		int e = errno;

		close(fd);
		freeaddrinfo(res);
		return -e;
	}
	freeaddrinfo(res);
	rd->conn_fd = fd;
	rd->tcp_st = CRDV_TCP_CONNECTING;
	rd->in_len = 0;
	rd->out_len = rd->out_off = 0;
	rd->info_expect = 0;
	rd->peer_qp = 0;
	rd->peer_up = 0;
	rd->peer_got = 0;
	rd->peer_gid_valid = 0;
	return 0;
}

CRT_INTERNAL int crdv_tcp_reconnect(struct crdv *rd, int64_t now_ms)
{
	int rc;

	if (rd->conn_fd >= 0)
		return 0;
	if (rd->next_retry_ms && now_ms < rd->next_retry_ms)
		return 1;
	rc = crdv_tcp_connect_start(rd);
	if (rc) {
		crt_log("TCP connect failed errno=%d (backoff=%dms)", -rc,
			 rd->backoff_ms);
		rd->next_retry_ms = now_ms + rd->backoff_ms;
		rd->backoff_ms = rd->backoff_ms * 2 > CRDV_BACKOFF_MAX_MS ?
					 CRDV_BACKOFF_MAX_MS :
					 rd->backoff_ms * 2;
		return rc;
	}
	return 0;
}

CRT_INTERNAL int crdv_tcp_accept(struct crdv *rd)
{
	int fd;

	if (rd->listen_fd < 0 || rd->conn_fd >= 0)
		return 0;
	fd = accept(rd->listen_fd, NULL, NULL);
	if (fd < 0)
		return (errno == EAGAIN || errno == EWOULDBLOCK) ? 0 : -errno;
	fcntl(fd, F_SETFL, O_NONBLOCK);
	rd->conn_fd = fd;
	rd->tcp_st = CRDV_TCP_GREET_SEND;
	rd->in_len = 0;
	rd->out_len = rd->out_off = 0;
	rd->info_expect = 0;
	rd->peer_qp = 0;
	rd->peer_up = 0;
	rd->peer_got = 0;
	rd->peer_gid_valid = 0;
	crt_log("TCP accept fd=%d role=%c", fd, rd->role);
	return 0;
}

CRT_INTERNAL void crdv_tcp_conn_close(struct crdv *rd)
{
	if (rd->conn_fd >= 0) {
		close(rd->conn_fd);
		rd->conn_fd = -1;
	}
	rd->tcp_st = CRDV_TCP_IDLE;
	rd->in_len = 0;
	rd->out_len = rd->out_off = 0;
	rd->info_expect = 0;
}

static size_t crdv_build_blob(const struct crdv *rd, char *buf, size_t cap)
{
	size_t n = 0;
	int i;

	n += (size_t)snprintf(buf + n, cap - n, "qp %u\n", rd->own_qp);
	if (rd->own_gid_valid) {
		n += (size_t)snprintf(buf + n, cap - n, "gid ");
		for (i = 0; i < CRDV_GID_LEN; i++)
			n += (size_t)snprintf(buf + n, cap - n, "%02x",
					      rd->own_gid[i]);
		n += (size_t)snprintf(buf + n, cap - n, "\n");
	}
	if (rd->own_up)
		n += (size_t)snprintf(buf + n, cap - n, "up 1\n");
	return n;
}

static void crdv_queue_out(struct crdv *rd, const void *p, size_t n)
{
	if (rd->out_len + n > sizeof(rd->outbuf))
		return;
	memcpy(rd->outbuf + rd->out_len, p, n);
	rd->out_len += n;
}

static void crdv_queue_info(struct crdv *rd)
{
	char blob[CRDV_BLOB_MAX];
	char hdr[CRDV_LINE_MAX];
	size_t n = crdv_build_blob(rd, blob, sizeof(blob));

	snprintf(hdr, sizeof(hdr), "INFO %zu\n", n);
	crdv_queue_out(rd, hdr, strlen(hdr));
	crdv_queue_out(rd, blob, n);
}

static int crdv_send_flush(struct crdv *rd)
{
	while (rd->out_off < rd->out_len) {
		ssize_t w = send(rd->conn_fd, rd->outbuf + rd->out_off,
				 rd->out_len - rd->out_off, MSG_NOSIGNAL);

		if (w < 0 && errno == EINTR)
			continue;
		if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
			return 1;
		if (w <= 0)
			return -1;
		rd->out_off += (size_t)w;
	}
	rd->out_len = rd->out_off = 0;
	return 0;
}

static void crdv_apply_blob(struct crdv *rd, const char *b, size_t n)
{
	const char *s = b, *end = b + n;

	while (s < end) {
		const char *nl = memchr(s, '\n', (size_t)(end - s));
		size_t l = nl ? (size_t)(nl - s) : (size_t)(end - s);
		char line[CRDV_LINE_MAX];

		if (l >= sizeof(line))
			break;
		memcpy(line, s, l);
		line[l] = 0;
		s = nl ? nl + 1 : end;
		if (!strncmp(line, "qp ", 3)) {
			rd->peer_qp = (unsigned)strtoul(line + 3, NULL, 0);
			if (rd->peer_qp)
				rd->peer_got = 1;
		} else if (!strncmp(line, "up ", 3)) {
			rd->peer_up = (int)strtol(line + 3, NULL, 0);
		} else if (!strncmp(line, "gid ", 4) &&
			   strlen(line + 4) >= 32) {
			int i, ok = 1;

			for (i = 0; i < CRDV_GID_LEN; i++) {
				unsigned v;

				if (sscanf(line + 4 + i * 2, "%2x", &v) != 1) {
					ok = 0;
					break;
				}
				rd->peer_gid[i] = (uint8_t)v;
			}
			rd->peer_gid_valid = ok;
		}
	}
}

static size_t crdv_line_pop(struct crdv *rd, char *out, size_t cap)
{
	uint8_t *nl = memchr(rd->inbuf, '\n', rd->in_len);
	size_t l;

	if (!nl)
		return 0;
	l = (size_t)(nl - rd->inbuf);
	if (l + 1 > cap)
		return 0;
	memcpy(out, rd->inbuf, l);
	out[l] = 0;
	memmove(rd->inbuf, nl + 1, rd->in_len - (l + 1));
	rd->in_len -= l + 1;
	return l;
}

CRT_INTERNAL int crdv_tcp_peer_ready(const struct crdv *rd)
{
	return rd->conn_fd >= 0 && rd->peer_got && rd->peer_up;
}

CRT_INTERNAL int crdv_tcp_want_write(const struct crdv *rd)
{
	if (rd->conn_fd < 0)
		return 0;
	if (rd->out_off < rd->out_len)
		return 1;
	switch (rd->tcp_st) {
	case CRDV_TCP_CONNECTING:
	case CRDV_TCP_GREET_SEND:
	case CRDV_TCP_INFO_SEND:
	case CRDV_TCP_UP_SEND:
		return 1;
	default:
		return 0;
	}
}

CRT_INTERNAL int crdv_tcp_send_up(struct crdv *rd)
{
	if (rd->conn_fd < 0)
		return -1;
	crdv_queue_info(rd);
	return 0;
}

static int crdv_connect_complete(struct crdv *rd)
{
	int err = 0;
	socklen_t el = sizeof(err);

	if (getsockopt(rd->conn_fd, SOL_SOCKET, SO_ERROR, &err, &el))
		return -1;
	if (!err)
		return 0;
	if (err == EINPROGRESS || err == EALREADY || err == EWOULDBLOCK)
		return 1;
	return -1;
}

static int crdv_parse_inbuf(struct crdv *rd)
{
	for (;;) {
		char line[CRDV_LINE_MAX];
		size_t l;

		if (rd->info_expect) {
			size_t want = rd->info_expect;

			if (rd->in_len < want)
				return 0;
			crdv_apply_blob(rd, (const char *)rd->inbuf, want);
			memmove(rd->inbuf, rd->inbuf + want, rd->in_len - want);
			rd->in_len -= want;
			rd->info_expect = 0;
			crt_log("TCP INFO arrived (peer_qp=0x%x up=%d gid=%c)",
				 rd->peer_qp, rd->peer_up,
				 rd->peer_gid_valid ? 'Y' : 'N');
			continue;
		}
		l = crdv_line_pop(rd, line, sizeof(line));
		if (!l)
			return 0;
		if (!strncmp(line, "SYRC1 ", 6)) {
			char pr = line[6];

			if ((pr != 'a' && pr != 'b') || pr == rd->role) {
				crt_log("TCP greeting mismatch role_hex=%02x local=%c",
					 (unsigned char)pr, rd->role);
				return -1;
			}
			rd->greet_ok = 1;
			continue;
		}
		if (!strncmp(line, "INFO ", 5)) {
			rd->info_expect = (uint32_t)strtoul(line + 5, NULL, 10);
			if (!rd->info_expect ||
			    rd->info_expect > CRDV_BLOB_MAX) {
				crt_log("TCP INFO invalid length %u",
					 rd->info_expect);
				return -1;
			}
			continue;
		}
	}
}

static void crdv_fill_outbuf(struct crdv *rd)
{
	if (rd->out_len > rd->out_off)
		return;
	rd->out_len = rd->out_off = 0;
	switch (rd->tcp_st) {
	case CRDV_TCP_CONNECTING:
		return;
	case CRDV_TCP_GREET_SEND: {
		char g[16];

		snprintf(g, sizeof(g), "SYRC1 %c\n", rd->role);
		crdv_queue_out(rd, g, strlen(g));
		rd->tcp_st = CRDV_TCP_INFO_SEND;
		return;
	}
	case CRDV_TCP_INFO_SEND:
		crdv_queue_info(rd);
		rd->tcp_st = CRDV_TCP_DONE;
		return;
	case CRDV_TCP_UP_SEND:
		crdv_queue_info(rd);
		rd->tcp_st = CRDV_TCP_DONE;
		return;
	default:
		return;
	}
}

CRT_INTERNAL int crdv_tcp_progress(struct crdv *rd, int readable,
				    int writable)
{
	if (rd->tcp_st == CRDV_TCP_CONNECTING) {
		int cc;

		if (!writable)
			return 0;
		cc = crdv_connect_complete(rd);
		if (cc < 0) {
			int err = 0;
			socklen_t el = sizeof(err);

			(void)getsockopt(rd->conn_fd, SOL_SOCKET, SO_ERROR,
					 &err, &el);
			crt_log("TCP connect failed (SO_ERROR=%d) — backoff retry",
				 err);
			crdv_tcp_conn_close(rd);
			rd->tcp_st = CRDV_TCP_IDLE;
			rd->next_retry_ms = crt_now_ms() + rd->backoff_ms;
			rd->backoff_ms = rd->backoff_ms * 2 >
					 CRDV_BACKOFF_MAX_MS ?
					 CRDV_BACKOFF_MAX_MS :
					 rd->backoff_ms * 2;
			return 0;
		}
		if (cc > 0)
			return 0;
		rd->tcp_st = CRDV_TCP_GREET_SEND;
	}

	if (writable) {
		crdv_fill_outbuf(rd);
		if (crdv_send_flush(rd) < 0)
			return -1;
	}

	if (readable) {
		for (;;) {
			ssize_t r;

			r = recv(rd->conn_fd, rd->inbuf + rd->in_len,
				 sizeof(rd->inbuf) - rd->in_len, 0);
			if (r < 0 && errno == EINTR)
				continue;
			if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
				break;
			if (r <= 0) {
				crt_log("TCP peer EOF/error r=%zd errno=%d",
					 r, errno);
				return -1;
			}
			rd->in_len += (size_t)r;
			if (crdv_parse_inbuf(rd))
				return -1;
			if (rd->info_expect && rd->in_len == (size_t)rd->info_expect)
				continue;
		}
	}
	return 0;
}
