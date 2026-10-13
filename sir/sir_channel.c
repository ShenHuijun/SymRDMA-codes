/* SPDX-License-Identifier: GPL-2.0 */
/*
 * sir_channel.c — SIR 通道建立 (自 sir.c 拆分)
 *
 * 会合文件 (角色选举 O_EXCL 锁 / 自身 qp+导出表发布 / 对端发现与
 * mtime 缓存) + 控制 QP 建立 (真实 verbs: dlsym 规避 LD_PRELOAD 自
 * 拦截, INIT→RTR→RTS) + 双向 RTS 握手 + 异步建连线程 (容忍对端晚到,
 * 失败复位重试)。连接建立成功后由 sir_service.c 的服务线程接管 CQ。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <dlfcn.h>
#include <infiniband/verbs.h>
#include "sir.h"
#include "sir_internal.h"

/* ---- 真实函数解析 (规避 LD_PRELOAD 自拦截) ---- */
struct sir_fns {
	struct ibv_mr *(*reg_mr)(struct ibv_pd *, void *, size_t, int);
	int (*dereg_mr)(struct ibv_mr *);
	struct ibv_qp *(*create_qp)(struct ibv_pd *,
				    struct ibv_qp_init_attr *);
	int (*destroy_qp)(struct ibv_qp *);
	struct ibv_cq *(*create_cq)(struct ibv_context *, int, void *,
				    struct ibv_comp_channel *, int);
	int (*destroy_cq)(struct ibv_cq *);
	int (*modify_qp)(struct ibv_qp *, struct ibv_qp_attr *, int);
	int (*query_gid)(struct ibv_context *, int, int, union ibv_gid *);
	/* TCP 会合跨机 path_mtu 动态派生 (min(active_mtu, 4096)) */
	int (*query_port)(struct ibv_context *, uint8_t,
			  struct ibv_port_attr *);
};
static struct sir_fns F;

/* ---- TCP 网络会合前置声明 (实现在导出表节之后) ---- */
static void sir_build_info_blob_locked(void);
static void sir_tcp_pull_locked(int force);

static void *sir_sym(const char *name, const char *ver)
{
	void *p = ver ? dlvsym(RTLD_NEXT, name, ver) : NULL;

	if (!p)
		p = dlsym(RTLD_NEXT, name);
	return p;
}

/* 幂等加载 (sir_init TCP 分支 / ensure_channel 双入口; done 守卫的竞态
 * 为多写同值 — 良性) */
SIR_INTERNAL void sir_load_fns(void)
{
	static int done;
	if (done)
		return;
	done = 1;
	*(void **)&F.reg_mr    = sir_sym("ibv_reg_mr", "IBVERBS_1.1");
	*(void **)&F.dereg_mr  = sir_sym("ibv_dereg_mr", "IBVERBS_1.1");
	*(void **)&F.create_qp = sir_sym("ibv_create_qp", "IBVERBS_1.1");
	*(void **)&F.destroy_qp= sir_sym("ibv_destroy_qp", "IBVERBS_1.1");
	*(void **)&F.create_cq = sir_sym("ibv_create_cq", "IBVERBS_1.1");
	*(void **)&F.destroy_cq= sir_sym("ibv_destroy_cq", "IBVERBS_1.1");
	*(void **)&F.modify_qp = sir_sym("ibv_modify_qp", "IBVERBS_1.1");
	*(void **)&F.query_gid = sir_sym("ibv_query_gid", "IBVERBS_1.1");
	*(void **)&F.query_port = sir_sym("ibv_query_port", "IBVERBS_1.1");
}

/* ---- 导出表文件 (会合) ---- */

void sir_peer_info_path(char *buf, size_t n)
{
	snprintf(buf, n, "%s/%s.%c.info", S->path, S->key,
		 S->role == 'a' ? 'b' : 'a');
}

int sir_write_own_info(void)
{
	char tmp[720], fin[700], line[600];
	struct sir_export *e;
	FILE *f;

	/* TCP 会合: 无文件 I/O — 重建内存 blob (含 qp/gid/up +
	 * 导出表), 对端经 GET 拉取时快照读取; 调用方持 g_mu */
	if (S->use_tcp) {
		sir_build_info_blob_locked();
		return 0;
	}

	snprintf(fin, sizeof(fin), "%s/%s.%c.info", S->path, S->key,
		 S->role ? S->role : 'a');
	snprintf(tmp, sizeof(tmp), "%s.tmp", fin);
	f = fopen(tmp, "w");
	if (!f)
		return -1;
	if (S->ctl_qp)
		fprintf(f, "qp %u\n", S->ctl_qp->qp_num);
	if (S->ctl_qp && S->rts_done)
		fprintf(f, "up 1\n");
	for (e = S->exports; e; e = e->next) {
		snprintf(line, sizeof(line),
			 "E %u %u %llu %llu %u %llu %d\n",
			 e->data_rkey, e->write_rkey,
			 (unsigned long long)e->addr,
			 (unsigned long long)e->len,
			 e->v_rkey, (unsigned long long)e->v_addr,
			 e->mr_id);
		fputs(line, f);
	}
	if (fflush(f)) {
		fclose(f);
		unlink(tmp);
		return -1;
	}
	fclose(f);
	if (rename(tmp, fin)) {
		unlink(tmp);
		return -1;
	}
	return 0;
}

/* 读对端导出表并替换 (锁内调用; 原子重建链表) */
void sir_read_peer_info_locked(void)
{
	char path[700], line[600];
	FILE *f;
	struct sir_export *list = NULL, *e, **tail = &list;
	struct sir_export *t;
	struct stat st;

	/* TCP 会合: GET 拉取 (TTL 节流; I/O 在 g_mu 内 — 调用方
	 * 已持锁); 文件 mtime 缓存机制不适用 */
	if (S->use_tcp) {
		sir_tcp_pull_locked(0);
		return;
	}

	sir_peer_info_path(path, sizeof(path));
	/* mtime 缓存: 文件未变则不重读 */
	if (stat(path, &st) == 0 &&
	    (S->peers || st.st_mtime != S->peer_mtime.tv_sec)) {
		S->peer_mtime.tv_sec = st.st_mtime;
		S->peer_mtime.tv_nsec = st.st_mtim.tv_nsec;
	} else if (stat(path, &st) != 0) {
		return;    /* 对端还没写 (首连时等 ensure_channel 轮询) */
	} else {
		return;    /* 缓存命中 */
	}
	f = fopen(path, "r");
	if (!f)
		return;
	while (fgets(line, sizeof(line), f)) {
		unsigned long long a, l, va;
		unsigned int dr, wr, vr;
		int mid;

		if (sscanf(line, "E %u %u %llu %llu %u %llu %d",
			   &dr, &wr, &a, &l, &vr, &va, &mid) == 7) {
			e = calloc(1, sizeof(*e));
			if (!e)
				continue;
			e->data_rkey  = dr;
			e->write_rkey = wr;
			e->addr = a;
			e->len  = l;
			e->v_rkey = vr;
			e->v_addr = va;
			e->mr_id  = mid;
			*tail = e;
			tail = &e->next;
		}
	}
	fclose(f);
	while (S->peers) {
		t = S->peers;
		S->peers = t->next;
		free(t);
	}
	S->peers = list;
}

/* ---- TCP 网络会合 (下一步 2: L12/L13 跨机化前提) ----
 *
 * env SYMRDMA_SIR_TCP (sir_init 解析): "listen:<port>" = role a /
 * "<host>:<port>" = role b。行协议 (与文件会合同源, 增加 gid 行;
 * 单连接全双工):
 *   SIR1 <role>          — 问候 (协议/角色校验)
 *   qp <num>             — 控制 QP 号
 *   gid <32hex>          — 本机 sgid_index 处 GID (跨机 dgid 必需)
 *   up 1                 — 自身 QP 已 RTS
 *   E <dr> <wr> <addr> <len> <vr> <va> <mr_id>  — 导出 MR
 * 交换形态: 握手 = 双向 lockstep INFO (qp/gid/导出表); 之后导出表刷新 =
 * GET→INFO 拉取 (pull-only, TTL 节流; 无推送 — 对端导出变更的可见性依赖
 * 对端自身 pull 或服务线程的机遇式 GET 服务, 见 sir_thread_main)。
 * I/O 锁纪律: 握手阶段 fd 未发布 (conn 线程独占局部变量); 发布后一切
 * I/O 在 g_mu 内 (pull 调用方均已持锁; 单锁无逆序)。
 * 跨机 QP 参数: dgid = 对端 blob 的 gid 行 (RoCEv2 必需; 文件形态仍用
 * 本地 GID 自环), path_mtu = min(active_mtu, 4096) (L15 教训:
 * 测试床 active_mtu=1024, 硬编码 4096 令多包消息首包被丢)。
 */

static int64_t sir_now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* 有界追加 (blob 构建; 返回新长度, 截断安全) */
static size_t sir_appendf(char *p, size_t cap, size_t n, const char *fmt, ...)
{
	va_list ap;
	int w;

	if (n >= cap)
		return cap;
	va_start(ap, fmt);
	w = vsnprintf(p + n, cap - n, fmt, ap);
	va_end(ap);
	if (w < 0)
		return n;
	return (n + (size_t)w > cap) ? cap : n + (size_t)w;
}

/* 重建自身发布 blob (调用方持 g_mu): qp/gid/up + 导出表 — sir_write_own_info
 * (TCP 分支) 与 GET 服务共用; 结果存 S->info_blob (对端拉取时快照发送) */
static void sir_build_info_blob_locked(void)
{
	union ibv_gid g;
	struct sir_export *e;
	size_t n = 0, cap = sizeof(S->info_blob);

	n = sir_appendf(S->info_blob, cap, n, "qp %u\n",
			S->ctl_qp ? S->ctl_qp->qp_num : 0);
	/* gid 行: 跨机 dgid 必需; F 未加载或查询失败时省略 (对端回退本地
	 * GID — 仅单机 TCP 自环冒烟可达, 正常跨机部署须可查) */
	if (F.query_gid && S->ctx &&
	    !F.query_gid(S->ctx, 1, S->sgid_index, &g)) {
		int i;

		n = sir_appendf(S->info_blob, cap, n, "gid ");
		for (i = 0; i < 16; i++)
			n = sir_appendf(S->info_blob, cap, n, "%02x",
					g.raw[i]);
		n = sir_appendf(S->info_blob, cap, n, "\n");
	}
	if (S->rts_done)
		n = sir_appendf(S->info_blob, cap, n, "up 1\n");
	for (e = S->exports; e && n < cap - 128; e = e->next)
		n = sir_appendf(S->info_blob, cap, n,
				"E %u %u %llu %llu %u %llu %d\n",
				e->data_rkey, e->write_rkey,
				(unsigned long long)e->addr,
				(unsigned long long)e->len,
				e->v_rkey, (unsigned long long)e->v_addr,
				e->mr_id);
	S->info_len = n;
}

static int sir_tcp_send_all(int fd, const void *buf, size_t len)
{
	const char *p = buf;

	while (len) {
		ssize_t w = send(fd, p, len, MSG_NOSIGNAL);

		if (w < 0 && errno == EINTR)
			continue;
		if (w <= 0)
			return -1;
		p += w;
		len -= (size_t)w;
	}
	return 0;
}

static int sir_tcp_send_info(int fd, const char *blob, size_t len)
{
	char hdr[32];

	snprintf(hdr, sizeof(hdr), "INFO %zu\n", len);
	if (sir_tcp_send_all(fd, hdr, strlen(hdr)) ||
	    sir_tcp_send_all(fd, blob, len))
		return -1;
	return 0;
}

/* 读一行 (\n 结尾)。返回 0=完整行 / -1=EOF或错误 / -2=超时 (无字节消费) */
static int sir_tcp_read_line(int fd, char *buf, size_t cap)
{
	size_t n = 0;

	for (;;) {
		char c;
		ssize_t r = recv(fd, &c, 1, 0);

		if (r < 0 && errno == EINTR)
			continue;
		if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
			return n ? -1 : -2;   /* 部分行为错误 (防失步) */
		if (r <= 0)
			return -1;
		if (c == '\n') {
			buf[n] = 0;
			return 0;
		}
		if (n + 1 < cap)
			buf[n++] = c;   /* 超长截断 (前向兼容) */
	}
}

static int sir_tcp_read_n(int fd, char *buf, size_t len)
{
	size_t n = 0;

	while (n < len) {
		ssize_t r = recv(fd, buf + n, len - n, 0);

		if (r < 0 && errno == EINTR)
			continue;
		if (r <= 0)
			return -1;
		n += (size_t)r;
	}
	return 0;
}

/* 构建 + 发送自身 INFO (调用方持 g_mu — pull 路径与服务线程机遇式服务
 * 共用) */
static int sir_tcp_serve_get_locked(int fd)
{
	char snap[SIR_TCP_BLOB_MAX];
	size_t n;

	sir_build_info_blob_locked();
	n = S->info_len;
	memcpy(snap, S->info_blob, n);
	return sir_tcp_send_info(fd, snap, n);
}

/* 读一条消息 (循环直到 INFO); 途中收到的 GET 以当前 blob 应答 (对称拉取)。
 * serve_locked=1: 调用方持 g_mu (pull 路径, I/O 锁内);
 * serve_locked=0: 握手路径 — fd 未发布无并发发送者, 构建段自取锁。
 * 返回 0=INFO 已读入 payload / -1 失败 (失步风险 — 调用方关连接) /
 * -2 超时且未消费字节 (安全重试 — pull 调用方保留连接) */
static int sir_tcp_read_info(int fd, char *payload, size_t cap, size_t *len_out,
			     int serve_locked)
{
	char line[64];

	for (;;) {
		int rc = sir_tcp_read_line(fd, line, sizeof(line));

		if (rc)
			return rc == -2 ? -2 : -1;
		if (!strncmp(line, "GET", 4)) {
			int r;

			if (serve_locked) {
				r = sir_tcp_serve_get_locked(fd);
			} else {
				pthread_mutex_lock(&g_mu);
				r = sir_tcp_serve_get_locked(fd);
				pthread_mutex_unlock(&g_mu);
			}
			if (r)
				return -1;
			continue;
		}
		if (!strncmp(line, "INFO ", 5)) {
			size_t len = (size_t)strtoul(line + 5, NULL, 10);

			/* len < cap: 预留 1 字节 NUL — apply 的 while(*s)/strchr
			 * 依赖终结符, 否则扫越界栈内存 (实测偶发段错误) */
			if (!len || len >= cap || sir_tcp_read_n(fd, payload, len))
				return -1;
			payload[len] = '\0';
			*len_out = len;
			return 0;
		}
		/* 未知行: 忽略 (前向兼容) */
	}
}

/* 解析对端 blob (调用方持 g_mu): peer_qp/peer_up/peer_gid + peers 表
 * (原子重建 — 与文件形态 sir_read_peer_info_locked 同语义) */
static void sir_tcp_apply_blob_locked(const char *blob)
{
	struct sir_export *list = NULL, *e, **tail = &list;
	const char *s = blob;

	while (*s) {
		const char *nl = strchr(s, '\n');
		char line[512];
		size_t l = nl ? (size_t)(nl - s) : strlen(s);

		if (l >= sizeof(line))
			l = sizeof(line) - 1;
		memcpy(line, s, l);
		line[l] = 0;
		if (!nl)
			break;
		s = nl + 1;
		if (!strncmp(line, "qp ", 3)) {
			S->peer_qp = (unsigned)strtoul(line + 3, NULL, 0);
		} else if (!strncmp(line, "up ", 3)) {
			S->peer_up = (int)strtoul(line + 3, NULL, 0);
		} else if (!strncmp(line, "gid ", 4) &&
			   strlen(line + 4) >= 32) {
			int i, ok = 1;

			for (i = 0; i < 16; i++) {
				unsigned v;

				if (sscanf(line + 4 + i * 2, "%2x", &v) != 1) {
					ok = 0;
					break;
				}
				S->peer_gid[i] = (uint8_t)v;
			}
			S->peer_gid_valid = ok;
		} else if (line[0] == 'E') {
			unsigned long long a, l2, va;
			unsigned int dr, wr, vr;
			int mid;

			if (sscanf(line, "E %u %u %llu %llu %u %llu %d",
				   &dr, &wr, &a, &l2, &vr, &va, &mid) == 7) {
				e = calloc(1, sizeof(*e));
				if (!e)
					continue;
				e->data_rkey = dr;
				e->write_rkey = wr;
				e->addr = a;
				e->len = l2;
				e->v_rkey = vr;
				e->v_addr = va;
				e->mr_id = mid;
				*tail = e;
				tail = &e->next;
			}
		}
	}
	while (S->peers) {
		struct sir_export *t = S->peers;

		S->peers = t->next;
		free(t);
	}
	S->peers = list;
}

static void sir_tcp_set_timeouts(int fd)
{
	struct timeval tv = { .tv_sec = 0, .tv_usec = 500 * 1000 };
	struct timeval tv2 = { .tv_sec = 2, .tv_usec = 0 };

	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv2, sizeof(tv2));
}

/* connect 模式: 非阻塞 connect + poll 重试至 deadline */
static int sir_tcp_connect_peer(int *fd_out, int64_t deadline_ms)
{
	struct addrinfo hints, *res = NULL;
	char portstr[16];
	int fd = -1;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	snprintf(portstr, sizeof(portstr), "%d", S->tcp_port);
	if (getaddrinfo(S->tcp_host, portstr, &hints, &res) || !res)
		return -1;
	while (sir_now_ms() < deadline_ms) {
		int rc, err = 0, fl;
		socklen_t el = sizeof(err);
		struct pollfd pfd;

		fd = socket(res->ai_family, SOCK_STREAM, 0);
		if (fd < 0)
			break;
		fcntl(fd, F_SETFL, O_NONBLOCK);
		rc = connect(fd, res->ai_addr, res->ai_addrlen);
		if (rc == 0)
			goto connected;
		if (errno != EINPROGRESS) {
			close(fd);
			fd = -1;
			break;
		}
		pfd.fd = fd;
		pfd.events = POLLOUT;
		rc = poll(&pfd, 1, 300);
		if (rc > 0 &&
		    !getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el) && !err) {
		connected:
			/* 恢复阻塞模式 — 握手/拉取依赖 SO_RCVTIMEO 分界超时,
			 * 非阻塞残留会令 recvfrom 立即 EAGAIN (实测: 握手必败,
			 * 仅数据先行到位时侥幸通过) */
			fl = fcntl(fd, F_GETFL);
			if (fl >= 0)
				fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);
			break;
		}
		close(fd);
		fd = -1;
		usleep(100 * 1000);
	}
	freeaddrinfo(res);
	*fd_out = fd;
	return fd >= 0 ? 0 : -1;
}

/* listen 模式: bind/listen + poll accept 至 deadline (成功即关 listener) */
static int sir_tcp_accept_peer(int *fd_out, int64_t deadline_ms)
{
	struct sockaddr_in a;
	int lfd, fd = -1, one = 1;

	lfd = socket(AF_INET, SOCK_STREAM, 0);
	if (lfd < 0)
		return -1;
	setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	memset(&a, 0, sizeof(a));
	a.sin_family = AF_INET;
	a.sin_addr.s_addr = htonl(INADDR_ANY);
	a.sin_port = htons((uint16_t)S->tcp_port);
	if (bind(lfd, (struct sockaddr *)&a, sizeof(a)) || listen(lfd, 1)) {
		close(lfd);
		return -1;
	}
	while (sir_now_ms() < deadline_ms) {
		struct pollfd pfd = { .fd = lfd, .events = POLLIN };

		if (poll(&pfd, 1, 200) > 0) {
			fd = accept(lfd, NULL, NULL);
			break;
		}
	}
	close(lfd);
	*fd_out = fd;
	return fd >= 0 ? 0 : -1;
}

/* TCP 会合连接 + 握手 (ensure_channel 调用; 成功后 fd 经 *fd_out 返回,
 * 此时 fd 尚未发布到 S — 无并发 I/O)。对端 qp/gid/导出表就绪。 */
static int sir_tcp_handshake(int *fd_out)
{
	char line[64], blob[SIR_TCP_BLOB_MAX];
	size_t blen = 0;
	int64_t deadline = sir_now_ms() +
			   (int64_t)SIR_CONNECT_TICKS * SIR_WAIT_MS;
	int fd = -1;

	if (S->tcp_listen) {
		if (sir_tcp_accept_peer(&fd, deadline)) {
			sir_log("TCP accept/bind 失败 (errno=%d)", errno);
			return -1;
		}
	} else {
		if (sir_tcp_connect_peer(&fd, deadline)) {
			sir_log("TCP connect 失败 (errno=%d)", errno);
			return -1;
		}
	}
	sir_tcp_set_timeouts(fd);

	/* 问候: 协议/角色校验 (防 stale 连接/误连其他端口) */
	snprintf(line, sizeof(line), "SIR1 %c\n", S->role);
	if (sir_tcp_send_all(fd, line, strlen(line))) {
		sir_log("TCP 问候发送失败 (errno=%d)", errno);
		goto fail;
	}
	if (sir_tcp_read_line(fd, line, sizeof(line))) {
		sir_log("TCP 问候读取失败 (errno=%d)", errno);
		goto fail;
	}
	if (strncmp(line, "SIR1 ", 5) ||
	    (line[5] != 'a' && line[5] != 'b') || line[5] == S->role) {
		sir_log("TCP 问候不符: '%s' (本侧 role=%c)", line, S->role);
		goto fail;
	}

	/* lockstep blob 交换: 各自发 INFO → 读对端 INFO (途中 GET 即时服务) */
	pthread_mutex_lock(&g_mu);
	sir_build_info_blob_locked();
	{
		char snap[SIR_TCP_BLOB_MAX];
		size_t n = S->info_len;

		memcpy(snap, S->info_blob, n);
		pthread_mutex_unlock(&g_mu);
		if (sir_tcp_send_info(fd, snap, n)) {
			sir_log("TCP blob 发送失败 (errno=%d)", errno);
			goto fail;
		}
	}
	if (sir_tcp_read_info(fd, blob, sizeof(blob), &blen, 0)) {
		sir_log("TCP blob 读取失败 (errno=%d)", errno);
		goto fail;
	}
	pthread_mutex_lock(&g_mu);
	sir_tcp_apply_blob_locked(blob);
	pthread_mutex_unlock(&g_mu);
	sir_log("TCP 握手完成: 对端 qp=0x%x gid=%s up=%d blob=%zu B",
		S->peer_qp, S->peer_gid_valid ? "有" : "无", S->peer_up,
		blen);
	*fd_out = fd;
	return 0;
fail:
	close(fd);
	return -1;
}

/* 导出表/对端状态拉取 (调用方持 g_mu; force=1 绕过 TTL — up 等待环)。
 * 读取超时且未消费字节 → 保留连接下次重试; 其他 I/O 失败按失步风险关闭
 * 连接 (表保留旧值)。 */
static void sir_tcp_pull_locked(int force)
{
	int64_t now = sir_now_ms();
	char blob[SIR_TCP_BLOB_MAX];
	size_t blen = 0;
	int rc;

	if (S->tcp_fd < 0)
		return;
	if (!force && S->peers &&
	    now - S->last_pull_ms < SIR_TCP_PULL_TTL_MS)
		return;
	if (sir_tcp_send_all(S->tcp_fd, "GET\n", 4))
		return;   /* 发送失败: 保留旧表 (连接故障由后续检测处理) */
	rc = sir_tcp_read_info(S->tcp_fd, blob, sizeof(blob), &blen, 1);
	if (rc == -2)
		return;   /* 对端暂未响应 (未消费字节): 下次重试 */
	if (rc) {
		sir_log("TCP 拉取失败 (errno=%d) — 关闭会合连接 (保留旧表)",
			errno);
		sir_tcp_close_locked();
		return;
	}
	sir_tcp_apply_blob_locked(blob);
	S->last_pull_ms = now;
}

void sir_tcp_close_locked(void)   /* internal.h 声明; 调用方持 g_mu */
{
	if (S->tcp_fd >= 0) {
		close(S->tcp_fd);
		S->tcp_fd = -1;
	}
}

/* 服务线程机遇式调用 (调用方持 g_mu, sir_service.c): 若对端有积压消息
 * 则非阻塞服务一条 (GET → INFO 应答; 防对端拉取永久超时 + 对端导出变更
 * 可见性)。仅 poll(0) 探测, 无数据即返回; 读到非 GET 消息 (不应出现)
 * 丢弃以防失步。 */
void sir_tcp_opportunistic_locked(void)
{
	struct pollfd pfd = { .fd = S->tcp_fd, .events = POLLIN };
	char line[64];

	if (poll(&pfd, 1, 0) <= 0)
		return;
	if (sir_tcp_read_line(S->tcp_fd, line, sizeof(line)))
		return;
	if (!strncmp(line, "GET", 4))
		sir_tcp_serve_get_locked(S->tcp_fd);
}

/* ---- 控制 QP (真实实现) ---- */

static struct ibv_qp *sir_create_qp(struct ibv_cq **cq_out)
{
	struct ibv_cq *cq = F.create_cq(S->pd->context, SIR_CQ_DEPTH,
					NULL, NULL, 0);
	struct ibv_qp_init_attr a = {0};
	struct ibv_qp *qp;

	if (!cq)
		return NULL;
	a.send_cq = cq;
	a.recv_cq = cq;
	a.qp_type = IBV_QPT_RC;
	a.cap.max_send_wr  = SIR_CQ_DEPTH;
	a.cap.max_recv_wr  = SIR_CQ_DEPTH;
	a.cap.max_send_sge = 1;
	a.cap.max_recv_sge = 1;
	qp = F.create_qp(S->pd, &a);
	if (!qp) {
		F.destroy_cq(cq);
		return NULL;
	}
	*cq_out = cq;
	return qp;
}

static int sir_qp_to_rts(struct ibv_qp *qp, uint32_t dest_qp_num)
{
	struct ibv_qp_attr attr = {0};
	struct ibv_context *ctx = qp->pd->context;

	attr.qp_state        = IBV_QPS_INIT;
	attr.pkey_index      = 0;
	attr.port_num        = 1;
	attr.qp_access_flags = IBV_ACCESS_REMOTE_READ |
			       IBV_ACCESS_REMOTE_WRITE |
			       IBV_ACCESS_LOCAL_WRITE;
	if (F.modify_qp(qp, &attr,
			IBV_QP_STATE | IBV_QP_PKEY_INDEX |
			IBV_QP_PORT | IBV_QP_ACCESS_FLAGS))
		return -1;
	attr.qp_state           = IBV_QPS_RTR;
	/* TCP 会合 (跨机) path_mtu 动态派生 min(active_mtu, 4096)
	 * — 测试床 active_mtu=1024, 硬编码 4096 令多包消息首包被丢
	 * (L15 教训); 文件会合 (单机自环, 现有绿色路径) 不变 */
	attr.path_mtu           = IBV_MTU_4096;
	if (S->use_tcp && F.query_port) {
		struct ibv_port_attr pa;

		if (!F.query_port(ctx, 1, &pa) &&
		    pa.active_mtu < IBV_MTU_4096)
			attr.path_mtu = pa.active_mtu;
	}
	attr.dest_qp_num        = dest_qp_num;
	attr.rq_psn             = 0;
	attr.max_dest_rd_atomic = 1;
	attr.min_rnr_timer      = 12;
	attr.ah_attr.port_num   = 1;
	attr.ah_attr.is_global  = 1;
	/* sgid_index 由 SYMRDMA_SIR_GID 控制 (默认 0 不变); TCP
	 * 会合 dgid = 对端 blob 的 gid 行 (跨机 RoCEv2 必需), 文件会合仍用
	 * 本地 GID 0 (单机自环) */
	attr.ah_attr.grh.sgid_index = (uint8_t)S->sgid_index;
	if (S->use_tcp && S->peer_gid_valid) {
		memcpy(&attr.ah_attr.grh.dgid, S->peer_gid,
		       sizeof(S->peer_gid));
	} else if (F.query_gid(ctx, 1, 0, &attr.ah_attr.grh.dgid)) {
		return -1;
	}
	attr.ah_attr.grh.hop_limit  = 1;
	if (F.modify_qp(qp, &attr,
			IBV_QP_STATE | IBV_QP_MTU |
			IBV_QP_DEST_QPN | IBV_QP_RQ_PSN |
			IBV_QP_MAX_DEST_RD_ATOMIC |
			IBV_QP_MIN_RNR_TIMER | IBV_QP_AV))
		return -1;
	attr.qp_state      = IBV_QPS_RTS;
	attr.sq_psn        = 0;
	attr.timeout       = 14;
	attr.retry_cnt     = 7;
	attr.rnr_retry     = 7;
	attr.max_rd_atomic = 1;
	if (F.modify_qp(qp, &attr,
			IBV_QP_STATE | IBV_QP_SQ_PSN |
			IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT |
			IBV_QP_RNR_RETRY | IBV_QP_MAX_QP_RD_ATOMIC))
		return -1;
	return 0;
}

/* ---- 通道自动建立 (会合 + 控制 QP 对连 + 起服务线程) ---- */

static int sir_elect_role(void)
{
	char lockp[700];
	int fd;

	if (S->role)      /* 粘性: 重试/后续调用不改变角色 (防自锁反转) */
		return 0;
	snprintf(lockp, sizeof(lockp), "%s/%s%s", S->path, S->key,
		 SIR_ROLE_LOCK);
	fd = open(lockp, O_CREAT | O_EXCL | O_WRONLY, 0600);
	if (fd >= 0) {
		close(fd);
		S->role = 'a';
		sir_log("选举: pid=%d 创建锁 → role=a", (int)getpid());
		return 0;
	}
	S->role = 'b';   /* 锁已存在 → 对端为 a */
	sir_log("选举: pid=%d 锁已存在 → role=b (errno=%d)", (int)getpid(), errno);
	return 0;
}

/* 读对端信息文件: qp 号 + up 标志 (双向 RTS 握手) */
static void sir_read_peer_flags(unsigned int *qp_out, int *up_out)
{
	char p[700], line[600];
	FILE *f;

	*qp_out = 0;
	*up_out = 0;
	sir_peer_info_path(p, sizeof(p));
	f = fopen(p, "r");
	if (!f)
		return;
	while (fgets(line, sizeof(line), f)) {
		if (!strncmp(line, "qp ", 3))
			*qp_out = (unsigned int)strtoul(line + 3, NULL, 0);
		else if (!strncmp(line, "up ", 3))
			*up_out = (int)strtoul(line + 3, NULL, 0);
	}
	fclose(f);
}

/* 返回 0 通道就绪; -1 不可用 (errno 置位) */
static int sir_ensure_channel(void)
{
	struct ibv_qp *qp = NULL;
	struct ibv_cq *cq = NULL;
	struct ibv_mr *in_mr = NULL, *out_mr = NULL;
	uint8_t *in_buf = NULL, *out_buf = NULL;
	int in_id = -1, out_id = -1, i;

	pthread_mutex_lock(&g_mu);
	if (!S || !S->enabled) {
		pthread_mutex_unlock(&g_mu);
		errno = ENOTCONN;
		return -1;
	}
	if (S->connected) {
		pthread_mutex_unlock(&g_mu);
		return 0;
	}
	/* sym_fd 未开 (alloc_pd 钩子早于首次 reg_mr) → 返回失败让连接线程重试:
	 * 控制 buffer 的 IOMMU 映射 (ioctl REG_MR) 只在此处做一次, 若在
	 * sym_fd<0 时静默跳过, 写区域 MTT=VA+32GB 的 SEND DMA 读将落空
	 * (DMAR reason 06 → LOC_PROT_ERR → 控制 QP 报废, L13 实测)。
	 * 语义: 无 reg_mr 则无导出, 通道也无意义 — 等 fd 开启后重试无副作用。 */
	if (S->sym_fd < 0) {
		pthread_mutex_unlock(&g_mu);
		errno = EAGAIN;
		return -1;
	}
	pthread_mutex_unlock(&g_mu);

	sir_load_fns();
	if (!F.reg_mr || !F.dereg_mr || !F.create_qp || !F.create_cq ||
	    !F.modify_qp || !F.query_gid) {
		errno = ENOSYS;
		return -1;
	}

	/* 1. 会合目录 + 角色 */
	mkdir(S->path, 0700);
	sir_elect_role();

	/* 2. 控制 buffer (页粒度; mlock 防换出) */
	in_buf = mmap(NULL, SIR_MSG_SIZE, PROT_READ | PROT_WRITE,
		      MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	out_buf = mmap(NULL, SIR_MSG_SIZE, PROT_READ | PROT_WRITE,
		       MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (in_buf == MAP_FAILED || out_buf == MAP_FAILED)
		goto fail;
	memset(in_buf, 0x5A, SIR_MSG_SIZE);
	memset(out_buf, 0x5A, SIR_MSG_SIZE);
	if (mlock(in_buf, SIR_MSG_SIZE) || mlock(out_buf, SIR_MSG_SIZE)) {
		sir_log("mlock 控制 buffer 失败 (errno=%d) — SIR 禁用", errno);
		goto fail;
	}
	/* 修复: 控制 buffer 改用普通 pinned MR (去掉 identity 位 +
	 * ioctl REG_MR)。旧形态 = SymRDMA MR (nopin + notifier 附加) —
	 * NUMA balancing / 迁移 (edr_monitor 实测) 触发 invalidate 时
	 * follow_page 失败 → 模块"确认真缺失"→ 控制页被哨兵化且无修复
	 * 路径 (修复请求本身走本通道 = 死锁) → SEND 读到哨兵页内容
	 * (magic=0xdeadbeef 全填充) → 通道永久卡死 (racebw Fig 12 实测)。
	 * 普通 MR: GUP 长期引用 → 迁移/回收免疫, MTT=PA (普通 RDMA 语义),
	 * 不经 IOMMU VA 翻译, 无 notifier。in_id/out_id 恒 -1 (迟绑定
	 * 补映射块同步移除)。 */
	in_mr = F.reg_mr(S->pd, in_buf, SIR_MSG_SIZE,
			 IBV_ACCESS_LOCAL_WRITE);
	out_mr = F.reg_mr(S->pd, out_buf, SIR_MSG_SIZE,
			  IBV_ACCESS_LOCAL_WRITE);
	if (!in_mr || !out_mr) {
		sir_log("控制 MR 注册失败 (errno=%d)", errno);
		goto fail;
	}

	qp = sir_create_qp(&cq);
	if (!qp) {
		sir_log("控制 QP 创建失败 (errno=%d)", errno);
		goto fail;
	}

	pthread_mutex_lock(&g_mu);
	S->ctl_qp = qp;
	S->ctl_cq = cq;
	S->in_mr = in_mr;
	S->out_mr = out_mr;
	S->ctl_in = in_buf;
	S->ctl_out = out_buf;
	S->in_id = in_id;
	S->out_id = out_id;
	S->tag_hi = (S->role == 'a') ? 0x80000000u : 0u;
	S->next_tag = 1;
	S->have_recv = 0;
	S->saved_valid = 0;
	pthread_mutex_unlock(&g_mu);

	/* 2.5 TCP 会合连接 + 握手: blob 交换后对端 qp/gid/导出表
	 * 就绪 (S->peer_* / S->peers); fd 在成功后才发布到 S->tcp_fd。
	 * 文件会合形态不进入本分支 (零改动)。 */
	if (S->use_tcp) {
		int tfd = -1;

		if (sir_tcp_handshake(&tfd))
			goto fail2;   /* 真实 errno 已在握手内日志化 */
		pthread_mutex_lock(&g_mu);
		S->tcp_fd = tfd;          /* 发布 — 此后 pull 路径可见 */
		S->last_pull_ms = sir_now_ms();
		pthread_mutex_unlock(&g_mu);
		if (!S->peer_qp) {        /* 对端 blob 缺 qp 行: 异常重试 */
			sir_log("TCP 握手后对端 qp=0 — 重试");
			goto fail2;
		}
	}

	/* 3. 发布自身 (qp + 导出表) → 等对端 qp → 本方 RTS → 发布 up */
	sir_log("ensure pid=%d role=%c 开始, qp=0x%x", (int)getpid(), S->role,
		 qp->qp_num);
	sir_write_own_info();
	if (S->use_tcp) {
		/* TCP: 对端 qp 已知, 直接 RTS (重试 — 传输层重传覆盖对端晚 RTR);
		 * RTS 成功后重建 blob (up 行) 由对端拉取 */
		for (i = 0; i < SIR_CONNECT_TICKS && !S->rts_done; i++) {
			if (sir_qp_to_rts(qp, S->peer_qp) == 0) {
				S->rts_done = 1;
				sir_log("pid=%d RTS 成功 (TCP 会合) → blob up",
					(int)getpid());
				sir_write_own_info();
			} else {
				sir_log("RTS 到对端 qp 0x%x 失败 (errno=%d)",
					S->peer_qp, errno);
				usleep(SIR_WAIT_MS * 1000);
			}
		}
	} else {
		for (i = 0; i < SIR_CONNECT_TICKS && !S->rts_done; i++) {
			unsigned int peer_qp = 0;
			int peer_up = 0;

			sir_read_peer_flags(&peer_qp, &peer_up);
			if (peer_qp) {
				sir_log("pid=%d 见对端 qp=0x%x → RTS", (int)getpid(), peer_qp);
				if (sir_qp_to_rts(qp, peer_qp) == 0) {
					S->rts_done = 1;
					sir_log("pid=%d RTS 成功 → 发布 up", (int)getpid());
					sir_write_own_info();   /* 带 up 1 */
				} else {
					sir_log("RTS 到对端 qp 0x%x 失败 (errno=%d)",
						peer_qp, errno);
				}
			}
			usleep(SIR_WAIT_MS * 1000);
		}
	}
	if (!S->rts_done) {
		errno = ETIMEDOUT;
		goto fail2;
	}

	/* 4. 等对端 up (双向 RTS 就绪才起服务线程 — 防早发 RNR/RETRY_EXC) */
	if (S->use_tcp) {
		for (i = 0; i < SIR_CONNECT_TICKS; i++) {
			pthread_mutex_lock(&g_mu);
			sir_tcp_pull_locked(1);   /* 强制拉取 (看对端 up) */
			if (S->peer_up) {
				pthread_mutex_unlock(&g_mu);
				break;
			}
			pthread_mutex_unlock(&g_mu);
			usleep(SIR_WAIT_MS * 1000);
		}
		pthread_mutex_lock(&g_mu);
		if (!S->peer_up) {
			pthread_mutex_unlock(&g_mu);
			sir_log("TCP: 对端 up 等待超时");
			errno = ETIMEDOUT;
			goto fail2;
		}
		pthread_mutex_unlock(&g_mu);
	} else {
		for (i = 0; i < SIR_CONNECT_TICKS; i++) {
			unsigned int peer_qp = 0;
			int peer_up = 0;

			sir_read_peer_flags(&peer_qp, &peer_up);
			if (peer_up)
				break;
			usleep(SIR_WAIT_MS * 1000);
		}
		{
			unsigned int peer_qp = 0;
			int peer_up = 0;

			sir_read_peer_flags(&peer_qp, &peer_up);
			if (!peer_up) {
				errno = ETIMEDOUT;
				goto fail2;
			}
		}
	}

	/* 5. 服务线程 */
	if (pthread_create(&S->thread, NULL, sir_thread_main, NULL) != 0) {
		errno = EAGAIN;
		goto fail2;
	}
	pthread_mutex_lock(&g_mu);
	S->connected = 1;
	S->serving = 1;
	pthread_mutex_unlock(&g_mu);
	sir_log("通道建立: role=%c qp=0x%x 服务线程已起 (双向 RTS)", S->role,
		qp->qp_num);
	return 0;

fail:
fail2:
	/* 复位 S 控制通道字段 (重试会重建); TCP 会合连接一并关闭 (fd 可能
	 * 已在 RTS/up 超时路径前发布) */
	pthread_mutex_lock(&g_mu);
	sir_tcp_close_locked();
	pthread_mutex_unlock(&g_mu);
	S->ctl_qp = NULL;
	S->ctl_cq = NULL;
	S->in_mr = NULL;
	S->out_mr = NULL;
	S->ctl_in = NULL;
	S->ctl_out = NULL;
	S->in_id = -1;
	S->out_id = -1;
	S->rts_done = 0;
	if (qp)
		F.destroy_qp(qp);
	if (cq)
		F.destroy_cq(cq);
	if (in_mr)
		F.dereg_mr(in_mr);
	if (out_mr)
		F.dereg_mr(out_mr);
	if (S->sym_fd >= 0) {
		if (in_id >= 0)
			ioctl(S->sym_fd, SYMRDMA_IOC_DEREG_MR, in_id);
		if (out_id >= 0)
			ioctl(S->sym_fd, SYMRDMA_IOC_DEREG_MR, out_id);
	}
	if (in_buf && in_buf != MAP_FAILED)
		munmap(in_buf, SIR_MSG_SIZE);
	if (out_buf && out_buf != MAP_FAILED)
		munmap(out_buf, SIR_MSG_SIZE);
	sir_log("通道建立失败 (errno=%d)", errno);
	return -1;
}

/* 异步建连线程: 重试至成功或 quit (owner 服务就绪必需控制通道) */
static void *sir_conn_thread(void *arg)
{
	int tries = 0;

	(void)arg;
	sir_log("连接线程启动");
	while (tries++ < 150) {
		if (sir_ensure_channel() == 0)
			break;
		pthread_mutex_lock(&g_mu);
		if (S->quit) {
			pthread_mutex_unlock(&g_mu);
			break;
		}
		if (tries % 10 == 0)
			sir_log("conn try=%d sym_fd=%d connected=%d",
				tries, S ? S->sym_fd : -99,
				S ? S->connected : 0);
		pthread_mutex_unlock(&g_mu);
		usleep(300000);
	}
	pthread_mutex_lock(&g_mu);
	sir_log("连接线程退出 (tries=%d)", tries);
	S->conn_running = 0;
	pthread_mutex_unlock(&g_mu);
	return NULL;
}

void sir_start_connector(void)   /* internal.h 声明 */
{
	pthread_mutex_lock(&g_mu);
	if (!S || !S->enabled || S->connected || S->conn_running) {
		pthread_mutex_unlock(&g_mu);
		return;
	}
	S->conn_running = 1;
	pthread_mutex_unlock(&g_mu);
	if (pthread_create(&S->conn, NULL, sir_conn_thread, NULL) != 0) {
		pthread_mutex_lock(&g_mu);
		S->conn_running = 0;
		pthread_mutex_unlock(&g_mu);
	}
}

int sir_ensure_start(void)
{
	sir_start_connector();
	return 0;
}
