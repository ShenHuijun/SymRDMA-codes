/*
 * netcoord.h — 跨机测试协调通道 (下一步 2: L12/L13 跨机会合)
 *
 * 测试程序的参数/事件交换原本走 /tmp 文件 (单机双进程形态)。跨机运行时
 * 文件不可见 — 本头文件提供 TCP 形态, 由 env SYMRDMA_TEST_TCP 启用:
 *
 *   SYMRDMA_TEST_TCP=listen:<port>   — server 侧 (监听并等待 client 连接)
 *   SYMRDMA_TEST_TCP=<host>:<port>   — client 侧 (连接, 重试 ≤30s)
 *
 * 未设置时 nc_active()==0, 测试程序维持文件语义 (单机回归形态零改动)。
 *
 * 消息 (行协议 + 二进制负载; 与 SIR TCP 会合同风格):
 *   EVT <tag>\n                 — 事件通知 (evt_set; 一次性消息)
 *   PARAM <tag> <len>\n + len B — 参数块 (write_params/read_params)
 *
 * 接收侧维护 pending 队列 (≤NC_PEND 条): evt_wait/nc_get 不匹配的消息
 * 暂存 — 先 set 后 wait / 双向并发 set+wait 均安全 (文件形态的 clear
 * 在消息语义下为无操作: 消息不可重复消费)。
 *
 * 并发约定: 单读者 (测试进程主线程串行调用 wait/get); 发送侧互斥。
 * 仅用于测试编排 (非数据面), 阻塞读以 SO_RCVTIMEO 分片轮询至截止时间。
 */
#ifndef NETCOORD_H
#define NETCOORD_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>

#define NC_PEND         16      /* 暂存队列深度 (测试编排规模内) */
#define NC_PAYLOAD_MAX  1024    /* 参数块上限 (conn_params 文本 ~300B) */
#define NC_ACCEPT_SEC   90      /* server 等待 client 连接上限 */
#define NC_CONNECT_SEC  30      /* client 连接重试上限 */

struct nc_msg {
	char     tag[64];
	size_t   len;
	char     payload[NC_PAYLOAD_MAX];
};

static struct nc_state {
	int      fd;             /* 协调连接 (-1=未建立) */
	int      inited;
	pthread_mutex_t mu;      /* 发送互斥 */
	struct nc_msg pend[NC_PEND];
	int      npend;
} NC = { .fd = -1, .mu = PTHREAD_MUTEX_INITIALIZER };

__attribute__((unused))
static int nc_active(void)
{
	return NC.inited && NC.fd >= 0;
}

__attribute__((unused))
static int nc_send_all(const void *buf, size_t len)
{
	const char *p = buf;

	while (len) {
		ssize_t w = send(NC.fd, p, len, MSG_NOSIGNAL);

		if (w < 0 && errno == EINTR)
			continue;
		if (w <= 0)
			return -1;
		p += w;
		len -= (size_t)w;
	}
	return 0;
}

/* 读一行 (\n 结尾); 阻塞 ≤ SO_RCVTIMEO, 返回 0 / -1 (超时/EOF/错误) */
__attribute__((unused))
static int nc_read_line(char *buf, size_t cap)
{
	size_t n = 0;

	for (;;) {
		char c;
		ssize_t r = recv(NC.fd, &c, 1, 0);

		if (r < 0 && errno == EINTR)
			continue;
		if (r <= 0)
			return -1;
		if (c == '\n') {
			buf[n] = 0;
			return 0;
		}
		if (n + 1 < cap)
			buf[n++] = c;
	}
}

__attribute__((unused))
static int nc_read_n(char *buf, size_t len)
{
	size_t n = 0;

	while (n < len) {
		ssize_t r = recv(NC.fd, buf + n, len - n, 0);

		if (r < 0 && errno == EINTR)
			continue;
		if (r <= 0)
			return -1;
		n += (size_t)r;
	}
	return 0;
}

/* 入队一条消息 (满则丢弃最旧 — 测试编排的消息量远低于队列容量) */
__attribute__((unused))
static void nc_enqueue(const char *tag, const char *payload, size_t len)
{
	struct nc_msg *m;

	if (NC.npend >= NC_PEND) {
		memmove(&NC.pend[0], &NC.pend[1],
			sizeof(NC.pend[0]) * (NC_PEND - 1));
		NC.npend--;
	}
	m = &NC.pend[NC.npend++];
	snprintf(m->tag, sizeof(m->tag), "%s", tag);
	m->len = len < NC_PAYLOAD_MAX ? len : NC_PAYLOAD_MAX;
	memcpy(m->payload, payload, m->len);
}

__attribute__((unused))
static struct nc_msg *nc_dequeue(const char *tag)
{
	int i;

	for (i = 0; i < NC.npend; i++)
		if (!strcmp(NC.pend[i].tag, tag))
			return &NC.pend[i];
	return NULL;
}

/* 消息泵: 从连接读到一条消息并入队; 无消息返回 -1 (100ms 轮询分片) */
__attribute__((unused))
static int nc_pump_one(void)
{
	char line[96], tag[64];

	if (nc_read_line(line, sizeof(line)))
		return -1;
	if (!strncmp(line, "EVT ", 4)) {
		nc_enqueue(line + 4, "", 0);
		return 0;
	}
	if (!strncmp(line, "PARAM ", 6)) {
		size_t len;

		if (sscanf(line + 6, "%63s %zu", tag, &len) != 2 ||
		    len > NC_PAYLOAD_MAX)
			return -1;
		{
			char payload[NC_PAYLOAD_MAX];

			if (nc_read_n(payload, len))
				return -1;
			nc_enqueue(tag, payload, len);
		}
		return 0;
	}
	return -1;   /* 未知消息 */
}

/* server 侧: listen + accept (阻塞至连接或超时; 成功即关 listener) */
__attribute__((unused))
static int nc_server(int port)
{
	struct sockaddr_in a;
	int lfd, fd = -1, one = 1, i;

	if (NC.inited)
		return nc_active() ? 0 : -1;
	lfd = socket(AF_INET, SOCK_STREAM, 0);
	if (lfd < 0)
		return -1;
	setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	memset(&a, 0, sizeof(a));
	a.sin_family = AF_INET;
	a.sin_addr.s_addr = htonl(INADDR_ANY);
	a.sin_port = htons((uint16_t)port);
	if (bind(lfd, (struct sockaddr *)&a, sizeof(a)) || listen(lfd, 1)) {
		close(lfd);
		return -1;
	}
	for (i = 0; i < NC_ACCEPT_SEC * 10 && fd < 0; i++) {
		struct pollfd pfd = { .fd = lfd, .events = POLLIN };

		if (poll(&pfd, 1, 100) > 0)
			fd = accept(lfd, NULL, NULL);
	}
	close(lfd);
	if (fd < 0)
		return -1;
	{
		struct timeval tv = { .tv_sec = 0, .tv_usec = 100 * 1000 };

		setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	}
	NC.fd = fd;
	NC.inited = 1;
	return 0;
}

/* client 侧: 连接 (重试 ≤ NC_CONNECT_SEC) */
__attribute__((unused))
static int nc_client(const char *hostport)
{
	char host[128], portstr[16];
	const char *colon = strrchr(hostport, ':');
	struct addrinfo hints, *res = NULL;
	int i;

	if (NC.inited)
		return nc_active() ? 0 : -1;
	if (!colon || colon == hostport ||
	    (size_t)(colon - hostport) >= sizeof(host))
		return -1;
	memcpy(host, hostport, (size_t)(colon - hostport));
	host[colon - hostport] = 0;
	snprintf(portstr, sizeof(portstr), "%s", colon + 1);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	if (getaddrinfo(host, portstr, &hints, &res) || !res)
		return -1;
	for (i = 0; i < NC_CONNECT_SEC * 5; i++) {
		int fd = socket(res->ai_family, SOCK_STREAM, 0);

		if (fd >= 0) {
			struct timeval tv = { .tv_sec = 0, .tv_usec = 100 * 1000 };

			if (connect(fd, res->ai_addr, res->ai_addrlen) == 0) {
				setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO,
					   &tv, sizeof(tv));
				NC.fd = fd;
				NC.inited = 1;
				break;
			}
			close(fd);
		}
		usleep(200 * 1000);
	}
	freeaddrinfo(res);
	return nc_active() ? 0 : -1;
}

/* env 解析 + 角色初始化 (main 里一次): 返回 0 成功 / -1 失败; 未设置 env
 * 返回 0 且 nc_active()==0 (文件形态) */
__attribute__((unused))
static int nc_init(int is_server)
{
	const char *e = getenv("SYMRDMA_TEST_TCP");

	if (!e || !e[0])
		return 0;
	if (is_server) {
		if (strncmp(e, "listen:", 7))
			return -1;
		return nc_server(atoi(e + 7));
	}
	return nc_client(e);
}

__attribute__((unused))
static void nc_evt_set(const char *tag)
{
	char line[96];

	if (!nc_active())
		return;
	snprintf(line, sizeof(line), "EVT %s\n", tag);
	pthread_mutex_lock(&NC.mu);
	if (nc_send_all(line, strlen(line)))
		fprintf(stderr, "[netcoord] EVT %s 发送失败\n", tag);
	pthread_mutex_unlock(&NC.mu);
}

__attribute__((unused))
static void nc_evt_clear(const char *tag)
{
	(void)tag;   /* 消息一次性语义, 清除为无操作 */
}

/* 等事件 (sec 秒; 期间参数消息入队暂存) */
__attribute__((unused))
static int nc_evt_wait(const char *tag, int sec)
{
	int i;

	if (!nc_active())
		return -1;
	for (i = 0; i < sec * 10; i++) {
		struct nc_msg *m;

		while ((m = nc_dequeue(tag)) != NULL) {
			/* 从队列摘除 */
			int idx = (int)(m - NC.pend);
			int j;

			for (j = idx; j < NC.npend - 1; j++)
				NC.pend[j] = NC.pend[j + 1];
			NC.npend--;
			return 0;
		}
		(void)nc_pump_one();   /* 无消息/未知消息: 100ms 轮询分片 */
	}
	return -1;
}

__attribute__((unused))
static int nc_put(const char *tag, const void *buf, size_t len)
{
	char hdr[96];

	if (!nc_active())
		return -1;
	snprintf(hdr, sizeof(hdr), "PARAM %s %zu\n", tag, len);
	pthread_mutex_lock(&NC.mu);
	if (nc_send_all(hdr, strlen(hdr)) || nc_send_all(buf, len)) {
		pthread_mutex_unlock(&NC.mu);
		return -1;
	}
	pthread_mutex_unlock(&NC.mu);
	return 0;
}

/* 收参数块 (sec 秒; 期间事件消息入队暂存); 返回实际长度 / -1 */
__attribute__((unused))
static int nc_get(const char *tag, void *buf, size_t cap, int sec)
{
	int i;

	if (!nc_active())
		return -1;
	for (i = 0; i < sec * 10; i++) {
		struct nc_msg *m = nc_dequeue(tag);

		if (m) {
			int idx = (int)(m - NC.pend);
			int j;
			size_t len = m->len < cap ? m->len : cap;

			memcpy(buf, m->payload, len);
			for (j = idx; j < NC.npend - 1; j++)
				NC.pend[j] = NC.pend[j + 1];
			NC.npend--;
			return (int)len;
		}
		(void)nc_pump_one();   /* 无消息/未知消息: 100ms 轮询分片 */
	}
	return -1;
}

#endif /* NETCOORD_H */
