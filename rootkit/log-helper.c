#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define DEV_PATH "/dev/sys_monitor"
#define COLLECTOR_PORT 4444
#define READ_BUF_SIZE 512
#define BATCH_SIZE 1
#define LINE_BUF_SIZE 1024
#define MAX_BACKOFF_SEC 10

static volatile sig_atomic_t running = 1;

static void
handle_sig(int signo)
{
	(void)signo;
	running = 0;
}

static int
connect_collector(const char *ip, uint16_t port)
{
	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		perror("socket");
		return (-1);
	}

	struct sockaddr_in dst;
	memset(&dst, 0, sizeof(dst));
	dst.sin_family = AF_INET;
	dst.sin_port = htons(port);

	if (inet_pton(AF_INET, ip, &dst.sin_addr) != 1) {
		fprintf(stderr, "Invalid IPv4 address: %s\n", ip);
		close(sock);
		return (-1);
	}

	if (connect(sock, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
		close(sock);
		return (-1);
	}

	return (sock);
}

static int
connect_with_retry(const char *ip, uint16_t port)
{
	unsigned int backoff = 1;

	while (running) {
		int sock = connect_collector(ip, port);
		if (sock >= 0) {
			fprintf(stderr, "[+] Connected to collector %s:%u\n", ip, port);
			return (sock);
		}

		if (errno != ECONNREFUSED && errno != ENETUNREACH &&
		    errno != EHOSTUNREACH && errno != ETIMEDOUT) {
			perror("connect");
		}

		for (unsigned int slept = 0; slept < backoff && running; slept++) {
			sleep(1);
		}

		if (backoff < MAX_BACKOFF_SEC) {
			backoff *= 2;
			if (backoff > MAX_BACKOFF_SEC)
				backoff = MAX_BACKOFF_SEC;
		}
	}

	return (-1);
}

static int
write_all(int fd, const char *buf, size_t len)
{
	size_t sent = 0;
	while (sent < len) {
		ssize_t n = write(fd, buf + sent, len - sent);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return (-1);
		}
		if (n == 0)
			return (-1);
		sent += (size_t)n;
	}
	return (0);
}

static int
send_framed_byte(int *sock_fd, const char *ip, uint16_t port, char ch)
{
	char framed[64];
	int m = snprintf(framed, sizeof(framed), "[sys_monitor] %c\n", ch);
	if (m <= 0)
		return (0);

	while (running) {
		if (*sock_fd < 0) {
			*sock_fd = connect_with_retry(ip, port);
			if (*sock_fd < 0)
				return (-1);
		}

		if (write_all(*sock_fd, framed, (size_t)m) == 0)
			return (0);

		fprintf(stderr, "[!] Collector connection lost, reconnecting...\n");
		close(*sock_fd);
		*sock_fd = -1;
	}

	return (-1);
}

int
main(int argc, char *argv[])
{
	if (argc != 2) {
		fprintf(stderr, "Usage: %s <ip>\n", argv[0]);
		return (1);
	}

	const char *collector_ip = argv[1];
	uint16_t port = COLLECTOR_PORT;

	signal(SIGPIPE, SIG_IGN);

	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = handle_sig;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	int dev_fd = open(DEV_PATH, O_RDONLY);
	if (dev_fd < 0) {
		perror("open " DEV_PATH);
		return (1);
	}

	int sock_fd = connect_with_retry(collector_ip, port);
	if (sock_fd < 0) {
		close(dev_fd);
		return (0);
	}

	char raw_buf[READ_BUF_SIZE];

	while (running) {
		ssize_t n = read(dev_fd, raw_buf, sizeof(raw_buf));
		if (n < 0) {
			if (errno == EINTR)
				continue;
			perror("read(" DEV_PATH ")");
			break;
		}

		if (n == 0) {
			usleep(50000);
			continue;
		}

		for (ssize_t i = 0; i < n && running; i++) {
			if (send_framed_byte(&sock_fd, collector_ip, port,
			    raw_buf[i]) < 0) {
				running = 0;
				break;
			}
		}
	}

	if (sock_fd >= 0) {
		close(sock_fd);
	}
	close(dev_fd);
	return (0);
}