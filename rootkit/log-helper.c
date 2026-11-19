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
#define DEFAULT_PORT 1337
#define READ_BUF_SIZE 512
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
send_framed_line(int *sock_fd, const char *ip, uint16_t port,
    const char *line, int has_newline)
{
	char framed[LINE_BUF_SIZE + 32];
	int m = snprintf(framed, sizeof(framed), "[sys_monitor] %s%s",
	    line, has_newline ? "" : "\n");
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
	if (argc != 2 && argc != 3) {
		fprintf(stderr, "Usage: %s <collector_ip> [port]\n", argv[0]);
		return (1);
	}

	const char *collector_ip = argv[1];
	uint16_t port = DEFAULT_PORT;

	if (argc == 3) {
		char *endp = NULL;
		errno = 0;
		long port_val = strtol(argv[2], &endp, 10);
		if (errno != 0 || endp == argv[2] || *endp != '\0' ||
		    port_val <= 0 || port_val > 65535) {
			fprintf(stderr, "Invalid port: %s\n", argv[2]);
			return (1);
		}
		port = (uint16_t)port_val;
	}

	/* Ignore SIGPIPE so a dropped peer returns EPIPE instead of killing the process */
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
	char line_buf[LINE_BUF_SIZE];
	size_t line_len = 0;

	while (running) {
		ssize_t n = read(dev_fd, raw_buf, sizeof(raw_buf));
		if (n < 0) {
			if (errno == EINTR)
				continue;
			perror("read(" DEV_PATH ")");
			break;
		}

		if (n == 0) {
			usleep(100000);
			continue;
		}

		for (ssize_t i = 0; i < n && running; i++) {
			char ch = raw_buf[i];
			if (line_len < sizeof(line_buf) - 1)
				line_buf[line_len++] = ch;

			if (ch == '\n' || line_len == sizeof(line_buf) - 1) {
				line_buf[line_len] = '\0';
				if (send_framed_line(&sock_fd, collector_ip, port,
				    line_buf, ch == '\n') < 0) {
					running = 0;
					break;
				}
				line_len = 0;
			}
		}
	}

	if (line_len > 0 && sock_fd >= 0) {
		line_buf[line_len] = '\0';
		(void)send_framed_line(&sock_fd, collector_ip, port, line_buf, 0);
	}

	if (sock_fd >= 0)
		close(sock_fd);
	close(dev_fd);
	return (0);
}