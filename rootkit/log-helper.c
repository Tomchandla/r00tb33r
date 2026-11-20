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
#define LISTEN_PORT 4444
#define READ_BUF_SIZE 512
#define BATCH_SIZE 4
#define LINE_BUF_SIZE 1024

static volatile sig_atomic_t running = 1;

static void
handle_sig(int signo)
{
	(void)signo;
	running = 0;
}

static int
setup_listener(uint16_t port)
{
	int srv_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (srv_fd < 0) {
		perror("socket");
		return (-1);
	}

	int opt = 1;
	if (setsockopt(srv_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
		perror("setsockopt");
		close(srv_fd);
		return (-1);
	}

	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(port);

	if (bind(srv_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("bind");
		close(srv_fd);
		return (-1);
	}

	if (listen(srv_fd, 8) < 0) {
		perror("listen");
		close(srv_fd);
		return (-1);
	}

	return (srv_fd);
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
send_framed_line(int client_fd, const char *line, int has_newline)
{
	char framed[LINE_BUF_SIZE + 32];
	int m = snprintf(framed, sizeof(framed), "[sys_monitor] %s%s",
	    line, has_newline ? "" : "\n");
	if (m <= 0)
		return (0);
	return (write_all(client_fd, framed, (size_t)m));
}

static int
flush_batch(int client_fd, char *batch_buf, size_t *batch_len)
{
	if (*batch_len == 0)
		return (0);

	batch_buf[*batch_len] = '\0';
	int rc = send_framed_line(client_fd, batch_buf, 0);
	*batch_len = 0;
	return (rc);
}

int
main(void)
{
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

	int srv_fd = setup_listener(LISTEN_PORT);
	if (srv_fd < 0) {
		close(dev_fd);
		return (1);
	}

	fprintf(stderr, "[+] Listening on 0.0.0.0:%u\n", LISTEN_PORT);

	char raw_buf[READ_BUF_SIZE];
	char batch_buf[BATCH_SIZE + 1];
	size_t batch_len = 0;

	while (running) {
		struct sockaddr_in peer;
		socklen_t peer_len = sizeof(peer);
		int client_fd = accept(srv_fd, (struct sockaddr *)&peer, &peer_len);
		if (client_fd < 0) {
			if (errno == EINTR)
				continue;
			perror("accept");
			break;
		}

		char ip_str[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &peer.sin_addr, ip_str, sizeof(ip_str));
		fprintf(stderr, "[+] Client connected from %s:%u\n",
		    ip_str, ntohs(peer.sin_port));

		batch_len = 0;

		while (running) {
			ssize_t n = read(dev_fd, raw_buf, sizeof(raw_buf));
			if (n < 0) {
				if (errno == EINTR)
					continue;
				perror("read(" DEV_PATH ")");
				running = 0;
				break;
			}

			if (n == 0) {
				if (flush_batch(client_fd, batch_buf, &batch_len) < 0) {
					fprintf(stderr, "[!] Client disconnected\n");
					client_fd = -1;
					break;
				}
				usleep(100000);
				continue;
			}

			int client_ok = 1;
			for (ssize_t i = 0; i < n && running; i++) {
				batch_buf[batch_len++] = raw_buf[i];
				if (batch_len == BATCH_SIZE) {
					if (flush_batch(client_fd, batch_buf, &batch_len) < 0) {
						fprintf(stderr, "[!] Client disconnected\n");
						client_fd = -1;
						client_ok = 0;
						break;
					}
				}
			}

			if (!client_ok)
				break;
		}

		if (client_fd >= 0) {
			(void)flush_batch(client_fd, batch_buf, &batch_len);
			close(client_fd);
		}
	}

	close(srv_fd);
	close(dev_fd);
	return (0);
}