#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TARGET_PORT 4444

static volatile sig_atomic_t running = 1;

static void
handle_sig(int signo)
{
	(void)signo;
	running = 0;
}

int
main(int argc, char *argv[])
{
	if (argc != 2) {
		fprintf(stderr, "Usage: %s <target-ip>\n", argv[0]);
		return (1);
	}

	const char *target_ip = argv[1];

	signal(SIGPIPE, SIG_IGN);
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = handle_sig;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		perror("socket");
		return (1);
	}

	struct sockaddr_in dst;
	memset(&dst, 0, sizeof(dst));
	dst.sin_family = AF_INET;
	dst.sin_port = htons(TARGET_PORT);

	if (inet_pton(AF_INET, target_ip, &dst.sin_addr) != 1) {
		fprintf(stderr, "Invalid IPv4 address: %s\n", target_ip);
		close(sock);
		return (1);
	}

	if (connect(sock, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
		perror("connect");
		close(sock);
		return (1);
	}

	fprintf(stderr, "[+] Connected to %s:%d\n", target_ip, TARGET_PORT);

	char buf[1024];
	while (running) {
		ssize_t n = read(sock, buf, sizeof(buf));
		if (n < 0) {
			if (errno == EINTR)
				continue;
			perror("read");
			break;
		}
		if (n == 0) {
			fprintf(stderr, "\n[!] Disconnected from target\n");
			break;
		}

		fwrite(buf, 1, (size_t)n, stdout);
		fflush(stdout);
	}

	close(sock);
	return (0);
}