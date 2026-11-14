#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/module.h>

int main(int argc, char* argv[]) {
    int syscall_num, modid, result;
    struct module_stat stat;
    if (argc != 2) {
        printf("Usage: %s <port>\n", argv[0]);
        exit(0);
    }

    uint16_t port = strtol(argv[1], NULL, 10);

    /* Determine port-hiding offset value */
    stat.version = sizeof(stat);
    modid = modfind("sys/port_hiding");
    if (modid == -1) {
        perror("modfind");
        exit(1);
    }

    result = modstat(modid, &stat);
    if (result != 0) {
        perror("modstat");
        exit(1);
    }
    syscall_num = stat.data.intval;

    return(syscall(syscall_num, port));
}
