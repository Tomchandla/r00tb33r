
#include "netinet/in.h"
#include <fcntl.h>
#include <kvm.h>
#include <limits.h>
#include <nlist.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

typedef int	ipproto_input_t(struct mbuf **, int *, int);

int main(int argc, char *argv[])
{
    char errbuf[_POSIX2_LINE_MAX];
    kvm_t *kd;
    
    struct nlist nl[] = {
        { .n_name = "ip_protox" },
        { .n_name = "icmp_input" },
    };

    kd = kvm_openfiles(NULL, NULL, NULL, O_RDONLY, errbuf);

    if (!kd) {
        fprintf(stderr, "ERROR: %s\n", errbuf);
        exit(-1);
    }

    /* Find address of ip_protox and icmp_input */
    if (kvm_nlist(kd, nl) < 0) {
        fprintf(stderr, "ERROR: %s\n", kvm_geterr(kd));
        exit(-1);
    }
    if (!nl[0].n_value) {
        fprintf(stderr, "ERROR: %s not found\n", nl[0].n_name);
        exit(-1);
    } else if (!nl[1].n_value) {
        fprintf(stderr, "ERROR: %s not found\n", nl[1].n_name);
        exit(-1);
    }

    /* Get address of actual icmp_input */
    ipproto_input_t *icmp_input;
    unsigned long addr = nl[0].n_value + IPPROTO_ICMP * sizeof(icmp_input);
    if (kvm_read(kd, addr, &icmp_input, sizeof(icmp_input)) < 0) {
        fprintf(stderr, "ERROR: failed to read icmp_input at %p\n", (void *) addr);
        exit(-1);
    }
    
    /* Check if address of ip_protox[IPPROTO_ICMP] == icmp_input */
    if ((uintptr_t) icmp_input != nl[1].n_value) {
        printf("ICMP hook detected!\n");
    }

    if (kvm_close(kd) < 0) {
        fprintf(stderr, "ERROR: %s\n", kvm_geterr(kd));
        exit(-1);
    }

    exit(0);
}
