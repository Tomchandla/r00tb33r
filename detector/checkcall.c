#include <fcntl.h>
#include <kvm.h>
#include <limits.h>
#include <nlist.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/sysent.h>
#include <sys/syscall.h>
#include <sys/queue.h>
#include <sys/linker.h>

struct vm {
    char filename[256];
    uintptr_t start;
    uintptr_t end;
};

struct linker_file_list {
    struct linker_file *tqh_first;
    struct linker_file **tqh_last;
};

struct my_linker_file {
    struct kobj_ops *ops;
    int			refs;		/* reference count */
    int			userrefs;	/* kldload(2) count */
    int			flags;
    TAILQ_ENTRY(linker_file) link;	/* list of all loaded files */
    char*		filename;	/* file which was loaded */
    char*		pathname;	/* file name with full path */
    int			id;		/* unique id */
    caddr_t		address;	/* load address */
    size_t		size;		/* size of file */
    caddr_t		ctors_addr;	/* address of .ctors/.init_array */
    size_t		ctors_size;	/* size of .ctors/.init_array */
};

int main(int argc, char *argv[])
{
    char errbuf[_POSIX2_LINE_MAX];
    kvm_t *kd;
    
    /* initialise nl list with sysent and linker files */
    struct nlist nl[] = {
        { .n_name = "sysent" },
        { .n_name = "linker_files" }
    };

    kd = kvm_openfiles(NULL, NULL, NULL, O_RDONLY, errbuf);

    if (!kd) {
        fprintf(stderr, "ERROR: %s\n", errbuf);
        exit(-1);
    }

    /* Find the address of sysent and linker_files*/
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

    /* Iterate through linker files and store mapped virtual memory */
    struct vm vms[64] = {};
    int index = 0;

    struct linker_file_list head;

    if (kvm_read(kd, nl[1].n_value, &head, sizeof(head)) != sizeof(head)) {
        fprintf(stderr, "ERROR: failed to read linker_files at %p\n", (void *) nl[1].n_value);
        exit(-1);
    }

    uintptr_t curr = (uintptr_t) head.tqh_first;

    while (curr != 0) {
        struct my_linker_file lf;
        if (kvm_read(kd, curr, &lf, sizeof(lf)) != sizeof(lf)) {
            fprintf(stderr, "ERROR: failed to read individual linker file at %p\n", (void *) curr);
            exit(-1);
        }

        /* Get name, address and size */
        if (kvm_read(kd, (unsigned long) lf.filename, &(vms[index].filename), sizeof(vms[index].filename) - 1) == -1) {
            fprintf(stderr, "ERROR: failed to read filename at %p\n", (void *)lf.filename);
        }
        vms[index].start = (uintptr_t) lf.address;
        vms[index].end = vms[index].start + lf.size;

        int offset;
        printf("[%d] %n%s\n", index + 1, &offset, vms[index].filename);
        printf("%*s%p\n", offset, "", (void *) vms[index].start);
        printf("%*s%p\n", offset, "", (void *) vms[index].end);

        curr = (uintptr_t) lf.link.tqe_next;
        index++;
    }

    printf("\nFound %d loaded kernel modules\n\n", index);

    /* Search for syscall entry that has a function pointer not mapped by known
    KLDs */
    for (int i = 0; i < SYS_MAXSYSCALL; i++) {
        struct sysent se;
        unsigned long addr = nl[0].n_value + (sizeof(struct sysent) * i);

        if (kvm_read(kd, addr, &se, sizeof(se)) < 0)  {
            fprintf(stderr, "ERROR: failed to read sysent for %d\n", i);
            continue;
        }

        uintptr_t call = (uintptr_t) se.sy_call;
        int mapped = 0;
        for (int j = 0; j < index; j++) {
            if (vms[j].start <= call && call < vms[j].end) {
                mapped = 1;
                break;
            }
        }

        if (!mapped) {
            printf("[+] Syscall handler %d not mapped by any known kernel modules\n", i);
        }
    }

    if (kvm_close(kd) < 0) {
        fprintf(stderr, "ERROR: %s\n", kvm_geterr(kd));
        exit(-1);
    }

    exit(0);
}
