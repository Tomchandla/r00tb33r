#include <sys/param.h>
#include <netinet/in.h>

#include <kvm.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include "kutil.h"

#define PH_TRIES      3
#define PH_MAXBUCKETS (1UL << 22)
#define PH_MAXPCBS    (1UL << 20)

struct k_le {
	uintptr_t next;
	uintptr_t prev;
};

struct k_inpcbinfo {
	char      ipi_lock[32];
	uintptr_t ipi_listhead;
	u_int     ipi_count;
	uint64_t  ipi_gencnt;
	u_short   ipi_lastport, ipi_lastlow, ipi_lasthi;
	uintptr_t ipi_zone, ipi_portzone, ipi_smr;
	char      ipi_hash_lock[32];
	uintptr_t ipi_hash_exact;
	uintptr_t ipi_hash_wild;
	u_long    ipi_hashmask;
};

struct k_inpcb {
	struct k_le inp_hash_exact;
	struct k_le inp_hash_wild;
	char        inp_lock[32];
	u_int       inp_refcount;
	int         inp_flags, inp_flags2;
	uint8_t     inp_numa_domain;
	uintptr_t   inp_ppcb, inp_socket;
	uintptr_t   inp_pcbinfo;
	uintptr_t   inp_cred;
	uint32_t    inp_flow;
	u_char      inp_vflag, inp_ip_ttl, inp_ip_p, inp_ip_minttl;
	uint32_t    inp_flowid;
	uint32_t    inp_smr;
	uintptr_t   inp_snd_tag;
	uint32_t    inp_flowtype;
	struct {
		uint8_t  inc_flags, inc_len;
		uint16_t inc_fibnum;
		uint16_t ie_fport;
		uint16_t ie_lport;
		char     rest[36];
	} inp_inc;
	uintptr_t   inp_label, inp_sp;
	union {
		char a[24];
		char b[32];
	} proto;
	struct k_le inp_portlist;
	uintptr_t   inp_phd;
	uint64_t    inp_gencnt;
	uintptr_t   spare_ptr;
	uint32_t    inp_rt_cookie;
	union {
		uintptr_t align;
		char      route[64];
	} cache;
	struct k_le inp_list;
};

struct k_vnet {
	struct k_le vnet_le;
	u_int       vnet_magic_n, vnet_ifcnt, vnet_sockcnt, vnet_state;
	uintptr_t   vnet_data_mem;
	uintptr_t   vnet_data_base;
};

struct pcb {
	uintptr_t addr;
	uint16_t  lport;
};

struct pcbset {
	struct pcb *v;
	size_t      n, cap;
};

static int set_add(struct pcbset *s, uintptr_t addr, uint16_t lport)
{
	if (s->n == s->cap) {
		size_t nc = s->cap ? s->cap * 2 : 256;
		struct pcb *nv = realloc(s->v, nc * sizeof(*nv));
		if (nv == NULL)
			return (-1);
		s->v = nv;
		s->cap = nc;
	}
	s->v[s->n].addr = addr;
	s->v[s->n].lport = lport;
	s->n++;
	return (0);
}

static int pcb_cmp(const void *a, const void *b)
{
	uintptr_t x = ((const struct pcb *)a)->addr;
	uintptr_t y = ((const struct pcb *)b)->addr;

	return (x < y ? -1 : x > y);
}

static int set_has(const struct pcbset *s, uintptr_t addr)
{
	struct pcb key = { addr, 0 };

	return (bsearch(&key, s->v, s->n, sizeof(key), pcb_cmp) != NULL);
}

static void set_finish(struct pcbset *s)
{
	size_t i, j = 0;

	if (s->n == 0)
		return;
	qsort(s->v, s->n, sizeof(*s->v), pcb_cmp);
	for (i = 0; i < s->n; i++)
		if (j == 0 || s->v[j - 1].addr != s->v[i].addr)
			s->v[j++] = s->v[i];
	s->n = j;
}

static int read_pcb(kvm_t *kd, uintptr_t pcb, uintptr_t info, struct k_inpcb *out)
{
	if (kvm_read(kd, pcb, out, sizeof(*out)) != (ssize_t)sizeof(*out))
		return (-1);
	if (out->inp_pcbinfo != info)
		return (-2);
	return (0);
}

static int walk_hash(kvm_t *kd, uintptr_t info, uintptr_t base, u_long mask,
    int is_wild, struct pcbset *out)
{
	struct k_inpcb pcb;
	size_t lo = is_wild ? offsetof(struct k_inpcb, inp_hash_wild)
	                    : offsetof(struct k_inpcb, inp_hash_exact);
	u_long nb = mask + 1, b;

	if (mask == 0 || nb > PH_MAXBUCKETS || (nb & mask) != 0)
		return (-2);
	for (b = 0; b < nb; b++) {
		uintptr_t cur;
		size_t guard = 0;

		if (kvm_read(kd, base + b * sizeof(uintptr_t), &cur,
		    sizeof(cur)) != (ssize_t)sizeof(cur))
			return (-1);
		while (cur != 0) {
			uintptr_t p = cur - lo;
			int rc;

			if (++guard > PH_MAXPCBS || out->n > PH_MAXPCBS)
				return (-2);
			if ((rc = read_pcb(kd, p, info, &pcb)) != 0)
				return (rc);
			if (set_add(out, p, ntohs(pcb.inp_inc.ie_lport)) != 0)
				return (-1);
			cur = is_wild ? pcb.inp_hash_wild.next
			              : pcb.inp_hash_exact.next;
		}
	}
	return (0);
}

static int walk_list(kvm_t *kd, uintptr_t info, uintptr_t head, struct pcbset *out)
{
	struct k_inpcb pcb;
	size_t lo = offsetof(struct k_inpcb, inp_list);
	uintptr_t cur = head;
	size_t guard = 0;

	while (cur != 0) {
		uintptr_t p = cur - lo;
		int rc;

		if (++guard > PH_MAXPCBS)
			return (-2);
		if ((rc = read_pcb(kd, p, info, &pcb)) != 0)
			return (rc);
		if (set_add(out, p, ntohs(pcb.inp_inc.ie_lport)) != 0)
			return (-1);
		cur = pcb.inp_list.next;
	}
	return (0);
}

static int find_tcbinfo(kvm_t *kd, uintptr_t *out)
{
	uintptr_t entry, vnet0p, vnet0;
	struct k_vnet vn;

	if (resolve(kd, "vnet_entry_tcbinfo", &entry) == 0 &&
	    resolve(kd, "vnet0", &vnet0p) == 0 &&
	    kvm_read(kd, vnet0p, &vnet0, sizeof(vnet0)) == (ssize_t)sizeof(vnet0) &&
	    vnet0 != 0 &&
	    kvm_read(kd, vnet0, &vn, sizeof(vn)) == (ssize_t)sizeof(vn) &&
	    vn.vnet_data_base != 0) {
		*out = vn.vnet_data_base + entry;
		return (0);
	}
	return (resolve(kd, "tcbinfo", out));
}

static int snapshot(kvm_t *kd, uintptr_t info_addr, struct pcbset *A, struct pcbset *B)
{
	struct k_inpcbinfo info;
	int rc;

	A->n = B->n = 0;
	if (kvm_read(kd, info_addr, &info, sizeof(info)) != (ssize_t)sizeof(info))
		return (-1);
	if ((rc = walk_hash(kd, info_addr, info.ipi_hash_exact, info.ipi_hashmask,
	    0, A)) != 0)
		return (rc);
	if ((rc = walk_hash(kd, info_addr, info.ipi_hash_wild, info.ipi_hashmask,
	    1, A)) != 0)
		return (rc);
	if ((rc = walk_list(kd, info_addr, info.ipi_listhead, B)) != 0)
		return (rc);
	set_finish(A);
	set_finish(B);
	return (0);
}

int check_port_hiding(kvm_t *kd, const struct modmap *m)
{
	struct pcbset A = { 0 }, B = { 0 };
	uintptr_t info_addr;
	int try, rc = 0, bad = 0;
	size_t i;

	(void)m;
	if (find_tcbinfo(kd, &info_addr) != 0) {
		report_err("warn: cannot resolve 'tcbinfo'");
		return (0);
	}

	for (try = 0; try < PH_TRIES; try++) {
		if (try > 0)
			usleep(20000);
		rc = snapshot(kd, info_addr, &A, &B);
		if (rc != 0) {
			report_err("warn: tcbinfo walk failed (%s); port_hiding "
			    "check skipped", rc == -2 ?
			    "layout mismatch / bad table" : "kvm read error");
			free(A.v);
			free(B.v);
			return (0);
		}
		bad = 0;
		for (i = 0; i < A.n; i++)
			if (!set_has(&B, A.v[i].addr))
				bad++;
		if (bad == 0) {
			free(A.v);
			free(B.v);
			return (0);
		}
	}

	for (i = 0; i < A.n; i++)
		if (!set_has(&B, A.v[i].addr))
			report_hook("tcp pcb %#lx (local port %u) is in the "
			    "connection hash table but not in tcbinfo "
			    "ipi_listhead: port hidden from netstat/sockstat "
			    "(rootkit)", (unsigned long)A.v[i].addr,
			    (unsigned)A.v[i].lport);
	free(A.v);
	free(B.v);
	return (bad);
}
