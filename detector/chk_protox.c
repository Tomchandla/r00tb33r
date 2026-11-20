/*
 * chk_protox.c - validate the IP protocol input demux table ip_protox[].
 *
 * Any entry pointing outside the base kernel is a HARD finding.
 * IPPROTO_ICMP is skipped here: chk_icmp_hook.c checks it with a stricter
 * exact match against icmp_input.
 */
#include <sys/param.h>
#include <netinet/in.h>

#include <kvm.h>

#include "kutil.h"

int check_ip_protox(kvm_t *kd, const struct modmap *m)
{
	uintptr_t addr;
	void *ptrs[IPPROTO_MAX];
	ssize_t want = (ssize_t)sizeof(ptrs);
	int i, owner, findings = 0;

	if (resolve(kd, "ip_protox", &addr) != 0) {
		report_err("warn: cannot resolve 'ip_protox'");
		return (0);
	}
	if (kvm_read(kd, addr, ptrs, want) != want) {
		report_err("warn: cannot read ip_protox[]");
		return (0);
	}

	for (i = 0; i < IPPROTO_MAX; i++) {
		uintptr_t p = (uintptr_t)ptrs[i];

		if (i == IPPROTO_ICMP)
			continue;       /* owned by chk_icmp_hook.c */
		owner = classify(m, p);
		if (owner == OWNER_NULL || owner_is_kernel(m, owner))
			continue;
		if (owner == OWNER_HIDDEN)
			report_hook("ip_protox[%d]=%#lx -> HIDDEN memory: "
			    "DKOM-hidden network hook (rootkit)",
			    i, (unsigned long)p);
		else
			report_hook("ip_protox[%d]=%#lx -> module '%s': "
			    "IP input hook (rootkit)",
			    i, (unsigned long)p, m->mods[owner].name);
		findings++;
	}
	return (findings);
}
