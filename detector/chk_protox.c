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
			continue; //already checked in different file
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
