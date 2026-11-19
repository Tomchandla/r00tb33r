#include <sys/param.h>
#include <netinet/in.h>
#include <kvm.h>
#include "kutil.h"

int check_icmp_hook(kvm_t *kd, const struct modmap *m)
{
	uintptr_t protox, icmp_input, p;
	void *ptr;
	const char *where;
	int owner;

	if (resolve(kd, "ip_protox", &protox) != 0) {
		report_err("warn: cannot resolve 'ip_protox'");
		return (0);
	}
	if (resolve(kd, "icmp_input", &icmp_input) != 0) {
		report_err("warn: cannot resolve 'icmp_input'");
		return (0);
	}
	if (kvm_read(kd, protox + IPPROTO_ICMP * sizeof(ptr), &ptr,
	    sizeof(ptr)) != sizeof(ptr)) {
		report_err("warn: cannot read ip_protox[IPPROTO_ICMP]");
		return (0);
	}

	p = (uintptr_t)ptr;
	if (p == icmp_input)
		return (0);

	owner = classify(m, p);
	if (owner == OWNER_HIDDEN)
		where = "HIDDEN memory (no visible module owns it)";
	else if (owner == OWNER_NULL)
		where = "NULL";
	else
		where = m->mods[owner].name;
	report_hook("ip_protox[IPPROTO_ICMP]=%#lx != icmp_input (%#lx), "
	    "points into %s: ICMP handler redirected (rootkit)",
	    (unsigned long)p, (unsigned long)icmp_input, where);
	return (1);
}
