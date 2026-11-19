/*
 * kcheck - kernel function-pointer integrity checker (libkvm, userland)
 *
 * Reads live kernel memory via /dev/kmem (libkvm) as root and verifies that
 * the function pointers in the kernel's dispatch tables still land inside the
 * base kernel, or inside a currently kldstat-VISIBLE module.
 *
 * Layout:
 *   kcheck.c      main(): build module map once, open kvm once, run checks
 *   kutil.[ch]    shared helpers (module map, classify, resolve, reporting)
 *   chk_*.c       one file per check; add to checks[] below + kutil.h
 *
 * Exit codes:
 *   0  no kernel-pointer anomaly found
 *   1  anomaly found (rootkit indicator)
 *   2  engine unavailable (cannot open kvm / enumerate modules) -> caller
 *      should fall back to userland checks rather than treat as clean.
 */
#include <sys/param.h>

#include <fcntl.h>
#include <kvm.h>
#include <limits.h>
#include <stdio.h>

#include "kutil.h"

static const struct {
	const char *name;
	int (*fn)(kvm_t *, const struct modmap *);
} checks[] = {
	{ "modlist",   check_modlist },
	{ "sysent",    check_sysent },
	{ "ip_protox", check_ip_protox },
	{ "icmp_hook", check_icmp_hook },
	{ "inline",    check_inline },
};

int main(void)
{
	static struct modmap map;
	char errbuf[_POSIX2_LINE_MAX];
	kvm_t *kd;
	size_t i;
	int n, findings = 0;

	if (build_module_map(&map) != 0) {
		report_err("error: kldstat enumeration failed");
		return (2);
	}

	kd = kvm_open(NULL, NULL, NULL, O_RDONLY, errbuf);
	if (kd == NULL) {
		report_err("engine unavailable: %s", errbuf);
		return (2);
	}

	for (i = 0; i < nitems(checks); i++) {
		n = checks[i].fn(kd, &map);
		printf("[kcheck] %-10s %d finding(s)\n", checks[i].name, n);
		findings += n;
	}

	kvm_close(kd);

	if (findings > 0) {
		printf("[kcheck] RESULT: %d hard finding(s) -> rootkit\n",
		    findings);
		return (1);
	}
	printf("[kcheck] RESULT: no kernel-pointer anomaly\n");
	return (0);
}
