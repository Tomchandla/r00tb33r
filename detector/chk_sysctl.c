#include <sys/param.h>
#include <stdint.h>
#include <kvm.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "kutil.h"

#define SC_MAXNODES  200000

#define RBE_LEFT     1
#define RBE_RIGHT    2

struct ksysctl_oid {
	struct { uintptr_t rbh_root; } oid_children;
	uintptr_t oid_parent;
	struct { uintptr_t rbe_link[3]; } oid_link;
	int       oid_number;
	u_int     oid_kind;
	uintptr_t oid_arg1;
	intmax_t  oid_arg2;
	uintptr_t oid_name;
	uintptr_t oid_handler;
};

static void read_name(kvm_t *kd, uintptr_t p, char *buf, size_t len)
{
	if (len == 0)
		return;
	buf[0] = '\0';
	if (p == 0)
		return;
	if (kvm_read(kd, p, buf, len - 1) < 0) {
		strlcpy(buf, "?", len);
		return;
	}
	buf[len - 1] = '\0';
}

int check_sysctl(kvm_t *kd, const struct modmap *m)
{
	struct ksysctl_oid oid;
	uintptr_t root_head, first, *stack;
	char name[64];
	long visited = 0;
	int sp = 0, findings = 0;

	if (resolve(kd, "sysctl__children", &root_head) != 0) {
		report_err("warn: cannot resolve 'sysctl__children'");
		return (0);
	}
	if ((stack = malloc((size_t)SC_MAXNODES * sizeof(*stack))) == NULL)
		return (0);
	if (kvm_read(kd, root_head, &first, sizeof(first)) !=
	    (ssize_t)sizeof(first)) {
		report_err("warn: cannot read sysctl root; sysctl check skipped");
		free(stack);
		return (0);
	}
	if (first != 0)
		stack[sp++] = first;

	while (sp > 0) {
		uintptr_t cur = stack[--sp];
		uintptr_t h, child, l, r;
		int owner;

		if (cur == 0)
			continue;
		if (++visited > SC_MAXNODES) {
			report_err("warn: sysctl tree exceeded %d nodes; "
			    "skipped", SC_MAXNODES);
			free(stack);
			return (0);
		}
		if (kvm_read(kd, cur, &oid, sizeof(oid)) != (ssize_t)sizeof(oid)) {
			report_err("warn: sysctl node read failed; sysctl "
			    "check skipped");
			free(stack);
			return (0);
		}

		// validate handler pointer
		h = (uintptr_t)oid.oid_handler;
		if (h != 0) {
			owner = classify(m, h);
			if (owner == OWNER_HIDDEN) {
				read_name(kd, (uintptr_t)oid.oid_name, name,
				    sizeof(name));
				report_hook("sysctl '%s' (#%d) oid_handler=%#lx "
				    "-> HIDDEN memory (no visible module owns "
				    "it): sysctl handler hijack (rootkit)",
				    name, oid.oid_number, (unsigned long)h);
				findings++;
			}
		}

		// traverse tree
		child = (uintptr_t)oid.oid_children.rbh_root;
		l = (uintptr_t)oid.oid_link.rbe_link[RBE_LEFT];
		r = (uintptr_t)oid.oid_link.rbe_link[RBE_RIGHT];
		if (sp + 3 > SC_MAXNODES) {
			report_err("warn: sysctl stack overflow; sysctl check "
			    "skipped");
			free(stack);
			return (0);
		}
		if (child != 0)
			stack[sp++] = child;
		if (l != 0)
			stack[sp++] = l;
		if (r != 0)
			stack[sp++] = r;
	}
	free(stack);
	return (findings);
}
