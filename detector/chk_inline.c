#include <sys/param.h>
#include <sys/sysent.h>
#include <sys/syscall.h>
#include <kvm.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "kutil.h"

#define PROLOGUE_LEN 24

static const char *const hot_funcs[] = {
	"kern_fcntl", "kern_kill", "kern_execve", "kern_getdirentries",
	"kern_openat", "kern_readv", "kern_writev",
	"ttydisc_read", "ttydisc_write", "tty_ioctl", "sys_getdirentries",
	"sys_kill", "sys_read", "sys_execve", "sys_exit", "sys_rmdir",
	"tcp_input", "ip_input", "icmp_input", "linker_file_foreach",
};

static int decode_jump(const unsigned char *b, uintptr_t fn, uintptr_t *target)
{
	int32_t rel;
	int32_t imm;
	uint64_t t;

	if (b[0] == 0xF3 && b[1] == 0x0F && b[2] == 0x1E && b[3] == 0xFA) {
		b += 4;
		fn += 4;
	}
	if (b[0] == 0x48 && b[1] == 0xB8 &&
	    ((b[10] == 0xFF && b[11] == 0xE0) ||
	     (b[10] == 0x50 && b[11] == 0xC3))) {
		memcpy(&t, b + 2, 8);
		*target = (uintptr_t)t;
		return (1);
	}
	if (b[0] == 0x49 && b[1] == 0xBB && b[10] == 0x41 && b[11] == 0xFF &&
	    b[12] == 0xE3) {
		memcpy(&t, b + 2, 8);
		*target = (uintptr_t)t;
		return (1);
	}
	if (b[0] == 0xFF && b[1] == 0x25 && b[2] == 0 && b[3] == 0 &&
	    b[4] == 0 && b[5] == 0) {
		memcpy(&t, b + 6, 8);
		*target = (uintptr_t)t;
		return (1);
	}
	if (b[0] == 0xE9) {
		memcpy(&rel, b + 1, 4);
		*target = fn + 5 + (intptr_t)rel;
		return (1);
	}
	if (b[0] == 0x68 && b[5] == 0xC3) {
		memcpy(&imm, b + 1, 4);
		*target = (uintptr_t)(intptr_t)imm;
		return (1);
	}
	return (0);
}

static int check_func(kvm_t *kd, const struct modmap *m, const char *what,
    uintptr_t fn)
{
	unsigned char b[PROLOGUE_LEN];
	uintptr_t target;
	int owner;

	if (kvm_read(kd, fn, b, sizeof(b)) != (ssize_t)sizeof(b))
		return (0);
	if (!decode_jump(b, fn, &target))
		return (0);
	owner = classify(m, target);
	if (owner == OWNER_NULL || owner_is_kernel(m, owner))
		return (0);
	if (owner == OWNER_HIDDEN)
		report_hook("%s at %#lx starts with a jump to %#lx in HIDDEN "
		    "memory: inline-hooked by a DKOM-hidden rootkit", what,
		    (unsigned long)fn, (unsigned long)target);
	else
		report_hook("%s at %#lx starts with a jump to %#lx in module "
		    "'%s': inline hook (rootkit)", what, (unsigned long)fn,
		    (unsigned long)target, m->mods[owner].name);
	return (1);
}

int check_inline(kvm_t *kd, const struct modmap *m)
{
	uintptr_t sysent_addr, addr;
	struct sysent *se;
	ssize_t want;
	size_t i;
	int n, owner, findings = 0;
	char what[64];

	if (resolve(kd, "sysent", &sysent_addr) == 0) {
		want = (ssize_t)SYS_MAXSYSCALL * (ssize_t)sizeof(struct sysent);
		if ((se = malloc(want)) != NULL) {
			if (kvm_read(kd, sysent_addr, se, want) == want) {
				for (n = 0; n < SYS_MAXSYSCALL; n++) {
					uintptr_t p = (uintptr_t)se[n].sy_call;

					owner = classify(m, p);
					if (!owner_is_kernel(m, owner))
						continue;
					snprintf(what, sizeof(what),
					    "sysent[%d] handler", n);
					findings += check_func(kd, m, what, p);
				}
			}
			free(se);
		}
	} else
		report_err("warn: cannot resolve 'sysent'");

	for (i = 0; i < nitems(hot_funcs); i++) {
		if (resolve(kd, hot_funcs[i], &addr) != 0)
			continue;
		snprintf(what, sizeof(what), "%s", hot_funcs[i]);
		findings += check_func(kd, m, what, addr);
	}
	return (findings);
}
