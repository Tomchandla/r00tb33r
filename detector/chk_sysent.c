/*
 * chk_sysent.c - validate every sysent[].sy_call pointer.
 *
 *   - pointer into memory owned by no visible module   -> HARD (hidden module)
 *   - well-known base syscall redirected into a module -> HARD
 *   - other slot pointing into a visible module        -> WARN (added syscall)
 */
#include <sys/param.h>
#include <sys/sysent.h>
#include <sys/syscall.h>

#include <kvm.h>
#include <stdlib.h>

#include "kutil.h"

/* Base syscalls a stock kernel implements in-kernel and no legitimate loadable
 * module replaces. */
static const int base_syscalls[] = {
#ifdef SYS_read
	SYS_read,
#endif
#ifdef SYS_write
	SYS_write,
#endif
#ifdef SYS_open
	SYS_open,
#endif
#ifdef SYS_openat
	SYS_openat,
#endif
#ifdef SYS_close
	SYS_close,
#endif
#ifdef SYS_execve
	SYS_execve,
#endif
#ifdef SYS_fexecve
	SYS_fexecve,
#endif
#ifdef SYS_fork
	SYS_fork,
#endif
#ifdef SYS_kill
	SYS_kill,
#endif
#ifdef SYS_exit
	SYS_exit,
#endif
#ifdef SYS_setuid
	SYS_setuid,
#endif
#ifdef SYS_setgid
	SYS_setgid,
#endif
#ifdef SYS_seteuid
	SYS_seteuid,
#endif
#ifdef SYS_setegid
	SYS_setegid,
#endif
#ifdef SYS_setreuid
	SYS_setreuid,
#endif
#ifdef SYS_setregid
	SYS_setregid,
#endif
#ifdef SYS_setresuid
	SYS_setresuid,
#endif
#ifdef SYS_setresgid
	SYS_setresgid,
#endif
#ifdef SYS_getdirentries
	SYS_getdirentries,
#endif
#ifdef SYS_getdents
	SYS_getdents,
#endif
#ifdef SYS_mkdir
	SYS_mkdir,
#endif
#ifdef SYS_rmdir
	SYS_rmdir,
#endif
#ifdef SYS_chmod
	SYS_chmod,
#endif
#ifdef SYS_unlink
	SYS_unlink,
#endif
#ifdef SYS_setsockopt
	SYS_setsockopt,
#endif
#ifdef SYS___sysctl
	SYS___sysctl,
#endif
#ifdef SYS_ptrace
	SYS_ptrace,
#endif
#ifdef SYS_reboot
	SYS_reboot,
#endif
};

static int is_base_syscall(int n)
{
	size_t i;

	for (i = 0; i < nitems(base_syscalls); i++)
		if (base_syscalls[i] == n)
			return (1);
	return (0);
}

int check_sysent(kvm_t *kd, const struct modmap *m)
{
	uintptr_t sysent_addr;
	struct sysent *se;
	ssize_t want;
	int i, owner, findings = 0;

	if (resolve(kd, "sysent", &sysent_addr) != 0) {
		report_err("warn: cannot resolve 'sysent'");
		return (0);
	}
	want = (ssize_t)SYS_MAXSYSCALL * (ssize_t)sizeof(struct sysent);
	if ((se = malloc(want)) == NULL)
		return (0);
	if (kvm_read(kd, sysent_addr, se, want) != want) {
		report_err("warn: cannot read sysent[]");
		free(se);
		return (0);
	}

	for (i = 0; i < SYS_MAXSYSCALL; i++) {
		uintptr_t p = (uintptr_t)se[i].sy_call;

		owner = classify(m, p);
		if (owner == OWNER_NULL || owner_is_kernel(m, owner))
			continue;

		if (owner == OWNER_HIDDEN) {
			report_hook("sysent[%d].sy_call=%#lx -> HIDDEN memory "
			    "(no visible module owns it): DKOM-hidden rootkit",
			    i, (unsigned long)p);
			findings++;
		} else if (is_base_syscall(i)) {
			report_hook("sysent[%d].sy_call=%#lx -> module '%s': "
			    "base syscall replaced (rootkit)",
			    i, (unsigned long)p, m->mods[owner].name);
			findings++;
		} else {
			report_warn("sysent[%d].sy_call=%#lx -> module '%s' "
			    "(custom/added syscall; review)",
			    i, (unsigned long)p, m->mods[owner].name);
		}
	}
	free(se);
	return (findings);
}
