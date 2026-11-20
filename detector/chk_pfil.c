#include <sys/param.h>
#include <kvm.h>
#include <stdio.h>
#include <string.h>
#include "kutil.h"

#define PF_MAXHOOKS   100000 		//arbitrary number 

// amd offsets
#define VNET_MAGIC_OFF   16
#define VNET_BASE_OFF    40
#define VNET_MAGIC_N     0x5e4a6f28U

struct kpfil_hook {
	uintptr_t hook_mbuf_chk;
	uintptr_t hook_mem_chk;
	uintptr_t hook_ruleset;
	int       hook_flags;
	int       hook_links;
	int       hook_type;
	uintptr_t hook_modname;
	uintptr_t hook_rulname;
	struct { uintptr_t le_next, le_prev; } hook_list;
};

/*
 * Stock FreeBSD modules that register pfil(9) hooks. Matched on
 * the kld file names that the hook author can't control.
 */
static const char *const pfil_known[] = {
	"pf.ko", "ipfw.ko", "ipl.ko", "siftr.ko", NULL
};

static int pfil_module_known(const char *kld)
{
	int i;
	for (i = 0; pfil_known[i] != NULL; i++)
		if (strcmp(kld, pfil_known[i]) == 0)
			return (1);
	return (0);
}

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

/* Resolve the address of the LIST_HEAD(, pfil_hook) for the default stack. */
static int pfil_list_head(kvm_t *kd, uintptr_t *out)
{
	uintptr_t vnet0_ptr, vnet, base, sym;
	unsigned magic;

	if (resolve(kd, "vnet0", &vnet0_ptr) == 0) {
		if (kvm_read(kd, vnet0_ptr, &vnet, sizeof(vnet)) !=
		    (ssize_t)sizeof(vnet) || vnet == 0)
			return (-1);
		if (kvm_read(kd, vnet + VNET_MAGIC_OFF, &magic,
		    sizeof(magic)) != (ssize_t)sizeof(magic) ||
		    magic != VNET_MAGIC_N)
			return (-1);
		if (kvm_read(kd, vnet + VNET_BASE_OFF, &base, sizeof(base)) !=
		    (ssize_t)sizeof(base))
			return (-1);
		if (resolve(kd, "vnet_entry_pfil_hook_list", &sym) != 0)
			return (-1);
		*out = base + sym;
		return (0);
	}
	if (resolve(kd, "pfil_hook_list", out) == 0)
		return (0);
	return (-1);
}

int check_pfil(kvm_t *kd, const struct modmap *m)
{
	struct kpfil_hook hk;
	uintptr_t head, cur;
	long visited = 0;
	int findings = 0;

	if (pfil_list_head(kd, &head) != 0) {
		report_err("warn: cannot locate pfil hook list; pfil check "
		    "skipped");
		return (0);
	}
	if (kvm_read(kd, head, &cur, sizeof(cur)) != (ssize_t)sizeof(cur)) {
		report_err("warn: cannot read pfil hook list; pfil check "
		    "skipped");
		return (0);
	}

	for (; cur != 0; cur = hk.hook_list.le_next) {
		uintptr_t hidden = 0, inmod = 0;
		const char *hidden_fn = NULL, *inmod_fn = NULL;
		int inmod_owner = -1, i;
		char mod[64];
		struct { const char *nm; uintptr_t p; } H[2];

		if (++visited > PF_MAXHOOKS) {
			report_err("warn: pfil hook list too long (>%d); "
			    "pfil check skipped", PF_MAXHOOKS);
			return (0);
		}
		if (kvm_read(kd, cur, &hk, sizeof(hk)) != (ssize_t)sizeof(hk)) {
			report_err("warn: pfil hook read failed; pfil check "
			    "truncated");
			break;
		}

		H[0].nm = "hook_mbuf_chk"; H[0].p = hk.hook_mbuf_chk;
		H[1].nm = "hook_mem_chk";  H[1].p = hk.hook_mem_chk;

		for (i = 0; i < 2; i++) {
			int owner = classify(m, H[i].p);

			if (owner == OWNER_HIDDEN) {
				if (hidden == 0) {
					hidden = H[i].p;
					hidden_fn = H[i].nm;
				}
			} else if (owner >= 0 && !owner_is_kernel(m, owner)) {
				if (inmod == 0) {
					inmod = H[i].p;
					inmod_fn = H[i].nm;
					inmod_owner = owner;
				}
			}
		}

		read_name(kd, hk.hook_modname, mod, sizeof(mod));
		if (hidden != 0) {
			report_hook("pfil hook '%s' %s=%#lx -> HIDDEN memory "
			    "(no visible module owns it): packet-filter "
			    "backdoor (rootkit)", mod, hidden_fn,
			    (unsigned long)hidden);
			findings++;
		} else if (inmod != 0 &&
		    !pfil_module_known(m->mods[inmod_owner].name)) {
			report_hook("pfil hook '%s' %s=%#lx -> module '%s', "
			    "which is not a stock packet filter: packet-"
			    "inspection backdoor (rootkit)", mod, inmod_fn,
			    (unsigned long)inmod, m->mods[inmod_owner].name);
			findings++;
		}
	}
	return (findings);
}
