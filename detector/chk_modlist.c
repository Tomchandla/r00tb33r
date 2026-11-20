#include <sys/param.h>
#include <sys/queue.h>
#include <kvm.h>
#include <stdio.h>
#include <string.h>
#include "kutil.h"

#define MODLIST_TRIES 3

struct klinker_file {
	void       *ops;
	int         refs;
	int         userrefs;
	int         flags;
	struct {
		struct klinker_file  *tqe_next;
		struct klinker_file **tqe_prev;
	} link;
	char       *filename;
	char       *pathname;
	int         id;
	caddr_t     address;
	size_t      size;
};

struct klinker_head {
	struct klinker_file  *tqh_first;
	struct klinker_file **tqh_last;
};

struct kent {
	int       id;
	uintptr_t start;
	uintptr_t end;
	char      name[64];
};

// Walk linker_files in kernel memory. Returns entry count, or -1 on error.
static int walk_linker_files(kvm_t *kd, uintptr_t head_addr, struct kent *out, int max)
{
	struct klinker_head head;
	struct klinker_file lf;
	uintptr_t cur;
	int n = 0;

	if (kvm_read(kd, head_addr, &head, sizeof(head)) != sizeof(head))
		return (-1);
	for (cur = (uintptr_t)head.tqh_first; cur != 0;
	    cur = (uintptr_t)lf.link.tqe_next) {
		if (n >= max)
			return (-1);    // too long so skip
		if (kvm_read(kd, cur, &lf, sizeof(lf)) != sizeof(lf))
			return (-1);
		out[n].id    = lf.id;
		out[n].start = (uintptr_t)lf.address;
		out[n].end   = (uintptr_t)lf.address + lf.size;
		out[n].name[0] = '\0';
		if (lf.filename != NULL &&
		    kvm_read(kd, (uintptr_t)lf.filename, out[n].name,
		    sizeof(out[n].name) - 1) < 0)
			strlcpy(out[n].name, "?", sizeof(out[n].name));
		out[n].name[sizeof(out[n].name) - 1] = '\0';
		n++;
	}
	return (n);
}

static int in_kldstat(const struct modmap *m, const struct kent *e)
{
	for (int i = 0; i < m->n; i++)
		if (m->mods[i].start == e->start && m->mods[i].end == e->end)
			return (1);
	return (0);
}

static int in_kvm(const struct kent *k, int nk, const struct krange *r)
{
	for (int i = 0; i < nk; i++)
		if (k[i].start == r->start && k[i].end == r->end)
			return (1);
	return (0);
}

/* Compare once; returns mismatch count, prints only if `verbose`. */
static int compare(const struct kent *k, int nk, const struct modmap *m, int verbose)
{
	int bad = 0;
	for (int i = 0; i < nk; i++) {
		if (in_kldstat(m, &k[i]))
			continue;
		bad++;
		if (verbose)
			report_hook("linker_files has id %d '%s' [%#lx-%#lx) "
			    "that kldstat does not report: module list "
			    "tampering (rootkit)", k[i].id, k[i].name,
			    (unsigned long)k[i].start, (unsigned long)k[i].end);
	}
	for (int i = 0; i < m->n; i++) {
		if (in_kvm(k, nk, &m->mods[i]))
			continue;
		bad++;
		if (verbose)
			report_hook("kldstat reports '%s' [%#lx-%#lx) that is "
			    "not in linker_files: module list tampering "
			    "(rootkit)", m->mods[i].name,
			    (unsigned long)m->mods[i].start,
			    (unsigned long)m->mods[i].end);
	}
	return (bad);
}

int check_modlist(kvm_t *kd, const struct modmap *m)
{
	static struct kent kents[MAXMODS];
	static struct modmap fresh;
	const struct modmap *cur = m;
	uintptr_t head_addr;
	int try, nk, bad = 0;

	if (resolve(kd, "linker_files", &head_addr) != 0) {
		report_err("warn: cannot resolve 'linker_files'");
		return (0);
	}

	for (try = 0; try < MODLIST_TRIES; try++) {
		if (try > 0) {
			if (build_module_map(&fresh) != 0)
				return (0);
			cur = &fresh;
		}
		nk = walk_linker_files(kd, head_addr, kents, MAXMODS);
		if (nk < 0) {
			report_err("warn: linker_files walk failed; skipped");
			return (0);
		}
		bad = compare(kents, nk, cur, 0);
		if (bad == 0)
			return (0);
	}
	/* persisted across all re-reads: report the details */
	return (compare(kents, nk, cur, 1));
}
