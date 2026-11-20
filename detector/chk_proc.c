/*
 * chk_proc.c - detect processes hidden by DKOM (allproc / pidhashtbl unlink).
 *
 * A process lives in several independent kernel structures:
 *   allproc    - list walked by ps/top/sysctl kern.proc  (p_list)
 *   pidhashtbl - pid lookup used by kill/ps -p            (p_hash)
 *   the process tree, rooted at proc0 via p_children      (p_sibling)
 *
 * Rootkits that hide a process unlink it from allproc and/or pidhashtbl.
 * They typically leave the parent's children list alone. So any process we
 * can reach through the tree or the pid hash but that is absent from allproc
 * is hidden. Findings must persist across several full snapshots so that
 * processes forking/exiting during the walk do not cause false positives.
 *
 * Uses the real struct proc from <sys/proc.h> (as libkvm does), so offsets
 * always match the running release.
 */
#include <sys/param.h>
#define _WANT_UCRED
#include <sys/ucred.h>
#include <sys/queue.h>
#include <sys/_lock.h>
#include <sys/_mutex.h>
#include <sys/_task.h>
#include <sys/cpuset.h>
#include <sys/user.h>
#include <sys/proc.h>

#include <kvm.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "kutil.h"

#define PR_TRIES    3
#define PR_MAXPROCS 200000
#define PR_MAXBUCK  (1UL << 22)

struct pent {
	uintptr_t addr;
	int       pid;
	char      comm[20];
};

struct pset {
	struct pent *v;
	size_t       n, cap;
};

static int pset_add(struct pset *s, uintptr_t addr, const struct proc *p)
{
	if (s->n == s->cap) {
		size_t nc = s->cap ? s->cap * 2 : 256;
		struct pent *nv = realloc(s->v, nc * sizeof(*nv));

		if (nv == NULL)
			return (-1);
		s->v = nv;
		s->cap = nc;
	}
	s->v[s->n].addr = addr;
	s->v[s->n].pid = p->p_pid;
	strlcpy(s->v[s->n].comm, p->p_comm, sizeof(s->v[s->n].comm));
	s->n++;
	return (0);
}

static int pent_cmp(const void *a, const void *b)
{
	uintptr_t x = ((const struct pent *)a)->addr;
	uintptr_t y = ((const struct pent *)b)->addr;

	return (x < y ? -1 : x > y);
}

static void pset_finish(struct pset *s)
{
	size_t i, j = 0;

	if (s->n == 0)
		return;
	qsort(s->v, s->n, sizeof(*s->v), pent_cmp);
	for (i = 0; i < s->n; i++)
		if (j == 0 || s->v[j - 1].addr != s->v[i].addr)
			s->v[j++] = s->v[i];
	s->n = j;
}

static int pset_has(const struct pset *s, uintptr_t addr)
{
	struct pent key;

	key.addr = addr;
	return (bsearch(&key, s->v, s->n, sizeof(key), pent_cmp) != NULL);
}

/* 0 ok, -1 read error, -2 implausible proc (layout mismatch). */
static int read_proc(kvm_t *kd, uintptr_t addr, struct proc *p)
{
	if (kvm_read(kd, addr, p, sizeof(*p)) != (ssize_t)sizeof(*p))
		return (-1);
	if (p->p_pid < 0 || p->p_pid > 1000000)
		return (-2);
	return (0);
}

static int walk_allproc(kvm_t *kd, uintptr_t head, struct pset *out)
{
	struct proc p;
	uintptr_t cur;
	size_t guard = 0;
	int rc;

	if (kvm_read(kd, head, &cur, sizeof(cur)) != (ssize_t)sizeof(cur))
		return (-1);
	while (cur != 0) {
		if (++guard > PR_MAXPROCS)
			return (-2);
		if ((rc = read_proc(kd, cur, &p)) != 0)
			return (rc);
		if (pset_add(out, cur, &p) != 0)
			return (-1);
		cur = (uintptr_t)LIST_NEXT(&p, p_list);
	}
	return (0);
}

static int walk_tree(kvm_t *kd, uintptr_t root, struct pset *out)
{
	struct proc p, c;
	uintptr_t *stack, node, child;
	size_t sp = 0, guard = 0;
	int rc = 0;

	if ((stack = malloc(PR_MAXPROCS * sizeof(*stack))) == NULL)
		return (-1);
	stack[sp++] = root;
	if ((rc = read_proc(kd, root, &p)) != 0)
		goto out;
	if (pset_add(out, root, &p) != 0) {
		rc = -1;
		goto out;
	}
	while (sp > 0) {
		node = stack[--sp];
		if ((rc = read_proc(kd, node, &p)) != 0)
			goto out;
		child = (uintptr_t)LIST_FIRST(&p.p_children);
		while (child != 0) {
			if (++guard > PR_MAXPROCS || sp >= PR_MAXPROCS) {
				rc = -2;
				goto out;
			}
			if ((rc = read_proc(kd, child, &c)) != 0)
				goto out;
			if (pset_add(out, child, &c) != 0) {
				rc = -1;
				goto out;
			}
			stack[sp++] = child;
			child = (uintptr_t)LIST_NEXT(&c, p_sibling);
		}
	}
out:
	free(stack);
	return (rc);
}

static int walk_pidhash(kvm_t *kd, uintptr_t tbl_sym, uintptr_t mask_sym,
    struct pset *out)
{
	struct proc p;
	uintptr_t tbl, cur;
	u_long mask, nb, b;
	size_t guard = 0;
	int rc;

	if (kvm_read(kd, tbl_sym, &tbl, sizeof(tbl)) != (ssize_t)sizeof(tbl) ||
	    kvm_read(kd, mask_sym, &mask, sizeof(mask)) != (ssize_t)sizeof(mask))
		return (-1);
	nb = mask + 1;
	if (tbl == 0 || mask == 0 || nb > PR_MAXBUCK || (nb & mask) != 0)
		return (-2);
	for (b = 0; b < nb; b++) {
		if (kvm_read(kd, tbl + b * sizeof(uintptr_t), &cur,
		    sizeof(cur)) != (ssize_t)sizeof(cur))
			return (-1);
		while (cur != 0) {
			if (++guard > PR_MAXPROCS)
				return (-2);
			if ((rc = read_proc(kd, cur, &p)) != 0)
				return (rc);
			if (pset_add(out, cur, &p) != 0)
				return (-1);
			cur = (uintptr_t)LIST_NEXT(&p, p_hash);
		}
	}
	return (0);
}

static int snapshot(kvm_t *kd, uintptr_t allproc_a, uintptr_t proc0_a,
    uintptr_t tbl_a, uintptr_t mask_a, struct pset *V, struct pset *T,
    struct pset *H)
{
	int rc;

	V->n = T->n = H->n = 0;
	if ((rc = walk_allproc(kd, allproc_a, V)) != 0)
		return (rc);
	if ((rc = walk_tree(kd, proc0_a, T)) != 0)
		return (rc);
	if ((rc = walk_pidhash(kd, tbl_a, mask_a, H)) != 0)
		return (rc);
	pset_finish(V);
	pset_finish(T);
	pset_finish(H);
	return (0);
}

static int count_missing(const struct pset *src, const struct pset *V)
{
	size_t i;
	int bad = 0;

	for (i = 0; i < src->n; i++)
		if (!pset_has(V, src->v[i].addr))
			bad++;
	return (bad);
}

int check_proc_hiding(kvm_t *kd, const struct modmap *m)
{
	struct pset V = { 0 }, T = { 0 }, H = { 0 };
	uintptr_t allproc_a, proc0_a, tbl_a, mask_a;
	int try, rc, bad = 0, findings = 0;
	size_t i;

	(void)m;
	if (resolve(kd, "allproc", &allproc_a) != 0 ||
	    resolve(kd, "proc0", &proc0_a) != 0 ||
	    resolve(kd, "pidhashtbl", &tbl_a) != 0 ||
	    resolve(kd, "pidhash", &mask_a) != 0) {
		report_err("warn: cannot resolve process tables; "
		    "proc check skipped");
		return (0);
	}

	for (try = 0; try < PR_TRIES; try++) {
		if (try > 0)
			usleep(30000);
		rc = snapshot(kd, allproc_a, proc0_a, tbl_a, mask_a, &V, &T, &H);
		if (rc != 0) {
			report_err("warn: process walk failed (%s); proc check "
			    "skipped", rc == -2 ? "layout mismatch / bad table"
			    : "kvm read error");
			goto out;
		}
		if (V.n < 2) {
			report_err("warn: allproc implausibly short; proc "
			    "check skipped");
			goto out;
		}
		bad = count_missing(&T, &V) + count_missing(&H, &V);
		if (bad == 0)
			goto out;
	}

	for (i = 0; i < T.n; i++)
		if (!pset_has(&V, T.v[i].addr)) {
			report_hook("pid %d (%s) at %#lx is in the process tree "
			    "but missing from allproc: hidden from ps/top "
			    "(rootkit)", T.v[i].pid, T.v[i].comm,
			    (unsigned long)T.v[i].addr);
			findings++;
		}
	for (i = 0; i < H.n; i++)
		if (!pset_has(&V, H.v[i].addr)) {
			report_hook("pid %d (%s) at %#lx is in pidhashtbl but "
			    "missing from allproc: hidden from ps/top "
			    "(rootkit)", H.v[i].pid, H.v[i].comm,
			    (unsigned long)H.v[i].addr);
			findings++;
		}
out:
	free(V.v);
	free(T.v);
	free(H.v);
	return (findings);
}
