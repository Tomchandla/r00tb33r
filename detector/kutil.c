/*
 * kutil.c - module map, pointer classification, symbol resolution, reporting.
 */
#include <sys/param.h>
#include <sys/linker.h>
#include <kvm.h>
#include <nlist.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include "kutil.h"

// Build the map of loaded files (kernel + modules) via the kldstat(2) API.
int build_module_map(struct modmap *m)
{
	struct kld_file_stat st;
	int f_id = 0;

	m->n = 0;
	while ((f_id = kldnext(f_id)) > 0) {
		if (m->n >= MAXMODS) {
			report_err("warn: more than %d linker files; map truncated",
			    MAXMODS);
			break;
		}
		memset(&st, 0, sizeof(st));
		st.version = sizeof(st);
		if (kldstat(f_id, &st) < 0)
			continue;
		strlcpy(m->mods[m->n].name, st.name, sizeof(m->mods[m->n].name));
		m->mods[m->n].start = (uintptr_t)st.address;
		m->mods[m->n].end   = (uintptr_t)st.address + st.size;
		m->mods[m->n].is_kernel = (strcmp(st.name, "kernel") == 0);
		m->n++;
	}
	return (m->n > 0 ? 0 : -1);
}

// Returns index in m->mods[] that owns p, OWNER_HIDDEN, or OWNER_NULL
int classify(const struct modmap *m, uintptr_t p)
{
	int i;
	if (p == 0)
		return (OWNER_NULL);
	for (i = 0; i < m->n; i++)
		if (p >= m->mods[i].start && p < m->mods[i].end)
			return (i);
	return (OWNER_HIDDEN);
}

int owner_is_kernel(const struct modmap *m, int owner)
{
	return (owner >= 0 && m->mods[owner].is_kernel);
}

int resolve(kvm_t *kd, const char *sym, uintptr_t *out)
{
	struct nlist nl[2];

	memset(nl, 0, sizeof(nl));
	nl[0].n_name = (char *)sym;
	nl[1].n_name = NULL;            /* kvm_nlist needs a terminator */
	if (kvm_nlist(kd, nl) != 0 || nl[0].n_value == 0)
		return (-1);
	*out = (uintptr_t)nl[0].n_value;
	return (0);
}

static void vreport(FILE *fp, const char *tag, const char *fmt, va_list ap)
{
	fprintf(fp, "%s ", tag);
	vfprintf(fp, fmt, ap);
	fputc('\n', fp);
}

void report_hook(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vreport(stdout, "[HOOK]", fmt, ap);
	va_end(ap);
}

void report_err(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vreport(stderr, "[kcheck]", fmt, ap);
	va_end(ap);
}
