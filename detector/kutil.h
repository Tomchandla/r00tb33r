/*
 * kutil.h - shared engine state and helpers for kcheck.
 *
 * Every check lives in its own chk_*.c file and has the signature
 *
 *     int check_xxx(kvm_t *kd, const struct modmap *m);
 *
 * returning the number of HARD findings (0 = clean). Soft observations are
 * printed with report_warn() and never counted. Register new checks in the
 * checks[] table in kcheck.c and declare them at the bottom of this header.
 */
#ifndef KUTIL_H
#define KUTIL_H

#include <sys/param.h>

#include <kvm.h>
#include <stdint.h>

#define MAXMODS 512

struct krange {
	char      name[MAXPATHLEN];
	uintptr_t start;
	uintptr_t end;
	int       is_kernel;
};

struct modmap {
	struct krange mods[MAXMODS];
	int           n;
};

// classify() errors
#define OWNER_NULL    (-2)  /* null pointer: not a hook, ignore */
#define OWNER_HIDDEN  (-1)  /* owned by no visible module */

int  build_module_map(struct modmap *m);
int  classify(const struct modmap *m, uintptr_t p);
int  owner_is_kernel(const struct modmap *m, int owner);
int  resolve(kvm_t *kd, const char *sym, uintptr_t *out);

void report_hook(const char *fmt, ...) __printflike(1, 2);
void report_warn(const char *fmt, ...) __printflike(1, 2);
void report_err(const char *fmt, ...) __printflike(1, 2);

/* ---- checks (one per chk_*.c) ---- */
int check_sysent(kvm_t *kd, const struct modmap *m);
int check_ip_protox(kvm_t *kd, const struct modmap *m);
int check_icmp_hook(kvm_t *kd, const struct modmap *m);
int check_modlist(kvm_t *kd, const struct modmap *m);
int check_inline(kvm_t *kd, const struct modmap *m);
int check_proc_hiding(kvm_t *kd, const struct modmap *m);
int check_bootcfg(kvm_t *kd, const struct modmap *m);

#endif /* KUTIL_H */
