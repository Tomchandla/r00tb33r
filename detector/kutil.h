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
#define OWNER_NULL    (-2)
#define OWNER_HIDDEN  (-1)

int  build_module_map(struct modmap *m);
int  classify(const struct modmap *m, uintptr_t p);
int  owner_is_kernel(const struct modmap *m, int owner);
int  resolve(kvm_t *kd, const char *sym, uintptr_t *out);

void report_hook(const char *fmt, ...) __printflike(1, 2);
void report_err(const char *fmt, ...) __printflike(1, 2);

/* ---- checks (one per chk_*.c) ---- */
int check_sysent(kvm_t *kd, const struct modmap *m);
int check_ip_protox(kvm_t *kd, const struct modmap *m);
int check_icmp_hook(kvm_t *kd, const struct modmap *m);
int check_modlist(kvm_t *kd, const struct modmap *m);
int check_sysctl(kvm_t *kd, const struct modmap *m);
int check_cdevsw(kvm_t *kd, const struct modmap *m);
int check_pfil(kvm_t *kd, const struct modmap *m);
int check_inline(kvm_t *kd, const struct modmap *m);
int check_proc_hiding(kvm_t *kd, const struct modmap *m);
int check_bootcfg(kvm_t *kd, const struct modmap *m);

#endif
