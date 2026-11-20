#include <sys/param.h>
#include <sys/queue.h>
#include <sys/time.h>
#include <sys/conf.h>
#include <kvm.h>
#include <stdio.h>
#include <string.h>
#include "kutil.h"

#define CD_MAXDEV   200000
#define CD_SEEN     8192

/*
 * Prefix of the kernel's `struct cdevsw`.
 * All members below d_name are function pointers.
 * Read them as plain addresses.
 */
struct kcdevsw {
	int        d_version;
	u_int      d_flags;
	uintptr_t  d_name;
	uintptr_t  d_open;
	uintptr_t  d_fdopen;
	uintptr_t  d_close;
	uintptr_t  d_read;
	uintptr_t  d_write;
	uintptr_t  d_ioctl;
	uintptr_t  d_poll;
	uintptr_t  d_mmap;
	uintptr_t  d_strategy;
	uintptr_t  d_spare0;
	uintptr_t  d_kqfilter;
};

int check_cdevsw(kvm_t *kd, const struct modmap *m)
{
	struct {
		uintptr_t tqh_first;
		uintptr_t tqh_last;
	} head;
	struct cdev cdv;
	struct kcdevsw sw;
	uintptr_t headsym, cur, seen[CD_SEEN];
	long visited = 0;
	int nseen = 0, findings = 0;

	if (resolve(kd, "cdevp_list", &headsym) != 0) {
		report_err("warn: cannot resolve 'cdevp_list'");
		return (0);
	}
	if (kvm_read(kd, headsym, &head, sizeof(head)) != (ssize_t)sizeof(head)) {
		report_err("warn: cannot read cdevp_list; cdevsw check skipped");
		return (0);
	}

	for (cur = head.tqh_first; cur != 0; ) {
		uintptr_t devsw, hidden = 0;
		const char *hidden_fn = NULL;
		int i, dup = 0;
		char dname[SPECNAMELEN + 1];
		struct hptr { const char *nm; uintptr_t p; } H[9];

		if (++visited > CD_MAXDEV) {
			report_err("warn: cdevp_list too long (>%d); cdevsw "
			    "check skipped", CD_MAXDEV);
			return (0);
		}
		if (kvm_read(kd, cur, &cdv, sizeof(cdv)) != (ssize_t)sizeof(cdv)) {
			report_err("warn: cdev read failed; cdevsw check "
			    "skipped");
			return (0);
		}

		devsw = (uintptr_t)cdv.si_devsw;
		if (devsw == 0)
			goto next;
		for (i = 0; i < nseen; i++)
			if (seen[i] == devsw) { dup = 1; break; }
		if (dup)
			goto next;
		if (nseen < CD_SEEN)
			seen[nseen++] = devsw;

		if (kvm_read(kd, devsw, &sw, sizeof(sw)) != (ssize_t)sizeof(sw))
			goto next;
		memcpy(dname, cdv.si_name, sizeof(dname));
		dname[sizeof(dname) - 1] = '\0';

		H[0].nm = "d_open";     H[0].p = sw.d_open;
		H[1].nm = "d_fdopen";   H[1].p = sw.d_fdopen;
		H[2].nm = "d_close";    H[2].p = sw.d_close;
		H[3].nm = "d_read";     H[3].p = sw.d_read;
		H[4].nm = "d_write";    H[4].p = sw.d_write;
		H[5].nm = "d_ioctl";    H[5].p = sw.d_ioctl;
		H[6].nm = "d_poll";     H[6].p = sw.d_poll;
		H[7].nm = "d_mmap";     H[7].p = sw.d_mmap;
		H[8].nm = "d_kqfilter"; H[8].p = sw.d_kqfilter;

		for (i = 0; i < (int)(sizeof(H) / sizeof(H[0])); i++) {
			if (classify(m, H[i].p) == OWNER_HIDDEN) {
				hidden = H[i].p;
				hidden_fn = H[i].nm;
				break;
			}
		}
		if (hidden != 0) {
			report_hook("/dev/%s cdevsw %s=%#lx -> HIDDEN memory "
			    "(no visible module owns it): char-device backdoor "
			    "(rootkit)", dname, hidden_fn,
			    (unsigned long)hidden);
			findings++;
		}
next:
		if (kvm_read(kd, cur + sizeof(struct cdev), &cur,
		    sizeof(cur)) != (ssize_t)sizeof(cur)) {
			report_err("warn: cdevp_list walk read failed; "
			    "cdevsw check truncated");
			break;
		}
	}
	return (findings);
}
