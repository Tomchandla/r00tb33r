# R00TB33R

## Installation

## Detection

`detect` exits with `0` on a clean system and `1` when a rootkit is detected. 
Because false positives are penalised, we prioritised surefire methods of rootkit 
detection: a check only contributes to an exit `1` verdict when it is a near-certain
rootkit signature.

### Core design: kernel function-pointer validation

Our core design focuses on kernel function-pointer validation. After reading
through each team's design specifications, we saw common methods in syscall
hooks, ICMP hooks and sysctl hijacks. These all require changing a function
pointer within a kernel dispatch table so that an unauthorised function is
called instead of an approved kernel one. Thus, for every pointer we can reach,
we check whether it lands inside the kernel's own code or inside a currently
loaded module's code, in which case it is legitimate. Any other location is
deemed a sign of a rootkit.

We do this by traversing the `kldstat` listing to build a module map, noting
each loaded file's address and `address + size` range (and whether that range
is the kernel itself). Every pointer we examine is then allocated to one of
three categories:

1. **Kernel/module owned** — the pointer lands in the kernel or in a module that
   `kldstat` currently reports. This is a legitimate pointer.
2. **Owner hidden** — the pointer points into executable memory that falls
   inside no `kldstat`-visible range. This is the strongest signal of a rootkit: code
   is resident in kernel memory that is hidden from the module listing, which is
   exactly the DKOM signature of a module that has unlinked itself from the
   kernel's loaded-module list while still actively hooking the kernel.
3. **Owner null** — an empty (null) pointer, e.g. an unused table slot.

A key consequence of this design is that the detector needs nothing
pre-installed on the target. It reasons purely about where pointers
land relative to the live module map.

### How we read kernel memory

`kcheck` is a userland program, linked against `libkvm`, that reads kernel
memory and performs a series of checks to determine whether a rootkit is
present. It resolves kernel symbols (`sysent`, `linker_files`, `allproc`,
`ip_protox`, ...) with `kvm_nlist` and reads their contents from live kernel
memory via `/dev/kmem`. Running as root at the default secure level which is
fully readable. We chose a userland `libkvm` engine rather than a loadable
kernel module specifically so that the detector requires no installation on the
target and cannot itself be subverted as easily as a loaded `.ko`. If kvm
cannot be opened `kcheck` returns a distinct "engine unavailable" exit code
rather than guessing, so a blocked engine is never silently reported as "clean."
`detect` itself compiles the check sources at run time, so the whole detector 
ships as source and builds against the FreeBSD base system. `kcheck` builds 
the module map and opens kvm once, then runs every check in sequence.

### Ten checks

1. **`sysent` — syscall table hooks.** We read the `sysent` array and classify
   every `sy_call` pointer as above. This finds rootkits that hook syscalls to
   escalate privilege or hide themselves. A pointer into hidden memory is sign
   of a rootkit. A pointer into a visible module is a sign of a rootkit only 
   when it sits at a slot the base kernel owns (`read`, `setuid`, `execve`,
   `getdirentries`, ...). A non-base slot pointing into a visible module is
   deliberately ignored, because legitimate modules are allowed to register
   their own new syscalls. Flagging these would be a false positive.
2. **`ip_protox` — IP protocol backdoors.** Like `sysent`, we traverse the
   `ip_protox` array and identify input handlers that resolve into hidden or
   non-kernel memory like an IP-layer packet backdoor.
3. **`icmp_hook` — ICMP handler redirection.** A targeted check that compares
   `ip_protox[IPPROTO_ICMP]` directly against the resolved address of
   `icmp_input` and flags any irregularities. This is the direct counter to a
   covert channel driven through crafted ICMP packets.
4. **`sysctl` — sysctl handler hijack.** We walk the `sysctl` OID tree
   rather than an array as above, and validate every node's `oid_handler`.
   The walk is bounded so a corrupted or cyclic tree causes the check to skip
   cleanly rather than hang.
5. **`cdevsw` — character-device backdoors.** We inspect every character-device
   driver's operation handlers (`open`, `read`, `write`, `ioctl`, `mmap`, ...)
   and flag any that point into hidden memory. This covers `/dev` backdoors
   such as the keylogger's `/dev/sys_monitor` device.
6. **`pfil` — packet-filter hooks.** Checks packet-filtering hooks that link to
   hidden code. A hook into a visible module is flagged only when that module
   is not a known stock packet filter (`pf`, `ipfw`, `ipl`, `siftr`) which are
   the kld filenames the attacker can't control, so legitimate firewalls never
   trip the check.
7. **`inline` — prologue patches.** For rootkits that patch kernel code
   directly instead of the dispatch table, we read the prologue bytes of a
   curated list of commonly-patched functions and flag a prologue that jumps out
   of kernel text into hidden or non-kernel memory. This is kept as a
   corroborating check because legitimate runtime patching can exist.
8. **`modlist` — DKOM module-list desync.** We walk the kernel's `linker_files`
   list directly through kvm and cross-check it against the `kldstat`-visible
   set by address range. Any linker file in one view but not the other means the
   module listing has been changed. To defeat a rootkit that presents a
   momentarily consistent map, the comparison is repeated and only a mismatch
   that persists across every re-read is reported.
9. **`proc` — DKOM process hiding.** We build three independent views of the
   live process set: the `allproc` list, the parent/child process tree, and the
   `pidhashtbl` hash. We report any process that appears in the tree or the
   hash but is missing from `allproc`. That means a process unlinked from `allproc`
   to hide it from `ps`/`top`. Like `modlist`, it re-snapshots to avoid racing a
   fork/exit and checks each process again so a layout mismatch skips rather
   than resulting in a false positive.
10. **`bootcfg` — persistence.** The one userland check: it parses
    `/boot/loader.conf*`, `/etc/rc.conf*` and their `.d` directories to list
    every module configured to load at boot, then cross-references each against
    the `kldstat` listing.  This catches a module that resolves via
    `kldfind`/`modfind` but is filtered out of the listing, or one staged to
    load but not actually loaded or visible.

## Remote



## Keylogger

The logger captures stdin read activity on the FreeBSD target ($TARGET) via a kld and streams those bytes over TCP to a collector/listener ($REMOTE) via a user-space helper (log-helper) invoked through the ./log <IP> wrapper. The module hooks SYS_read and specifically targets stdin so only normal shell input is captured while prompts that read directly from /dev/tty such as passwords and stuff are not captured - this could have been done but it would also open up another detection avenue that we would have to consider. 


Synchronized Ring Buffer: Bytes copied from user space via copyin() are pushed into the ring_buffer protected by a kernel mutex. When the ring buffer reaches capacity (next_head == tail), additional incoming bytes are dropped rather than overwriting unread data or overflowing the buffer. A character device (monitor_cdevsw) exposes the buffered bytes to user space. monitor_read() drains ring_buffer into a staging buffer under ring_mtx and transfers data to user space via uiomove() outside the lock so it does not sleep or fault while holding the mutex.

Because read_hook only fires when a process executes read(fd = 0), ./log <IP> is run in the background (./log <IP> &) or in a separate session so the interactive shell remains active and issues read(fd = 0) calls as commands and characters are typed. This is useful for testing.

log-helper opens /dev/sys_monitor (O_RDONLY), connects over TCP to the collector port (4444) with exponential backoff retry and automatic reconnection if the socket drops, and forwards read bytes (byte-by-byte or in configured batches) to the listener.

### Testing Notes
Because read_hook only triggers when a process executes read(fd = 0), running ./log <IP> & in the background—or running ./log <IP> in a separate session/SSH window—keeps the interactive shell active so typing commands and characters issues read(fd = 0) calls that flow through /dev/sys_monitor to the listener.

### Video

Here you can access a video of our keylogger [keyloggerexamplevideo](https://unsw-my.sharepoint.com/:v:/g/personal/z5479498_ad_unsw_edu_au/IQDCpq4GZL_EQJ0vRCJEZK39AbhFxIYRrnVDTFxg6awkqPc?nav=eyJyZWZlcnJhbEluZm8iOnsicmVmZXJyYWxBcHAiOiJTdHJlYW1XZWJBcHAiLCJyZWZlcnJhbFZpZXciOiJTaGFyZURpYWxvZy1MaW5rIiwicmVmZXJyYWxBcHBQbGF0Zm9ybSI6IldlYiIsInJlZmVycmFsTW9kZSI6InZpZXcifX0%3D&e=6OrF3k)
