# R00TB33R

All attempts at concealment are mentioned in each section below.

## Installation

The install script compile our kernel loadable modules (KLD) and load them using the `kldload` command. This install all hooked syscalls that implement escalation, keylogging and remote access logic. In the future we will make it conceal it's traces by removing logs from dmesg and /var/log/messages. It will also delete source files and potentially setup persistence by writing to /boot/loader.conf.

## Privilege Escalation
We attain root privileges by hooking the setuid syscall. setuid changes the privileges of a program to be different to that of the user. Calling setuid(0) to gain root access is prevented by the kernel which requires syscall hooking to change the behaviour to allow this. To achieve this we save the original syscall entry (sysent[SYS_setuid].sy_call) and replace it with our own handler which searches for a process called elevate. Processes that do not match this name are ignored. Then it manually sets the uid to 0 by creating a new credential structure.
To hide this from a detector, we traverse through FreeBSD's global list of loaded kernel modules and remove "elevate.ko" from the list. This means that detection methods such as kldstat will traverse this same list and not print "elevate.ko" as a module. The same unlinking and privilege escalation method can be applied to most syscalls, not just setuid.

## Bonus Marks

We plan to attempt two Bonus Marks in this assignment, that being the reverse shell and the keylogger. 

### Reverse Shell

Our reverse shell will work by using a persistent TCP listener on the host workstation. A userspace process on the target VM will then open a outbound connection back to that listener, then call our custom elevation syscall (elevate-kld), which modifies the calling thread's credentials in kernel space to grant root privileges. The process then duplicates the socket onto stdin, stdout, and stderr with dup2() and executes /bin/sh, so the shell runs with root privileges and provides a fully interactive prompt over the connection. To hide the process, we plan to use DKOM to unlink its process descriptor from both the global allproc list and its process group (pg_members) chain. To conceal the network connection, the port_hiding-kld module uses DKOM to unlink the connection's local port structure from the global network reporting list.

### Keylogger

Our keylogger works like so: It first hooks SYS_read to capture standard input and writes the data into a thread-safe circular ring buffer in kernel memory. Buffering this way reduces network overhead and performance impact: data is flushed to a companion userspace daemon only once 64 bytes have accumulated. The daemon maintains an outbound TCP connection and sends each 64-byte chunk to the remote collector. The daemon is concealed using the same techniques as the reverse shell: DKOM removes its process descriptor from the allproc list and the pg_members chain. Its socket is hidden by port_hiding-kld.c, which uses DKOM through a custom syscall to unlink the daemon's local port structure from the global network connection reporting list.
