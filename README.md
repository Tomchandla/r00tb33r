# r00tb33r

Kernel loadable module FreeBSD Rootkit

## Manual testing

All commands must be run inside a FreeBSD environment. Run make to compile the kld file. Make sure that you have the kernel source tree installed at `/usr/src`.

```sh
make
```

Then load the kld to the kernel!

```sh
sudo kldload ./elevate.ko
```

Don't forget to unload it.

```sh
sudo kldunload elevate.ko
```
