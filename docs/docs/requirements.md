# SeaBee System Requirements

SeaBee only works on Linux.

SeaBee needs root or 'sudo' or run.

We specifically run tests to ensure support on the following distributions:

* Fedora 43, 44, 45
* RHEL/Rocky 9, 10
* Ubuntu 22.04, 24.04, 26.04

However, in theory, SeaBee should work on any Linux kernel 5.14+ since we do not rely on any features added after 5.14.

## Fedora 43, 44, 45

Should work out of the box

## RHEL/Rocky 9, 10

Should work out of the box

## Ubuntu 22.04, 24.04, 26.04

As of Ubuntu 24.04, Ubuntu has the kernel config option `CONFIG_BPF_LSM`, but it does not enable BPF LSM by default.
We must enable it in order for this code to work.

```bash
# get current LSM list
sudo cat /sys/kernel/security/lsm
# edit new GRUB config stub
sudo vim /etc/default/grub.d/99-bpf-lsm.cfg
# add a line with ",bpf" at the end with the current LSM list preceding, something like
# GRUB_CMDLINE_LINUX_DEFAULT="${GRUB_CMDLINE_LINUX_DEFAULT} lsm=lockdown,capability,landlock,yama,apparmor,bpf"
#
# update GRUB config
sudo update-grub
# reboot and check LSM list again
sudo reboot
sudo cat /sys/kernel/security/lsm
# If you see 'bpf' in the list, then you are good to go!
```

## Other Distributions

If you have tested SeaBee on another distribution/environment, and have instructions for how you did it,
please create a PR so we can add those steps to our documentation and benefit anyone who wants to use SeaBee!
