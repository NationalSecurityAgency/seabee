# SeaBee

SeaBee is a stylized acronym for "Security Enhanced Architecture for eBPF"

## Documentation

* [Project Architecture](./docs/docs/architecture.md)
* [Threat Model](./docs/docs/threat_model.md)
* [Capabilities](./docs/docs/capabilities.md)
* [Implementation Notes](./docs/docs/implementation.md)
* [Testing Philosophy](./docs/docs/testing.md)

## Supported Kernel Versions

* Fedora 41, 42
* Ubuntu 22.04, 24.04
* Rocky 9
* In theory, any Linux kernel 5.14+

## Installation

* Clone this repository with `git`
* Change into the directory `cd seabee`
* Install the dependencies with `scripts/update_dependencies.sh`
* Reload shell `source ~/.bashrc`

### Fedora 41, 42

Should work out of the box

### Ubuntu 22.04, 24.04

As of Ubuntu 24.04, Ubuntu does use the Kconfig option `CONFIG_BPF_LSM`, but it does not enable BPF LSM by default.
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
reboot
sudo cat /sys/kernel/security/lsm
```

## General Instructions

### Compile

* To compile the debug version: `make all`
* To compile the release version: `make release`

### Generate a root key

SeaBee requires a root key in order to run. This key is used to turn off SeaBee and
optionally to verify the keys used to add SeaBee policies (if `--verify-keys` is enabled)

Read more here: [Cryptography in SeaBee](./docs/docs/crypto.md)

* The SeaBee root public key is stored at `/etc/seabee/seabee_root_key.pem`
* The SeaBee root private key should be encrypted and ideally stored on separate secure system
* The SeaBee root key can be either an ECDSA or RSA key
* Use `make gen-root-key` to generate an encrypted RSA keypair for SeaBee
* Use `make install-root-key` to copy the resulting public key to `/etc/seabee/seabee_root_key.pem`
* The above commands require openssl installed on the system

### Install binaries

* Use `make install` to install compiled binaries to `/usr/sbin`

### Run

To run in terminal

* `make all`
* `sudo target/debug/seabee`
* we highly recommend running with options during testing/experimentaiton to prevent needing to reboot the machine in order to stop the program.
  This may occur because the program is designed to be difficult to remove, even in the prescense of a malicious superuser.
* `-s allow` allow killing the program with ctrl+c (sigint)
* `-p allow` allows removing the pinned programs from the bpf filesystem which effectively stops the program.
  * remove pins with `sudo rm -r /sys/fs/bpf/seabee`

To run as systemd daemon or service

* To launch the daemon with release version: `make run`
* To install the daemon to run on next boot: `make enable`
* can currently be reversed with `sudo systemctl disable seabee.service`
* TODO: In current implementation, daemon can only be stopped via reboot.
  Do not try `systemctl stop`.

### Test

Before running tests

* create a root key
* run `make install`

run full test suite: `make test`

### Docs

* To build the documentation:
  * Reload the shell `source ~/.bashrc`
  * `make docs` and then `make -C docs build`
* To view the documentation: `make -C docs serve-build`

### Update Dependencies

* Run `make update`

## Disclaimer of Endorsement

Nothing in this Work is intended to constitute an endorsement, explicit or implied,
by the United States Government of any particular manufacturer's product or service.

Any reference made herein by the United States Government to any specific commercial
product, process, or service by trade name, trademark, manufacturer, or otherwise,
in this Work does not constitute an endorsement, recommendation, or favoring by the
United States Government and shall not be construed as a reference for advertising
or product endorsement purposes.
