# SeaBee Configuration

This document explains how to configure SeaBee.
SeaBee configuration controls how SeaBee runs and is distinct from
SeaBee Policy which controls how SeaBee protects other applications.

SeaBee configuration is mostly explained through the help menu with
`seabee --help`

The SeaBee configuration cannot be updated while SeaBee is running.
Use `seabeectl show-config` to see the configuration SeaBee is running with.

Some of the SeaBee configuration options overlap with SeaBee policy options.
This is because SeaBee uses the same underlying mechanisms to protect itself
and other applications.

## Default Configuration

The default configuration is a secure way to use SeaBee.

Here is the default configuration in YAML format:

```yaml
# Info provides helpful, but not security-related information to the user
log_level: info
# Block access to SeaBee created maps
map_access: block
# Enable pin protection for SeaBee created pins
include_pins: true
# sigint is not allowed
sigint: false
# kernel module loading is only audited
kmod: audit
# block access to SeaBee files and policy
file_write_access: block
# block ptrace
ptrace_access: block
# nothing is excluded
# exclude:
# digital signature verification is enabled
verify_policy: true
# by default anyone can add a key to SeaBee
verify_keys: false
```

## Configuration Options

This section will look each configuration option with more detail.

### `log-level`

Specifies the minimum log level for SeaBee.
If `warn` is specified, then only `warn` and `error` messages will be logged.

see [logging docs](./logging.md) for descriptions of each log level.

### `map-access`

Specifies action for external access to SeaBee created eBPF maps.

It is important for SeaBee security that this option is set to `block`.

### `include-pins`

Specifies whether or not eBPF pins created by SeaBee are protected.
If true, then they will be protected according to the value of the `file_write_access` option.

Because SeaBee pins its program, they will remain running if Seabee crashes unexpectedly.
If this occurs, the only way to recover and restart SeaBee is through a reboot.

### `sigint`

If true, allows you to kill SeaBee with signal 2 or `SIGINT` or ctrl+C.
This is very useful for testing and debugging.

Default is false to ensure that SeaBee remains running at all times.

### `kmod`

Specify security level for loading kernel modules.

SeaBee is not designed for controlling the loading of kernel modules.
Using `block` will block all kernel module loads which is likely to break
functionality.

This option is included to make sure SeaBee audits modifications to the kernel.
While SeaBee considers compromised kernels outside of its threat model,
it is still possible for privileged users to modify the kernel.

There are many other mechanisms, most notably signed kernel modules,
secure boot, and runtime attestation, which are better suited for controlling
kernel modules.

### `file-write-access`

Specify action for external write access to SeaBee files including

- everything under `etc/seabee/`
- `/usr/sbin/seabee` and `usr/sbin/seabeectl`
- `/sys/fs/bpf/seabee/`
- service file: `/etc/systemd/system/seabee.service`

### `ptrace-access`

Specify action for external ptrace on the SeaBee userspace process.

Ptrace can be used to maliciously manipulate the SeaBee userspace process.
However, it also used by debuggers such as `gdb`.

For security, this option should be set to `block`.

### `exclude`

This options allows excluding certain types of logs altogether.

This can be useful for debugging if you only want to see
`map-access` related logs for example.

This can also be used if certain log types are very noisy on a system.
For example, `ptrace` can often be rather noisy.

If a log type is excluded, SeaBee will still `block` that action,
but there will be no record of that action in the logs.

To maximally reduce noise on a production system, it is better put `log-level`
to `warn`. This will include all security-critical events and
nothing more.

### `verify-policy`

If true, every SeaBee policy must be signed by a key already
added to SeaBee.

If false, any policy can be added or removed without verification.

Should always be true for security.

### `verify-keys`

False by default.
True means every key file added to SeaBee must be signed by the root key.
This effectively means the controller of the root key must authorize every other key that is used by SeaBee.
This allows a system administrator to control who can use SeaBee.

If this option is disabled, then anyone can use SeaBee and add keys.
This does not inherently represent an integrity problem since a policy
update must be signed with the same key used to create the policy.
However, if anyone is allowed to add keys, it may open the door for availability attacks.

This is because a file or binary cannot be tracked by two different SeaBee
policies ([see policy.md](./policy.md)).
This means that errors will occur if two different entities create conflicting SeaBee policies.

Enabling this option allows control over who is creating SeaBee policies,
but also adds a layer of complexity for using SeaBee since each user
will have to obtain a signature from the root key.

## Ways to Configure SeaBee

### Configuration via the Command Line

`seabee --help` explains all of the possible configuration options.

### Configuration via a File

At startup, SeaBee pulls configuration information from `/etc/seabee/config.yaml`

For convenience, this file can be updated while SeaBee is turned off via [`seabeectl config`](./seabeectl.md#seabeectl-config).

This file can accept all of the same key-value pairs as the command line.

### Specifying Configuration in Multiple Places

Any option not specified will remain as the default.

If the same option is specified in a file and on the command line, the command line takes precedence.
