
# `seabeectl`

`seabeectl` is a command line client for the SeaBee daemon.
`seabeectl` sends requests to the SeaBee daemon and returns responses to the user.
These requests include things such as updating policy, adding keys, and turning off SeaBee.
`seabeectl` also has various convenient features that don't interact with the SeaBee daemon
such as signing SeaBee policies and some testing/debugging commands.

`seabeectl` does it best to be self-documenting with `seabeectl --help` or
`seabeectl <command> --help`. This documentation gives and overview of
`seabeectl` and may explain in more detail that tool's help menu.

## `seabeectl alg`

This will always display up to date information about what cryptographic algorithms are supported.

example: `sudo seabeectl alg`

Currently SeaBee supports RSA and ECDSA keys. We also support SHA-2 and SHA-3 message digests.
SeaBee also expects keys to be in `.pem` format.

PQC support will be added with [issue 42](https://github.com/NationalSecurityAgency/seabee/issues/42).

If cryptographic support is a barrier for using SeaBee please create an issue and we can
add support for more algorithms.

## `seabeectl sign`

Sign a target file with a private signing key.

example: `sudo seabeectl sign -t tests/policies/sample_policy.yaml -k seabee-root-private-key.pem`

- `-t` to specify a path to a file that should be signed
- `-k` the path to a key to a signing key
- `-o` the path the signature file should be output to
- `-d` an algorithm used to compute the message digest (default: SHA3-256)
- `-n` don't prompt for a password, only use for unencrypted signing keys which is insecure

This uses the rust [openssl crate](https://docs.rs/openssl/latest/openssl/) to sign a target file.

## `seabeectl verify`

Verify a signature on a file with a public verification key.

example: `sudo seabeectl verify -t tests/policies/sample_policy.yaml -s signature.sign -k /etc/seabee/seabee_root_key.pem`

- `-t` the file for which the signature was generated
- `-s` the signature for the file
- `-k` the path to the public verification key
- `-d` the digest used to generate the signature if not using the default (SHA3-256)

This uses the rust [openssl crate](https://docs.rs/openssl/latest/openssl/) to verify a target file.

This command is mostly used for testing and experimentation.
It uses the same underlying logic as SeaBee to verify files.

## `seabeectl clean`

Used to clean up SeaBee files. Use with caution, this will delete saved keys, policies, signatures, and configs.

example: `sudo seabeectl clean policy`

This command can only be used while SeaBee is turned off.
This is because it deletes saved SeaBee files.
Whenever a policy or key is added, SeaBee will save it to `/etc/seabee`.
This allows SeaBee to reload keys or policies when the system reboots.
While SeaBee is running, these files cannot be modified.

- `policy` deletes saved policies and their signatures
- `keys` deletes saved keys and signatures
- `root-key` deletes the root key. Note that SeaBee needs a root key in order to run.
- `config` deletes the saved SeaBee config.
- `all` does all of the above by deleting `/etc/seabee`

## `seabeectl config`

Add, update, or delete the saved SeaBee config.

example: `sudo seabeectl config get`

This command adds convenience for interacting with the SeaBee _saved_ configuration.
The saved configuration lives at `/etc/seabee/config.yaml`.
It is important to remember that the SeaBee saved configuration may be different than
the actual configuration that SeaBee is using.
This is because the any option not specified in the saved configuration will use a default.
Also, if command line arguments are used together with saved configuration, then
the command line option will take precedence over a saved configuration.
For more information about SeaBee configuration, see the [config docs](./config.md).

There are three subcommands for `seabeectl config`

- `get` dumps the contents of the current saved SeaBee config
- `update` update the current config with a new one from a file.
This just performs a copy and overwrites the existing saved config.
- `delete` deletes the current saved config.

## `seabeectl shutdown-request`

Generate a SeaBee shutdown request for this machine.

example: `seabeectl shutdown-request /path/to/shutdown_request.yaml`

By default, the file will be created as `shutdown_request.yaml` in the current directory.
Optionally, a path can be passed to this command as a final argument.

See [shutdown](#seabeectl-shutdown) for how to use the generated file to shutdown SeaBee.

## `seabeectl list`

Shows a list of all currently loaded SeaBee policies

## `seabeectl show`

Displays a single loaded SeaBee policy.
This can also be used to check if a particular policy exists.

example: `seabeectl show name sample-policy`

For this command you will have to choose how to identify the policy

- by policy id with `id`
- by name with `name`
- by a policy file with `file`

## `seabeectl update`

Takes a policy file as an argument and adds it to SeaBee if
a policy with the same name does not exist or updates a policy if it does exist.

example: `sudo seabeectl update -t tests/policies/sample_policy.yaml -s signature.sign`

note: this example may fail if you have not yet done `sudo mkdir /etc/test_seabee_policy`

- `-t` is the path to the policy you are adding
- `-s` is the signature for that policy
- `-d` is the message digest used for the signature (only if you are not using the default)

If `--verify-policy` is enabled, which is necessary for security, then this command
requires a signature for the policy. The [crypto docs](./crypto.md) explains how to sign
and load a SeaBee policy. Basically, you need to create a public key pair, add the public
key to SeaBee with `seabeectl add-key`, sign the policy with `seabeectl sign`, then
add the policy with `seabeectl update`.

If the signature was not generated using the default message digest (SHA3-256), then
you will need to use the `-d` option to specify the digest algorithm.
This ensures that the signature can be properly verified.

All files or directories specified in a policy must exist on policy load.

The scope of a policy cannot be changed via a policy update.
This is partially due to implementation limitations, but also from intuition.
The scope defines where the policy applies.
Changing the scope intuitively suggests that a new policy is being created.

Policy updates require the version number to be increased.
This prevents an attacker from trying to load an older version of the same policy,
which may be less secure. It ensures that a new signature is always needed to
update policy.
You can view the current version number for a policy with with `seabeectl show` or `seabeectl list`

## `seabeectl remove`

This is used to remove a SeaBee policy. 
This immediately drops protections on all protected objects in the policy. 

example: `sudo seabeectl remove -t tests/policies/remove_sample_policy.yaml -s signature.sign`

- `-t` the path to a SeaBee remove request
- `-s` signature for the remove request, must be signed by same key as the policy being removed
- `-d` as with all signed requests, the digest is needed if the default is not being used

A SeaBee remove request only includes the name and version of the policy to be removed.

```Yaml
# Example remove request
name: sample-policy
version: 1
```

If a policy is removed and then re-added, any objects specified in the policy will no longer
be protected unless they are recreated. This means it is necssary 
to restart the application after the policy has been added in order for the policy to be enforced.
If your goal is to change protections on files, then `seabeectl update` is preferable to `remove` and `udpate`. 
If your goal is to change protections on processes or eBPF maps, then the processes and maps will need to
be created after the new policy takes effect.

The remove request is important because it ensures that the signature for removing
a policy is different from the signature for adding a policy.

To explain why this is important, more context is needed.
When a SeaBee policy is added, its signature is saved.
Anyone can view these signatures at `/etc/seabee/policy_sigs`.
This means an attacker has access to the policy files and valid signatures for those files.
If the signature for removing a SeaBee policy was the same as the signature for adding,
then an attacker could replay a signature to remove any SeaBee policy.

## `seabeectl list-keys`

Lists all of the keys currently added to SeaBee.

example: `sudo seabeectl list-keys`

Specifically, for each key it will display:

- `Added from:` file path were the key was added from
- `id:` unique numerical identifier for the key
- `Type:` the type of key
- `Size:` the length of the key

## `seabeectl show-key`

Displays a single SeaBee key. This can also be used to specify if a
particular key exists.

example: `sudo seabeectl show-key id 0`

note: id 0 is always the root key

You can search for a key using the following fields:

- `id`: the unique numerical identifier that SeaBee assigns for the key
- `file`: SeaBee will load a key from the path specified and check if the key
at that path matches any key that SeaBee has saved.

## `seabeectl add-key`

Add a new verification key to SeaBee.

example: `sudo seabeectl add-key -t new-seabee-public-key.pem`

options for this command include

- `-t` the path to the key being added
- `-s` a signature for the key from the root key.
Only required if `--verify-keys` enabled in SeaBee config
- `-d` the digest used by signature if it doesn't use the default (SHA3-256)

Use `seabeectl alg` to see a list of supported cryptographic algorithms and key formats

## `seabeectl remove-key`

Remove a SeaBee key.

example: `seabeectl remove-key -t new-seabee-public-key.pem -s signature.sign`

Options for this command include

- `-t` the path to the key being removed
- `-s` the path to a signature of the key file from the corresponding private key or the root key
- `-d` the digest used by signature if it doesn't use the default (SHA3-256)

Removing a key requires passing a path to the key file (pem) and a valid
signature for that file.
The signature must be verified using the key itself or the SeaBee root key.
Removing a key does not automatically revoke any polices that were signed by that key.
Instead, during reboot, all policies are reloaded and re-verified.
The removal of a key may cause some policies to generate verification errors on reboot.
The SeaBee root key cannot be removed, it can only be changed while SeaBee is turned off.

## `seabeectl shutdown`

Shutdown SeaBee with a shutdown request.

example: `sudo seabeectl shutdown -t shutdown_request.yaml -s shutdown_signature.sign`

The shutdown request is a YAML file with Linux machine id from `/etc/machine-id`.
This file can be generated with [`seabeectl shutdown-request`](#seabeectl-shutdown-request).
The shutdown request must be signed with the SeaBee root key.

Options for this command include

- `-t` the path to the shutdown request file
- `-s` the path to the signature for the shutdown request
- `-d` the digest used by signature if it doesn't use the default (SHA3-256)
