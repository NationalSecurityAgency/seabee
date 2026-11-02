# SeaBee Capabilities

This document exists as a way to track what the userspace program does
  and what it still needs to do.

## Threats mitigated

* Block access to the userspace's eBPF maps via the `BPF_GET_FD_BY_ID` command
    in the `security_bpf` LSM hook
* Block signals that would interrupt or terminate the userspace process group
    via `security_task_kill`
* Block unlinking of eBPF pinned programs via the `security_inode_unlink` LSM hook
* Block unmounting of `/sys` or `/sys/bpf` via the `security_sb_umount` LSM hook
* Block kernel module loading via the `security_kernel_read_file`,
    `security_kernel_load_data`, and `security_kernel_module_request` LSM hooks
* Block ptrace of the userspace via the `security_ptrace_access_check` LSM hook
* Block killing a parent process of the userspace by running under systemd

## Threats investigated and dismissed

* Multiple eBPF programs on the same LSM hook cannot override a "deny" result
* Blocking eBPF pinned map access because the userspace's maps aren't pinned
* ptrace through `security_ptrace_traceme` is out of scope since it is only invoked
by the process requesting to be traced and the SeaBee userspace is not doing that
* uprobe attaching to the userspace process is not a concern as long as `bpf_probe_write_user` is blocked

## Threats addressed by other tools

## Threats yet to be addressed

* Handle safe `security_kernel_module_request` calls for kernel modules
* Manipulating the BPF pinned programs through `sys_bpf`
  * open, write, read, etc.
* prevention of blocking our necessary permissions
* Does mounting BPFFS in a container/namespace cause the umount protections to fail?
* Prevent removing `bpf` from the LSM kernel command-line in the GRUB config
* Signals sent from eBPF programs. The `bpf_send_signal` and `bpf_send_signal_thread`
    helpers only signal the `current` task, but a privileged user can attach an eBPF
    program to a hook that runs in the context of the userspace process, such as a
    tracepoint on a system call it makes. Recent kernels also provide the
    `bpf_send_signal_task` kfunc, which can signal any task. These signals are sent
    by the kernel (`SEND_SIG_PRIV` or `SI_KERNEL`), so `security_task_kill` is not
    called and they are not blocked.
