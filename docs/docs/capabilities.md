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
* The `bpf_send_signal` helper can only signal the `current` task
* uprobe attaching to the userspace process is not a concern as long as `bpf_probe_write_user` is blocked

## Threats addressed by other tools

## Threats yet to be addressed

* Kills that skip `security_task_kill`. The OOM killer and a write of `1` to the
    userspace's `cgroup.kill` send `SIGKILL` from the kernel, so signal protection
    does not apply. A privileged user can push the userspace into the OOM killer by
    raising `/proc/<pid>/oom_score_adj` (raising it needs no capability) or lowering
    its cgroup's `memory.max`, stop it with `cgroup.freeze`, starve it with
    `pids.max` or `cpu.max`, or move it into a restricted cgroup through that
    cgroup's `cgroup.procs`. A policy covering the service's cgroup directory could
    protect its control files. Migration is checked against the common ancestor's
    `cgroup.procs`, `oom_score_adj` is a per-process procfs file that a policy does
    not label, and the OOM kill itself cannot be blocked.
* Handle safe `security_kernel_module_request` calls for kernel modules
* Manipulating the BPF pinned programs through `sys_bpf`
  * open, write, read, etc.
* prevention of blocking our necessary permissions
* Does mounting BPFFS in a container/namespace cause the umount protections to fail?
* Prevent removing `bpf` from the LSM kernel command-line in the GRUB config
