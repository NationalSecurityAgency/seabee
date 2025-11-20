// SPDX-License-Identifier: GPL-2.0-only
/**
 * @file seabee.bpf.c
 */

#include <bpf/vmlinux.h>
#include <bpf/vmlinux_features.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "logging.h"
#include "logging_types.h"
#include "seabee_log.h"
#include "seabee_maps.h"
#include "seabee_utils.h"
#include "shared_rust_types.h"

/// License of the BPF program
char LICENSE[] SEC("license") = "GPL";

// bss segment

/// @brief The level of the logs to filter out
u32 log_level;
/// @brief The level of access for kernel modules
u32 kmod_modification;
/// @brief The process id of the userspace that loads these programs
u32 my_pid;
/// @brief The device id of the /sys/bpf mount point inode
u64 bpf_dev_id;
/// @brief The device id of the /sys mount point inode
u64 sys_dev_id;
/// @brief The path of the seabee binary. u8 plays nicer with rust
u8  my_binary_path[PATH_MAX];
/// @brief used to null a buffer
u8  null_path[PATH_MAX];

/// eBPF Maps

/// @brief  logs data back to userspace
struct log_ringbuf log_ringbuf     SEC(".maps");
/// @brief  maps and inode to a policy id
struct inode_storage inode_storage SEC(".maps");
/// @brief Hashmap from policy id to policy config
struct policy_map policy_map       SEC(".maps");
/// @brief maps process pid to policy id
struct task_storage task_storage   SEC(".maps");
/// @brief struct sock to policy id
struct sk_storage sk_storage       SEC(".maps");
/// @brief maps a map id to a policy id
struct map_to_pol_id map_to_pol_id SEC(".maps");

struct path_to_pol_id {
	/// @brief Hashtable map type
	__uint(type, BPF_MAP_TYPE_HASH);
	/// @brief The name of the file
	__type(key, char[PATH_MAX]);
	/// @brief The policy id for this file
	__type(value, u32);
};
/// @brief Maps a filename to a policy id
struct path_to_pol_id path_to_pol_id SEC(".maps");

/// @brief storage path buffers which cannot fit on ebpf stack
/// per cpu is important to prevent concurrency issues
struct path_storage {
	/// @brief Per-CPU array map type
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	/// @brief array index
	__type(key, int);
	/// @brief Full pathname struct
	__type(value, char[PATH_MAX]);
};
/// @brief storage for paths
struct path_storage path_storage SEC(".maps");

// Helpers

static __always_inline enum SecurityLevel
type_to_security_level(enum EventType type, u32 policy_id)
{
	struct c_policy_config *cfg = get_policy_config(policy_id);
	// If no config exists for a policy ID, then that policy must have been revoked
	if (!cfg) {
		u64 data[] = { (u64)policy_id };
		log_generic_msg(LOG_LEVEL_TRACE, LOG_REASON_DEBUG,
		                "no policy associated with id %d", data, sizeof(data));
		return SECURITY_ALLOW;
	}

	switch (type) {
	case EVENT_TYPE_FILE_ACCESS:
		return cfg->file_write_access;
	case EVENT_TYPE_BPF_MAP:
		return cfg->map_access;
	case EVENT_TYPE_PTRACE_ACCESS_CHECK:
		return cfg->ptrace_access;
	case EVENT_TYPE_TASK_KILL:
		return cfg->signal_access;
	default: { // Brackets needed see: https://en.cppreference.com/w/cpp/language/switch#Notes
		u64 data[] = { (u64)policy_id, (u64)type };
		log_generic_msg(LOG_LEVEL_ERROR, LOG_REASON_ERROR,
		                "Error: security uninit for id %d, type: %d", data,
		                sizeof(data));
		return SECURITY_UNINIT;
	}
	}
}

static __always_inline u32 decide_inode_access(enum InodeAction     action,
                                               struct inode        *inode,
                                               const unsigned char *name)
{
	u32 inode_pol_id = get_inode_pol_id(inode);
	if (inode_pol_id == NO_POL_ID) {
		return ALLOW;
	}
	u32 pid_pol_id = get_task_pol_id();

	// Same policy id: Allow
	if (pid_pol_id == inode_pol_id) {
		return ALLOW;
	}

	// set file name
	if (!name) {
		name = (const unsigned char *)"<unknown file name>";
	}

	// take action based on security level
	enum SecurityLevel level =
		type_to_security_level(EVENT_TYPE_FILE_ACCESS, inode_pol_id);
	switch (level) {
	case SECURITY_ALLOW:
		return ALLOW;
	case SECURITY_AUDIT:
		log_inode_access(LOG_LEVEL_INFO, LOG_REASON_AUDIT, action, name,
		                 inode_pol_id);
		return ALLOW;
	case SECURITY_BLOCK:
		log_inode_access(LOG_LEVEL_WARN, LOG_REASON_DENY, action, name,
		                 inode_pol_id);
		return DENY;
	default: {
		u64 data[] = { (u64)level };
		log_generic_msg(LOG_LEVEL_ERROR, LOG_REASON_ERROR,
		                "inode access: nonexistent security level: %d", data,
		                sizeof(data));
		return DENY;
	}
	}
}

// return null on error, pointer to pathbuf on success
static __always_inline char *thread_safe_write_str_to_path(const char *data)
{
	u32   zero = 0;
	char *path = bpf_map_lookup_elem(&path_storage, &zero);
	if (!path) {
		log_generic_msg(LOG_LEVEL_ERROR, LOG_REASON_ERROR,
		                "Error: failed get path buffer", 0, 0);
		return NULL;
	}

	// null path
	int err = 0;
	err     = bpf_probe_read(path, PATH_MAX, &null_path);
	if (err < 0) {
		log_generic_msg(LOG_LEVEL_ERROR, LOG_REASON_ERROR,
		                "Error: failed to null path buffer", 0, 0);
		return NULL;
	}

	// write to path
	err = bpf_probe_read_str(path, PATH_MAX, data);
	if (err < 0) {
		u64 data[] = { (u64)data };
		log_generic_msg(LOG_LEVEL_ERROR, LOG_REASON_ERROR,
		                "Error: failed to write data '%s' to path buf", data,
		                sizeof(data));
		return NULL;
	}

	return path;
}

// eBPF programs

/**
 * @brief Blocks manipulation a protected map.
 *
 * This is achieved by preventing BPF file descriptors from
 * being created for protected maps.
 *
 * A file descriptor for a map can be obtained via the commands:
 *
 * @param map internal BPF map structure
 * @param fmode file mode to open with (read / write / etc)
 * @param ret return code from previous LSM hook
 *
 * @return {@link ALLOW} or {@link DENY}
 */
SEC("lsm/bpf_map")
int BPF_PROG(seabee_bpf_map, struct bpf_map *map, fmode_t fmode, int ret)
{
	u32 map_pol_id = get_map_pol_id(map);
	if (map_pol_id == NO_POL_ID) {
		return ALLOW;
	}
	u32 pid_pol_id = get_task_pol_id();

	// Same policy id: Allow
	if (pid_pol_id == map_pol_id) {
		return ALLOW;
	}

	// take action based on config
	enum SecurityLevel level =
		type_to_security_level(EVENT_TYPE_BPF_MAP, map_pol_id);
	switch (level) {
	case SECURITY_ALLOW:
		return ALLOW;
	case SECURITY_AUDIT:
		log_bpf_map(LOG_LEVEL_INFO, LOG_REASON_AUDIT, map, map_pol_id);
		return ALLOW;
	case SECURITY_BLOCK:
		log_bpf_map(LOG_LEVEL_WARN, LOG_REASON_DENY, map, map_pol_id);
		return DENY;
	default: {
		u64 data[] = { level };
		log_generic_msg(LOG_LEVEL_ERROR, LOG_REASON_ERROR,
		                "bpf_map: nonexistent security level: %d", data,
		                sizeof(data));
		return DENY;
	}
	}
}

/**
 * @brief Blocks the use of the bpf_write_user() helper.
 *
 * This helper function is dangerous and it is better to disable it.
 *
 * @param what why the lockdown hook is firing.
 *
 * @see `man 7 kernel_lockdown`
 */
SEC("lsm/locked_down")
int BPF_PROG(seabee_locked_down, enum lockdown_reason what)
{
	int ret = ALLOW; //default allow
	switch (what) {
	case LOCKDOWN_BPF_WRITE_USER:
		ret = DENY;
		log_generic(LOG_LEVEL_WARN, LOG_REASON_DENY, EVENT_TYPE_BPF_WRITE_USER,
		            BASE_POLICY_ID);
		break;
	default:
		break;
	}
	return ret;
}

/**
 * @brief Block unwanted signals to the seabee userspace process.
 *
 * Deny any outside userspace signal that will stop our corresponding userspace process
 * almost every signal will kill our process, we choose to enumerate (and allow) those which
 * do not stop our process. Signals that originate from the kernel may not be caught because
 * they may use a different code path that does not include this lsm hook. These signals include
 * the {@link ZERO} signal and any signal specified in the {@link signal_allow_mask}
 *
 * @param p target process
 * @param info signal info, can also be NULL or 1
 * @param sig signal value
 * @param cred credentials of sender, may be NULL
 * @param ret the return code of the previous LSM hook
 *
 * @return {@link ALLOW} or {@link DENY}
 *
 * @see signal numbering and default actions: `man signal`
 */
SEC("lsm/task_kill")
int BPF_PROG(seabee_task_kill, struct task_struct *p,
             struct kernel_siginfo *info, int sig, const struct cred *cred,
             int ret)
{
	// allow if no seabee policy
	u32 target_pol_id = get_target_task_pol_id(p);
	if (!target_pol_id) {
		return ALLOW;
	}
	// allow if same seabee policy
	u32 sender_pol_id = get_task_pol_id();
	if (target_pol_id == sender_pol_id) {
		return ALLOW;
	}
	// allow if no policy has been removed
	struct c_policy_config *cfg = get_policy_config(target_pol_id);
	if (!cfg) {
		return ALLOW;
	}
	// allow if policy config is allow
	if (cfg->signal_access == SECURITY_ALLOW) {
		return ALLOW;
	}
	// allow if not blocked by signal_allow_mask
	if (sig == ZERO || (1ULL << (sig - 1)) & cfg->signal_allow_mask) {
		log_task_kill(LOG_LEVEL_DEBUG, LOG_REASON_ALLOW, p, sig, target_pol_id);
		return ALLOW;
	}

	// otherwise audit or block and log
	if (cfg->signal_access == SECURITY_AUDIT) {
		log_task_kill(LOG_LEVEL_INFO, LOG_REASON_AUDIT, p, sig, target_pol_id);
		return ALLOW;
	} else if (cfg->signal_access == SECURITY_BLOCK) {
		log_task_kill(LOG_LEVEL_WARN, LOG_REASON_DENY, p, sig, target_pol_id);
		return DENY;
	} else {
		u64 data[] = { cfg->signal_access };
		log_generic_msg(LOG_LEVEL_ERROR, LOG_REASON_ERROR,
		                "task_kill: nonexistent security level: %d", data,
		                sizeof(data));
		return DENY;
	}
}

// from include/linux/fs.h
#define FMODE_WRITE (1 << 1)

/**
 * @brief make protected files read-only.
 *
 * This hook is called to check if a file is allowed to be accessed.
 * Deny access to protected files by checking file->f_mode. This tells
 * if the file is being opened for reading or writing.
*/
SEC("lsm/file_open")
int BPF_PROG(seabee_file_open, struct file *file)
{
	// only file write requests are considered
	if ((BPF_CORE_READ(file, f_mode) & FMODE_WRITE) == 0) {
		return ALLOW;
	}
	return decide_inode_access(FILE_OPEN, file->f_path.dentry->d_inode,
	                           file->f_path.dentry->d_name.name);
}

/**
 * @brief prevent writes to protected inodes
 *
 * @param inode inode
 * @param mask access mask
*/
SEC("lsm/inode_permission")
int BPF_PROG(seabee_inode_permission, struct inode *inode, int mask)
{
	// only file write requests are considered
	if ((mask & FMODE_WRITE) == 0) {
		return ALLOW;
	}
	return decide_inode_access(INODE_PERMISSION, inode, NULL);
}

/**
 * @brief Prevents unlinking/removing protected files or pins
 *
 * @param dir the parent directory
 * @param dentry the file being unlinked
 *
 * @return {@link ALLOW} or {@link DENY}
 */
SEC("lsm/inode_unlink")
int BPF_PROG(seabee_inode_unlink, struct inode *dir, struct dentry *dentry)
{
	return decide_inode_access(INODE_UNLINK, dentry->d_inode,
	                           dentry->d_name.name);
}

/**
 * @brief Prevents unlinking/removing protected folders.
 *
 * @param dir the parent directory
 * @param dentry the directory to be removed
 *
 * @return {@link ALLOW} or {@link DENY}
 */
SEC("lsm/inode_rmdir")
int BPF_PROG(seabee_inode_rmdir, struct inode *dir, struct dentry *dentry)
{
	return decide_inode_access(INODE_RMDIR, dentry->d_inode,
	                           dentry->d_name.name);
}

/**
 * @brief prevents modification of attributes on protected inodes
 *
 * @param dentry file
*/
SEC("lsm/inode_setattr")
#ifdef HAS_INODE_SETATTR_IDMAP
int BPF_PROG(seabee_inode_setattr, struct mnt_idmap *idmap,
             struct dentry *dentry, struct iattr *attr)
#else
int BPF_PROG(seabee_inode_setattr, struct dentry *dentry, struct iattr *attr)
#endif
{
	return decide_inode_access(INODE_SETATTR, dentry->d_inode,
	                           dentry->d_name.name);
}

/**
 * @brief prevent modification of extended attributes on protected inodes
 *
 * @param dentry file
*/
SEC("lsm/inode_setxattr")
#ifdef HAS_INODE_SETXATTR_IDMAP
int BPF_PROG(seabee_inode_setxattr, struct mnt_idmap *idmap,
             struct dentry *dentry, const char *name, const void *value,
             size_t size, int flags)
#else
int BPF_PROG(seabee_inode_setxattr, struct user_namespace *mnt_userns,
             struct dentry *dentry, const char *name, const void *value,
             size_t size, int flags)
#endif
{
	return decide_inode_access(INODE_SETXATTR, dentry->d_inode,
	                           dentry->d_name.name);
}

/**
 * @brief prevent rename of a protected inode
 *
 @param new_dentry the new file which will be replaced by old file
*/
SEC("lsm/inode_rename")
int BPF_PROG(seabee_inode_rename, struct inode *old_dir,
             struct dentry *old_dentry, struct inode *new_dir,
             struct dentry *new_dentry, unsigned int flags)
{
	return decide_inode_access(INODE_RENAME, new_dentry->d_inode,
	                           new_dentry->d_name.name);
}

/**
 * @brief Prevent unmounting the BPF filesystem
 *
 * @param mnt mounted filesystem
 * @param flags unmount flags
 * @param ret the return code of the previous LSM hook
 *
 * @return {@link ALLOW} or {@link DENY}
*/
SEC("lsm/sb_umount")
int BPF_PROG(seabee_sb_umount, struct vfsmount *mnt, int flags, int ret)
{
	int target = BPF_CORE_READ(mnt, mnt_sb, s_dev);
	if (target == bpf_dev_id || target == sys_dev_id) {
		log_sb_umount(LOG_LEVEL_WARN, LOG_REASON_DENY, target);
		return DENY;
	}
	return ALLOW;
}

/**
 * @brief Prevent a kernel module from being automatically loaded by the kernel.
 *
 * lsm/kernel_module_request is invoked when module auto-loading is triggered by
 * some attempt to access kernel functionality implemented by a module. It is
 * used internally by the kernel to check if loading a module is allowed.
 *
 * @param kmod_name the name of ther kernel module to be loaded
 *
 * @return {@link ALLOW} or {@link DENY}
 */
SEC("lsm/kernel_module_request")
int BPF_PROG(seabee_kernel_module_request, char *kmod_name)
{
	if (kmod_modification == (u32)SECURITY_BLOCK) {
		log_kernel_module_request(LOG_LEVEL_WARN, LOG_REASON_DENY,
		                          (const unsigned char *)kmod_name);
		return DENY;
	} else if (kmod_modification == (u32)SECURITY_AUDIT) {
		log_kernel_module_request(LOG_LEVEL_INFO, LOG_REASON_AUDIT,
		                          (const unsigned char *)kmod_name);
	}
	return ALLOW;
}

/**
 * @brief Blocks the loading of a kernel module via a file handle.
 *
 * lsm/kernel_read_file is invoked when the kernel is about to directly read
 * from a file or the file system specified by userspace for some purpose
 * including but not limited to kernel modules loaded via finit_module()
 *
 * enum kernel_load_data_id is the same as __kernel_read_file_id defined in
 * https://elixir.bootlin.com/linux/latest/source/include/linux/kernel_read_file.h#L9
 * It has several types including unknown, firmware, module, kexec-image,
 * kexec-initramfs, security-policy, and x509-certificate. kernel-module seems
 * most appropriate for our purposes, but the others should be taken into
 * account later on.
 *
 * @param file the file from which to read
 * @param id identifies the type of data that is being read
 * @param contents true if security_post_read_file() will be called
 *
 * @return {@link ALLOW} or {@link DENY}
 */
SEC("lsm/kernel_read_file")
int BPF_PROG(seabee_kernel_read_file, struct file *file,
             enum kernel_read_file_id id, bool contents)
{
	if (id == READING_MODULE && kmod_modification == (u32)SECURITY_BLOCK) {
		log_kernel_read_file(LOG_LEVEL_WARN, LOG_REASON_DENY, id,
		                     file->f_path.dentry->d_name.name);
		return DENY;
	} else if (kmod_modification == (u32)SECURITY_AUDIT) {
		log_kernel_read_file(LOG_LEVEL_INFO, LOG_REASON_AUDIT, id,
		                     file->f_path.dentry->d_name.name);
	}
	return ALLOW;
}

/**
 * @brief Blocks the loading of a kernel module via a data blob.
 *
 * lsm/kernel_load_data is invoked when userspace tries to load a data blob from
 * its memory into the kernel, including but not limited to kernel modules
 * loaded via init_module().
 *
 * enum kernel_load_data_id is the same as __kernel_read_file_id defined in
 * https://elixir.bootlin.com/linux/latest/source/include/linux/kernel_read_file.h#L9
 * It has several types including unknown, firmware, module, kexec-image,
 * kexec-initramfs, security-policy, and x509-certificate. kernel-module seems
 * most appropriate for our purposes, but the others should be taken into
 * account later on.
 *
 * @param id defines what kind of data is being read.
 * @param contents true if security_kernel_post_load_data() will be called
 *
 * @return {@link ALLOW} or {@link DENY}
 */
SEC("lsm/kernel_load_data")
int BPF_PROG(seabee_kernel_load_data, enum kernel_load_data_id id,
             bool contents)
{
	if (id == LOADING_MODULE && kmod_modification == (u32)SECURITY_BLOCK) {
		log_kernel_load_data(LOG_LEVEL_WARN, LOG_REASON_DENY, id);
		return DENY;
	} else if (kmod_modification == (u32)SECURITY_AUDIT) {
		log_kernel_load_data(LOG_LEVEL_INFO, LOG_REASON_AUDIT, id);
	}
	return ALLOW;
}

/**
 * @brief Blocks attempts to ptrace a protected process.
 *
 * This hook is called by a "tracer" process that is trying to use ptrace
 * on a "tracee" process. In this case, the "child" argument.
 *
 * note: there is also an lsm/ptrace_traceme hook. This hook is not checked
 * because it is only invoked by the child process.
 *
 * @param child the process that is going to be traced (tracee)
 * @param mode PTRACE_MODE flags, see linux/ptrace.h
 * @param ret the return code of the previous LSM hook
 *
 * @return {@link ALLOW} or {@link DENY}
 */
SEC("lsm/ptrace_access_check")
int BPF_PROG(seabee_ptrace_access_check, struct task_struct *child,
             unsigned int mode, int ret)
{
	// allow if tracee not tracked by SeaBee
	u32 tracee_label = get_target_task_pol_id(child);
	if (!tracee_label) {
		return ALLOW;
	}

	// otherwise take action based on config
	u32 tracer_label = get_task_pol_id();
	if (tracer_label != tracee_label) {
		enum SecurityLevel level = type_to_security_level(
			EVENT_TYPE_PTRACE_ACCESS_CHECK, tracee_label);
		switch (level) {
		case SECURITY_ALLOW:
			return ALLOW;
		case SECURITY_AUDIT:
			log_ptrace_access_check(LOG_LEVEL_INFO, LOG_REASON_AUDIT, child,
			                        mode, tracee_label);
			return ALLOW;
		case SECURITY_BLOCK:
			// info level because this hook generates a lot of noise
			log_ptrace_access_check(LOG_LEVEL_INFO, LOG_REASON_DENY, child,
			                        mode, tracee_label);
			return DENY;
		default: {
			u64 data[] = { level };
			log_generic_msg(
				LOG_LEVEL_ERROR, LOG_REASON_ERROR,
				"ptrace_access_check: nonexistent security level: %d", data,
				sizeof(data));
			return DENY;
		}
		}
	}
	return ALLOW;
}

/**
 * @brief Blocks attempts to fork() the seabee process.
 *
 * A fork() / clone() of the seabee process will inherit all of
 * the memory and file-descriptors of the parent process. This would
 * allow the child process to unload the BPF program or alter the map
 * contents. This is more of a safety-net than anything.
 *
 * @param task the process that is going to be forked
 * @param clone_flags flags from struct kernel_clone_args
 * @param ret the return code of the previous LSM hook
 *
 * @return {@link ALLOW} or {@link DENY}
 */
SEC("lsm/task_alloc")
int BPF_PROG(seabee_task_alloc, struct task_struct *task,
             unsigned long clone_flags, int ret)
{
	int caller_pid = get_pid();
	if (my_pid == caller_pid) {
		log_generic(LOG_LEVEL_WARN, LOG_REASON_DENY, EVENT_TYPE_TASK_ALLOC,
		            BASE_POLICY_ID);
		return DENY;
	}
	return ALLOW;
}

/**
 * @brief used to label a socket on creation.
 *
 * This will only label sockets created by the SeaBee userspace. Specifically
 * this is used to control access to SeaBee's listening socket to ensure only
 * seabeectl can connect to it.
 *
 * @param sock the socket being bound
 * @param address requested bind address
 * @param addrlen length of address
 *
 * @return {@link ALLOW} to allow access
 */
SEC("lsm/socket_bind")
int BPF_PROG(seabee_label_sock, struct socket *sock, struct sockaddr *address,
             int addrlen)
{
	// ignore sockets not created by SeaBee
	if (BASE_POLICY_ID != get_task_pol_id()) {
		return ALLOW;
	}

	// create new label
	u32          label     = BASE_POLICY_ID;
	u32         *new_label = NULL;
	struct sock *target    = sock->sk; // makes verifier happy
	if (target) {
		new_label = bpf_sk_storage_get(&sk_storage, target, &label,
		                               BPF_SK_STORAGE_GET_F_CREATE);
	}

	// log label creation
	if (new_label) {
		u64 data[1] = { label };
		log_generic_msg(LOG_LEVEL_DEBUG, LOG_REASON_DEBUG,
		                "label socket as %llu", data, sizeof(data));
		return ALLOW;
	}

	// If we fail to label the socket, it presents a huge security flaw,
	// return DENY to generate an error in the userspace
	log_generic_msg(LOG_LEVEL_ERROR, LOG_REASON_ERROR, "failed to label socket",
	                0, 0);
	return DENY;
}

/**
 * @brief check if a process is allowed to connect to a socket.
 *
 * This is used to enforce that only seabeectl is allowed to connect to
 * the listening socket of SeaBee in order to receive commands.
 *
 * @param sock originating sock
 * @param other peer sock
 * @param newsk new sock
 *
 * @return {@link ALLOW} to allow access
 */
SEC("lsm/unix_stream_connect")
int BPF_PROG(seabeectl_auth, struct sock *sock, struct sock *other,
             struct sock *newsk)
{
	u32 *sock_label = bpf_sk_storage_get(&sk_storage, other, 0, 0);
	if (sock_label && *sock_label == BASE_POLICY_ID) {
		u32 task_id = get_task_pol_id();
		if (task_id != BASE_POLICY_ID) {
			log_generic(LOG_LEVEL_WARN, LOG_REASON_DENY,
			            EVENT_TYPE_UNIX_STREAM_CONNECT, BASE_POLICY_ID);
			return DENY;
		}
	}
	return ALLOW;
}

/**
 * @brief Label a process when it starts
 *
 * This uses the path_to_pol_id map and the linux_binprm structure to
 * attach a label to a task based on the path of the executable that started
 * the task. This hook can be called multiple times during an execve, for
 * example, if executing a script.
 *
 * @param bprm holds information about a binary that is going to be executed
 *
 * @return {@link ALLOW} since this check is just for labeling and not
 * for enforcement
 */
SEC("lsm/bprm_check_security")
int BPF_PROG(seabee_label_process, struct linux_binprm *bprm, int ret)
{
	char *path = thread_safe_write_str_to_path(bprm->filename);
	if (!path) {
		u64 data[] = { (u64)data };
		log_generic_msg(LOG_LEVEL_ERROR, LOG_REASON_ERROR,
		                "Error: failed to write data '%s' to path buf", data,
		                sizeof(data));
		return ALLOW;
	}

	// Label task if path is in scope
	// TODO: this does not account for symbolic links, see https://github.com/NationalSecurityAgency/seabee/issues/12
	u32 *policy_id = bpf_map_lookup_elem(&path_to_pol_id, path);
	if (policy_id) {
		struct task_struct *task = get_task();
		label_task(task, bprm->file->f_path.dentry->d_name.name, *policy_id);
	}

	return ALLOW;
}

/**
 * @brief Label a child process with same policy id as its parent
 */
SEC("lsm/task_alloc")
int BPF_PROG(seabee_label_child_process, struct task_struct *child_task,
             unsigned long clone_flags)
{
	// don't label if parent has no label
	u32 parent_task_pol_id = get_task_pol_id();
	if (parent_task_pol_id == NO_POL_ID) {
		return ALLOW;
	}

	label_task(child_task, (const unsigned char *)child_task->comm,
	           parent_task_pol_id);
	return ALLOW;
}

// defined in vmlinux_features.h
#ifdef HAS_BPF_MAP_CREATE
/**
 * @brief Label an eBPF map on creation using the same label as the process that
 * created it
 */
SEC("lsm/bpf_map_create")
int BPF_PROG(seabee_label_map, struct bpf_map *map, union bpf_attr *attr,
             struct bpf_token *token, int ret)
{
	return label_map(map);
}

/**
 * @brief Unlabel an eBPF map when it is freed
 */
SEC("lsm/bpf_map_free")
int BPF_PROG(seabee_unlabel_map, struct bpf_map *map, int ret)
{
	return unlabel_map(map);
}
#else
/**
 * @brief Label a bpf map on creation using the same label as the process that
 * created it
 */
SEC("lsm/bpf_map_alloc_security")
int BPF_PROG(seabee_label_map, struct bpf_map *map, int ret)
{
	return label_map(map);
}

/**
 * @brief Unlabel an eBPF map when it is freed
 */
SEC("lsm/bpf_map_free_security")
int BPF_PROG(seabee_unlabel_map, struct bpf_map *map, int ret)
{
	return unlabel_map(map);
}
#endif

/**
 * @brief Used to identify a bpf program is being pinned
 */
SEC("lsm/bpf")
int BPF_PROG(seabee_start_pin, int cmd, union bpf_attr *attr, unsigned int size,
             int ret)
{
	if (cmd == BPF_OBJ_PIN) {
		set_task_pinning(true);
	}
	return ALLOW;
}

/**
 * @brief Label an inode associated with a bpf pin
 *
 * This hook is called when a dentry becomes associated with an inode.
 */
SEC("lsm/d_instantiate")
int BPF_PROG(seabee_label_pin, struct dentry *dentry, struct inode *inode)
{
	struct seabee_task_data *data = get_task_data();
	if (data && data->pol_id != NO_POL_ID && data->is_pinning) {
		label_inode(dentry, inode, data->pol_id);
	}
	return ALLOW;
}

/**
 * @brief Used to identify that a process has finished pinning
 */
SEC("tracepoint/syscalls/sys_exit_bpf")
int BPF_PROG(seabee_stop_pin, struct dentry *dentry, struct inode *inode)
{
	set_task_pinning(false);
	return ALLOW;
}

/**
 * @brief Label inodes created at runtime giving them the same
 * label as the parent
 *
 * security_d_instantiate is called whenever a dentry is first associated with
 * an inode. That could be on creation or when it is first looked up.
 *
 * @param dentry dentry
 * @param inode inode
*/
SEC("lsm/d_instantiate")
int BPF_PROG(seabee_label_inode_runtime, struct dentry *dentry,
             struct inode *inode)
{
	// don't label if parent has no label
	u32 parent_pol_id = get_inode_pol_id(dentry->d_parent->d_inode);
	if (parent_pol_id == NO_POL_ID) {
		return ALLOW;
	}
	// only label if child does not already have a label
	label_inode(dentry, inode, parent_pol_id);
	return ALLOW;
}
