// SPDX-License-Identifier: GPL-2.0-only
/**
 * @file seabee.bpf.c
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <linux/version.h>

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
/// @brief A mask of the signals allowed to be sent to {@link my_pid}
u64 sigmask;
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

/// return 0 for no policy id
static __always_inline u32 get_inode_pol_id(struct inode *inode)
{
	u32 *policy_id = bpf_inode_storage_get(&inode_storage, inode, 0, 0);
	if (policy_id) {
		return *policy_id;
	} else {
		return NO_POL_ID;
	}
}

/// return 0 for no policy id
static __always_inline u32 get_map_pol_id(struct bpf_map *map)
{
	struct bpf_map_data *data = bpf_map_lookup_elem(&map_to_pol_id, &map);
	if (data) {
		return data->policy_id;
	} else {
		return NO_POL_ID;
	}
}

static __always_inline enum SecurityLevel
type_to_security_level(enum EventType type, u32 policy_id)
{
	struct c_policy_config *cfg = get_policy_config(policy_id);
	// If no config exists for a policy ID, then that policy must have been revoked
	if (!cfg) {
		return SECURITY_ALLOW;
	}

	switch (type) {
	case EVENT_TYPE_FILE_OPEN:
		return cfg->file_modification;
	case EVENT_TYPE_INODE_UNLINK:
		return cfg->pin_removal;
	case EVENT_TYPE_BPF_MAP:
		return cfg->map_access;
	default: { // Brackets needed see: https://en.cppreference.com/w/cpp/language/switch#Notes
		u64 data[] = { (u64)policy_id, (u64)type };
		log_generic_msg(LOG_LEVEL_ERROR, LOG_REASON_ERROR,
		                "Error: security uninit for id %d, type: %d", data,
		                sizeof(data));
		return SECURITY_UNINIT;
	}
	}
}

static __always_inline u32 decide_inode_access(enum EventType type,
                                               struct dentry *dentry)
{
	u32 inode_pol_id = get_inode_pol_id(dentry->d_inode);
	if (inode_pol_id == NO_POL_ID) {
		return ALLOW;
	}
	u32 pid_pol_id = get_task_pol_id();

	// Same policy id: Allow
	if (pid_pol_id == inode_pol_id) {
		return ALLOW;
	}

	// take action based on security level
	enum SecurityLevel level = type_to_security_level(type, inode_pol_id);
	switch (level) {
	case SECURITY_ALLOW:
		return ALLOW;
	case SECURITY_AUDIT:
		log_inode_access(type, LOG_LEVEL_INFO, LOG_REASON_AUDIT,
		                 dentry->d_name.name, inode_pol_id);
		return ALLOW;
	case SECURITY_BLOCKED:
		log_inode_access(type, LOG_LEVEL_WARN, LOG_REASON_DENY,
		                 dentry->d_name.name, inode_pol_id);
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
	case SECURITY_BLOCKED:
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
 * the {@link ZERO} signal and any signal specified in the {@link sigmask}
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
	// we use p->tgid instead of p->pid because p->pid actually gives tid for threads.
	// we want to protect all threads in out thread group (process)
	int target_pid = BPF_CORE_READ(p, tgid);
	int sender_pid = -1;
	// if this produces a compiler warning, it is okay
	if (info != NULL && (long)info != 1) {
		sender_pid = BPF_CORE_READ(info, _sifields._kill._pid);
	}

	// Deny any process from killing my group
	if (target_pid == my_pid) {
		// compare signal with sigmask
		if (sig == ZERO || (1ULL << (sig - 1)) & sigmask) {
			log_task_kill(LOG_LEVEL_DEBUG, LOG_REASON_ALLOW, target_pid,
			              p->comm, sig);
			return ALLOW;
		}
		log_task_kill(LOG_LEVEL_WARN, LOG_REASON_DENY, target_pid, p->comm,
		              sig);
		return DENY;
	}
	return ALLOW;
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
	return decide_inode_access(EVENT_TYPE_FILE_OPEN, file->f_path.dentry);
}

/**
 * @brief Prevents unlinking/removing the protected pins.
 *
 * @param dir the parent directory
 * @param dentry the file being unlinked
 * @param ret the return code of the previous LSM hook
 *
 * @return {@link ALLOW} or {@link DENY}
 */
SEC("lsm/inode_unlink")
int BPF_PROG(seabee_inode_unlink, struct inode *dir, struct dentry *dentry,
             int ret)
{
	return decide_inode_access(EVENT_TYPE_INODE_UNLINK, dentry);
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
	if (kmod_modification == (u32)SECURITY_BLOCKED) {
		log_kernel_module_request(LOG_LEVEL_WARN, LOG_REASON_DENY,
		                          (const unsigned char *)kmod_name);
		return DENY;
	}
	log_kernel_module_request(LOG_LEVEL_INFO, LOG_REASON_ALLOW,
	                          (const unsigned char *)kmod_name);
	return ALLOW;
}

/**
 * @brief Blocks the loading of a kernel module via a file handle.
 *
 * lsm/kernel_read_file is invoked when the kernel is about to directly read
 * from a file or the file system specified by userspace for some purpose
 * including but not limited to kernel modules laoded via finit_module()
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
	if (id == READING_MODULE) {
		log_kernel_read_file(LOG_LEVEL_WARN, LOG_REASON_DENY, id,
		                     file->f_path.dentry->d_name.name);
		return DENY;
	}
	log_kernel_read_file(LOG_LEVEL_INFO, LOG_REASON_ALLOW, id,
	                     file->f_path.dentry->d_name.name);
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
	if (id == LOADING_MODULE) {
		log_kernel_load_data(LOG_LEVEL_WARN, LOG_REASON_DENY, id);
		return DENY;
	}
	log_kernel_load_data(LOG_LEVEL_INFO, LOG_REASON_ALLOW, id);
	return ALLOW;
}

/**
 * @brief Blocks attempts to trace the seabee userspace process.
 *
 * This hook is not loaded if ptrace protections are disabled.
 *
 * note: there is also an lsm/ptrace_traceme hook. This hook is not checked
 * because it is only invoked by the child process. Since our process will
 * not ask to be ptraced. We do not need to implement that hook. If our process
 * is exec'd by a process that is being ptraced already, we believe we have
 * already lost all security.
 *
 * @param child the process that is going to be traced
 * @param mode PTRACE_MODE flags
 * @param ret the return code of the previous LSM hook
 *
 * @return {@link ALLOW} or {@link DENY}
 */
SEC("lsm/ptrace_access_check")
int BPF_PROG(seabee_ptrace_access_check, struct task_struct *child,
             unsigned int mode, int ret)
{
	// we use p->tgid instead of p->pid because p->pid actually gives tid for threads.
	// we want to protect all threads in our thread group (process)
	int tracee_pid = BPF_CORE_READ(child, tgid);
	if (my_pid == tracee_pid) {
		log_ptrace_access_check(LOG_LEVEL_INFO, LOG_REASON_DENY, tracee_pid,
		                        child->comm);
		return DENY;
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
	u32 parent_task_pol_id = get_task_pol_id();
	if (parent_task_pol_id != NO_POL_ID) {
		label_task(child_task, child_task->comm, parent_task_pol_id);
	}

	return ALLOW;
}

#if BPF_CODE_VERSION >= KERNEL_VERSION(6, 9, 0)
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
 * @brief Label an inode associted with a bpf pin
 *
 * This hook is called when a dentry becomes associted with an inode.
 */
SEC("lsm/d_instantiate")
int BPF_PROG(seabee_label_pin, struct dentry *dentry, struct inode *inode,
             int ret)
{
	struct seabee_task_data *data = get_task_data();
	if (data && data->pol_id != NO_POL_ID && data->is_pinning) {
		label_inode(dentry, inode, &data->pol_id);
	}
	return ALLOW;
}

/**
 * @brief Used to identify that a process has finished pinning
 */
SEC("tracepoint/syscalls/sys_exit_bpf")
int BPF_PROG(seabee_stop_pin, struct dentry *dentry, struct inode *inode,
             int ret)
{
	set_task_pinning(false);
	return ALLOW;
}
