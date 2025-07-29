// SPDX-License-Identifier: GPL-2.0-only
/**
 * @file lable_file.bpf.c
 */

#include <bpf/vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "seabee_maps.h"
#include "seabee_utils.h"
#include "logging.h"

/// License of the BPF program
char LICENSE[] SEC("license") = "GPL";

/// @brief Pid of the userspace process
u32 user_pid;
/// @brief The level of the logs to filter out
u32 log_level;

// External maps
/// @brief local storage for inodes
struct inode_storage inode_storage SEC(".maps");
struct log_ringbuf log_ringbuf     SEC(".maps");

struct filename_to_policy_id {
	/// @brief Hashtable map type
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	/// @brief The name of a file, limited to MAX_NAME_LEN
	__type(key, char[MAX_STR_LEN]);
	/// @brief The policy id for this file
	__type(value, u32);
};
/// @brief Maps a filename to a policy id
struct filename_to_policy_id filename_to_policy_id SEC(".maps");

/**
 * @brief This hook is used to label files because it is an LSM hook that
 * provides a 'dentry' as an argument. This is important because a
 * 'struct file' is too broad and does not trigger on eBPF pins, but
 * a 'struct inode' is too granular because we do not know the name of
 * the inode on the filesystem which we want for logging.
 *
 * @param dir the parent directory
 * @param dentry the file being unlinked
 *
 * @return {@link ALLOW} or {@link DENY}
 */
SEC("lsm/inode_unlink")
int BPF_PROG(seabee_label_target_file, struct inode *dir, struct dentry *dentry)
{
	// only trigger for actions taken by associated user space
	u32 target_pid = bpf_get_current_pid_tgid() >> 32;
	if (target_pid != user_pid) {
		return ALLOW;
	}
	// get name of file
	const unsigned char *name = BPF_CORE_READ(dentry, d_name.name);
	char                 name_copy[MAX_STR_LEN] = { 0 };
	int                  err                    = 0;
	err = bpf_probe_read_kernel_str(&name_copy, sizeof(name_copy), name);
	if (err < 0) {
		u64 data[] = { (u64)name };
		log_generic_msg(LOG_LEVEL_ERROR, LOG_REASON_ERROR,
		                "Error: failed to copy '%s' to local buffer", data,
		                sizeof(data));
		return ALLOW;
	}

	// get policy_id and label inode
	u32 *policy_id = bpf_map_lookup_elem(&filename_to_policy_id, &name_copy);
	if (policy_id) {
		label_inode(dentry, dentry->d_inode, policy_id);
		// we don't actually want to delete this inode
		return DENY;
	}

	return ALLOW;
}
