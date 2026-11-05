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
/// @brief Hashmap from policy id to policy config
struct policy_map policy_map       SEC(".maps");
struct log_ringbuf log_ringbuf     SEC(".maps");

/// @brief A request to add or remove a policy id
struct label_request {
	/// @brief The policy id
	u32 policy_id;
	/// @brief 0 to add the policy id, 1 to remove it
	u32 remove;
};

struct filename_to_policy_id {
	/// @brief Hashtable map type
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	/// @brief The name of a file, limited to MAX_NAME_LEN
	__type(key, char[MAX_STR_LEN]);
	/// @brief The label request for this file
	__type(value, struct label_request);
};
/// @brief Maps a filename to a policy id
struct filename_to_policy_id filename_to_policy_id SEC(".maps");

/**
 * @brief This hook is used to label files because it is an LSM hook that
 * is easy to trigger and provides our eBPF program access to an existing
 * dentry. This is important because a 'struct file' does not
 * trigger on eBPF pins, buta  'struct inode' is not connected to a name
 * which we use for initial labeling and for logging.
 *
 * @param path the path being labeled
 *
 * @return {@link ALLOW} or {@link DENY}
 */
SEC("lsm/inode_getattr")
int BPF_PROG(seabee_label_target_path, const struct path *path)
{
	// only trigger for actions taken by associated user space
	u32 target_pid = bpf_get_current_pid_tgid() >> 32;
	if (target_pid != user_pid) {
		return ALLOW;
	}
	// get name of file
	const unsigned char *name = BPF_CORE_READ(path, dentry, d_name.name);
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

	// get request and label or unlabel inode
	struct label_request *req =
		bpf_map_lookup_elem(&filename_to_policy_id, &name_copy);
	if (req) {
		if (req->remove) {
			unlabel_inode(path->dentry, path->dentry->d_inode, req->policy_id);
		} else if (label_inode(path->dentry, path->dentry->d_inode,
		                       req->policy_id) < 0) {
			// ALLOW signals to userspace that labeling failed
			return ALLOW;
		}
		// DENY signals to userspace that labeling worked
		return DENY;
	}

	return ALLOW;
}
