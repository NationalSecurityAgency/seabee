// SPDX-License-Identifier: GPL-2.0-only
#ifndef SEABEE_UTILS_H_
#define SEABEE_UTILS_H_
/**
 * @file seabee_utils.h
 */

#include <bpf/vmlinux.h>
#include <bpf/bpf_helpers.h>

#include "seabee_maps.h"
#include "shared_rust_types.h"
#include "logging.h"
#include "logging_types.h"

/// An alias for the literal number 0.
#define ZERO  0
/// LSM return code for allowing an operation to continue.
#define ALLOW 0
/// LSM return code for denying an operation.
#define DENY  -1

extern struct inode_storage inode_storage;
extern struct task_storage  task_storage;
extern struct policy_map    policy_map;
extern struct map_to_pol_id map_to_pol_id;

/**
 * @brief gets the pid for the current context
 */
static __always_inline u32 get_pid()
{
	// we use tgid instead of pid because tgid == pid in userspace.
	// we want to protect all threads in our thread group (process)
	return bpf_get_current_pid_tgid() >> 32;
}

/**
 * @brief gets the task for the current context
 */
struct task_struct *get_task()
{
	return bpf_get_current_task_btf();
}

/**
 * @brief get the policy_config for a policy id
 *
 * @param policy_id target policy id
 *
 * @return a policy config associated with the policy_id or NULL if
 * none was found.
 */
static __always_inline struct c_policy_config *get_policy_config(u32 policy_id)
{
	return bpf_map_lookup_elem(&policy_map, &policy_id);
}

/**
 * @brief gets the data associated with current task
 *
 * @return the seabee_task_data for current task or NULL if task is not
 * tracked by seabee
 */
static __always_inline struct seabee_task_data *get_task_data()
{
	struct task_struct *task = get_task();
	return bpf_task_storage_get(&task_storage, task, 0, 0);
}

/**
 * @brief gets the policy id for a task
 *
 * @return the policy id for the task or NO_POL_ID
 */
static __always_inline u32 get_task_pol_id()
{
	struct seabee_task_data *data = get_task_data();
	if (data) {
		return data->pol_id;
	} else {
		return NO_POL_ID;
	}
}

/**
 * @brief Checks if this task is associataed with a SeaBee policy id.
 * If so, set a flag that determines whether or not the current task is
 * executing BPF_OBJ_PIN
 *
 * @param b a u32 that will be the new flag. 0 for false. 1 for true.
 */
static __always_inline void set_task_pinning(u32 flag)
{
	struct task_struct      *task = get_task();
	struct seabee_task_data *data =
		bpf_task_storage_get(&task_storage, task, 0, 0);
	if (data && data->pol_id != NO_POL_ID) {
		data->is_pinning = flag;
		// log
		u64 log[3]       = { (u64)task->comm, (u64)task->tgid, (u64)flag };
		log_generic_msg(LOG_LEVEL_TRACE, LOG_REASON_DEBUG,
		                "set task %s(%d) pinning to %lu", log, sizeof(log));
	}
}

/**
 * @brief label a task with a policy id
 *
 * @param task the task to label
 * @param policy_id the label for the task
 */
static __always_inline void label_task(struct task_struct  *task,
                                       const unsigned char *task_name,
                                       u32                  policy_id)
{
	struct seabee_task_data  new_data      = { policy_id, 0 };
	struct seabee_task_data *new_data_blob = bpf_task_storage_get(
		&task_storage, task, &new_data, BPF_LOCAL_STORAGE_GET_F_CREATE);
	u64 log[3] = { (u64)task_name, (u64)task->tgid, (u64)policy_id };
	if (new_data_blob) {
		log_generic_msg(LOG_LEVEL_TRACE, LOG_REASON_DEBUG,
		                "label task %s(%d) as %d", log, sizeof(log));
	} else {
		log_generic_msg(LOG_LEVEL_ERROR, LOG_REASON_ERROR,
		                "failed to label task %s(%d) as %d", log, sizeof(log));
	}
}

/**
 * @brief label an inode with a policy id
 *
 * @param dentry the dentry associated with the inode
 * @param inode the inode to label
 * @param policy_id the label to use
 */
static __always_inline void label_inode(struct dentry *dentry,
                                        struct inode *inode, u32 *policy_id)
{
	const unsigned char *name = dentry->d_name.name;
	u32 *label = bpf_inode_storage_get(&inode_storage, inode, policy_id,
	                                   BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (label) {
		u64 data[2] = { (u64)name, *label };
		log_generic_msg(LOG_LEVEL_TRACE, LOG_REASON_DEBUG,
		                "label file '%s' as %d", data, sizeof(data));
	} else {
		u64 data[1] = { (u64)name };
		log_generic_msg(LOG_LEVEL_ERROR, LOG_REASON_ERROR,
		                "failed to label file: %s", data, sizeof(data));
	}
}

/**
 * @brief label a map a with a policy id.
 *
 * @param map the map to label
 * @param policy_id the id for the map
 *
 * @return will return ALLOW
 */
static __always_inline int label_map_with_id(struct bpf_map *map, u32 policy_id)
{
	// unsure if map can be null, but this made the verifier happy
	if (!map) {
		return ALLOW;
	}

	struct bpf_map_data map_data;
	map_data.policy_id = policy_id;
	BPF_CORE_READ_STR_INTO(&map_data.name, map, name);

	long err = bpf_map_update_elem(&map_to_pol_id, &map, &map_data, BPF_ANY);
	u64  data[3] = { (u64)map_data.name, (u64)BPF_CORE_READ(map, id),
		             (u64)policy_id };
	if (err < 0) {
		log_generic_msg(LOG_LEVEL_ERROR, LOG_REASON_ERROR,
		                "Error: update elem failed map %s(%d) for policy %d",
		                data, sizeof(data));
	} else {
		log_generic_msg(LOG_LEVEL_TRACE, LOG_REASON_DEBUG,
		                "label map %s(%d) as %d", data, sizeof(data));
	}
	return ALLOW;
}

/**
 * @brief label a map automatically based the policy id of the current task.
 *
 * The label will be NO_POL_ID if task has no policy id associated with it.
 *
 * @param map the map to label
 *
 * @return will return ALLOW
 */
static __always_inline int label_map(struct bpf_map *map)
{
	return label_map_with_id(map, get_task_pol_id());
}

static __always_inline int unlabel_map(struct bpf_map *map)
{
	// unsure if map can be null, but this made the verifier happy
	if (!map) {
		return ALLOW;
	}

	// exit early if map is not tracked
	u32 *policy_id = bpf_map_lookup_elem(&map_to_pol_id, &map);
	if (!policy_id) {
		return ALLOW;
	}

	// delete map
	s32  err = bpf_map_delete_elem(&map_to_pol_id, &map);
	char map_name[BPF_MAP_NAME_LEN];
	BPF_CORE_READ_STR_INTO(&map_name, map, name);
	u64 data[] = { (u64)map_name, (u64)BPF_CORE_READ(map, id) };
	if (err < 0) {
		log_generic_msg(LOG_LEVEL_ERROR, LOG_REASON_ERROR,
		                "Error: failed to unlabel map: %s(%d)", data,
		                sizeof(data));
	} else {
		log_generic_msg(LOG_LEVEL_TRACE, LOG_REASON_DEBUG, "unlabel map %s(%d)",
		                data, sizeof(data));
	}
	return ALLOW;
}

#endif // SEABEE_UTILS_H_
