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

/// return NULL for no policy ids
static __always_inline struct pol_ids *get_inode_pol_ids(struct inode *inode)
{
	return bpf_inode_storage_get(&inode_storage, inode, 0, 0);
}

/// return NULL for no policy ids
static __always_inline struct pol_ids *get_map_pol_ids(struct bpf_map *map)
{
	struct bpf_map_data *data = bpf_map_lookup_elem(&map_to_pol_id, &map);
	if (data) {
		return &data->pol_ids;
	} else {
		return NULL;
	}
}

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
	if (policy_id == NO_POL_ID) {
		return NULL;
	}
	return bpf_map_lookup_elem(&policy_map, &policy_id);
}

/**
 * @brief checks if there is a valid policy configuration for the policy id
 *
 * @param policy_id target policy id
 *
 * @return true if the policy id has a valid config, false otherwise
 */
static __always_inline bool is_valid_policy_id(u32 policy_id)
{
	return get_policy_config(policy_id) != NULL;
}

/**
 * @brief checks if a set of policy ids contains a policy id
 *
 * @param pol_ids the set, may be NULL
 * @param policy_id the policy id to find
 *
 * @return true if found
 */
static __always_inline bool has_pol_id(const struct pol_ids *pol_ids,
                                       u32                   policy_id)
{
	if (!pol_ids || policy_id == NO_POL_ID) {
		return false;
	}
#pragma unroll
	for (int i = 0; i < MAX_POL_IDS; i++) {
		if (pol_ids->ids[i] == policy_id) {
			return true;
		}
	}
	return false;
}

/**
 * @brief adds a policy id to a set of policy ids. A slot is free if it holds
 * NO_POL_ID or an id that no longer has a policy.
 *
 * @param pol_ids the set
 * @param policy_id the policy id to add
 *
 * @return 0 if the id was added or already present, -1 if the set is full
 */
static __always_inline int add_pol_id(struct pol_ids *pol_ids, u32 policy_id)
{
	if (has_pol_id(pol_ids, policy_id)) {
		return 0;
	}
#pragma unroll
	for (int i = 0; i < MAX_POL_IDS; i++) {
		if (!is_valid_policy_id(pol_ids->ids[i])) {
			pol_ids->ids[i] = policy_id;
			return 0;
		}
	}
	return -1;
}

/**
 * @brief removes a policy id from a set of policy ids
 *
 * @param pol_ids the set
 * @param policy_id the policy id to remove
 */
static __always_inline void remove_pol_id(struct pol_ids *pol_ids,
                                          u32             policy_id)
{
#pragma unroll
	for (int i = 0; i < MAX_POL_IDS; i++) {
		if (pol_ids->ids[i] == policy_id) {
			pol_ids->ids[i] = NO_POL_ID;
		}
	}
}

/**
 * @brief checks if a set of policy ids holds at least one valid policy id
 *
 * @param pol_ids the set, may be NULL
 *
 * @return true if a valid policy id was found
 */
static __always_inline bool has_valid_pol_id(const struct pol_ids *pol_ids)
{
	if (!pol_ids) {
		return false;
	}
#pragma unroll
	for (int i = 0; i < MAX_POL_IDS; i++) {
		if (is_valid_policy_id(pol_ids->ids[i])) {
			return true;
		}
	}
	return false;
}

/**
 * @brief gets the data associated with a particular task
 *
 * @param t target task
 *
 * @return the seabee_task_data for the target task or NULL if task is not
 * tracked by seabee
 */
static __always_inline struct seabee_task_data *
get_target_task_data(struct task_struct *t)
{
	return bpf_task_storage_get(&task_storage, t, 0, 0);
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
	return get_target_task_data(task);
}

/**
 * @brief gets the policy ids for a target task
 *
 * @param t the target task
 * @return the policy ids for the task or NULL
 */
static __always_inline struct pol_ids *
get_target_task_pol_ids(struct task_struct *t)
{
	struct seabee_task_data *data = get_target_task_data(t);
	if (data) {
		return &data->pol_ids;
	} else {
		return NULL;
	}
}

/**
 * @brief gets the policy ids for the current task
 *
 * @return the policy ids for the task or NULL
 */
static __always_inline struct pol_ids *get_task_pol_ids()
{
	return get_target_task_pol_ids(get_task());
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
	// Check task is tracked by SeaBee
	struct task_struct      *task = get_task();
	struct seabee_task_data *data =
		bpf_task_storage_get(&task_storage, task, 0, 0);
	if (!data) {
		return;
	}
	// Check pin protections are enabled for one of its policies
	bool protect_pins = false;
#pragma unroll
	for (int i = 0; i < MAX_POL_IDS; i++) {
		struct c_policy_config *cfg = get_policy_config(data->pol_ids.ids[i]);
		if (cfg && cfg->protect_pins) {
			protect_pins = true;
		}
	}
	// set flag if it has changed
	if (protect_pins && data->is_pinning != flag) {
		data->is_pinning = flag;
		u64 log[3]       = { (u64)task->comm, (u64)task->tgid, (u64)flag };
		log_generic_msg(LOG_LEVEL_TRACE, LOG_REASON_DEBUG,
		                "set task %s(%d) pinning to %lu", log, sizeof(log));
	}
}

/**
 * @brief label a task with a policy id. A task can have up to
 * MAX_POL_IDS policy ids.
 *
 * @param task the task to label
 * @param policy_id the label for the task
 */
static __always_inline void label_task(struct task_struct  *task,
                                       const unsigned char *task_name,
                                       u32                  policy_id)
{
	u64 log[3] = { (u64)task_name, (u64)task->tgid, (u64)policy_id };
	if (!is_valid_policy_id(policy_id)) {
		// Don't propagate invalid policy ids
		log_generic_msg(LOG_LEVEL_TRACE, LOG_REASON_DEBUG,
		                "Did not label task %s(%d) since %d is invalid", log,
		                sizeof(log));
		return;
	}
	struct seabee_task_data  new_data = { 0 };
	struct seabee_task_data *data     = bpf_task_storage_get(
        &task_storage, task, &new_data, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!data) {
		log_generic_msg(LOG_LEVEL_ERROR, LOG_REASON_ERROR,
		                "failed to label task %s(%d) as %d", log, sizeof(log));
		return;
	}
	if (has_pol_id(&data->pol_ids, policy_id)) {
		// Already labeled
		return;
	}
	if (add_pol_id(&data->pol_ids, policy_id) < 0) {
		log_generic_msg(
			LOG_LEVEL_ERROR, LOG_REASON_ERROR,
			"failed to label task %s(%d) as %d. Task has too many policies",
			log, sizeof(log));
		return;
	}
	log_generic_msg(LOG_LEVEL_DEBUG, LOG_REASON_DEBUG,
	                "label task %s(%d) as %d", log, sizeof(log));
}

/**
 * @brief label a task with every valid policy id in a set
 *
 * @param task the task to label
 * @param task_name name used for logging
 * @param pol_ids the policy ids
 */
static __always_inline void label_task_with_ids(struct task_struct   *task,
                                                const unsigned char  *task_name,
                                                const struct pol_ids *pol_ids)
{
#pragma unroll
	for (int i = 0; i < MAX_POL_IDS; i++) {
		u32 policy_id = pol_ids->ids[i];
		if (is_valid_policy_id(policy_id)) {
			label_task(task, task_name, policy_id);
		}
	}
}

/**
 * @brief label an inode with a policy id. An inode can have up to
 * MAX_POL_IDS policy ids.
 *
 * @param dentry the dentry associated with the inode
 * @param inode the inode to label
 * @param policy_id the label to use
 *
 * @return 0 if the inode has the label, -1 otherwise
 */
static __always_inline int label_inode(struct dentry *dentry,
                                       struct inode *inode, u32 policy_id)
{
	const unsigned char *name   = dentry->d_name.name;
	u64                  log[2] = { (u64)name, (u64)policy_id };
	if (!is_valid_policy_id(policy_id)) {
		// Don't propagate invalid policy ids
		log_generic_msg(LOG_LEVEL_TRACE, LOG_REASON_DEBUG,
		                "Did not label inode %s since %d is invalid", log,
		                sizeof(log));
		return -1;
	}
	struct pol_ids  new_ids = { 0 };
	struct pol_ids *ids = bpf_inode_storage_get(&inode_storage, inode, &new_ids,
	                                            BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!ids) {
		log_generic_msg(LOG_LEVEL_ERROR, LOG_REASON_ERROR,
		                "failed to label inode for %s as %d", log, sizeof(log));
		return -1;
	}
	if (has_pol_id(ids, policy_id)) {
		// Already labeled
		return 0;
	}
	if (add_pol_id(ids, policy_id) < 0) {
		log_generic_msg(
			LOG_LEVEL_ERROR, LOG_REASON_ERROR,
			"failed to label inode for %s as %d. Inode has too many policies",
			log, sizeof(log));
		return -1;
	}
	log_generic_msg(LOG_LEVEL_TRACE, LOG_REASON_DEBUG,
	                "label inode for '%s' as %d", log, sizeof(log));
	return 0;
}

/**
 * @brief label an inode with every valid policy id in a set
 *
 * @param dentry the dentry associated with the inode
 * @param inode the inode to label
 * @param pol_ids the policy ids
 */
static __always_inline void label_inode_with_ids(struct dentry        *dentry,
                                                 struct inode         *inode,
                                                 const struct pol_ids *pol_ids)
{
#pragma unroll
	for (int i = 0; i < MAX_POL_IDS; i++) {
		u32 policy_id = pol_ids->ids[i];
		if (is_valid_policy_id(policy_id)) {
			label_inode(dentry, inode, policy_id);
		}
	}
}

/**
 * @brief remove a policy id from an inode
 *
 * @param dentry the dentry associated with the inode
 * @param inode the inode to unlabel
 * @param policy_id the label to remove
 */
static __always_inline void unlabel_inode(struct dentry *dentry,
                                          struct inode *inode, u32 policy_id)
{
	struct pol_ids *ids = get_inode_pol_ids(inode);
	if (ids) {
		remove_pol_id(ids, policy_id);
	}
	u64 log[2] = { (u64)dentry->d_name.name, (u64)policy_id };
	log_generic_msg(LOG_LEVEL_TRACE, LOG_REASON_DEBUG,
	                "unlabel inode for '%s' as %d", log, sizeof(log));
}

/**
 * @brief label a map with a policy id.
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

	char map_name[BPF_MAP_NAME_LEN];
	BPF_CORE_READ_STR_INTO(&map_name, map, name);
	u64 data[3] = { (u64)map_name, (u64)BPF_CORE_READ(map, id),
		            (u64)policy_id };

	// add to an existing label
	struct bpf_map_data *map_data = bpf_map_lookup_elem(&map_to_pol_id, &map);
	if (map_data) {
		if (add_pol_id(&map_data->pol_ids, policy_id) < 0) {
			log_generic_msg(LOG_LEVEL_ERROR, LOG_REASON_ERROR,
			                "Error: map %s(%d) has too many policies to add %d",
			                data, sizeof(data));
		} else {
			log_generic_msg(LOG_LEVEL_TRACE, LOG_REASON_DEBUG,
			                "label map %s(%d) as %d", data, sizeof(data));
		}
		return ALLOW;
	}

	// create a new label
	struct bpf_map_data new_data = { 0 };
	new_data.pol_ids.ids[0]      = policy_id;
	BPF_CORE_READ_STR_INTO(&new_data.name, map, name);
	long err =
		bpf_map_update_elem(&map_to_pol_id, &map, &new_data, BPF_NOEXIST);
	if (err < 0) {
		u64 err_data[4] = { (u64)map_name, (u64)BPF_CORE_READ(map, id),
			                (u64)policy_id, (u64)err };
		log_generic_msg(
			LOG_LEVEL_ERROR, LOG_REASON_ERROR,
			"Error: update elem failed map %s(%d) for policy %d, code: %d",
			err_data, sizeof(err_data));
	} else {
		log_generic_msg(LOG_LEVEL_TRACE, LOG_REASON_DEBUG,
		                "label map %s(%d) as %d", data, sizeof(data));
	}
	return ALLOW;
}

/**
 * @brief label a map automatically based the policy ids of the current task.
 *
 * The map is not labeled if the task has no valid policy id.
 *
 * @param map the map to label
 *
 * @return will return ALLOW
 */
static __always_inline int label_map(struct bpf_map *map)
{
	struct pol_ids *task_ids = get_task_pol_ids();
	if (!task_ids) {
		return ALLOW;
	}
#pragma unroll
	for (int i = 0; i < MAX_POL_IDS; i++) {
		u32 policy_id = task_ids->ids[i];
		if (is_valid_policy_id(policy_id)) {
			label_map_with_id(map, policy_id);
		}
	}
	return ALLOW;
}

static __always_inline int unlabel_map(struct bpf_map *map)
{
	// unsure if map can be null, but this made the verifier happy
	if (!map) {
		return ALLOW;
	}

	// exit early if map is not tracked
	struct bpf_map_data *map_data = bpf_map_lookup_elem(&map_to_pol_id, &map);
	if (!map_data) {
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
