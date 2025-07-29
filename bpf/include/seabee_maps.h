// SPDX-License-Identifier: Apache-2.0
#ifndef SEABEE_MAPS_H_
#define SEABEE_MAPS_H_
/**
 * @file seabee_maps.h
 */

#include <bpf/vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "shared_rust_types.h"

struct seabee_task_data {
	u32 pol_id;
	u32 is_pinning; // treated like a bool
};

struct task_storage {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	// this flag is required for this map type
	__uint(map_flags, BPF_F_NO_PREALLOC);
	// must be 4 bytes
	__type(key, u32);
	// seabee task data
	__type(value, struct seabee_task_data);
};

struct inode_storage {
	__uint(type, BPF_MAP_TYPE_INODE_STORAGE);
	// this flag is required for this map type
	__uint(map_flags, BPF_F_NO_PREALLOC);
	// must be 4 bytes
	__type(key, u32);
	// policy id
	__type(value, u32);
};

struct sk_storage {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	// this flag is required for this map type
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, u32);
	// policy id
	__type(value, u32);
};

struct policy_map {
	/// @brief Hash map so we don't have to prealloc memory
	__uint(type, BPF_MAP_TYPE_HASH);
	/// @brief  enables more efficient memory usage
	__uint(map_flags, BPF_F_NO_PREALLOC);
	/// @brief a seabee policy ID
	__type(key, u32);
	/// @brief a seabee security policy
	__type(value, struct c_policy_config);
};

/**
 * SeaBee data for an eBPF map
 */
struct bpf_map_data {
	unsigned int policy_id;
	char         name[BPF_MAP_NAME_LEN];
};

struct map_to_pol_id {
	/// @brief Hash map so we don't have to prealloc memory
	__uint(type, BPF_MAP_TYPE_HASH);
	/// @brief  for more efficient memory usage
	__uint(map_flags, BPF_F_NO_PREALLOC);
	/// @brief map pointer
	__type(key, struct bpf_map *);
	/// @brief  map data
	__type(value, struct bpf_map_data);
};

#endif // SEABEE_MAPS_H_
