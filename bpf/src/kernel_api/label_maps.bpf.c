// SPDX-License-Identifier: GPL-2.0-only
/**
 * @file lable_maps.bpf.c
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

/// @brief Filter our logs below this level
u32 log_level;

// maps
struct map_to_pol_id map_to_pol_id SEC(".maps");
struct log_ringbuf log_ringbuf     SEC(".maps");

struct map_id_to_pol_id {
	/// @brief Hashtable map type
	__uint(type, BPF_MAP_TYPE_HASH);
	/// @brief A map id to label
	__type(key, u32);
	/// @brief The policy id for this map
	__type(value, u32);
};
/// @brief A list of map ids to label
struct map_id_to_pol_id map_id_to_pol_id SEC(".maps");

/**
 * @brief label a map whe the map is accessed. This function is triggered by
 * bpf_get_fd_by_id.
 *
 * @param map an eBPF map that is being accessed
 *
 * @return always return ALLOW
 */
SEC("lsm/bpf_map")
int BPF_PROG(seabee_label_target_map, struct bpf_map *map, fmode_t fmode,
             int ret)
{
	u32  map_id    = BPF_CORE_READ(map, id);
	u32 *policy_id = bpf_map_lookup_elem(&map_id_to_pol_id, &map_id);
	if (policy_id) {
		label_map_with_id(map, *policy_id);
	}

	return ALLOW;
}
