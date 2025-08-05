// SPDX-License-Identifier: GPL-2.0-only
/**
 * @file lable_task.bpf.c
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
/// @brief the policy_id for the userspace process
u32 policy_id;
/// @brief The level of the logs to filter out
u32 log_level;

// External maps
/// @brief local storage for tasks
struct task_storage task_storage SEC(".maps");
struct log_ringbuf log_ringbuf   SEC(".maps");

/**
 * @brief This hook was chosen to label files because it is an LSM
 * making it relatively stable, it is simple to trigger, and it will
 * not be called many times during the duration of the program,
 * making it low overhead.
*/
SEC("lsm/file_open")
int BPF_PROG(seabee_label_target_process, struct file *file)
{
	if (get_pid() == user_pid) {
		struct task_struct *task = get_task();
		label_task(task, task->comm, policy_id);
	}

	return ALLOW;
}
