// SPDX-License-Identifier: GPL-2.0-only
#ifndef SEABEE_ENFORCE_LOG_H_
#define SEABEE_ENFORCE_LOG_H_
/**
 * @file seabee_log.h
 */

#include "logging.h"
#include "seabee_utils.h"
#include "shared_rust_types.h"

static inline void log_sb_umount(enum LogLevel level, enum LogReason reason,
                                 unsigned long target_dev)
{
	struct sb_umount_log *log;
	log = log_buf(level, reason, EVENT_TYPE_SB_UMOUNT, sizeof(*log), NO_POL_ID);
	if (log) {
		log->target_dev = target_dev;
		bpf_ringbuf_submit(log, 0);
	}
}

static inline void log_bpf_map(enum LogLevel level, enum LogReason reason,
                               struct bpf_map *map, unsigned int pol_id)
{
	struct bpf_map_log *log;
	log = log_buf(level, reason, EVENT_TYPE_BPF_MAP, sizeof(*log), pol_id);
	if (log) {
		log->map_id = map->id;
		BPF_CORE_READ_STR_INTO(&log->name, map, name);
		bpf_ringbuf_submit(log, 0);
	}
}

static inline void log_kernel_module_request(enum LogLevel        level,
                                             enum LogReason       reason,
                                             const unsigned char *kmod_name)
{
	struct kernel_module_request_log *log;
	log = log_buf(level, reason, EVENT_TYPE_KERNEL_MODULE_REQUEST, sizeof(*log),
	              NO_POL_ID);
	if (log) {
		bpf_probe_read_str(log->kmod_name, sizeof(log->kmod_name), kmod_name);
		bpf_ringbuf_submit(log, 0);
	}
}

static inline void log_task_kill(enum LogLevel level, enum LogReason reason,
                                 int target_pid, char *target_comm, int signum)
{
	struct task_kill_log *log;
	log = log_buf(level, reason, EVENT_TYPE_TASK_KILL, sizeof(*log), NO_POL_ID);
	if (log) {
		log->target_pid = target_pid;
		bpf_probe_read_str(log->target_comm, sizeof(log->target_comm),
		                   target_comm);
		log->signum = signum;
		bpf_ringbuf_submit(log, 0);
	}
}

static inline void log_kernel_read_file(enum LogLevel  level,
                                        enum LogReason reason, unsigned int id,
                                        const unsigned char *filename)
{
	struct kernel_read_file_log *log;
	log = log_buf(level, reason, EVENT_TYPE_KERNEL_READ_FILE, sizeof(*log),
	              NO_POL_ID);
	if (log) {
		log->id = id;
		bpf_probe_read_str(log->filename, sizeof(log->filename), filename);
		bpf_ringbuf_submit(log, 0);
	}
}

static inline void log_kernel_load_data(enum LogLevel  level,
                                        enum LogReason reason, unsigned int id)
{
	struct kernel_load_data_log *log;
	log = log_buf(level, reason, EVENT_TYPE_KERNEL_LOAD_DATA, sizeof(*log),
	              NO_POL_ID);
	if (log) {
		log->id = id;
		bpf_ringbuf_submit(log, 0);
	}
}

static inline void log_ptrace_access_check(enum LogLevel  level,
                                           enum LogReason reason,
                                           int target_pid, char *target_comm)
{
	struct ptrace_access_check_log *log;
	log = log_buf(level, reason, EVENT_TYPE_PTRACE_ACCESS_CHECK, sizeof(*log),
	              NO_POL_ID);
	if (log) {
		log->target_pid = target_pid;
		bpf_probe_read_str(log->target_comm, sizeof(log->target_comm),
		                   target_comm);
		bpf_ringbuf_submit(log, 0);
	}
}

static inline void log_inode_access(enum EventType type, enum LogLevel level,
                                    enum LogReason       reason,
                                    const unsigned char *file_name,
                                    unsigned int         pol_id)
{
	struct inode_access_log *log;
	log = log_buf(level, reason, type, sizeof(*log), pol_id);
	if (log) {
		bpf_probe_read_str(log->name, sizeof(log->name), file_name);
		bpf_ringbuf_submit(log, 0);
	}
}

#endif // SEABEE_ENFORCE_LOG_H_
