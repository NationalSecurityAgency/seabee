// SPDX-License-Identifier: GPL-2.0-only
#ifndef LOGGING_H_
#define LOGGING_H_
/**
 * @file logging.h
 */

#include <bpf/vmlinux.h>
#include <bpf/bpf_helpers.h>

#include "logging_types.h"
#include "shared_rust_types.h"

/// 256KB is the default, but can be set in the skeleton before load
#define DEFAULT_RINGBUF_SIZE (256 * 1024)

/// @brief Ring buffer structure that the user space will read logs from
struct log_ringbuf {
	/// @brief Ringbuffer map type
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	/// @brief Can be updated with OpenMap::set_max_entries()
	__uint(max_entries, DEFAULT_RINGBUF_SIZE);
};

/// Defined in each .bpf.c file. Specifies which logs to output to the ringbuf
extern u32                log_level;
/// Defined in each .bpf.c file. Specifies the ringbuf map to output logs to
extern struct log_ringbuf log_ringbuf;

/**
 * Decides whether a log should be output and if so, reserve space
 * in the ringbuf and populate the header.
 *
 * @param level The severity of the outgoing log
 * @param reason The reason for the log being sent
 * @param type The log structure being used
 * @param size The length of the log (in bytes) to reserve from the ringbuf
 *
 * @return buffer if being logged, NULL if not
 */
static inline void *log_buf(enum LogLevel level, enum LogReason reason,
                            enum EventType type, size_t size,
                            unsigned long pol_id)
{
	if (level > log_level)
		return NULL;

	void *log = bpf_ringbuf_reserve(&log_ringbuf, size, 0);
	if (!log) {
		bpf_printk("Unable to reserve from ringbuf of size %lu", size);
		return NULL;
	}

	struct log_hdr *hdr = (struct log_hdr *)log;
	hdr->level          = level;
	hdr->type           = type;
	hdr->reason         = reason;
	// kernel tgid == user space process id
	// kernel pid == user space thread id
	u64 pid_tgid        = bpf_get_current_pid_tgid();
	hdr->pid            = pid_tgid >> 32;
	hdr->tid            = pid_tgid & 0xFFFFFFFF;
	hdr->uid            = bpf_get_current_uid_gid() & 0xFFFFFFFF;
	hdr->pol_id         = pol_id;
	bpf_get_current_comm(hdr->comm, sizeof(hdr->comm));
	return log;
}

static inline void log_generic(enum LogLevel level, enum LogReason reason,
                               enum EventType type, unsigned int pol_id)
{
	void *log = log_buf(level, reason, type, sizeof(struct log_hdr), pol_id);
	if (log) {
		bpf_ringbuf_submit(log, 0);
	}
}

/**
 * @brief logs a message to userspace.
 *
 * @param level the severity of the log
 * @param fmt a format string, see documentation for bpf_snprintf
 * @param data a data array for the corresponding fmt string, see
 * documentation for bpf_snprintf. can be initialized like:
 * u64 data [2] = {(u64) str_ptr, a_number};
 * @param data_len the length of data
*/
static inline void log_generic_msg(enum LogLevel level, enum LogReason reason,
                                   const char *fmt, __u64 *data, __u32 data_len)
{
	struct generic_msg_log *log;
	log = log_buf(level, reason, EVENT_TYPE_MSG, sizeof(*log), NO_POL_ID);
	if (log) {
		long ret = bpf_snprintf((char *)log->msg, sizeof(log->msg), fmt, data,
		                        data_len);
		if (ret < 0) {
			bpf_printk("Error: log_generic_msg: bpf_snprintf failed");
		}
		bpf_ringbuf_submit(log, 0);
	}
}

#endif // LOGGING_H_
