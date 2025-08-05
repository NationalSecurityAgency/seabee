// SPDX-License-Identifier: GPL-2.0-only
/**
 * @file test_tool.bpf.c
 */

#include <bpf/vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/// License of the BPF program
char LICENSE[] SEC("license") = "GPL";

#define LOG_SIZE 128
#define ALLOW    0

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} ringbuf SEC(".maps");

struct log_entry {
	char name[LOG_SIZE];
};

/**
 * @brief used for testing
*/
SEC("lsm/file_open")
int BPF_PROG(test_seabee, struct file *file)
{
	// reserve ringbuf space
	struct log_entry *log = bpf_ringbuf_reserve(&ringbuf, LOG_SIZE, 0);
	if (!log) {
		bpf_printk("Unable to reserve from ringbuf of size %lu", LOG_SIZE);
		return ALLOW;
	}

	// get data
	s32 err = bpf_probe_read_kernel_str(log->name, LOG_SIZE,
	                                    file->f_path.dentry->d_name.name);
	if (err < 0) {
		bpf_printk("error reading name");
	}

	// log data
	bpf_ringbuf_submit(log, 0);

	return ALLOW;
}
