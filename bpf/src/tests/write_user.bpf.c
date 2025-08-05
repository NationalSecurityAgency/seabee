// SPDX-License-Identifier: GPL-2.0-only
#include <bpf/vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MSG        "overwritten!"
#define MSG_LENGTH sizeof(MSG)

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096 /* one page */);
} ringbuf SEC(".maps");

SEC("uprobe")
int BPF_UPROBE(bpf_write_user, char *a_string)
{
	bpf_printk("activated rust test uprobe!");

	int *value;
	value = bpf_ringbuf_reserve(&ringbuf, sizeof(int), 0);
	if (value) {
		*value = 1;
		bpf_ringbuf_submit(value, 0);
	}

	//overwrite str
	const char new_msg[MSG_LENGTH] = MSG;
	int        ret = bpf_probe_write_user(a_string, &new_msg, MSG_LENGTH);
	if (ret < 0) {
		bpf_printk("write user failed, code %d", ret);
	}

	return 0;
}

char _license[] SEC("license") = "GPL";
