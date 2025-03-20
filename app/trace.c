//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char _license[] SEC("license") = "GPL";

#define ARGSIZE 256 

struct execve_event {
	__u8 filename[ARGSIZE];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("raw_tracepoint/sys_enter")
int handle_execve_raw_tp(struct bpf_raw_tracepoint_args *ctx) {
    struct execve_event *event;
    event = bpf_ringbuf_reserve(&events, sizeof(struct execve_event), 0);
    if (!event) {
	bpf_printk("could not reserve events ringbuf memory");
        return false;
    }

    // There is no method to attach a raw_tp or tp_btf directly to a single syscall... 
    // this is because there are no static defined tracepoints on single syscalls but only on generic sys_enter/sys_exit
    // So we have to filter by syscall ID
    unsigned long id = BPF_CORE_READ(ctx, args[1]); // Syscall ID is the second element
    if (id != 59) {   // execve sycall ID
	bpf_ringbuf_discard(event, 0);
	return 0;
    }

    struct pt_regs *regs = (struct pt_regs *)BPF_CORE_READ(ctx, args[0]);

    char *filename = (char *)PT_REGS_PARM1_CORE(regs);
    int ret = bpf_probe_read_user_str(&event->filename, sizeof(event->filename), filename);
    if (ret < 0) {
	bpf_printk("could not read filename into event struct: %d", ret);
	bpf_ringbuf_discard(event, 0);
	return 1;
    }

    bpf_ringbuf_submit(event, 0);

    return 0;
}
