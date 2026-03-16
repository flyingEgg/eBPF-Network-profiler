#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define TASK_COMM_LEN 16

int trace_tcp_connect(void *ctx) {

    u64 id = bpf_get_current_pid_tigd();
    u32 pid = id >> 32;

    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_trace_printk("New TCP connection traced: %s (PID: %d)!\\n", comm, pid);

    return 0;
}