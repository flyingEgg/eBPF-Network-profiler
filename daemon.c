#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/types.h>


#define TASK_COMM_LEN 16

int trace_tcp_connect(void *ctx) {

    // Obtain PID and TGID
    __u64 id = bpf_get_current_pid_tigd();
    __u32 pid = id >> 32;

    // Get process name (e.g. "firefox", "bash")
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_trace_printk("New TCP connection traced: %s (PID: %d)!\\n", comm, pid);

    return 0;
}