#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/bpf.h>
#include <vmlinux.h>


#define TASK_COMM_LEN 16

int trace_tcp_connect(void *ctx) {

    struct net_event data = {};

    __u64 id = bpf_get_current_pid_tgid(); // Get combined PID and TGID
    data.pid = id >> 32; // Fetch PID

    bpf_get_current_comm(&data.comm, sizeof(data.comm)); // Fetch process name
    events.perf_submit(ctx, &data, sizeof(data)); // Submit event data to user space

    // Open to suggestions for additional data to capture (e.g., socket info, destination IP/port) 

    // Next possible feature: Capture socket information (e.g., destination IP and port) for TCP connect events.

    return 0;
}