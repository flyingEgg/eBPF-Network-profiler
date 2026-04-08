#include <linux/ptrace.h>

#define TASK_COMM_LEN 16

// Define a structure to hold event data (if needed)
struct net_event {
    __u32 pid;                  // PID
    char comm[TASK_COMM_LEN];   // Process name
};
BPF_PERF_OUTPUT(events);   // Define a map to send events to user space


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