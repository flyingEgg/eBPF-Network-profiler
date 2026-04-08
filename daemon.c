#include <linux/ptrace.h>

#define TASK_COMM_LEN 16

struct mock_sock {
    unsigned int daddr;        // Dest address
    unsigned int rcv_saddr;    // Source address
    unsigned int hash;         // Socket hash (for identification)
    unsigned short dport;        // Dest port
    unsigned short lport;        // Local port
};

// Define a structure to hold event data (if needed)
struct net_event {
    unsigned int pid;                  // PID
    unsigned int daddr;
    unsigned short dport;
    char comm[TASK_COMM_LEN];   // Process name
};
BPF_PERF_OUTPUT(events);   // Define a map to send events to user space


int trace_tcp_connect(struct pt_regs *ctx, struct mock_sock *sock) {

    struct net_event data = {};

    __u64 id = bpf_get_current_pid_tgid(); // Get combined PID and TGID
    data.pid = id >> 32; // Fetch PID

    bpf_get_current_comm(&data.comm, sizeof(data.comm)); // Fetch process name

    data.daddr = sock->daddr; // Capture destination address
    data.dport = sock->dport; // Capture destination port

    events.perf_submit(ctx, &data, sizeof(data)); // Submit event data to user space

    return 0;
}