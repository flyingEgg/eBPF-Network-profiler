/*   
 *   Copyright (C) 2026  Giacomo Rossi giaco14mw@gmail.com
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <https://www.gnu.org/licenses/>.
 * 
 */

#include <linux/ptrace.h>

#define TASK_COMM_LEN 16

struct mock_sockaddr_in {
    unsigned short sin_family;
    unsigned short sin_port;   // Port number
    unsigned int   sin_addr;   // IPv4 address
};

struct mock_sock {
    unsigned int daddr;        // Dest address
    unsigned int rcv_saddr;    // Source address
    unsigned int hash;         // Socket hash (for identification)
    unsigned short dport;        // Dest port
    unsigned short lport;        // Local port
};

BPF_HASH(active_sessions, u64);

// Define a structure to hold event data (if needed)
struct net_event {
    unsigned int pid;                  // PID
    unsigned int daddr;
    unsigned short dport;
    char comm[TASK_COMM_LEN];   // Process name
    unsigned long long duration_ns; // Duration in nanoseconds
};
BPF_PERF_OUTPUT(events);   // Define a map to send events to user space

// Opens a connection
int trace_tcp_connect(struct pt_regs *ctx, void *sock, struct mock_sockaddr_in *uaddr) {
    __u64 start_ts = bpf_ktime_get_ns();    // Get start timestamp in nanoseconds
    __u64 sock_pts = (__u64)sock;           // Cast pointer as unique identifier

    active_sessions.update(&sock_pts, &start_ts);

    return 0;
}


int trace_tcp_close(struct pt_regs *ctx, struct mock_sock *sk) {

    __u64 sk_ptr = (__u64)sk;

    __u64 *start_ts = active_sessions.lookup(&sk_ptr);
    if (start_ts == 0){
        return 0; // Ignore if the connection started before running the program
    }    


    struct net_event data = {};

    __u64 id = bpf_get_current_pid_tgid(); // Get combined PID and TGID
    data.pid = id >> 32; // Fetch PID

    bpf_get_current_comm(&data.comm, sizeof(data.comm)); // Fetch process name

    bpf_probe_read_kernel(&data.daddr, sizeof(data.daddr), (void *)&sk->daddr);   // Read destination address from kernel memory
    bpf_probe_read_kernel(&data.dport, sizeof(data.dport), (void *)&sk->dport);   // Read destination port from kernel memory

    data.duration_ns = bpf_ktime_get_ns() - *start_ts;

    events.perf_submit(ctx, &data, sizeof(data)); // Submit event data to user space

    active_sessions.delete(&sk_ptr);
    return 0;
}
