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

// Define a structure to hold event data (if needed)
struct net_event {
    unsigned int pid;                  // PID
    unsigned int daddr;
    unsigned short dport;
    char comm[TASK_COMM_LEN];   // Process name
};
BPF_PERF_OUTPUT(events);   // Define a map to send events to user space


int trace_tcp_connect(struct pt_regs *ctx, void *sock, struct mock_sockaddr_in *uaddr) {

    struct net_event data = {};

    __u64 id = bpf_get_current_pid_tgid(); // Get combined PID and TGID
    data.pid = id >> 32; // Fetch PID

    bpf_get_current_comm(&data.comm, sizeof(data.comm)); // Fetch process name

    bpf_probe_read_kernel(&data.daddr, sizeof(data.daddr), (void *)&uaddr->sin_addr);   // Read destination address from kernel memory
    bpf_probe_read_kernel(&data.dport, sizeof(data.dport), (void *)&uaddr->sin_port);   // Read destination port from kernel memory

    events.perf_submit(ctx, &data, sizeof(data)); // Submit event data to user space

    return 0;
}
