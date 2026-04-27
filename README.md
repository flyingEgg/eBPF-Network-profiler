# eBPF Network Profiler

A lightweight Linux profiler that intercepts outgoing TCP connections using eBPF, enriching each event with the originating process name and an asynchronous DNS resolution layer.

> Built with BCC/Python + Scapy. No kernel module required.

## How it works

```
Kernel Space                        User Space
─────────────────────────────────────────────────────────
kprobe on tcp_v4_connect            Main thread
  └─ populate net_event struct        └─ reads from perf buffer
  └─ submit to Perf Buffer            └─ cross-references DNS cache
                                      └─ prints enriched event

                                    DNS Snooper thread (daemon)
                                      └─ sniffs UDP/53 with Scapy
                                      └─ populates ip → domain cache
```

Each time a process opens a TCP connection, the kernel probe fires, bundles the PID, destination IP/port, and process name into a struct, and ships it to userspace via a **Perf Buffer**. Meanwhile, a background thread passively sniffs DNS responses and keeps a live cache — so most IPs are already resolved by the time they're printed.

---

## Requirements

**System**
- Linux kernel ≥ 4.9 (for kprobe + Perf Buffer support)
- Root / `CAP_BPF` + `CAP_NET_ADMIN` capabilities

**Python dependencies**
```bash
pip install bcc scapy
```

> `bcc` also requires the BCC toolkit installed at the system level:
> ```bash
> # Debian/Ubuntu
> sudo apt install bpfcc-tools python3-bpfcc linux-headers-$(uname -r)
>
> # Arch
> sudo pacman -S bcc bcc-tools python-bcc
> ```

---

## Project Structure

```
.
├── daemon.c          # eBPF kernel probe (kprobe on tcp_v4_connect)
├── net_sensor.py     # Python controller — loads BPF, handles events
└── DNSThread.py      # Async DNS snooper using Scapy
```

---

## Usage

```bash
sudo python3 net_sensor.py
```

Example output:
```
[2026-04-16 19:40:28.819845] - New connection from "node", PID: 3011 -> api.github.com:443
[2026-04-16 19:40:50.944022] - New connection from "Socket Thread", PID: 6839 -> www.google-analytics.com:443
```

---

## Architecture Notes

### Why mock structs instead of `vmlinux.h`?
Importing `vmlinux.h` in a BCC/Python environment causes redefinition conflicts with headers that BCC injects automatically. Mock structs using standard C types (`unsigned int`, `unsigned short`) sidestep this entirely while keeping the parser happy.

### Endianness
IP addresses and ports arrive in **Network Byte Order** (Big-Endian). The Python controller uses `socket.ntohs` and `struct.pack` to convert them before display.

### Memory safety in eBPF
Direct pointer dereferencing is forbidden by the eBPF verifier. All kernel memory reads go through `bpf_probe_read_kernel` — skipping this will cause the verifier to reject the program at load time.

### Async DNS resolution
DNS lookups are synchronous by nature and would bottleneck the event loop. The `DNSThread` sniffs UDP port 53 responses passively with Scapy, populating a shared `ip → domain` dict. No outbound DNS queries are made by the profiler itself.

---

## Possible future developements

- [ ] CO-RE migration (Compile Once – Run Everywhere) with `libbpf`
- [ ] TUI with [`Rich`](https://github.com/Textualize/rich)
- [ ] Hook on `tcp_close` for connection duration and byte count

---

## Contributing

This is an open project and contributions are welcome! If you're into eBPF, Linux internals, or network tooling — feel free to open an issue or a PR. Even just feedback on the architecture is appreciated.

