import os
import sys
import debugpy
import struct
import socket
import datetime


from scapy.layers.dns import DNS, DNSRR
from bcc import BPF
from ctypes import Structure, c_uint32, c_char, cast, POINTER
from DNSThread import DNSThread


# Class to represent the event data structure (must match the one in daemon.c)
class NetEvent(Structure):
    _fields_ = [
        ("pid", c_uint32),          # PID
        ("comm", c_char * 16)      # Process name (TASK_COMM_LEN)
    ]


dns_cache = {}          # This is an in-memory cache to store resolved DNS queries (hostname -> IP address)
dns_snopper = DNSThread(dns_cache, capture_dns_responses)

if os.geteuid() != 0: 
    print("This program must be run as root. Exiting.")
    exit(1)


# Debugpy launcher
if "--debug" in sys.argv:
    try:                            # If there are any errors, program will continue without debugging
        port = 10819
        debugpy.listen(port)
        print(f"Debugpy listening on port {port} - press F5 to attach debugger")
        debugpy.wait_for_client()
        print("Debugger attached, starting sensor...")
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
        exit(0);
    except RuntimeError as e:
        print(f"Error: port {port} is already in use. Please free the port or choose a different one.")
    except Exception as e:
        print(f"Unexpected error while setting up debugpy: {e}")
else:
    print ("Proceeding without debugger. To enable debugging, run with --debug flag.")


# Initialise
print("Compiling daemon...")
try:
    b = BPF(src_file="daemon.c")
except Exception as e:
    print(f"Error compiling BPF program: {e}")
    exit(1)

try:
    b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_tcp_connect")
    print(f"Hook tcp_v4_connect attached successfully.")
except Exception as ex:
    print(f"Error attaching kprobe to tcp_v4_connect: {ex}")
    sys.exit(1)

# Callback to process events from the kernel
def process_event(cpu, data, size):
    event = b["events"].event(data)

    #event = cast(data, POINTER(NetEvent)).contents
    process_name = event.comm.decode('utf-8', 'replace')

    ip_dest = socket.inet_ntop(socket.AF_INET, struct.pack("I", event.daddr))
    port_dest = socket.ntohs(event.dport)

    final_dest = dns_cache.get(ip_dest, ip_dest)  # Check if the IP address has a resolved hostname in the cache

    print(f"[{datetime.datetime.now()}] - New connection from \"{process_name}\", PID: {event.pid} -> {final_dest}:{port_dest}")

# Open the perf buffer to receive events from the kernel
b["events"].open_perf_buffer(process_event)

# User space
print("Ready! Listening new TCP connections... (Ctrl+C to quit)")

# trace_print() legge il buffer circolare dove bpf_trace_printk scrive i messaggi
try:
    while True:
        b.perf_buffer_poll(timeout=100)
except KeyboardInterrupt:
    print("\n"+"Closing sensor.")

def capture_dns_responses(pkt):
    if pkt.haslayer(DNSRR):
        try:
            for i in range(pkt[DNS].ancount):
                dns_rr = pkt[DNSRR][i]
                if dns_rr.type == 1:
                    solved_hostname = dns_rr.rdata
                    domain = dns_rr.rname.decode('utf-8').rstrip('.')

                   
                    dns_cache[solved_hostname] = domain
        except Exception as e:
            print(f"Error processing DNS response: {e}")
