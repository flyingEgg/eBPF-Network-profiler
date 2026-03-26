import os
import sys
import debugpy

from bcc import BPF

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

def process_event(cpu, data, size):
    event = b["events"].event(data)

    process_name = event.comm.decode('utf-8', 'replace')
    print(f"New connection from PID: {event.pid} - Process Name: {process_name}")

if os.geteuid() != 0: 
    print("This program must be run as root. Exiting.")
    exit(1)


# Initialise
print("Compiling daemon...")
try:
    b = BPF(src_file="daemon.c")
except Exception as e:
    print(f"Error compiling BPF program: {e}")
    exit(1)


# Kernel must hook up the C function to sys event 'tcp_v4_connect'
b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_tcp_connect")

# User space
print("Ready! Listening new TCP connections... (Ctrl+C to quit)")

# trace_print() legge il buffer circolare dove bpf_trace_printk scrive i messaggi
try:
    b.trace_print()
except KeyboardInterrupt:
    print("\n"+"Closing sensor.")