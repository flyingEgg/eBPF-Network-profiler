from bcc import BPF


# Initialise
print("Compiling daemon...")
b = BPF(src_file="daemon.c")


# Kernel must hook up the C function to sys event 'tcp_v4_connect'
b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_tcp_connect")

# User space
print("Ready! Listening new TCP connections... (Ctrl+C to quit)")

# trace_print() legge il buffer circolare dove bpf_trace_printk scrive i messaggi
try:
    b.trace_print()
except KeyboardInterrupt:
    print("\n"+"Closing sensor.")