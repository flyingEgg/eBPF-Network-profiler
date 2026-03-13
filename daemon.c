int trace_tcp_connect(void *ctx) {
    bpf_trace_printk("Nuova connessione TCP intercettata!\\n");
    return 0;
}