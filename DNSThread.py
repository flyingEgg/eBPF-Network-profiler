import threading

from scapy.all import sniff

class DNSThread:
    def __init__(self, dns_cache, on_dns_captured):
        self.dns_cache = dns_cache
        self.callback = on_dns_captured
        self.thread = threading.Thread(
            target=lambda: sniff(filter="udp src port 53", prn=self.callback, store=0),
            daemon=True
        )

    def start(self):
        self.thread.start()
        