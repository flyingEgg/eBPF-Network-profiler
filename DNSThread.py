# Copyright (C) 2026  Giacomo Rossi giaco14mw@gmail.com
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.


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
    
    def alive_check(self):
        return self.thread.is_alive()
        