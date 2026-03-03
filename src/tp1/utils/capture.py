from tp1.utils.lib import choose_interface
from tp1.utils.config import logger
from scapy.all import sniff, Raw
from scapy.layers.inet import TCP, UDP, IP
from scapy.layers.l2 import ARP
import re
from urllib.parse import unquote


class Capture:
    def __init__(self):
        self.interface = choose_interface()
        self.protocols_count = {}
        self.alerts = []
        self.arp_table = {}

    def capture_traffic(self):
        logger.info("Capture in %s - Ctrl+C to stop.", self.interface)
        sniff(iface=self.interface, prn=self._process_packet, store=False)

    def _process_packet(self, packet):
        protocol = self._get_protocol(packet)
        self.protocols_count[protocol] = self.protocols_count.get(protocol, 0) + 1

        if packet.haslayer(ARP) and packet[ARP].op == 2:
            self._check_arp_spoofing(packet)

        if packet.haslayer(Raw):
            payload = unquote(packet[Raw].load.decode(errors="ignore"))
            self._check_sql_injection(packet, payload)

    def _get_protocol(self, packet):
        protocol = packet.lastlayer().name
        if protocol == "Raw":
            port = None
            if packet.haslayer(TCP):
                port = packet[TCP].dport
            elif packet.haslayer(UDP):
                port = packet[UDP].dport
            port_map = {80: "HTTP", 443: "HTTPS", 21: "FTP", 22: "SSH", 25: "SMTP"}
            protocol = port_map.get(port, "Raw")
        return protocol

    def _check_arp_spoofing(self, packet):
        ip = packet[ARP].psrc
        mac = packet[ARP].hwsrc

        if ip in self.arp_table and self.arp_table[ip] != mac:
            logger.warning("ARP Spoofing detected : %s (%s -> %s)", ip, self.arp_table[ip], mac)
            self.alerts.append({
                "threat": "ARP Spoofing",
                "protocol": "ARP",
                "src_ip": ip,
                "src_mac": mac,
            })

        self.arp_table[ip] = mac

    def _check_sql_injection(self, packet, payload):
        patterns = [
            r"(?i)'\s*(OR|AND)\s+1\s*=\s*1",
            r"(?i)UNION\s+(ALL\s+)?SELECT",
            r"(?i);\s*(DROP|DELETE|INSERT|UPDATE)",
            r"(?i)'\s*;\s*--",
            r"(?i)SLEEP\s*\(",
            r"(?i)'\s*OR\s+'.*'\s*=\s*'",
        ]

        for pattern in patterns:
            if re.search(pattern, payload):
                src_ip = packet[IP].src if packet.haslayer(IP) else "N/A"
                protocol = self._get_protocol(packet)
                logger.warning("SQL Injection detected from %s", src_ip)
                self.alerts.append({
                    "threat": "SQL Injection",
                    "protocol": protocol,
                    "src_ip": src_ip,
                    "src_mac": "N/A",
                })
                break

    def sort_network_protocols(self):
        return dict(sorted(self.protocols_count.items(), key=lambda x: x[1], reverse=True))

    def get_summary(self):
        return "\n".join(
            f"[{a['threat']}] ip: {a['src_ip']} | mac: {a['src_mac']}"
            for a in self.alerts
        )
