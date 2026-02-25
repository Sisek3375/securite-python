from src.tp1.utils.lib import choose_interface
from tp1.utils.config import logger
from scapy.all import sniff, Raw
from scapy.layers.inet import TCP, UDP, IP
from scapy.layers.l2 import ARP
import re

class Capture:
    def __init__(self) -> None:
        self.interface = choose_interface()
        self.protocols_count = {}
        self.alerts = []
        self.summary = ""
        self._arp_table = {}

    def capture_traffic(self) -> None:
        logger.info("Capture traffic from interface : %s - Press Ctrl + C to stop", self.interface)
        sniff(iface=self.interface, prn=self._process_packet, store=False)

    def _process_packet(self, packet) -> None:
        protocol = self._get_protocol(packet)
        self.protocols_count[protocol] = self.protocols_count.get(protocol, 0) + 1
        logger.info("Packet captured: [%s] %s", protocol, packet.summary())
        self.analyse(packet)

    def _get_protocol(self, packet) -> str:
        protocol = packet.lastlayer().name
        if protocol == "Raw":
            port = None
            if packet.haslayer(TCP):
                port = packet[TCP].dport
            elif packet.haslayer(UDP):
                port = packet[UDP].dport
            port_map = {80: "HTTP", 443: "HTTPS", 21: "FTP", 22: "SSH", 25: "SMTP", 8080: "HTTP"}
            protocol = port_map.get(port, "Raw")
        return protocol

    def sort_network_protocols(self) -> dict:
        return dict(sorted(self.protocols_count.items(), key=lambda x: x[1], reverse=True))

    def analyse(self, packet) -> None:
        if self.arp_poisoning(packet):
            self._alarm(packet, "ARP Poisoning")
            return

        if packet.haslayer(Raw):
            payload = packet[Raw].load.decode(errors="ignore")
            if self.sql_injection(payload):
                self._alarm(packet, "SQL Injection")
            if self.xss_injection(payload):
                self._alarm(packet, "XSS")

    def _alarm(self, packet, threat_type) -> None:
        src_ip = packet[IP].src if packet.haslayer(IP) else "N/A"
        src_mac = packet[ARP].hwsrc if packet.haslayer(ARP) else "N/A"
        protocol = self._get_protocol(packet)

        alert = {
            "threat": threat_type,
            "protocol": protocol,
            "src_ip": src_ip,
            "src_mac": src_mac,
        }
        self.alerts.append(alert)
        logger.warning("[ALARME] %s | protocole: %s | src_ip: %s | src_mac: %s", threat_type, protocol, src_ip, src_mac)

    def sql_injection(self, payload: str) -> bool:
        patterns = [
            r"(?i)(select|union|insert|drop|update|delete|from|where)",
            r"(?i)(or\s+1=1|and\s+1=1)",
            r"'.*--",
            r";.*--"
        ]
        return any(re.search(p, payload) for p in patterns)

    def xss_injection(self, payload: str) -> bool:
        patterns = [
            r"(?i)<script.*?>",
            r"(?i)javascript:",
            r"(?i)on\w+\s*=",
        ]
        return any(re.search(p, payload) for p in patterns)

    def arp_poisoning(self, packet) -> bool:
        if packet.haslayer(ARP) and packet[ARP].op == 2:
            ip = packet[ARP].psrc
            mac = packet[ARP].hwsrc
            if ip in self._arp_table and self._arp_table[ip] != mac:
                return True
            self._arp_table[ip] = mac
        return False

    def get_summary(self) -> str:
        return "\n".join(
            f"[{a['threat']}] protocole: {a['protocol']} | src_ip: {a['src_ip']} | src_mac: {a['src_mac']}"
            for a in self.alerts
        )