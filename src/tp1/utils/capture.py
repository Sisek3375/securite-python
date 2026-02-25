from scapy.modules.p0f import packet2p0f

from src.tp1.utils.lib import choose_interface
from tp1.utils.config import logger
from scapy.all import sniff, packet

class Capture:
    def __init__(self) -> None:
        self.interface = choose_interface()
        self.summary = ""
        self.packets = []

    def capture_traffic(self) -> None:
        """
        Capture network traffic from an interface
        """
        logger.info(f"Capture traffic from interface : %s - Press Ctrl + C to stop", self.interface)
        sniff(iface=self.interface, prn=self.sort_network_protocols, store=False)

    def _process_packet(self):
        """
        Process each packet in real time
        """
        self.packets.append(packet)
        logger.info("Packet captured: %s", packet.summary())
        self.analyse(packet)

    def sort_network_protocols(self):
        """
        Sort and return all captured network protocols
        """
        protocols = {}
        for packet in self.packets:
            layer = packet.lastlayer()
            protocol_name = layer.name
            protocols[protocol_name] = protocols.get(protocol_name, 0) + 1
        return protocols

    def get_all_protocols(self) -> str:
        """
        Return all protocols captured with total packets number
        """
        return ""

    def analyse(self, protocols: str) -> None:
        """
        Analyse all captured data and return statement
        Si un tra c est illégitime (exemple : Injection SQL, ARP
        Spoo ng, etc)
        a Noter la tentative d'attaque.
        b Relever le protocole ainsi que l'adresse réseau/physique
        de l'attaquant.
        c (FACULTATIF) Opérer le blocage de la machine
        attaquante.
        Sinon a cher que tout va bien
        """
        all_protocols = self.get_all_protocols()
        sort = self.sort_network_protocols()
        logger.debug(f"All protocols: {all_protocols}")
        logger.debug(f"Sorted protocols: {sort}")

        self.summary = self._gen_summary()

    def get_summary(self) -> str:
        """
        Return summary
        :return:
        """
        return self.summary

    def _gen_summary(self) -> str:
        """
        Generate summary
        """
        summary = ""
        return summary
