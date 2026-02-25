from fpdf import FPDF
import matplotlib.pyplot as plt
import tempfile
from tp1.utils.capture import Capture

class Report:
    def __init__(self, capture: Capture, filename: str):
        self.capture = capture
        self.filename = filename
        self.pdf = FPDF()

    def _generate_title(self) -> None:
        self.pdf.add_page()
        self.pdf.set_font("Helvetica", "B", 16)
        self.pdf.cell(0, 10, "Rapport d'analyse réseau", ln=True, align="C")
        self.pdf.ln(10)

    def _generate_array(self) -> None:
        self.pdf.set_font("Helvetica", "B", 12)
        self.pdf.cell(0, 10, "Alarmes détectées", ln=True)
        self.pdf.set_font("Helvetica", size=10)

        # Header du tableau
        self.pdf.set_fill_color(200, 200, 200)
        self.pdf.cell(50, 8, "Type", border=1, fill=True)
        self.pdf.cell(40, 8, "Protocole", border=1, fill=True)
        self.pdf.cell(50, 8, "IP Source", border=1, fill=True)
        self.pdf.cell(50, 8, "MAC Source", border=1, ln=True, fill=True)

        # Lignes
        for alert in self.capture.alerts:
            self.pdf.cell(50, 8, alert["threat"], border=1)
            self.pdf.cell(40, 8, alert["protocol"], border=1)
            self.pdf.cell(50, 8, alert["src_ip"], border=1)
            self.pdf.cell(50, 8, alert["src_mac"], border=1, ln=True)

        self.pdf.ln(10)

    def _generate_graph(self) -> None:
        protocols = self.capture.sort_network_protocols()

        # Générer le graphique avec matplotlib
        fig, ax = plt.subplots()
        ax.pie(protocols.values(), labels=protocols.keys(), autopct="%1.1f%%")
        ax.set_title("Répartition des protocoles")

        # Sauvegarder en image temporaire
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp:
            fig.savefig(tmp.name)
            self.pdf.set_font("Helvetica", "B", 12)
            self.pdf.cell(0, 10, "Répartition des protocoles", ln=True)
            self.pdf.image(tmp.name, w=150)

        plt.close(fig)

    def generate(self) -> None:
        self._generate_title()
        self._generate_array()
        self._generate_graph()

    def save(self) -> None:
        self.generate()
        self.pdf.output(self.filename)