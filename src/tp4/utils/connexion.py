from src.tp4.utils.config import logger
import socket

class Connexion:
    def __init__(self):
        self.ip = "31.220.95.27"
        self.port = 13337
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def connect(self):
        self.s.connect((self.ip, self.port))
        logger.info(f"Connected to {self.ip}:{self.port}")

    def receive(self):
        data = self.s.recv(4096).decode("utf-8")
        logger.info(f"Received: {data}")
        return data

    def send(self, data):
        self.s.sendall(data + b"\n")

    def close(self):
        self.s.close()

