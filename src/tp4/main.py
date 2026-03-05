from src.tp4.utils.config import logger
from src.tp4.utils.connexion import Connexion
from pwn import *
import base64
import socket

def main():
    logger.info("Starting TP4")
    connexion = Connexion()
    logger.info("Starting server")
    connexion.connect()
    data = connexion.receive()
    line = data.strip().decode("utf-8")
    encoded = line.split(": "[-1])
    decoded = bytes.fromhex(encoded[0])
    connexion.send(decoded).encode()

    connexion.receive()
    connexion.close()

if __name__ == "__main__":
    main()