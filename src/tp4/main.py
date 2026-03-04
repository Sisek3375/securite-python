import src.tp4.utils.config as logger
from pwn import *
import base64
import socket

def main():
    logger.info("Starting TP4")

    ip = "31.220.95.27"
