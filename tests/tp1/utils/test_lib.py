from scapy.all import get_if_list
from tp1.utils.config import logger


def choose_interface() -> str:
    """
    Return network interface and input user choice

    :return: network interface
    """
    interface = input("Choose network interface :")
    return interface

def main():
    choose_interface()