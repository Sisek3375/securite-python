from scapy.all import get_if_list
from tp1.utils.config import logger


def choose_interface() -> str:
    """
    Return network interface and input user choice

    :return: network interface
    """
    interface_list = get_if_list()

    logger.info(interface_list)
    user_choice_interface = input("Enter the number for network interface: ")

    index = int(user_choice_interface)
    logger.info("you choose : %s", interface_list[index])
    interface = interface_list[index]

    return interface