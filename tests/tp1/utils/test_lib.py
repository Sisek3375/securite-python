from scapy.all import get_if_list
from tp1.utils.config import logger
from tp1.utils.lib import choose_interface

def test_choose_interface_returns_string():
    assert choose_interface(["eth0", "wlan0"], 0) == "eth0"

def test_choose_interface_index_out_of_range():
    assert choose_interface(["eth0", "wlan0"], 99) == "Invalid network interface"