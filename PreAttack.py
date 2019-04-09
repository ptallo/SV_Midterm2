from logging import getLogger, ERROR
from scapy import *

class PreAttack:
    def __init__(self, target, interface):
        self.target = target
        self.interface = interface

    # Return the mac address using Scapy arp request
    def get_mac(self):
        return srp(Ethter(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=self.target), timeout= 10, iface=self.interface)[0][0][1][ARP].hwsrc

    class ToggleForward:
        def __init__(self, path = '/proc/sys/net/ipv4/ip_forward'):
            self.path = path

        # Turn on ip forwarding and returns true
        def enable_ip_forward(self):
            with open(self.path, 'wb') as file:
                file.write('1')
            return True

        # Turn off ip forwarding and returns false
        def disable_ip_forward(self):
            with open(self.path, 'wb') as file:
                file.write('0')
            return False
