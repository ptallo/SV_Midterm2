import os
import sys
from scapy.all import *

# Imports from our project
from encoding_scheme import *
from utility import *


def main():
    # Create 1 packet for each character in the message
    message = "Hello World!"
    packets = [IP(dst="github.com") / TCP() for x in range(len(message))]
    responses = []

    # Encode message into packet ID
    ip_steg = IpIdSteganography()
    ip_steg.encode_message_in_packets(packets, message)

    # Send packets, collect responses, display packets
    send(packets)


if __name__ == "__main__":
    main()
