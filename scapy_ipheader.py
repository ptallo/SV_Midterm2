import os
import sys
from scapy.all import *

# Imports from our project
from encoding_scheme import *
from utility import *


def main():
    # Create 1 packet for each character in the message
    message = "Hello World!"
    packets = [IP(dst="github.com") / TCP() for x in range(num_packets)]
    responses = []

    # Encode message into packet ID
    ip_steg = IpIdSteganography()
    ip_steg.encode_message_in_packets(packets, message)

    # Send packets, collect responses, display packets
    sys.stdout = open("output/packets.txt", 'w')
    for p in packets:
        response = sr1(p)
        responses.append(response)
        p.show()


if __name__ == "__main__":
    main()
