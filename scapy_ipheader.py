import os
import sys
from scapy.all import *

# Imports from our project
from encoding_scheme import *
from utility import *


def main():
    # Generate the output folder if it does not exist
    output_path = "./output/"
    os.makedirs(output_path, exist_ok=True)

    # Create 1 packet for each character in the message
    message = "Phil is the best coder in the world and chris and solomon aren't"
    packets = [IP(dst="yahoo.com") / TCP() for x in range(len(message)+1)]

    # Encode message into packet ID
    ip_steg = IpIdSteganography()
    ip_steg.encode_message_in_packets(packets, message)

    # Send packets, collect responses, display packets
    send(packets)
    sys.stdout = open(output_path + "packets.txt", 'w')
    for p in packets:
        p.show()


if __name__ == "__main__":
    main()
