import os
import sys
from scapy.all import *
import time
import random

# Imports from our project
from encoding_scheme import *


shared_key = 6969
random.seed(shared_key)
max_sequence_value = 2 ** 32
random_sequence = random.randint(0, max_sequence_value)

def filter_packet(p):
    global random_sequence
    if p.haslayer(IP) and p.haslayer(TCP):
        print(p[TCP].seq)
        if p[TCP].seq == random_sequence:
            random_sequence = random.randint(0, max_sequence_value)
            print("got packet")
            return True
    return False


def end_filter(p):
    return p[IP].id == 65535


def main():
    # Generate the output folder if it does not exist
    output_path = "./output/"
    os.makedirs(output_path, exist_ok=True)

    # Sniff until num_packets packets match the BPF filter
    print("Sniffing...")
    sniffed_packets = sniff(store=True, lfilter=filter_packet, stop_filter=end_filter)

    sys.stdout = open(output_path + "message.txt", 'w')
    ip_steg = IpIdSteganography()
    print("MESSAGE: " + ip_steg.decode_message_from_packets(sniffed_packets) + "\n\n")
    for p in sniffed_packets:
        p.show()


if __name__ == "__main__":
    main()
