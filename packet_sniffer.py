import os
import sys
import utility
from scapy.all import *

# Imports from our project
from encoding_scheme import *

random.seed(utility.get_random_seed())
sequence_numbers = [random.randint(2 ** 31, 2 ** 32) for x in range(len(utility.get_one_time_pad()))]


def filter_packet(p):
    return p.haslayer(IP) and p.haslayer(TCP) and p[TCP].seq in sequence_numbers


def end_filter(p):
    return p[IP].id == utility.get_escape_sequence()


def main():
    # Generate the output folder if it does not exist
    output_path = "./output/"
    os.makedirs(output_path, exist_ok=True)

    # Sniff until num_packets packets match the BPF filter
    print("Sniffing...")
    sniffed_packets = sniff(store=True, lfilter=filter_packet, stop_filter=end_filter)

    sys.stdout = open(output_path + "recieved_packets.txt", 'w')
    ip_steg = IpIdSteganography()
    for p in sniffed_packets:
        p.show()

    sys.stdout = open(output_path + "message.txt", 'w')
    print(ip_steg.decode_message_from_packets(sniffed_packets, sequence_numbers))


if __name__ == "__main__":
    main()
