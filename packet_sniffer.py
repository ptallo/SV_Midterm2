import os
import sys
from scapy.all import *

# Imports from our project
from encoding_scheme import *

random.seed(6969)
max_sequence_value = 2 ** 32
next_sequence_number = random.randint(0, max_sequence_value)


def filter_packet(p):
    global next_sequence_number
    if p.haslayer(IP) and p.haslayer(TCP) and p[TCP].seq == next_sequence_number:
        next_sequence_number = random.randint(0, max_sequence_value)
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
