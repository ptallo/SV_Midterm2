import os
import sys
from scapy.all import *

# Imports from our project
from encoding_scheme import *
from utility import *

def filter_packet(p):
    return p[TCP].seq == 0

def end_filter(p):
    return p[IP].id == 65535

def main():
    # Create Berkeley Packet Filter (BPF) string for sniffing packets
    # Filter will throw out any packets that do not match the IP src and dst
    bpf_filter = "dst host yahoo.com"

    # Sniff until num_packets packets match the BPF filter
    sniffed_packets = sniff(store=True, filter=bpf_filter, lfilter=filter_packet, stop_filter=end_filter)

    sys.stdout = open("output/message.txt", 'w')
    ip_steg = IpIdSteganography()
    print("MESSAGE: " + ip_steg.decode_message_from_packets(sniffed_packets) + "\n\n")
    for p in sniffed_packets:
        p.show()


if __name__ == "__main__":
    main()
