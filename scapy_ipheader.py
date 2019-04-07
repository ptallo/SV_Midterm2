import os
import sys
from scapy.all import *

# Imports from our project
from encoding_scheme import *
from utility import *


def main():
    message = "Hello World!"
    num_packets = len(message)

    # Create 1 packet for each character in the message
    packets = [IP(dst="github.com") / TCP() for x in range(num_packets)]
    responses = []

    # Encode message into packet ID
    IPSteg.encode_message_in_packets(packets, message)

    # Create Berkeley Packet Filter (BPF) string for sniffing packets
    # Filter will throw out any packets that do not match the IP src and dst
    bpf_filter = "dst host github.com and src host localhost"

    # Sniff until num_packets packets match the BPF filter
    sniffedPackets = sniff(store=True, count=num_packets, filter=bpf_filter)

    # Send packets, collect responses, display packets
    sys.stdout = open("output/packets.txt", 'w')
    for p in packets:
        responses.append(sr1(p))
        p.show()

    sys.stdout = open("output/sniffedPackets.txt", 'w')
    for p in sniffedPackets:
        p.show()

    sys.stdout = open("output/responses.txt", 'w')
    # Display responses
    for i, r in enumerate(responses):
        print("Response {}".format(i))
        r.show()

    # Output the message
    sys.stdout = open("output/message.txt", 'w')
    print(IPSteg.decode_message_from_packets(responses))


def sniffPackets(packet):
    if packet.haslayer(IP):
        pckt_src = str(packet[IP].src)
        pckt_dst = str(packet[IP].dst)
        pckt_ttl = str(packet[IP].ttl)
        print("IP Packet:" + pckt_src + " is going to " + pckt_dst + " and has ttl value " + pckt_ttl)


if __name__ == "__main__":
    main()
