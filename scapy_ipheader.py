import os
import sys
from scapy.all import *

# Imports from our project
from encoding_scheme import *
from utility import *


def main():
    message = "Hello World!"
    # Create 12 packets
    packets = [IP(dst="github.com") / TCP() for x in range(12)]
    responses = []

    # Encode message into packet ID
    IPSteg.encode_message_in_packets(packets, message)

    sniffedPackets = sniff(store=1, count=12)
    #TODO: add filter to sniff to throw out packets that do not match the IP src and dst

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
