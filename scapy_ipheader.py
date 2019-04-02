import os
import sys
from scapy.all import *


def main():
    message = "Hello World!"
    # Create 12 packets
    packets = [IP(dst="github.com") / TCP() for x in range(12)]
    responses = []

    # Encode message into packet ID
    encode_message_in_packets(packets, message)

    sys.stdout = open("output/packets.txt", 'w')

    sniffedPackets = sniff(store=1, count=12)

    # Send packets, collect responses, display packets
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
    print(decode_message_from_packets(responses))


def sniffPackets(packet):
    if packet.haslayer(IP):
        pckt_src = str(packet[IP].src)
        pckt_dst = str(packet[IP].dst)
        pckt_ttl = str(packet[IP].ttl)
        print("IP Packet:" + pckt_src + " is going to " + pckt_dst + " and has ttl value " + pckt_ttl)


def encode_message_in_packets(packets, message):
    for i, c in enumerate(message):
        packets[i][IP].id = encode_character_in_string(packets[i][IP].id, c)


def encode_character_in_string(string_to_modify, character):
    bits_to_encode = string_to_bits(string_to_modify)
    code_bits = string_to_bits(character)
    bits_to_encode[len(bits_to_encode) - len(code_bits):] = code_bits
    return bits_to_encode


def decode_message_from_packets(packets):
    message = []
    for p in packets:
        message.append(decode_character_from_packet(p))
    return "".join(message)


def decode_character_from_packet(p):
    return "A"


def string_to_bits(s):
    result = []
    for c in s:
        bits = bin(ord(c))[2:]
        bits = '00000000'[len(bits):] + bits
        result.extend([int(b) for b in bits])
    return result


def bits_to_string(bits):
    chars = []
    for b in range(int(len(bits) / 8)):
        byte = bits[b * 8:(b + 1) * 8]
        chars.append(chr(int(''.join([str(bit) for bit in byte]), 2)))
    return ''.join(chars)


if __name__ == "__main__":
    main()
